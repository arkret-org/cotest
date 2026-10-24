//! Accepted private runtime reply recovered by one bounded Account attempt.

use arkret_models_collaboration::agent_sidecar::{
    AgentSidecarEventExchangeBinding, AgentSidecarExchangeRequestContext, AgentSidecarExchangeRole,
    AgentSidecarExchangeStatus, SidecarSourceTrackRef,
};
use cotest::scenarios::agent_runtime_live::AgentRuntimeSession;
use cotest::scenarios::mls_lifecycle_live::{
    accepted_full_view, canonical, fresh_uuid_v7, post_json,
};
use cotest::scenarios::sidecar_authority_live::PrivateAgentReadyContext;

use super::*;

pub(super) const CASE: &str = "sidecar_missing_tail_recovers_automatically_without_another_request";

struct PrivateReplyProbe {
    relay: RefCell<Option<cotest::harness::ScanGapRelay>>,
    directory: tempfile::TempDir,
    reader: std::path::PathBuf,
    result: RefCell<Option<super::super::CaseExecutionResult>>,
}

struct HealingRail {
    http: arkret_http_client::Client,
    fault: cotest::harness::ScanGapControl,
    path: std::path::PathBuf,
    scope: ScopeRef,
    account: arkret_wire::AccountId,
    before: Value,
    before_cut: (
        arkret_wire::RealmStateSnapshot,
        Vec<arkret_wire::CommittedEventFullView>,
    ),
    before_projection: Value,
    cursor: String,
    database_url: String,
    ack: String,
    ack_before: String,
    business_before: String,
    requests: Mutex<Vec<AccountSubscribeParameters>>,
    initial_scans: Mutex<Vec<arkret_wire::StreamScanRequestBody>>,
    dependencies: Mutex<Vec<Vec<arkret_wire::CommittedEventRef>>>,
}

const BUSINESS: &str = "SELECT jsonb_build_object(\
 'events',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY pk),'[]') FROM canonical_events t),\
 'commits',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY commit_id),'[]') FROM realm_commits t),\
 'welcomes',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]') FROM mls_welcome_deliveries t),\
 'queue',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY id),'[]') FROM device_messages t),\
 'requests',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY key),'[]') FROM device_message_txns t),\
 'messages',(SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY message_key),'[]') FROM device_message_idempotency t)\
 )::text";
const ACK: &str =
    "SELECT row_to_json(t)::text FROM device_message_ack_tokens t WHERE acknowledgement_token=$1";

fn business_evidence(database_url: &str) -> Result<String> {
    tokio::task::block_in_place(|| {
        let mut database = postgres::Client::connect(database_url, postgres::NoTls)?;
        let mut transaction = database
            .build_transaction()
            .isolation_level(postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()?;
        let core: String = transaction.query_one(BUSINESS, &[])?.get(0);
        let tables=transaction.query("SELECT tablename FROM pg_tables WHERE schemaname='public' AND (tablename LIKE '%\\_current_states' ESCAPE '\\' OR tablename IN ('current_state_heads','current_selector_origins','governance_current_ready','realm_authorities','replica_stream_anchors','replica_authorization_cuts','replica_authorization_rows','account_datas','account_data_changes')) ORDER BY tablename",&[])?;
        let mut currents = std::collections::BTreeMap::new();
        for row in tables {
            let table: String = row.get(0);
            ensure!(
                table
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
                "invalid current table name"
            );
            let sql = format!(
                "SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]')::text FROM public.\"{table}\" t"
            );
            let value: String = transaction.query_one(&sql, &[])?.get(0);
            currents.insert(table, value);
        }
        transaction.commit()?;
        Ok(serde_json::to_string(&(core, currents))?)
    })
}

fn changed_business_components(before: &str, after: &str) -> Result<Vec<String>> {
    let left: (String, std::collections::BTreeMap<String, String>) = serde_json::from_str(before)?;
    let right: (String, std::collections::BTreeMap<String, String>) = serde_json::from_str(after)?;
    let left_core: Value = serde_json::from_str(&left.0)?;
    let right_core: Value = serde_json::from_str(&right.0)?;
    let mut changed = left_core
        .as_object()
        .context("business core")?
        .keys()
        .filter(|key| left_core[*key] != right_core[*key])
        .cloned()
        .collect::<Vec<_>>();
    changed.extend(
        left.1
            .keys()
            .filter(|key| left.1.get(*key) != right.1.get(*key))
            .cloned(),
    );
    Ok(changed)
}

async fn await_franking(
    event: &arkret_wire::EventId,
    realm: &arkret_wire::RealmId,
    database_url: &str,
) -> Result<arkret_wire::CommittedEventFullView> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        // Observe completion of the genuine publication job without requiring
        // its private proof body to be disclosed on an ordinary Realm scan.
        let carrier = read_database_evidence(
            database_url,
            "SELECT COALESCE((SELECT jsonb_build_object('event',e.envelope,'commit',c.commit_json)::text FROM moderation_franking_proof_current_states r JOIN realm_commits c ON c.commit_id=r.current_commit_id AND c.realm_id=r.realm_id AND c.stream_position=r.current_stream_position JOIN canonical_events e ON e.pk=c.event_pk WHERE r.realm_id=$1 AND r.target_event_id=$2),'null')",
            &[&realm.as_str(), &event.as_str()],
        )?;
        let pending = read_database_evidence(
            database_url,
            "SELECT COUNT(*)::text FROM moderation_franking_jobs WHERE realm_id=$1 AND target_event_id=$2",
            &[&realm.as_str(), &event.as_str()],
        )?;
        if carrier != "null" && pending == "0" {
            let proof: arkret_wire::CommittedEventFullView = serde_json::from_str(&carrier)?;
            proof.validate_shape()?;
            ensure!(
                proof.event.kind == arkret_wire::EventKind::ModerationFrankingProof
                    && proof.event.payload["event_id"] == event.as_str(),
                "franking target changed"
            );
            return Ok(proof);
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "actual franking publication did not settle"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

impl AccountSubscribeTransport for HealingRail {
    async fn subscribe(
        &self,
        request: &AccountSubscribeParameters,
    ) -> garth::Result<AccountSubscribeSnapshotResult> {
        let attempt = {
            let mut requests = self.requests.lock().unwrap();
            if let Some(first) = requests.first()
                && serde_json::to_value(first).unwrap() != serde_json::to_value(request).unwrap()
            {
                return Err(garth::Error::Protocol(
                    "automatic retry replaced its frozen Account request".into(),
                ));
            }
            requests.push(request.clone());
            requests.len()
        };
        let held = (|| -> Result<()> {
            ensure!(
                attempt <= 2,
                "private tail recovery exceeded its two available attempts"
            );
            if attempt == 2 {
                ensure!(
                    !self.fault.observations().is_empty(),
                    "retry occurred without the actual HTTP missing row"
                );
                let mut store = inkson::LocalStateStore::with_path(&self.path);
                inkson::conformance::hydrate_native_private_cache(&mut store)?;
                ensure!(
                    store.sync_cursor().as_deref() == Some(self.cursor.as_str()),
                    "missing tail advanced the Account checkpoint"
                );
                ensure!(
                    inkson::conformance::retained_sidecar_cut(&store, &self.scope)?
                        == self.before_cut,
                    "missing tail changed private history or typed current"
                );
                let state = serde_json::to_value(store.load())?;
                ensure!(
                    state["mls_snapshots"] == self.before["mls_snapshots"],
                    "missing tail reset nonempty MLS private state"
                );
                ensure!(
                    serde_json::to_value(inkson::sidecar::cached_sidecar_exchange_projections(
                        &store,
                        &self.account,
                        self.scope.realm_id().as_str()
                    )?)? == self.before_projection,
                    "missing reply changed the original discussion projection"
                );
                ensure!(
                    read_database_evidence(&self.database_url, ACK, &[&self.ack])?
                        == self.ack_before,
                    "missing tail invalidated the exact issued ACK"
                );
                let business_after = business_evidence(&self.database_url)?;
                ensure!(
                    business_after == self.business_before,
                    "automatic retry changed business components: {:?}",
                    changed_business_components(&self.business_before, &business_after)?
                );
                *self.initial_scans.lock().unwrap() = self.fault.scan_requests();
                // Dependencies become available while the original Account call
                // is still pending. No application refresh or request is issued.
                self.fault.clear();
            }
            Ok(())
        })();
        held.map_err(|error| garth::Error::Protocol(format!("private retry boundary: {error:#}")))?;
        let batch = self.http.account_subscribe_batch(request).await?;
        let stream = arkret_wire::CommitStreamRef::from_scope(&self.scope, None)
            .map_err(|error| garth::Error::Protocol(error.to_string()))?;
        self.dependencies.lock().unwrap().push(
            batch
                .frames
                .iter()
                .flat_map(|frame| &frame.realms)
                .flat_map(|realms| realms.entries.values())
                .flat_map(|entry| entry.streams.iter().flatten())
                .filter(|window| window.stream_ref == stream)
                .filter_map(|window| window.window_start_basis.as_ref())
                .flat_map(|basis| basis.accepted_dependency_refs.iter().flatten().cloned())
                .collect(),
        );
        Ok(AccountSubscribeSnapshotResult::Batch(batch))
    }
}

fn metadata(binding: &AgentSidecarEventExchangeBinding) -> Result<Vec<u8>> {
    binding.validate_shape()?;
    let mut value = arkret::MessageMetadata::default();
    value.extra.insert(
        "sidecar_exchange_binding".into(),
        serde_json::to_value(binding)?,
    );
    Ok(arkret_canonical::canonical_json_bytes(&value)?)
}

fn seal(
    group: &mut arkret::ArkretMlsGroup,
    scope: &ScopeRef,
    state_ref: &arkret_wire::EventId,
    content_type: &str,
    bytes: &[u8],
) -> Result<arkret::EncryptedPayload> {
    let header = arkret::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        content_type,
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        scope.clone(),
        arkret_wire::EventKind::MessageCreate.as_str(),
        group.epoch(),
        state_ref.clone(),
        group.local_content_sender_domain()?,
        arkret::EventContentRoutingContext::None,
    )?;
    Ok(arkret::MessageCrypto::encrypt(group, fresh_uuid_v7(), header, bytes)?.payload)
}

#[async_trait::async_trait(?Send)]
impl SidecarSyncObserver for PrivateReplyProbe {
    fn requires_private_agent_reply(&self) -> bool {
        true
    }
    async fn before_station(&self, station: &mut cotest::harness::ArkretServer) -> Result<()> {
        *self.relay.borrow_mut() = Some(station.install_scan_gap_relay().await?);
        Ok(())
    }
    async fn before_genesis(&self, _controller: &Member, _scope: &ScopeRef) -> Result<()> {
        Ok(())
    }
    async fn after_genesis(
        &self,
        _controller: &Member,
        _other: &Member,
        _genesis: &Event,
        _group: &arkret::ArkretMlsGroup,
        _database: &str,
    ) -> Result<()> {
        Ok(())
    }

    async fn private_agent_ready(
        &self,
        controller: &Member,
        agent: &AgentRuntimeSession,
        controller_group: &mut arkret::ArkretMlsGroup,
        agent_group: &mut arkret::ArkretMlsGroup,
        accepted: &arkret_wire::CommittedEventFullView,
        context: PrivateAgentReadyContext<'_>,
    ) -> Result<()> {
        let PrivateAgentReadyContext { database_url, .. } = context;
        let scope = &accepted.event.scope_ref;
        let realm = scope.realm_id();
        let selection = arkret::ParticipationReplaceRequestBody {
            target_scope: arkret::ParticipationScope::Realm {
                realm_id: realm.clone(),
            },
            selection: arkret::ParticipationBits {
                message_creation_allowed: true,
                ..arkret::ParticipationBits::NONE
            },
            expected_version: 0,
        };
        let selected = controller
            .client
            .sdk()
            .agent_participation_replace(agent.agent_account.principal_id.as_str(), &selection)
            .await?;
        ensure!(
            selected
                .agent_participation_entries
                .iter()
                .any(|entry| entry.scope == selection.target_scope
                    && entry.selection == selection.selection
                    && entry.version == 1),
            "controller private reply selection was not installed"
        );
        controller
            .client
            .grant_realm_actions_to(
                realm.as_str(),
                agent.agent_did.as_str(),
                &["ak.message.create"],
            )
            .await?;
        let session =
            super::super::account_blocklist_projection::native_account_session(&controller.client)
                .await?;
        let path = self.directory.path().join("state.json");
        let host = NativeAccountHost::new_for_realm(
            session.client(),
            controller.account.clone(),
            controller.device.clone(),
            inkson::LocalStateStore::with_path(path.clone()),
            realm.clone(),
        )
        .await?;
        let secret = "private-sidecar-runtime-checkpoint-secret";
        let secure = inkson::secure_key_store::default_secure_key_store("inkson");
        inkson::mls::runtime::store_account_mls_secret(
            secure.as_ref(),
            &controller.account,
            secret,
        )?;
        let record = controller_group.export_state_record()?;
        ensure!(
            record.epoch == 1,
            "runtime join did not preserve the actual accepted Add epoch"
        );
        let mut checkpoint = garth::mls::checkpoint::encrypt_state(
            realm.as_str(),
            &record.group_id,
            record.epoch,
            &serde_json::to_vec(&record)?,
            secret,
            b"private-sidecar-runtime",
        );
        checkpoint.group_state_event_id = Some(accepted.event.event_id.clone());
        host.state_store_handle().write(|store| -> Result<()> {
            store
                .save_mls_checkpoint_for_scope(scope, checkpoint.clone())
                .map_err(anyhow::Error::msg)?;
            store
                .record_mls_group_state_ref_for_scope(
                    scope,
                    &record.group_id,
                    1,
                    accepted.event.event_id.clone(),
                )
                .map_err(anyhow::Error::msg)?;
            store.flush()?;
            Ok(())
        })?;
        host.catch_up_selected_realm_until_complete(realm).await?;
        host.refresh_authoring_authority().await?;
        let strand =
            arkret_wire::StrandId::new(controller.client.default_strand_id(realm.as_str())?)?;
        let source = SidecarSourceTrackRef {
            realm_id: realm.clone(),
            strand_id: strand.clone(),
            track_name: "discussion".into(),
        };
        let binding = AgentSidecarEventExchangeBinding {
            schema: arkret_wire::SchemaId::AGENT_SIDECAR_EVENT_EXCHANGE_BINDING_V1.into(),
            exchange_id: fresh_uuid_v7().replace('-', ""),
            role: AgentSidecarExchangeRole::Request,
            request_event_id: None,
            completes_exchange: None,
            coordinator_assignment_event_id: None,
            request_context: Some(AgentSidecarExchangeRequestContext {
                source_track_ref: source.clone(),
                source_hlc: arkret_hlc::HlcGenerator::new(
                    realm.as_str(),
                    controller.device.as_str(),
                    b"private-source-order",
                )
                .generate(),
                client_order_key: "private-source-order-1".into(),
                addressed_agent_ids: vec![agent.agent_account.principal_id.clone()],
                coordinator_agent_id: None,
                source_checkpoint_anchor_id: None,
            }),
        };
        let request_plain = arkret_canonical::canonical_json_bytes(&arkret::ContentBlock::text(
            "Return the private Sidecar recovery receipt",
        ))?;
        let request_metadata = metadata(&binding)?;
        let (request_content, request_meta) = host.state_store_handle().write(|store| {
            inkson::conformance::encrypt_private_sidecar_request(
                store,
                &controller.account,
                &controller.device,
                scope,
                accepted.event.event_id.clone(),
                &request_plain,
                &request_metadata,
            )
        })?;
        inkson::conformance::persist_native_private_cache(&host.state_store()).await?;
        let mut request=controller.client.author_event(realm.as_str(),arkret_wire::EventKind::MessageCreate.as_str(),canonical(serde_json::json!({
            "strand_id":strand,"track_name":"discussion","encrypted_content":request_content.to_envelope()?,
            "encrypted_metadata":request_meta.to_envelope()?,
        }))?).await?;
        request.scope_ref = scope.clone();
        cotest::harness::refresh_typed_event_proof(&mut request)?;
        let mut agent_executions = 0usize;
        let (status, outcome) = post_json(
            &controller.client,
            &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
                arkret_wire::EventAdmissionSubmission::new(request.clone()),
            ),
        )
        .await?;
        ensure!(
            status == reqwest::StatusCode::OK,
            "private request refused: {status} {outcome}"
        );
        let request_accepted = accepted_full_view(&controller.client, &request.event_id).await?;
        await_franking(&request.event_id, realm, database_url).await?;
        let cursor_before_readback = host.state_store().sync_cursor();
        let readback_fault = self
            .relay
            .borrow()
            .as_ref()
            .context("readback HTTP relay")?
            .control();
        readback_fault.clear_scan_requests();
        inkson::conformance::read_back_native_accepted_sidecar(
            &session.client(),
            &controller.account,
            scope,
            &request.event_id,
            host.state_store_handle(),
        )
        .await?;
        let readback_scans = readback_fault.scan_requests();
        ensure!(
            readback_scans
                .iter()
                .any(|scan| scan.stream_ref == request_accepted.commit.stream_ref),
            "accepted readback did not issue an independent private history request"
        );
        let readback_cut = inkson::conformance::retained_sidecar_cut(&host.state_store(), scope)?;
        ensure!(
            readback_cut.1.last() == Some(&request_accepted),
            "accepted private readback did not durably install the exact request cut"
        );
        ensure!(
            host.state_store().sync_cursor() == cursor_before_readback,
            "independent readback advanced the Account subscription cursor"
        );
        let readback_projection = inkson::sidecar::cached_sidecar_exchange_projections(
            &host.state_store(),
            &controller.account,
            realm.as_str(),
        )?;
        ensure!(
            readback_projection
                .iter()
                .any(|p| p.private_request_event_id == request.event_id
                    && p.source_track_ref == source),
            "accepted readback did not publish the authenticated source-card request"
        );
        let readback_mls = host
            .state_store()
            .mls_checkpoint_for_scope(scope)
            .context("accepted readback lost the native MLS checkpoint")?;
        ensure!(
            readback_mls.epoch == 1
                && readback_mls.group_state_event_id.as_ref() == Some(&accepted.event.event_id),
            "accepted readback changed its exact MLS basis"
        );
        host.catch_up_selected_realm_until_complete(realm).await?;
        let prior_projection = inkson::sidecar::cached_sidecar_exchange_projections(
            &host.state_store(),
            &controller.account,
            realm.as_str(),
        )?;
        ensure!(
            prior_projection.len() == 1
                && prior_projection[0].source_track_ref == source
                && prior_projection[0].private_request_event_id == request.event_id
                && prior_projection[0].status == AgentSidecarExchangeStatus::Delivered,
            "actual encrypted request did not install its original discussion projection"
        );

        // The runtime consumes a real authenticated continuous stream, verifies
        // the original controller signer and decrypts both application records.
        let own = agent
            .runtime
            .sdk()
            .own_station_result_client()?
            .context("runtime own-Station capability")?;
        let mut replica = garth::own_station_results::OwnStationReplica::new(realm.clone());
        replica.install_bound_snapshot(&own.snapshot_head(realm).await?)?;
        let head = arkret_wire::CommitStreamHead {
            stream_ref: accepted.commit.stream_ref.clone(),
            stream_position: accepted.commit.stream_position,
            commit_id: accepted.commit.commit_id.clone(),
        };
        replica
            .restore_checkpoint_head(&own, &head)
            .await
            .context("runtime authenticated Sidecar checkpoint")?;
        let page = replica
            .apply_bound_scan(
                &own,
                own.scan_commit_stream(&arkret_wire::StreamScanRequestBody {
                    realm_id: realm.clone(),
                    stream_ref: accepted.commit.stream_ref.clone(),
                    direction: arkret_wire::StreamScanDirection::After(Some(
                        accepted.commit.stream_position,
                    )),
                    limit: 100,
                })
                .await?,
            )
            .await?;
        ensure!(
            page.rows()?.len() == 1
                && page.rows()?[0].reducer_input() == Some(&request_accepted.event),
            "runtime did not consume exactly the accepted private request"
        );
        ensure!(
            agent_group.decrypt_payload(&request_content)? == request_plain
                && agent_group.decrypt_payload(&request_meta)? == request_metadata,
            "runtime did not authenticate and decrypt the original private request"
        );
        agent_executions += 1;
        let reply_plain = arkret_canonical::canonical_json_bytes(&arkret::ContentBlock::text(
            "Private Sidecar recovery receipt: executed once",
        ))?;
        let response_binding = AgentSidecarEventExchangeBinding {
            schema: binding.schema.clone(),
            exchange_id: binding.exchange_id.clone(),
            role: AgentSidecarExchangeRole::UserFacingResponse,
            request_event_id: Some(request.event_id.clone()),
            completes_exchange: None,
            coordinator_assignment_event_id: None,
            request_context: None,
        };
        let reply_content = seal(
            agent_group,
            scope,
            &accepted.event.event_id,
            "application/vnd.arkret.message+json",
            &reply_plain,
        )?;
        let reply_metadata = seal(
            agent_group,
            scope,
            &accepted.event.event_id,
            arkret::MESSAGE_METADATA_MLS_CONTENT_TYPE,
            &metadata(&response_binding)?,
        )?;
        let reply=agent.author_scoped_event(arkret_wire::EventKind::MessageCreate,scope.clone(),serde_json::json!({
            "strand_id":strand,"track_name":"discussion","encrypted_content":reply_content.to_envelope()?,
            "encrypted_metadata":reply_metadata.to_envelope()?,
        }),vec![arkret_wire::SemanticRef::new(request.event_id.to_string(),"after")])?;
        let (status, outcome) = post_json(
            &agent.runtime,
            &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::Event(
                arkret_wire::EventAdmissionSubmission::new(reply.clone()),
            ),
        )
        .await?;
        ensure!(
            status == reqwest::StatusCode::OK,
            "private runtime response refused: {status} {outcome}"
        );
        let reply_accepted = accepted_full_view(&controller.client, &reply.event_id).await?;
        let reply_franking = await_franking(&reply.event_id, realm, database_url).await?;
        ensure!(
            reply_accepted.commit.stream_ref == request_accepted.commit.stream_ref
                && reply_accepted.commit.stream_position
                    == request_accepted.commit.stream_position + 1,
            "private runtime reply is not the exact Sidecar successor"
        );

        let sentinel = queue_request(
            controller,
            &format!("ak:device_message:{}", fresh_uuid_v7()),
            chrono::Utc::now() + chrono::Duration::minutes(10),
        )?;
        controller
            .client
            .sdk()
            .send_device_messages("private-reply-unprocessed-sentinel", &sentinel)
            .await?;
        let queued = controller
            .client
            .sdk()
            .receive_device_messages(None, None)
            .await?;
        ensure!(
            !queued.deliveries.is_empty(),
            "private recovery needs a nonempty unprocessed queue"
        );
        let ack = queued
            .acknowledgement_token
            .context("issued private recovery ACK")?;
        let ack_before = read_database_evidence(database_url, ACK, &[&ack])?;
        ensure!(
            serde_json::from_str::<Value>(&ack_before)?["consumed_at"].is_null(),
            "fixture ACK already consumed"
        );
        let before = state(&host)?;
        ensure!(
            !before["mls_snapshots"]
                .as_object()
                .context("private MLS snapshots")?
                .is_empty(),
            "empty private MLS checkpoint"
        );
        let before_cut = inkson::conformance::retained_sidecar_cut(&host.state_store(), scope)?;
        let cursor = host
            .state_store()
            .sync_cursor()
            .context("original private Account cursor")?;
        let fault = self
            .relay
            .borrow()
            .as_ref()
            .context("real HTTP relay")?
            .control();
        fault.clear_scan_requests();
        fault.omit_position(
            reply_accepted.commit.stream_ref.clone(),
            reply_accepted.commit.stream_position,
        );
        let rail = HealingRail {
            http: session.client(),
            fault: fault.clone(),
            path: path.clone(),
            scope: scope.clone(),
            account: controller.account.clone(),
            before: before.clone(),
            before_cut,
            before_projection: serde_json::to_value(&prior_projection)?,
            cursor: cursor.clone(),
            database_url: database_url.into(),
            ack: ack.clone(),
            ack_before: ack_before.clone(),
            business_before: business_evidence(database_url)?,
            requests: Default::default(),
            initial_scans: Default::default(),
            dependencies: Default::default(),
        };
        host.catch_up_with_conformance_transport(&rail).await?;
        ensure!(
            rail.requests.lock().unwrap().len() == 2,
            "same-call automatic recovery did not perform exactly one bounded retry"
        );
        let scans = fault.scan_requests();
        let initial_scans = {
            let observed = rail.initial_scans.lock().unwrap();
            observed.clone()
        };
        let recovery_scans = scans
            .strip_prefix(initial_scans.as_slice())
            .context("automatic retry changed its original scan observations")?;
        let dependencies = rail.dependencies.lock().unwrap().clone();
        ensure!(
            dependencies.len() == 2,
            "missing original and retry dependency observations"
        );
        window_dependencies::assert_only_tail_and_dependency_scans(
            recovery_scans,
            &reply_accepted.commit.stream_ref,
            &dependencies[1],
        )?;
        ensure!(
            dependencies[0].iter().all(|reference| initial_scans
                .iter()
                .any(|scan| window_dependencies::is_exact_dependency_scan(scan, reference))),
            "initial private attempt skipped an issued dependency original"
        );
        let initial_progress_scans = initial_scans
            .iter()
            .filter(|scan| {
                !dependencies[0]
                    .iter()
                    .any(|reference| window_dependencies::is_exact_dependency_scan(scan, reference))
            })
            .collect::<Vec<_>>();
        for scan in initial_progress_scans
            .iter()
            .copied()
            .filter(|scan| scan.stream_ref != reply_accepted.commit.stream_ref)
        {
            let head = before["verified_commit_stream_cursors"]
                .as_object()
                .context("original independent heads")?
                .values()
                .find(|head| head["stream_ref"] == serde_json::to_value(&scan.stream_ref).unwrap())
                .context("healthy probe has no original durable head")?;
            ensure!(
                scan.limit == 1
                    && scan.direction
                        == arkret_wire::StreamScanDirection::After(Some(
                            head["stream_position"]
                                .as_u64()
                                .context("original position")?
                        ))
                    && initial_progress_scans
                        .iter()
                        .filter(|other| other.stream_ref == scan.stream_ref)
                        .count()
                        == 1,
                "healthy initial probe replayed history or reset its baseline"
            );
        }
        ensure!(
            read_database_evidence(database_url, ACK, &[&ack])? == ack_before
                && business_evidence(database_url)? == rail.business_before,
            "private recovery changed business state or invalidated its original ACK"
        );
        let projection = inkson::sidecar::cached_sidecar_exchange_projections(
            &host.state_store(),
            &controller.account,
            realm.as_str(),
        )?;
        ensure!(
            projection.len() == 1
                && projection[0].source_track_ref == source
                && projection[0].private_request_event_id == request.event_id
                && projection[0].user_facing_response_event_ids == vec![reply.event_id.clone()]
                && projection[0].participating_agent_ids
                    == vec![agent.agent_account.principal_id.clone()]
                && projection[0].status == AgentSidecarExchangeStatus::Responding,
            "automatic recovery did not update the original private discussion projection"
        );
        let visible = inkson::conformance::private_sidecar_response_plaintext(
            &host.state_store(),
            &controller.account,
            scope,
            &reply.event_id,
        )?;
        ensure!(
            visible == reply_plain,
            "actual user-facing Agent reply was not authenticated and decrypted"
        );
        inkson::conformance::persist_native_private_cache(&host.state_store()).await?;
        let request_submissions = fault.event_submission_count(&request.event_id);
        ensure!(
            fault.event_submission_count(&reply.event_id) == 1,
            "private runtime reply was submitted more than once"
        );
        ensure!(
            request_submissions == 1 && agent_executions == 1,
            "automatic recovery repeated the private request or Agent execution"
        );
        let after = state(&host)?;
        let heads = before["verified_commit_stream_cursors"]
            .as_object()
            .context("original stream inventory")?;
        let recovered = after["verified_commit_stream_cursors"]
            .as_object()
            .context("recovered stream inventory")?;
        ensure!(
            heads.keys().eq(recovered.keys()),
            "private recovery replaced the stream inventory"
        );
        let stream = serde_json::to_value(&reply_accepted.commit.stream_ref)?;
        let affected = before["verified_commit_stream_anchors"]
            .as_object()
            .context("original signed anchors")?
            .iter()
            .find(|(_, anchor)| anchor["stream_ref"] == stream)
            .map(|(key, _)| key)
            .context("original private signed anchor")?;
        let changed = heads
            .iter()
            .filter(|(key, head)| {
                recovered[*key] != **head
                    || after["verified_commit_stream_anchors"][*key]
                        != before["verified_commit_stream_anchors"][*key]
            })
            .map(|(key, _)| key)
            .collect::<std::collections::BTreeSet<_>>();
        let healthy = heads
            .iter()
            .find(|(_, head)| {
                head["stream_ref"]
                    == serde_json::to_value(&reply_franking.commit.stream_ref).unwrap()
            })
            .map(|(key, _)| key)
            .context("original healthy Realm head")?;
        let healthy_expected = arkret_wire::CommitStreamHead {
            stream_ref: reply_franking.commit.stream_ref.clone(),
            stream_position: reply_franking.commit.stream_position,
            commit_id: reply_franking.commit.commit_id.clone(),
        };
        ensure!(
            recovered[healthy] == serde_json::to_value(&healthy_expected)?
                && changed == [affected, healthy].into_iter().collect(),
            "private recovery changed heads beyond the exact reply and its already accepted franking carrier: {changed:?}"
        );
        let checkpoint = host
            .state_store()
            .mls_checkpoint_for_scope(scope)
            .context("recovered nonempty MLS checkpoint")?;
        ensure!(
            checkpoint.group_id == record.group_id.as_str()
                && checkpoint.epoch == 1
                && checkpoint.group_state_event_id.as_ref() == Some(&accepted.event.event_id),
            "automatic recovery reset the original MLS group, epoch or accepted reference"
        );
        let new_cursor = host
            .state_store()
            .sync_cursor()
            .context("recovered Account cursor")?;
        ensure!(
            new_cursor != cursor,
            "reply projection installed without advancing its durable Account cut"
        );
        let cut = inkson::conformance::retained_sidecar_cut(&host.state_store(), scope)?;
        ensure!(
            cut.1.last() == Some(&reply_accepted),
            "reply history and typed current did not install the same accepted cut"
        );
        let evidence = self.directory.path().join("expected-private-reply.json");
        std::fs::write(
            &evidence,
            serde_json::to_vec(&serde_json::json!({
                "account":controller.account,"realm":realm,"cut":inkson::conformance::retained_realm_current(&host.state_store(),&controller.account,realm).await?,
                "cursor":new_cursor,"private_sidecar_scope":scope,"private_sidecar_cut":cut,
                "private_state":recovery::private_state(&after),"stream_heads":after["verified_commit_stream_cursors"],
                "stream_anchors":after["verified_commit_stream_anchors"],"sidecar_exchange_projections":projection,
                "response_event_id":reply.event_id,"response_plaintext_digest":arkret_canonical::canonical_sha256(&serde_json::from_slice::<Value>(&reply_plain)?)?,
            }))?,
        )?;
        drop(host);
        let output = std::process::Command::new(&self.reader)
            .arg(&path)
            .arg(&evidence)
            .output()?;
        ensure!(
            output.status.success(),
            "fresh-process private reply readback: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        cotest::transcripts::record_vector_event(
            "sync.client_account_stream.private_agent_reply_recovery",
            &serde_json::json!({"case_id":CASE,"request_event_id":request.event_id,"reply_event_id":reply.event_id,"scope_ref":scope}),
            &serde_json::json!({"request_submissions":1,"agent_executions":1,"automatic_retry":true,"fresh_process_readback":true}),
            &serde_json::json!({"request_submissions":request_submissions,"agent_executions":agent_executions,"account_attempts":2,
                "authenticated_scan_requests":fault.scan_requests(),"missing_scan_outcomes":fault.observations(),
                "initial_scan_requests":*initial_scans,"automatic_recovery_scan_requests":recovery_scans,
                "ordinary_reply_franking_head":healthy_expected,
                "private_projection":projection,"visible_reply_digest":arkret_canonical::canonical_sha256(&serde_json::from_slice::<Value>(&visible)?)?,
                "ack_preserved":true,"business_writes_repeated":false,"baseline_redone":false,"mls_group_preserved":true,"fresh_process_readback":true,
                "accepted_request_independent_readback":true,"readback_account_cursor_preserved":true,"readback_exact_mls_and_durable_cut":true,
                "accepted_readback_scan_requests":readback_scans}),
        );
        *self.result.borrow_mut() = Some(super::super::CaseExecutionResult {
            case_id: CASE.into(),
            assertions: 35,
        });
        Ok(())
    }
}

pub(super) async fn run(reader: &std::path::Path) -> Result<super::super::CaseExecutionResult> {
    let fixture = cotest::conformance::load_fixture_value("client-sync-fixture.json")?;
    let case = fixture["reconnect"]
        .as_array()
        .context("canonical private reply reconnect cases")?
        .iter()
        .find(|case| case["name"] == CASE)
        .context("canonical private reply recovery case")?;
    ensure!(
        case["expected"] == "resume"
            && case["affected_stream_ref"]["kind"] == "sidecar"
            && case["recovered_streams"] == serde_json::json!(["sidecar"])
            && case["baseline_redone"] == false
            && case["mls_private_state_deleted"] == false
            && case["delivery_acks_invalidated"] == false,
        "private automatic recovery fixture drifted from spec"
    );
    let probe = PrivateReplyProbe {
        relay: Default::default(),
        directory: tempfile::tempdir()?,
        reader: reader.to_owned(),
        result: Default::default(),
    };
    cotest::scenarios::sidecar_authority_live::run_with_sync_observer(&probe).await?;
    probe
        .result
        .into_inner()
        .context("actual private runtime reply case never executed")
}
