//! Real signed Sidecar ensure and independent private stream reads.

use anyhow::{Context, Result, anyhow, bail, ensure};
use arkret_models_collaboration::sidecar_operations::{
    SidecarContextRef, SidecarEnsureCommitPhase, SidecarEnsureCommitRequestBody,
    SidecarEnsurePreparePhase, SidecarEnsurePrepareRequestBody, SidecarEnsureRequestBody,
    SidecarEnsureResponseBody,
};
use arkret_wire::{
    CommitStreamRef, EventKind, RealmId, StreamScanDirection, StreamScanRequestBody,
};
use serde_json::json;

use crate::harness::{CanonicalJsonBody, TestServerGroup, expect_json};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::cross_station_mls_welcome::genesis_creator_leaf_authority;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, membership_payload, station_env,
    submit_and_expect_commit,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use crate::scenarios::mls_lifecycle_live::{ACTIVE_SUITE, Member, canonical, upload_public_blob};

const GROUP: &str = "sidecar-authority-live";

pub(crate) mod private_reply;

pub async fn run() -> Result<()> {
    run_with_genesis_observer(None).await
}

pub async fn run_pending_agent_disclosure() -> Result<()> {
    run_with_options(None, None, true).await
}

pub async fn run_with_genesis_observer(
    observer: Option<&dyn crate::scenarios::mls_lifecycle_live::MlsGenesisObserver>,
) -> Result<()> {
    run_with_observers(observer, None).await
}

pub struct PrivateAgentReadyContext<'a> {
    pub coauth: &'a MockCoauthIntrospectionServer,
    pub database_url: &'a str,
}

#[async_trait::async_trait(?Send)]
pub trait SidecarSyncObserver {
    fn requires_private_agent_reply(&self) -> bool {
        false
    }

    async fn private_agent_ready(
        &self,
        _controller: &Member,
        _agent: &crate::scenarios::agent_runtime_live::AgentRuntimeSession,
        _controller_group: &mut arkret::ArkretMlsGroup,
        _agent_group: &mut arkret::ArkretMlsGroup,
        _accepted: &arkret_wire::CommittedEventFullView,
        _context: PrivateAgentReadyContext<'_>,
    ) -> Result<()> {
        Ok(())
    }
    async fn before_station(&self, _station: &mut crate::harness::ArkretServer) -> Result<()> {
        Ok(())
    }

    fn recipient_queue_capacity(&self) -> Option<usize> {
        None
    }

    fn requires_recovery_peer(&self) -> bool {
        false
    }

    async fn after_station_checks(
        &self,
        _controller: &Member,
        _genesis: &arkret_wire::Event,
        _coauth: &MockCoauthIntrospectionServer,
        _database_url: &str,
        _recovery_database_url: Option<&str>,
        _servers: &mut TestServerGroup,
    ) -> Result<()> {
        Ok(())
    }

    async fn before_genesis(
        &self,
        controller: &Member,
        scope: &arkret_wire::ScopeRef,
    ) -> Result<()>;
    async fn after_genesis(
        &self,
        controller: &Member,
        other_recipient: &Member,
        genesis: &arkret_wire::Event,
        creator_group: &arkret::ArkretMlsGroup,
        database_url: &str,
    ) -> Result<()>;
}

pub async fn run_with_sync_observer(observer: &dyn SidecarSyncObserver) -> Result<()> {
    run_with_options(
        None,
        Some(observer),
        observer.requires_private_agent_reply(),
    )
    .await
}

async fn run_with_observers(
    observer: Option<&dyn crate::scenarios::mls_lifecycle_live::MlsGenesisObserver>,
    sync_observer: Option<&dyn SidecarSyncObserver>,
) -> Result<()> {
    run_with_options(observer, sync_observer, false).await
}

async fn run_with_options(
    observer: Option<&dyn crate::scenarios::mls_lifecycle_live::MlsGenesisObserver>,
    sync_observer: Option<&dyn SidecarSyncObserver>,
    pending_agent: bool,
) -> Result<()> {
    let Some(database) = database(GROUP)? else {
        ensure!(
            observer.is_none() && sync_observer.is_none(),
            "timestamp evidence requires isolated PostgreSQL"
        );
        return Ok(());
    };
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let mut node_env = station_env(&database.connect_url, &coauth);
    if let Some(capacity) = sync_observer.and_then(|observer| observer.recipient_queue_capacity()) {
        ensure!(
            capacity > 0,
            "recipient queue fixture capacity must be nonzero"
        );
        node_env.push((
            "COLAND_TO_DEVICE_QUEUE_CAPACITY".into(),
            capacity.to_string(),
        ));
    }
    let recovery_database = if sync_observer.is_some_and(|probe| probe.requires_recovery_peer()) {
        Some(
            crate::scenarios::human_device_producer_live::database(GROUP)?
                .context("Sync recovery requires a distinct governance database")?,
        )
    } else {
        None
    };
    let mut node_envs = vec![node_env];
    if let Some(peer_database) = &recovery_database {
        node_envs.push(station_env(&peer_database.connect_url, &coauth));
    }
    let Some(mut servers) =
        TestServerGroup::try_multi_external_with_node_envs(GROUP, &node_envs).await?
    else {
        ensure!(
            observer.is_none() && sync_observer.is_none(),
            "timestamp evidence requires a real Coland binary"
        );
        return skip_or_fail(GROUP, "prebuilt Coland unavailable");
    };
    if let Some(probe) = sync_observer {
        probe.before_station(servers.server_mut(0)).await?;
    }
    let station = servers.server(0);
    let controller = Member::provision(
        station,
        &coauth,
        "sidecar-controller",
        "ak:device:01904100-0000-7000-8000-000000002871",
    )
    .await?;
    let outsider = Member::provision(
        station,
        &coauth,
        "sidecar-outsider",
        "ak:device:01904100-0000-7000-8000-000000002872",
    )
    .await?;
    let realm = RealmId::new(
        create_realm_with_join_rule(&controller.client, "Private Sidecar", "public", &[station])
            .await?,
    )?;
    let join = outsider.client.author_event(
        realm.as_str(), EventKind::MemberState.as_str(),
        membership_payload(realm.as_str(), outsider.account.clone(),
            arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join,
            "Sidecar privacy must exclude another current Realm member")?,
    ).await?;
    submit_and_expect_commit(
        &outsider.client,
        &outsider.account,
        outsider.device.as_str(),
        &join,
    )
    .await?;
    let agent = if pending_agent {
        use arkret_wire::ServiceOperationId as Op;
        let mut requested = vec![
            Op::SELF_COMMITTED_EVENT_READ_SCAN_V1,
            Op::SELF_REALM_READ_STREAMS_V1,
            Op::SELF_REALM_STATE_SNAPSHOT_READ_MANIFEST_HEAD_V1,
            Op::SELF_REALM_STATE_SNAPSHOT_READ_BY_REF_V1,
            Op::SELF_MLS_READ_GROUP_STATE_MATERIAL_V1,
            "ak.event.read",
            "ak.object.read",
            "ak.strand.read",
        ];
        if sync_observer.is_some_and(|probe| probe.requires_private_agent_reply()) {
            requested.extend([
                Op::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE_V1,
                Op::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM_V1,
                Op::SELF_KEYS_KEYPACKAGES_READ_CLAIM_V1,
                Op::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1,
                Op::SELF_MLS_READ_ROSTER_AUTHORITY_V1,
                Op::SELF_SIGNER_KEYS_READ_RESOLVE_V1,
                Op::SELF_CURRENT_STATE_READ_EXACT_V1,
                Op::SELF_EVENTS_COMMAND_SUBMIT_V1,
                Op::SELF_DEVICE_MESSAGES_READ_LIST_V1,
                Op::SELF_DEVICE_MESSAGES_COMMAND_ACK_V1,
                "ak.message.create",
            ]);
        }
        let operations =
            arkret_schema::agent_runtime_scope::complete_agent_runtime_scope(requested)?;
        let operations = operations.iter().map(String::as_str).collect::<Vec<_>>();
        let scope = serde_json::from_value(serde_json::json!({
            "actions":operations,
            "resources":operations.iter().filter(|action| Op::from_wire(action).is_some())
                .map(|action| serde_json::json!({"kind":"operation","operation":action}))
                .chain(std::iter::once(serde_json::json!({"kind":"realm","realm_id":realm})))
                .collect::<Vec<_>>()
        }))?;
        let mut agent =
            crate::scenarios::agent_runtime_live::AgentRuntimeSession::establish_with_scope(
                station,
                &coauth,
                &controller.client,
                &controller.account,
                "sidecar-pending-reader",
                scope,
            )
            .await?;
        if sync_observer.is_some_and(|probe| probe.requires_private_agent_reply()) {
            agent.runtime = station
                .bind_native_host_session(agent.runtime.clone(), &coauth)
                .await?;
        }
        let page = controller
            .client
            .sdk()
            .scan_commit_stream(&StreamScanRequestBody {
                realm_id: realm.clone(),
                stream_ref: CommitStreamRef::Realm {
                    realm_id: realm.clone(),
                },
                direction: StreamScanDirection::After(None),
                limit: 200,
            })
            .await?;
        let controller_generation = page
            .committed_events
            .iter()
            .filter_map(|row| row.reducer_input())
            .find(|event| {
                event.kind == EventKind::MemberState
                    && event.payload.get("member_id")
                        == serde_json::to_value(&controller.actor).ok().as_ref()
            })
            .ok_or_else(|| anyhow!("controller membership generation unavailable"))?
            .event_id
            .clone();
        let mut membership =
            arkret_models_collaboration::governance::membership_invite::MembershipPayload::join(
                realm.clone(),
                arkret_wire::ActorId::account(agent.agent_account.clone()),
                "pending Sidecar reader",
            );
        membership.agent_controller_binding = Some(arkret_models_collaboration::governance::agent_membership_cascade::AgentControllerMembershipBinding {
            controller_account_id: controller.account.clone(), controller_membership_generation_ref: controller_generation,
            controller_terminal_event_ref: None,
        });
        controller
            .client
            .submit_event(
                realm.as_str(),
                EventKind::MemberState.as_str(),
                membership.to_value()?,
            )
            .await?;
        Some(agent)
    } else {
        None
    };
    let desired = agent
        .as_ref()
        .map(|agent| vec![agent.agent_account.principal_id.clone()])
        .unwrap_or_default();
    let strand = controller
        .client
        .default_strand_id(realm.as_str())?
        .parse()?;
    let operation = arkret_wire::ProtocolOperationId::new("ak:operation:sidecar-live-create-0001")
        .map_err(|error| anyhow!(error))?;
    let prepare_idempotency = arkret_wire::IdempotencyKey::new("sidecar-live-prepare-0001")
        .map_err(|error| anyhow!(error))?;
    let prepare = SidecarEnsureRequestBody::Prepare(SidecarEnsurePrepareRequestBody {
        phase: SidecarEnsurePreparePhase::Prepare,
        operation_id: operation.clone(),
        idempotency_key: prepare_idempotency,
        source_realm_id: realm.clone(),
        controller_account_id: controller.account.clone(),
        context_ref: SidecarContextRef::Strand { strand_id: strand },
    });
    let prepared = controller
        .client
        .sdk()
        .agent_sidecar_ensure(&controller.client.verify_publication(prepare)?)
        .await?;
    let SidecarEnsureResponseBody::PreparedNew(prepared) = prepared else {
        bail!("fresh Sidecar did not prepare a new atomic unit");
    };
    let create = controller.client.sign_prepared_contact_event(
        &prepared.create_event_draft,
        EventKind::SidecarCreate.as_str(),
    )?;
    let attach = controller.client.sign_prepared_contact_event(
        &prepared.context_attach_event_draft,
        EventKind::SidecarContextAttach.as_str(),
    )?;
    let request = SidecarEnsureRequestBody::Commit(SidecarEnsureCommitRequestBody {
        phase: SidecarEnsureCommitPhase::Commit,
        operation_id: operation,
        idempotency_key: arkret_wire::IdempotencyKey::new("sidecar-live-commit-0001")
            .map_err(|error| anyhow!(error))?,
        reservation_handle: prepared.reservation_handle,
        create_event: create.clone(),
        context_attach_event: attach.clone(),
    });
    let accepted = controller
        .client
        .sdk()
        .agent_sidecar_ensure(&controller.client.verify_publication(request.clone())?)
        .await?;
    let SidecarEnsureResponseBody::Accepted(accepted) = accepted else {
        bail!("signed Sidecar unit was not accepted");
    };
    ensure!(accepted.sidecar_id == arkret_wire::SidecarId::from_event_id(&create.event_id));
    let view = controller
        .client
        .sdk()
        .agent_sidecar_get(&accepted.sidecar_id)
        .await?;
    ensure!(view.desired_agent_ids == desired && view.effective_agent_ids.is_empty());
    ensure!(
        view.mls_context.mls_group_id.is_none()
            && !view.mls_context.current_controller_device_ready,
        "an accepted ensure without MLS must not fabricate controller readiness"
    );
    ensure!(
        view.mls_context
            .authority_stream_head
            .contains(&create.event_id),
        "read view lost accepted private creation authority"
    );
    expect_json(
        outsider.client.get(&format!(
            "/_arkret/self/agent-sidecars/{}",
            accepted.sidecar_id
        )),
        reqwest::StatusCode::NOT_FOUND,
    )
    .await?;
    let replay = controller
        .client
        .sdk()
        .agent_sidecar_ensure(&controller.client.verify_publication(request.clone())?)
        .await?;
    ensure!(
        replay.sidecar_id() == Some(&accepted.sidecar_id),
        "exact replay changed Sidecar identity"
    );
    let stream = CommitStreamRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: accepted.sidecar_id,
    };
    let owner_snapshot = controller
        .client
        .sdk()
        .realm_state_snapshot_head(&realm)
        .await?;
    ensure!(
        owner_snapshot
            .visible_stream_heads
            .iter()
            .any(|head| head.stream_ref == stream),
        "controller snapshot omitted its private native head"
    );
    let outsider_snapshot = outsider
        .client
        .sdk()
        .realm_state_snapshot_head(&realm)
        .await?;
    ensure!(
        !outsider_snapshot
            .visible_stream_heads
            .iter()
            .any(|head| matches!(head.stream_ref, CommitStreamRef::Sidecar { .. })),
        "another Realm member received private native inventory"
    );
    ensure!(
        !outsider_snapshot
            .current_state_entries
            .iter()
            .any(|entry| matches!(
                entry,
                arkret_wire::CurrentState::Value {
                    selector: arkret_wire::CurrentSelector::Sidecar { .. }
                        | arkret_wire::CurrentSelector::SidecarContext { .. },
                    ..
                }
            )),
        "another Realm member received private Sidecar typed currents"
    );
    let parent_query = StreamScanRequestBody {
        realm_id: realm.clone(),
        stream_ref: CommitStreamRef::Realm {
            realm_id: realm.clone(),
        },
        direction: StreamScanDirection::After(None),
        limit: 50,
    };
    let public_page = outsider
        .client
        .sdk()
        .scan_commit_stream(&parent_query)
        .await?;
    public_page.validate_for_request(&parent_query)?;
    let private_genesis = public_page
        .committed_events
        .iter()
        .find(|row| row.commit().event_ref == create.event_id)
        .ok_or_else(|| {
            anyhow!("parent stream lost the accepted private command's covering commit")
        })?;
    ensure!(
        private_genesis.reducer_input().is_none(),
        "parent Realm membership disclosed another controller's Sidecar genesis"
    );
    ensure!(
        !public_page
            .committed_events
            .iter()
            .any(|row| row.commit().event_ref == attach.event_id),
        "native private context leaked into the parent Realm stream"
    );
    for direction in [
        StreamScanDirection::After(None),
        StreamScanDirection::Before(None),
    ] {
        let query = StreamScanRequestBody {
            realm_id: realm.clone(),
            stream_ref: stream.clone(),
            direction,
            limit: 50,
        };
        let outcome = controller.client.sdk().scan_commit_stream(&query).await?;
        outcome.validate_for_request(&query)?;
        ensure!(
            outcome.committed_events.len() == 1,
            "replay inserted duplicate private commits"
        );
        let committed = &outcome.committed_events[0];
        ensure!(
            committed
                .reducer_input()
                .is_some_and(|event| event.event_id == attach.event_id)
        );
        ensure!(
            committed.commit().stream_ref == stream && committed.commit().stream_position == 0,
            "Sidecar used parent Realm positions"
        );
        let denial = expect_json(
            outsider
                .client
                .post("/_arkret/self/streams/scan")
                .canonical_json(&query)?,
            reqwest::StatusCode::FORBIDDEN,
        )
        .await?;
        ensure!(
            denial["type"] == "https://arkret.org/problems/capability_denied",
            "another Realm member must receive the universal private scan denial"
        );
    }
    // Activate a real native OpenMLS group after proving the plaintext
    // context unit alone never claims MLS readiness.
    let sidecar = match &stream {
        CommitStreamRef::Sidecar { sidecar_id, .. } => sidecar_id.clone(),
        _ => unreachable!(),
    };
    let view = controller.client.sdk().agent_sidecar_get(&sidecar).await?;
    let scope = arkret_wire::ScopeRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    let binding = arkret::MlsGovernanceBindingPayload::sidecar(
        realm.clone(),
        sidecar.clone(),
        None,
        0,
        0,
        0,
        view.mls_context.participant_authority_digest,
        view.mls_context.authority_stream_head,
    )?;
    let mut group = controller
        .mls_identity()?
        .create_group_with_governance_binding(&scope, &binding)?;
    let leaf = genesis_creator_leaf_authority(&mut group, &controller)?;
    let (group_info, tree) = group.public_group_state_bytes()?;
    let group_info_ref = upload_public_blob(&controller.client, &realm, &group_info).await?;
    let tree_ref = upload_public_blob(&controller.client, &realm, &tree).await?;
    let mut genesis=controller.client.author_event(realm.as_str(),EventKind::MlsGenesis.as_str(),canonical(json!({
        "cipher_suite":ACTIVE_SUITE,"group_info_ref":group_info_ref,"ratchet_tree_ref":tree_ref,
        "governance_binding":binding,"creator_leaf_authority":leaf,
        "created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    }))?).await?;
    genesis.scope_ref = scope.clone();
    crate::harness::refresh_typed_event_proof(&mut genesis)?;
    if let Some(probe) = observer {
        probe
            .before(&controller, &mut genesis, &database.connect_url)
            .await?;
    }
    if let Some(probe) = sync_observer {
        probe.before_genesis(&controller, &scope).await?;
    }
    let accepted_genesis = submit_and_expect_commit(
        &controller.client,
        &controller.account,
        controller.device.as_str(),
        &genesis,
    )
    .await?;
    if let Some(probe) = sync_observer {
        probe
            .after_genesis(
                &controller,
                &outsider,
                &genesis,
                &group,
                &database.connect_url,
            )
            .await?;
    }
    if let Some(probe) = observer {
        probe
            .after(&controller, &genesis, &database.connect_url)
            .await?;
        servers.server_mut(0).restart_external_process().await?;
        probe.after_restart(&controller).await?;
    }
    ensure!(
        accepted_genesis.stream_ref == stream && accepted_genesis.stream_position == 1,
        "Sidecar MLS Genesis reused parent coordinates"
    );
    let ready = controller.client.sdk().agent_sidecar_get(&sidecar).await?;
    ensure!(
        ready.mls_context.current_controller_device_ready
            && ready.mls_context.epoch == Some(0)
            && ready.desired_agent_ids == desired
            && ready.effective_agent_ids.is_empty(),
        "native Genesis creator is not ready at its accepted participant cut"
    );
    let material=arkret_models_collaboration::mls_group_state_material::MlsMemberGroupStateMaterialReadRequestBody{
        realm_id:realm.clone(),effective_scope:scope.clone(),mls_group_id:scope.canonical_mls_group_id()?,epoch:Default::default(),
        group_state_event_id:genesis.event_id.clone(),caller_actor_id:controller.actor.clone(),target_commit_event_ref:genesis.event_id.clone(),target_epoch:0,
        group_info_ref:arkret_wire::BlobRef::new(group_info_ref)?,ratchet_tree_ref:arkret_wire::BlobRef::new(tree_ref)?,max_response_bytes:None,
    };
    if let Some(agent) = &agent {
        // Put a private row after the first public handshake so it falls
        // inside the pending recipient's interval and must be withheld.
        let mut private = controller
            .client
            .author_event(
                realm.as_str(),
                EventKind::SidecarContextAttach.as_str(),
                canonical(json!({
                    "sidecar_id":sidecar,"source_context_ref":attach.payload["source_context_ref"],
                    "version":2,"predecessor_event_ref":attach.event_id,
                }))?,
            )
            .await?;
        private.scope_ref = scope.clone();
        private.semantic_refs = vec![arkret_wire::SemanticRef::new(
            create.event_id.to_string(),
            "after",
        )];
        crate::harness::refresh_typed_event_proof(&mut private)?;
        let private_commit = submit_and_expect_commit(
            &controller.client,
            &controller.account,
            controller.device.as_str(),
            &private,
        )
        .await?;
        ensure!(private_commit.stream_position == 2 && private_commit.stream_ref == stream);
        verify_pending_agent_reads(
            agent,
            &controller,
            &realm,
            &stream,
            PendingAgentDisclosureEvents {
                create: &create,
                attach: &private,
                genesis: &genesis,
            },
            &material,
        )
        .await?;
    }
    let response = expect_json(
        controller
            .client
            .post("/_arkret/self/mls/group-state-material/query")
            .canonical_json(&material)?,
        reqwest::StatusCode::OK,
    )
    .await?;
    let response:arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialResponseBody=serde_json::from_value(response)?;
    let validated = response.validate_for_request(&material.as_peer_request())?;
    ensure!(
        validated.group_info_bytes == group_info && validated.ratchet_tree_bytes == tree,
        "native Sidecar material changed accepted bytes"
    );
    let roster =
        arkret_models_collaboration::mls_roster_authority::MlsMemberRosterAuthorityReadRequestBody {
            realm_id: realm.clone(),
            effective_scope: scope.clone(),
            mls_group_id: material.mls_group_id,
            target_commit_event_ref: genesis.event_id.clone(),
            target_epoch: 0,
            caller_actor_id: controller.actor.clone(),
            cursor: None,
        };
    let roster_response = controller
        .client
        .sdk()
        .self_mls_roster_authority(&roster)
        .await?;
    let selected = arkret::verify_mls_member_roster_authority_pages(
        std::slice::from_ref(&roster_response),
        &roster,
    )?;
    let roster_response = roster_response.roster;
    ensure!(
        selected.genesis_event_ref == genesis.event_id,
        "member roster selected another accepted Genesis"
    );
    ensure!(
        roster_response.records.len() == 1
            && roster_response.manifest.total_record_count == 1
            && roster_response.next_cursor.is_none(),
        "native Sidecar Genesis roster is partial"
    );
    if let Some(probe) = sync_observer.filter(|probe| probe.requires_private_agent_reply()) {
        let agent = agent
            .as_ref()
            .context("private reply requires a real Agent")?;
        let (accepted, mut agent_group) =
            private_reply::join_agent(&controller, agent, &mut group, &genesis).await?;
        probe
            .private_agent_ready(
                &controller,
                agent,
                &mut group,
                &mut agent_group,
                &accepted,
                PrivateAgentReadyContext {
                    coauth: &coauth,
                    database_url: &database.connect_url,
                },
            )
            .await?;
    }
    if let Some(probe) = sync_observer {
        probe
            .after_station_checks(
                &controller,
                &genesis,
                &coauth,
                &database.connect_url,
                recovery_database
                    .as_ref()
                    .map(|database| database.connect_url.as_str()),
                &mut servers,
            )
            .await?;
    }
    Ok(())
}

struct PendingAgentDisclosureEvents<'a> {
    create: &'a arkret_wire::Event,
    attach: &'a arkret_wire::Event,
    genesis: &'a arkret_wire::Event,
}

async fn verify_pending_agent_reads(
    agent: &crate::scenarios::agent_runtime_live::AgentRuntimeSession,
    controller: &Member,
    realm: &RealmId,
    stream: &CommitStreamRef,
    events: PendingAgentDisclosureEvents<'_>,
    material: &arkret_models_collaboration::mls_group_state_material::MlsMemberGroupStateMaterialReadRequestBody,
) -> Result<()> {
    let PendingAgentDisclosureEvents {
        create,
        attach,
        genesis,
    } = events;
    let http = agent.runtime.sdk();
    let list = http
        .realm_streams_page(realm, None, 500)
        .await
        .context("pending Agent stream discovery")?;
    ensure!(
        list.streams.iter().any(|row| &row.stream_ref == stream),
        "pending Agent cannot discover public handshake stream"
    );
    let snapshot = http
        .realm_state_snapshot_head(realm)
        .await
        .context("pending Agent snapshot head")?;
    ensure!(
        snapshot
            .visible_stream_heads
            .iter()
            .any(|head| &head.stream_ref == stream)
    );
    ensure!(
        !snapshot.current_state_entries.iter().any(|row| matches!(
            row,
            arkret_wire::CurrentState::Value {
                selector: arkret_wire::CurrentSelector::Sidecar { .. }
                    | arkret_wire::CurrentSelector::SidecarContext { .. },
                ..
            }
        )),
        "pending Agent received private current"
    );
    let public = snapshot
        .current_state_entries
        .iter()
        .filter(|row| {
            matches!(row,
        arkret_wire::CurrentState::Value { source_stream_ref, .. } if source_stream_ref == stream)
        })
        .collect::<Vec<_>>();
    ensure!(
        public.len() == 1
            && matches!(
                public[0],
                arkret_wire::CurrentState::Value {
                    selector: arkret_wire::CurrentSelector::MlsGroup { .. },
                    ..
                }
            ),
        "pending Agent must receive only public MLS current"
    );
    let exact = http
        .realm_state_snapshot_by_ref(realm, &snapshot.snapshot_id)
        .await
        .context("pending Agent exact snapshot by-ref")?;
    ensure!(
        exact == snapshot,
        "pending Agent by-ref changed the signed object"
    );
    for direction in [
        StreamScanDirection::After(None),
        StreamScanDirection::Before(None),
    ] {
        let query = StreamScanRequestBody {
            realm_id: realm.clone(),
            stream_ref: stream.clone(),
            direction,
            limit: 50,
        };
        let page = http
            .scan_commit_stream(&query)
            .await
            .context("pending Agent Sidecar scan")?;
        page.validate_for_request(&query)?;
        ensure!(page.committed_events.len() == 2 && !page.truncated);
        let (private, handshake) = match direction {
            StreamScanDirection::After(_) => (&page.committed_events[1], &page.committed_events[0]),
            StreamScanDirection::Before(_) => {
                (&page.committed_events[0], &page.committed_events[1])
            }
        };
        ensure!(
            private.commit().event_ref == attach.event_id && private.reducer_input().is_none(),
            "pending Agent received private context bytes"
        );
        ensure!(
            handshake
                .reducer_input()
                .is_some_and(|event| event == genesis),
            "pending Agent cannot verify MLS Genesis"
        );
        ensure!(
            private.commit().previous_commit_ref.as_ref() == Some(&handshake.commit().commit_id)
        );
    }
    let parent = http
        .scan_commit_stream(&StreamScanRequestBody {
            realm_id: realm.clone(),
            stream_ref: CommitStreamRef::Realm {
                realm_id: realm.clone(),
            },
            direction: StreamScanDirection::After(None),
            limit: 200,
        })
        .await?;
    ensure!(
        parent
            .committed_events
            .iter()
            .any(|row| row.commit().event_ref == create.event_id && row.reducer_input().is_none()),
        "Agent Realm membership disclosed controller-private creation"
    );
    let mut request = material.clone();
    request.caller_actor_id = arkret_wire::ActorId::account(agent.agent_account.clone());
    http.self_mls_group_state_material(&request)
        .await
        .context("pending Agent public group-state material")?
        .validate_for_request(&request.as_peer_request())?;
    // Another Account's issued object remains unavailable even when both know
    // the same public handshake head.
    let owner = controller
        .client
        .sdk()
        .realm_state_snapshot_head(realm)
        .await?;
    ensure!(
        http.realm_state_snapshot_by_ref(realm, &owner.snapshot_id)
            .await
            .is_err()
    );
    Ok(())
}
