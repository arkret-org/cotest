//! Actual Coauth ceilings and endpoint-specific Sidecar bootstrap/payload gates.

use arkret_models_collaboration::sidecar_operations::*;

use super::*;
use crate::harness::CanonicalJsonBody;
use crate::scenarios::mls_lifecycle_live::{ACTIVE_SUITE, Member, upload_public_blob};
use crate::scenarios::sidecar_authority_live::private_reply::{self, JoinObserver};

pub const REVIEWED_SIDECAR_CONTENT_CASES: [&str; 18] = [
    "sidecar_read_without_literal_grant",
    "sidecar_read_does_not_grant_write",
    "issue_pending_mls_is_only_ceiling",
    "bootstrap_desired_not_yet_effective",
    "bootstrap_wrong_endpoint",
    "bootstrap_missing_add_welcome_claim_lineage",
    "desired_cannot_read_payload",
    "effective_sidecar_payload",
    "wrong_sidecar_binding",
    "queued_welcome_after_desired_revoke",
    "future_epoch_material_after_desired_revoke",
    "valid_future_epoch_material",
    "realm_grant_cannot_replace_sidecar_authority",
    "project_grant_cannot_authorize_private_reply",
    "sidecar_explicit_write_grant",
    "sidecar_write_grant_without_effective",
    "sidecar_write_grant_after_desired_loss",
    "sidecar_material_not_a_write_grant_operation",
];

async fn diagnose_first_mode_failure(
    station: &ArkretServer,
    client: &TestActorClient,
    realm: &RealmId,
    agent: &AccountId,
    accepted_generation: u64,
) {
    let mut diagnostic = json!({
        "phase":"first_public_mode_failed",
        "sql_capture_ok":false,
        "same_sql_readonly_cut":false,
        "sql_is_failed_admission_cut":false,
        "sql_snapshot_sha256":null,
        "sql_head_position":null,
        "sql_head_sha256":null,
        "sql_head_generation":null,
        "sql_prefix_rows":null,
        "sql_prefix_distinct_positions":null,
        "sql_prefix_min":null,
        "sql_prefix_max":null,
        "sql_canonical_mode_originals":null,
        "sql_accepted_mode_originals":null,
        "sql_mode_projection_rows":null,
        "exact_current_kind":"unavailable",
        "exact_current_head_position":null,
        "exact_current_head_sha256":null,
        "exact_current_expected_generation":accepted_generation,
        "http_read_shares_sql_cut":false
    });
    if let Some(database) = station.configured_database_url() {
        let database = database.to_owned();
        let realm = realm.to_string();
        let agent = json!(agent);
        let captured = tokio::task::spawn_blocking(move || -> Result<serde_json::Value> {
            let mut config = database.parse::<postgres::Config>()?;
            config
                .connect_timeout(Duration::from_secs(2))
                .options("-c default_transaction_read_only=on -c statement_timeout=2000 -c lock_timeout=500");
            let mut database = config.connect(postgres::NoTls)?;
            let mut cut = database
                .build_transaction()
                .isolation_level(postgres::IsolationLevel::RepeatableRead)
                .read_only(true)
                .start()?;
            let mode_kind = arkret_wire::EventKind::AgentInteractionSet.as_str();
            let row = cut.query_one(
                "WITH prefix AS (
                    SELECT commit_id,stream_position,governance_generation,event_pk
                    FROM realm_commits
                    WHERE realm_id=$1 AND stream_ref=jsonb_build_object('kind','realm','realm_id',$1)
                )
                SELECT txid_current_snapshot()::text,
                    COUNT(*)::bigint,COUNT(DISTINCT stream_position)::bigint,
                    MIN(stream_position),MAX(stream_position),
                    (SELECT commit_id FROM prefix ORDER BY stream_position DESC LIMIT 1),
                    (SELECT governance_generation FROM prefix ORDER BY stream_position DESC LIMIT 1),
                    (SELECT COUNT(*)::bigint FROM canonical_events e WHERE e.realm_id=$1
                        AND e.kind=$3 AND e.state='committed'
                        AND e.envelope->'payload'->'agent_account_id'=$2),
                    (SELECT COUNT(*)::bigint FROM canonical_events e JOIN prefix c ON c.event_pk=e.pk
                        WHERE e.realm_id=$1 AND e.kind=$3 AND e.state='committed'
                        AND e.envelope->'payload'->'agent_account_id'=$2),
                    (SELECT COUNT(*)::bigint FROM agent_interaction_current_states
                        WHERE realm_id=$1 AND agent_account_id=$2)
                FROM prefix",
                &[&realm, &agent, &mode_kind],
            )?;
            let snapshot: String = row.try_get(0)?;
            let head: Option<String> = row.try_get(5)?;
            let captured = json!({
                "sql_capture_ok":true,
                "same_sql_readonly_cut":true,
                "sql_snapshot_sha256":arkret_canonical::sha256_hex(snapshot.as_bytes()),
                "sql_head_position":row.try_get::<_,Option<i64>>(4)?,
                "sql_head_sha256":head.map(|id| arkret_canonical::sha256_hex(id.as_bytes())),
                "sql_head_generation":row.try_get::<_,Option<i64>>(6)?,
                "sql_prefix_rows":row.try_get::<_,i64>(1)?,
                "sql_prefix_distinct_positions":row.try_get::<_,i64>(2)?,
                "sql_prefix_min":row.try_get::<_,Option<i64>>(3)?,
                "sql_prefix_max":row.try_get::<_,Option<i64>>(4)?,
                "sql_canonical_mode_originals":row.try_get::<_,i64>(7)?,
                "sql_accepted_mode_originals":row.try_get::<_,i64>(8)?,
                "sql_mode_projection_rows":row.try_get::<_,i64>(9)?
            });
            cut.commit()?;
            Ok(captured)
        })
        .await;
        if let Ok(Ok(captured)) = captured {
            for (key, value) in captured.as_object().into_iter().flatten() {
                diagnostic[key.as_str()] = value.clone();
            }
        }
    }
    // This later HTTP observation is not the failed admission cut or the SQL cut.
    use arkret_models_collaboration::exact_current_state::{
        ExactCurrentStateReadRequestBody, ExactCurrentStateReadResponseBody,
        ExactCurrentStateSelector,
    };
    let request = ExactCurrentStateReadRequestBody {
        realm_id: realm.clone(),
        selector: ExactCurrentStateSelector::AgentInteraction(
            arkret_models_collaboration::agent_interaction::AgentInteractionExactCurrentSelector::new(
                agent.clone(),
            ),
        ),
    };
    let sdk = client.sdk();
    if let Ok(Ok(outcome)) = tokio::time::timeout(
        Duration::from_secs(3),
        sdk.exact_current_state(&request, accepted_generation),
    )
    .await
    {
        let (kind, head) = match outcome {
            ExactCurrentStateReadResponseBody::Present {
                effective_stream_head,
                ..
            } => ("present", effective_stream_head),
            ExactCurrentStateReadResponseBody::NeverWritten {
                effective_stream_head,
                ..
            } => ("never_written", effective_stream_head),
        };
        diagnostic["exact_current_kind"] = json!(kind);
        diagnostic["exact_current_head_position"] = json!(head.stream_position);
        diagnostic["exact_current_head_sha256"] = json!(arkret_canonical::sha256_hex(
            head.commit_id.as_str().as_bytes()
        ));
    }
    use std::io::Write as _;
    let _ = writeln!(
        std::io::stderr().lock(),
        "[agent-sidecar-mode-diagnostic] {diagnostic}"
    );
}

async fn other_controller_content(
    deployment: &coauth_session_evidence::ActualAgentDeployment,
    agent: &AgentRuntimeSession,
    read: &TestActorClient,
    realm: &RealmId,
    strand: &arkret_wire::StrandId,
    own_message: &Event,
) -> Result<()> {
    let client = coauth_session_evidence::additional_controller(
        deployment,
        "bob",
        "ak:device:01904100-0000-7000-8000-000000002302",
    )
    .await?;
    let principal = client
        .principal
        .as_ref()
        .context("actual second controller")?;
    let account = AccountId::new(
        principal.core_id.clone(),
        deployment.station.service_id().clone(),
    );
    let join = MembershipPayload::join(
        realm.clone(),
        ActorId::account(account.clone()),
        "Independent Sidecar controller",
    );
    let joined: AuthoritySubmitResponseBody = serde_json::from_value(
        client
            .submit_event(realm.as_str(), "ak.member.state", join.to_value()?)
            .await?,
    )?;
    ensure!(matches!(
        joined,
        AuthoritySubmitResponseBody::Accepted {
            status: AuthorityCommitStatus::Committed,
            ..
        }
    ));
    deployment
        .controller
        .grant_realm_actions_to_client(
            realm.as_str(),
            &client,
            &["ak.event.read", "ak.message.create"],
        )
        .await?;
    let controller = Member {
        client: client.clone(),
        account: account.clone(),
        actor: ActorId::account(account.clone()),
        device: principal.device_id.clone(),
        method: DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
            .map_err(anyhow::Error::msg)?,
        key: principal.device_signing_key.clone(),
        authorize_event_id: principal.founding_authorize_event_id.clone(),
    };
    let operation = ProtocolOperationId::new(format!("ak:operation:{}", unique_uuid7()))
        .map_err(anyhow::Error::msg)?;
    let prepare = SidecarEnsureRequestBody::Prepare(SidecarEnsurePrepareRequestBody {
        phase: SidecarEnsurePreparePhase::Prepare,
        operation_id: operation.clone(),
        idempotency_key: IdempotencyKey::new(format!("other-prepare-{}", unique_uuid7()))
            .map_err(anyhow::Error::msg)?,
        source_realm_id: realm.clone(),
        controller_account_id: account.clone(),
        context_ref: SidecarContextRef::Strand {
            strand_id: strand.clone(),
        },
    });
    let SidecarEnsureResponseBody::PreparedNew(prepared) = client
        .sdk()
        .agent_sidecar_ensure(&client.verify_publication(prepare)?)
        .await?
    else {
        bail!("new independent Sidecar required")
    };
    let create = client.sign_prepared_contact_event(
        &prepared.create_event_draft,
        arkret_wire::EventKind::SidecarCreate.as_str(),
    )?;
    let attach = client.sign_prepared_contact_event(
        &prepared.context_attach_event_draft,
        arkret_wire::EventKind::SidecarContextAttach.as_str(),
    )?;
    let request = SidecarEnsureRequestBody::Commit(SidecarEnsureCommitRequestBody {
        phase: SidecarEnsureCommitPhase::Commit,
        operation_id: operation,
        idempotency_key: IdempotencyKey::new(format!("other-commit-{}", unique_uuid7()))
            .map_err(anyhow::Error::msg)?,
        reservation_handle: prepared.reservation_handle,
        create_event: create,
        context_attach_event: attach,
    });
    let SidecarEnsureResponseBody::Accepted(accepted) = client
        .sdk()
        .agent_sidecar_ensure(&client.verify_publication(request.clone())?)
        .await?
    else {
        bail!("independent Sidecar acceptance required")
    };
    let sidecar = accepted.sidecar_id;
    let source_realm = realm;
    let realm = &principal.pcr_realm_id;
    let view = client.sdk().agent_sidecar_get(&sidecar).await?;
    ensure!(
        view.sidecar.controller_account_id == account
            && view.sidecar.realm_id == *realm
            && view.sidecar.source_realm_id == *source_realm
            && view.desired_agent_ids.is_empty()
    );
    let scope = ScopeRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    ensure!(scope != own_message.scope_ref);
    let binding = arkret::MlsGovernanceBindingPayload::sidecar(
        realm.clone(),
        sidecar,
        None,
        0,
        0,
        0,
        view.mls_context.participant_authority_digest,
    )?;
    let mut group = controller
        .mls_identity()?
        .create_group_with_governance_binding(&scope, &binding)?;
    let leaf = crate::scenarios::cross_station_mls_welcome::genesis_creator_leaf_authority(
        &mut group,
        &controller,
    )?;
    let (info, tree) = group.public_group_state_bytes()?;
    let info = upload_public_blob(&client, realm, &info).await?;
    let tree = upload_public_blob(&client, realm, &tree).await?;
    let mut genesis = client
        .author_event(
            realm.as_str(),
            "ak.mls.genesis",
            json!({
        "cipher_suite":ACTIVE_SUITE,"group_info_ref":info,"ratchet_tree_ref":tree,
        "governance_binding":binding,"creator_leaf_authority":leaf,
        "created_at":arkret_canonical::format_timestamp_canonical(Utc::now())}),
        )
        .await?;
    genesis.scope_ref = scope;
    crate::harness::refresh_typed_event_proof_with_signing_seed(
        &mut genesis,
        controller.key.to_bytes(),
    )?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &client,
        &account,
        client.device_id.as_str(),
        &genesis,
    )
    .await?;
    let state =
        crate::scenarios::mls_lifecycle_live::accepted_full_view(&client, &genesis.event_id)
            .await?;
    let request = arkret::MlsMemberRosterAuthorityReadRequestBody {
        realm_id: realm.clone(),
        effective_scope: genesis.scope_ref.clone(),
        mls_group_id: genesis.scope_ref.canonical_mls_group_id()?,
        target_commit_event_ref: genesis.event_id.clone(),
        target_epoch: 0,
        caller_actor_id: controller.actor.clone(),
        cursor: None,
    };
    let page = client.sdk().self_mls_roster_authority(&request).await?;
    ensure!(page.roster.records.len() == 1 && page.roster.next_cursor.is_none());
    let peer =
        arkret::verify_mls_member_roster_authority_pages(std::slice::from_ref(&page), &request)?;
    let material = client
        .sdk()
        .self_mls_group_state_material(&arkret::mls_roster_genesis_material_request(
            &peer,
            &page.roster.manifest,
        ))
        .await?;
    arkret::install_verified_mls_self_roster_bindings(&mut group, &[page], &request, &material)
        .map_err(anyhow::Error::msg)?;
    let (target, _) = controller_message(&controller, &mut group, &state, strand).await?;
    let (grant, _) = deployment
        .controller
        .grant_realm_actions_to(realm.as_str(), agent.agent_did.as_str(), &["ak.event.read"])
        .await?;
    let grant = arkret_wire::GrantId::new(grant)?;
    let original = deployment
        .controller
        .sdk()
        .committed_event_get(&EventId::from_token_bytes(grant.token_bytes())?)
        .await?;
    let payload: arkret_models_collaboration::events_payloads::CapabilityGrantPayload =
        serde_json::from_value(serde_json::to_value(
            &original
                .reducer_input()
                .context("parent literal read grant")?
                .payload,
        )?)?;
    ensure!(payload.grant.actions == vec!["ak.event.read"]);
    ensure!(matches!(payload.grant.subject,
        arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(ref actor)
        if actor==&ActorId::account(agent.agent_account.clone())));
    ensure!(
        read.sdk()
            .committed_event_get(&own_message.event_id)
            .await?
            .reducer_input()
            == Some(own_message)
    );
    crate::harness::expect_api_error(
        read.get(&format!(
            "/_arkret/self/committed-events/{}",
            target.event_id
        )),
        StatusCode::NOT_FOUND,
        arkret_wire::ErrorCode::NOT_FOUND,
    )
    .await?;
    ensure!(
        client
            .sdk()
            .committed_event_get(&target.event_id)
            .await?
            .reducer_input()
            == Some(&target)
    );
    let leave = MembershipPayload::transition(
        arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Leave,
        controller.actor.clone(),
        "Recheck ordinary controller qualification after departure",
    );
    let left: AuthoritySubmitResponseBody = serde_json::from_value(
        client
            .submit_event(source_realm.as_str(), "ak.member.state", leave.to_value()?)
            .await?,
    )?;
    ensure!(matches!(
        left,
        AuthoritySubmitResponseBody::Accepted {
            status: AuthorityCommitStatus::Committed,
            ..
        }
    ));
    let retained = SidecarEnsureRequestBody::Prepare(SidecarEnsurePrepareRequestBody {
        phase: SidecarEnsurePreparePhase::Prepare,
        operation_id: ProtocolOperationId::new(format!("ak:operation:{}", unique_uuid7()))
            .map_err(anyhow::Error::msg)?,
        idempotency_key: IdempotencyKey::new(format!("departed-prepare-{}", unique_uuid7()))
            .map_err(anyhow::Error::msg)?,
        source_realm_id: source_realm.clone(),
        controller_account_id: account,
        context_ref: SidecarContextRef::Strand {
            strand_id: strand.clone(),
        },
    });
    let retained = client
        .sdk()
        .agent_sidecar_ensure(&client.verify_publication(retained)?)
        .await?;
    ensure!(
        matches!(retained, SidecarEnsureResponseBody::PreparedExisting(existing)
        if existing.sidecar_id == view.sidecar.id),
        "project departure lost the owner's established private context"
    );
    ensure!(
        read.sdk()
            .committed_event_get(&own_message.event_id)
            .await?
            .reducer_input()
            == Some(own_message)
    );
    println!(
        "[agent-other-sidecar] actual_second_controller_onboarded=1 accepted_same_realm_join=1 independent_sidecar_genesis=1 actual_other_private_message=1 parent_literal_read_grant_retained=1 own_sidecar_payload_full=1 other_sidecar_payload_not_delivered=1 actual_owner_original_full=1 departed_controller_fresh_ensure_denied=1 other_owner_departure_preserves_own_read=1"
    );
    Ok(())
}

async fn advance_epoch_material(
    controller: &Member,
    agent: &AgentRuntimeSession,
    read: &TestActorClient,
    group: &mut arkret::ArkretMlsGroup,
    agent_group: &mut arkret::ArkretMlsGroup,
    scope: &ScopeRef,
) -> Result<arkret_wire::CommittedEventFullView> {
    let ScopeRef::Sidecar {
        realm_id,
        sidecar_id,
    } = scope
    else {
        bail!("native Sidecar scope required")
    };
    let snapshot = controller
        .client
        .sdk()
        .realm_state_snapshot_head(realm_id)
        .await?;
    let base: arkret_wire::MlsGroupValue = snapshot
        .current_state_entries
        .iter()
        .find_map(|row| {
            let arkret_wire::CurrentState::Value {
                selector: arkret_wire::CurrentSelector::MlsGroup { scope_ref },
                value,
                ..
            } = row
            else {
                return None;
            };
            (scope_ref == scope).then(|| serde_json::from_value(value.clone()))
        })
        .context("current Sidecar epoch")??;
    ensure!(base.epoch == 1 && group.epoch() == 1 && agent_group.epoch() == 1);
    let view = controller
        .client
        .sdk()
        .agent_sidecar_get(sidecar_id)
        .await?;
    ensure!(
        view.desired_agent_ids == vec![agent.agent_account.principal_id.clone()]
            && view.effective_agent_ids == vec![agent.agent_account.principal_id.clone()]
    );
    let binding = arkret::MlsGovernanceBindingPayload::sidecar(
        realm_id.clone(),
        sidecar_id.clone(),
        Some(base.current_mls_commit_event_ref.clone()),
        base.epoch,
        base.epoch + 1,
        base.current_key_access_revision,
        view.mls_context.participant_authority_digest,
    )?;
    let update = group.self_update_commit_with_governance_binding(&binding)?;
    let payload = crate::scenarios::mls_lifecycle_live::commit_payload_with_public_material(
        &controller.client,
        group,
        base.current_mls_commit_event_ref.clone(),
        base.current_key_access_revision,
        &update,
        binding,
    )
    .await?;
    let mut event = controller
        .client
        .author_event(
            realm_id.as_str(),
            "ak.mls.commit",
            serde_json::to_value(payload)?,
        )
        .await?;
    event.scope_ref = scope.clone();
    crate::harness::refresh_typed_event_proof_with_signing_seed(
        &mut event,
        controller.key.to_bytes(),
    )?;
    let journal = tempfile::tempdir()?;
    let path = journal.path().join("pending-controller.json");
    let mut file = std::fs::File::create(&path)?;
    use std::io::Write as _;
    file.write_all(&serde_json::to_vec(&group.export_state_record()?)?)?;
    file.sync_all()?;
    let pending: arkret::MlsGroupStateRecord = serde_json::from_slice(&std::fs::read(&path)?)?;
    *group = arkret::ArkretMlsGroup::restore_from_state_record(&pending)?;
    let submission =
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::MlsCommit(
            arkret_wire::MlsCommitSubmission {
                recovery_source: None,

                commit_event: event.clone(),
                welcomes: vec![],
                idempotency_key: arkret_wire::UuidV7::new(
                    crate::scenarios::mls_lifecycle_live::fresh_uuid_v7().parse()?,
                )?,
            },
        );
    let (status, result) =
        crate::scenarios::mls_lifecycle_live::post_json(&controller.client, &submission).await?;
    ensure!(
        status == StatusCode::OK,
        "Sidecar real future Update refused: {status} {result}"
    );
    let accepted = crate::scenarios::mls_lifecycle_live::accepted_full_view(
        &controller.client,
        &event.event_id,
    )
    .await?;
    ensure!(group.install_accepted_commit(&accepted, &base)? == 2);
    let received = read.sdk().committed_event_get(&event.event_id).await?;
    let arkret_wire::CommittedEventView::Full(received) = received else {
        bail!("current effective Agent did not receive actual future epoch material")
    };
    ensure!(received == accepted && agent_group.install_accepted_commit(&received, &base)? == 2);
    for (http, participant, actor) in [
        (
            controller.client.sdk(),
            &mut *group,
            controller.actor.clone(),
        ),
        (
            read.sdk(),
            &mut *agent_group,
            ActorId::account(agent.agent_account.clone()),
        ),
    ] {
        let request = arkret::MlsMemberRosterAuthorityReadRequestBody {
            realm_id: realm_id.clone(),
            effective_scope: scope.clone(),
            mls_group_id: scope.canonical_mls_group_id()?,
            target_commit_event_ref: event.event_id.clone(),
            target_epoch: 2,
            caller_actor_id: actor,
            cursor: None,
        };
        let page = http.self_mls_roster_authority(&request).await?;
        ensure!(page.roster.records.len() == 2 && page.roster.next_cursor.is_none());
        let peer = arkret::verify_mls_member_roster_authority_pages(
            std::slice::from_ref(&page),
            &request,
        )?;
        let material = http
            .self_mls_group_state_material(&arkret::mls_roster_genesis_material_request(
                &peer,
                &page.roster.manifest,
            ))
            .await?;
        arkret::install_verified_mls_self_roster_bindings(
            participant,
            &[page],
            &request,
            &material,
        )
        .map_err(anyhow::Error::msg)?;
    }
    let path = journal.path().join("updated-agent.json");
    let mut file = std::fs::File::create(&path)?;
    file.write_all(&serde_json::to_vec(&agent_group.export_state_record()?)?)?;
    file.sync_all()?;
    let state: arkret::MlsGroupStateRecord = serde_json::from_slice(&std::fs::read(&path)?)?;
    *agent_group = arkret::ArkretMlsGroup::restore_from_state_record(&state)?;
    ensure!(agent_group.epoch() == 2);
    Ok(accepted)
}

pub(super) async fn controller_message(
    controller: &Member,
    group: &mut arkret::ArkretMlsGroup,
    state: &arkret_wire::CommittedEventFullView,
    strand: &arkret_wire::StrandId,
) -> Result<(Event, Vec<u8>)> {
    let scope = state.event.scope_ref.clone();
    let content = arkret::ContentBlock::text("Endpoint-specific actual Sidecar content");
    let plaintext = arkret_canonical::canonical_json_bytes(&content)?;
    let mut event = controller
        .client
        .author_event(
            scope.realm_id().as_str(),
            "ak.message.create",
            json!({"strand_id":strand,"track_name":"discussion","content":content}),
        )
        .await?;
    event.scope_ref = scope;
    crate::harness::refresh_typed_event_proof_with_signing_seed(
        &mut event,
        controller.key.to_bytes(),
    )?;
    let (event, _) = crate::harness::content::seal_device_message(
        &controller.client,
        group,
        &state.event.event_id,
        event,
    )
    .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &controller.client,
        &controller.account,
        controller.device.as_str(),
        &event,
    )
    .await?;
    ensure!(
        controller
            .client
            .sdk()
            .committed_event_get(&event.event_id)
            .await?
            .reducer_input()
            == Some(&event)
    );
    Ok((event, plaintext))
}

async fn agent_message(
    agent: &AgentRuntimeSession,
    group: &mut arkret::ArkretMlsGroup,
    state: &arkret_wire::CommittedEventFullView,
    strand: &arkret_wire::StrandId,
    original: &Event,
    basis: arkret_models_crypto::ContentRootContext,
) -> Result<(Event, Vec<u8>)> {
    use arkret_models_crypto::EventContentMaterial;
    let envelope: arkret::EncryptedEnvelope =
        serde_json::from_value(original.payload["encrypted_content"].clone())?;
    ensure!(
        original.scope_ref == state.event.scope_ref
            && basis.group_state_ref == state.event.event_id
    );
    let mut material = EventContentMaterial::from_original(
        original,
        &envelope,
        basis,
        group.original_content_endpoint(original)?,
    )?;
    let root = group.export_content_root(&material.content_context.root_context)?;
    ensure!(
        arkret_crypto::content_history::content_root_ref(
            &root,
            &material.content_context.root_context
        )? == material.content_context.root_ref
            && material.protection.root_refs == [material.content_context.root_ref.clone()]
            && !material.protection.backup_refs.is_empty()
    );
    let old_key =
        arkret_crypto::content_history::derive_content_key(&root, &material.content_context)?;
    ensure!(
        arkret_crypto::content_history::content_key_commitment(
            &material.content_context,
            &old_key
        )? == material.key_commitment
    );
    let content = arkret::ContentBlock::text("Explicitly authorized private Sidecar reply");
    let plaintext = arkret_canonical::canonical_json_bytes(&content)?;
    let mut event = agent.author_scoped_event(
        arkret_wire::EventKind::MessageCreate,
        state.event.scope_ref.clone(),
        json!({"strand_id":strand,"track_name":"discussion","content":content}),
        vec![],
    )?;
    material.content_context.producer = group.local_content_endpoint()?;
    material.content_context.content_key_salt =
        arkret_crypto::content_history::fresh_content_key_salt()?;
    let new_key =
        arkret_crypto::content_history::derive_content_key(&root, &material.content_context)?;
    material.key_commitment = arkret_crypto::content_history::content_key_commitment(
        &material.content_context,
        &new_key,
    )?;
    material.outer_event = EventContentMaterial::outer_event_for(&event)?;
    material.protection.blob_refs.clear();
    crate::harness::content::seal_message(
        group,
        &mut event,
        &state.event.event_id,
        &plaintext,
        material,
    )?;
    crate::harness::refresh_typed_event_proof_with_signing_seed(
        &mut event,
        agent.runtime_key.to_bytes(),
    )?;
    Ok((event, plaintext))
}

pub(super) async fn open_message(
    client: &TestActorClient,
    group: &mut arkret::ArkretMlsGroup,
    event: &Event,
) -> Result<Vec<u8>> {
    let envelope: arkret::EncryptedEnvelope =
        serde_json::from_value(event.payload["encrypted_content"].clone())?;
    let domain = arkret::mls_basic_credential_identity(event.actual_signer())?;
    let header = envelope.reconstruct_pre_encryption_header(
        arkret::EncryptedPayloadScheme::EpochContentAead,
        event.scope_ref.clone(),
        event.kind.as_str(),
        std::str::from_utf8(&domain)?,
        None,
        crate::harness::content::original_material(client, group, event, &envelope).await?,
    )?;
    let payload =
        arkret::mls::encrypted_envelope_to_payload_with_verified_header(&envelope, header)?;
    Ok(group.decrypt_payload(&payload)?)
}

struct PendingPayload<'a> {
    read: &'a TestActorClient,
    strand: &'a arkret_wire::StrandId,
    deployment: &'a coauth_session_evidence::ActualAgentDeployment,
    actions: &'a [&'a str],
    genesis: &'a Event,
    read_positive_only: bool,
    pending_message: std::sync::Mutex<Option<arkret_wire::CommittedEventView>>,
}

#[async_trait::async_trait(?Send)]
impl JoinObserver for PendingPayload<'_> {
    async fn before_submission(
        &self,
        controller: &Member,
        agent: &AgentRuntimeSession,
        submission: &arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody,
        claim_request: &arkret_models_crypto::KeyPackagesClaimRequestBody,
    ) -> Result<()> {
        use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody;

        use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;
        let SelfAuthoritySubmitRequestBody::MlsCommit(original) = submission else {
            bail!("actual Add/Welcome submission required")
        };
        ensure!(original.welcomes.len() == 1);
        for kind in ["wrong_endpoint", "missing_add_lineage"] {
            let mut invalid = original.clone();
            invalid.idempotency_key = arkret_wire::UuidV7::new(
                crate::scenarios::mls_lifecycle_live::fresh_uuid_v7().parse()?,
            )?;
            let welcome = &mut invalid.welcomes[0];
            if kind == "wrong_endpoint" {
                welcome.recipient_endpoint =
                    arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
                        verification_method: DidUrl::new(format!(
                            "{}#not-the-current-endpoint",
                            agent.agent_did
                        ))
                        .map_err(anyhow::Error::msg)?,
                    };
            } else {
                let identity = arkret::ArkretMlsIdentity::new_agent(
                    ActorId::account(agent.agent_account.clone()),
                    agent.verification_method.clone(),
                    agent.key_authorization.clone(),
                    ArkretMlsSigner::from_ed25519_signing_key(agent.runtime_key.clone()),
                )?;
                let package = identity.key_package_record()?;
                let upload = identity.signed_key_packages_upload_request(
                    std::slice::from_ref(&package),
                    agent.verification_method.as_str(),
                )?;
                ensure!(
                    agent
                        .runtime
                        .sdk()
                        .keypackages_upload(&upload)
                        .await?
                        .accepted_count
                        == 1
                );
                let mut candidate = serde_json::to_value(claim_request)?;
                let mut entropy = [0u8; 16];
                getrandom::fill(&mut entropy)
                    .map_err(|error| anyhow::anyhow!("claim entropy: {error}"))?;
                candidate["claim_request_id"] = json!(URL_SAFE_NO_PAD.encode(entropy));
                candidate["target_keypackage_ref"] = json!(package.keypackage_ref);
                let mut claim: arkret_models_crypto::KeyPackagesClaimRequestBody =
                    serde_json::from_value(candidate)?;
                let bytes = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
                    &claim.unsigned_request(),
                    &claim.service_binding,
                    &claim.requester_authorization,
                )?;
                let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device {
                    signature,
                    ..
                } = &mut claim.requester_authorization
                else {
                    bail!("normal controller device claim required")
                };
                signature.signature = arkret_wire::Base64UrlString::new(
                    URL_SAFE_NO_PAD.encode(controller.key.sign(&bytes).to_bytes()),
                )
                .map_err(anyhow::Error::msg)?;
                let claimed = controller.client.sdk().keypackages_claim(&claim).await?;
                ensure!(
                    claimed.claims.len() == 1
                        && claimed.claims[0].keypackage_ref == package.keypackage_ref.as_str()
                );
                let second: arkret_wire::KeypackageClaimId =
                    serde_json::from_value(json!(claimed.claims[0].claim_id))?;
                ensure!(
                    second != welcome.keypackage_claim_ref,
                    "second claim must differ from actual Add"
                );
                welcome.keypackage_claim_ref = second;
            }
            let mut unsigned = serde_json::to_value(&*welcome)?;
            unsigned
                .as_object_mut()
                .context("Welcome object")?
                .remove("producer_proof");
            welcome.producer_proof = arkret_signatures::detached_object::sign_detached_object(
                &unsigned,
                arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
                controller.method.clone(),
                Utc::now(),
                &controller.key,
            )?;
            let before = acceptance_rows_with_agent_stores(
                self.deployment
                    .station
                    .owned_database_url()
                    .context("owned Station database")?,
                true,
            )
            .await?;
            let (status, code) = (
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::FAILED_PRECONDITION,
            );
            let problem = crate::harness::expect_api_error(
                controller
                    .client
                    .post("/_arkret/self/events")
                    .canonical_json(&SelfAuthoritySubmitRequestBody::MlsCommit(invalid))?,
                status,
                code,
            )
            .await?;
            if kind == "wrong_endpoint" {
                ensure!(
                    problem
                        .detail
                        .contains("Welcome recipient's endpoint package"),
                    "wrong endpoint did not reach the actual claim binding gate"
                );
            }
            ensure!(
                acceptance_rows_with_agent_stores(
                    self.deployment
                        .station
                        .owned_database_url()
                        .context("owned Station database")?,
                    true
                )
                .await?
                    == before,
                "{kind} altered accepted, current, Agent or delivery business state"
            );
            let (queued, _) =
                crate::scenarios::mls_lifecycle_live::recipient_welcomes(self.read).await?;
            ensure!(queued.is_empty(), "rejected {kind} supplied a Welcome");
            println!(
                "[agent-sidecar-lineage] rejected={kind} real_controller_signature=1 real_add_and_claim=1 full_business_footprint_unchanged=1 no_welcome_delivered=1"
            );
        }
        Ok(())
    }

    async fn before_consume(
        &self,
        controller: &Member,
        agent: &AgentRuntimeSession,
        group: &mut arkret::ArkretMlsGroup,
        agent_group: &mut arkret::ArkretMlsGroup,
        accepted: &arkret_wire::CommittedEventFullView,
        durable_state_path: &std::path::Path,
    ) -> Result<()> {
        let ScopeRef::Sidecar { sidecar_id, .. } = &accepted.event.scope_ref else {
            bail!("Sidecar required")
        };
        let view = controller
            .client
            .sdk()
            .agent_sidecar_get(sidecar_id)
            .await?;
        ensure!(
            view.desired_agent_ids == vec![agent.agent_account.principal_id.clone()]
                && view.effective_agent_ids.is_empty()
        );
        let (event, _) = controller_message(controller, group, accepted, self.strand).await?;
        crate::harness::expect_api_error(
            self.read.get(&format!(
                "/_arkret/self/committed-events/{}",
                event.event_id
            )),
            StatusCode::FORBIDDEN,
            arkret_wire::ErrorCode::CAPABILITY_DENIED,
        )
        .await?;
        let original = controller
            .client
            .sdk()
            .committed_event_get(&event.event_id)
            .await?;
        *self.pending_message.lock().unwrap() = Some(original);
        println!(
            "[agent-sidecar-pending] actual_accepted_add=1 actual_delivered_welcome=1 durable_local_state=1 consume_not_yet_sent=1 desired_not_effective=1 payload_refused=1"
        );
        let write_only = self
            .actions
            .iter()
            .copied()
            .filter(|action| !matches!(*action, "ak.event.read" | "ak.object.read"))
            .collect::<Vec<_>>();
        let (write, claims) = content_direct_evidence::issue(
            self.deployment,
            agent,
            &write_only,
            &accepted.event.realm_id,
        )
        .await?;
        ensure!(
            claims
                .scopes
                .iter()
                .any(|action| action == "ak.message.create")
                && !claims.scopes.iter().any(|action| action == "ak.event.read")
        );
        ensure!(
            claims
                .scope_details
                .as_ref()
                .context("pending explicit write ceiling")?
                .capability_grant_refs
                .is_empty()
        );
        let material = arkret_models_collaboration::mls_group_state_material::MlsMemberGroupStateMaterialReadRequestBody {
            realm_id:accepted.event.realm_id.clone(), effective_scope:accepted.event.scope_ref.clone(),
            mls_group_id:accepted.event.scope_ref.canonical_mls_group_id()?, epoch:Default::default(),
            group_state_event_id:self.genesis.event_id.clone(), caller_actor_id:ActorId::account(agent.agent_account.clone()),
            target_commit_event_ref:accepted.event.event_id.clone(),target_epoch:1,
            group_info_ref:arkret_wire::BlobRef::new(self.genesis.payload["group_info_ref"].as_str().context("accepted Genesis info")?)?,
            ratchet_tree_ref:arkret_wire::BlobRef::new(self.genesis.payload["ratchet_tree_ref"].as_str().context("accepted Genesis tree")?)?,max_response_bytes:None,
        };
        let mut before_add = material.clone();
        before_add.target_commit_event_ref = self.genesis.event_id.clone();
        before_add.target_epoch = 0;
        crate::harness::expect_api_error(
            self.read
                .post("/_arkret/self/mls/group-state-material/query")
                .canonical_json(&before_add)?,
            StatusCode::NOT_FOUND,
            arkret_wire::ErrorCode::NOT_FOUND,
        )
        .await?;
        self.read
            .sdk()
            .self_mls_group_state_material(&material)
            .await
            .context("pending endpoint Genesis material for its exact accepted Add target")?
            .validate_for_request(&material.as_peer_request())?;
        let (available, _) = crate::scenarios::mls_lifecycle_live::recipient_welcomes(self.read)
            .await
            .context("read-only actual Welcome control")?;
        ensure!(
            available.len() == 1
                && available[0].effective_scope == accepted.event.scope_ref
                && available[0].commit_event_ref == accepted.event.event_id
        );
        crate::harness::expect_api_error(
            write.get("/_arkret/self/device-messages"),
            StatusCode::FORBIDDEN,
            arkret_wire::ErrorCode::CAPABILITY_DENIED,
        )
        .await?;
        let (retained, _) = crate::scenarios::mls_lifecycle_live::recipient_welcomes(self.read)
            .await
            .context("read-only actual Welcome control")?;
        ensure!(
            retained == available,
            "denied Welcome read acknowledged or removed the queued original"
        );
        if !self.read_positive_only {
            let (write_with_read, combined) = content_direct_evidence::issue(
                self.deployment,
                agent,
                self.actions,
                &accepted.event.realm_id,
            )
            .await?;
            ensure!(
                combined
                    .scopes
                    .iter()
                    .any(|action| action == "ak.event.read")
                    && combined
                        .scopes
                        .iter()
                        .any(|action| action == "ak.message.create")
            );
            ensure!(
                combined
                    .scope_details
                    .as_ref()
                    .context("pending full content ceiling")?
                    .capability_grant_refs
                    .is_empty()
            );
            let basis = crate::harness::content::root_context(
                &controller.client,
                group,
                &accepted.event.event_id,
            )
            .await?;
            let (pending_write, _) =
                agent_message(agent, agent_group, accepted, self.strand, &event, basis).await?;
            {
                use std::io::Write;
                let mut file = std::fs::File::create(durable_state_path)?;
                file.write_all(&serde_json::to_vec(&agent_group.export_state_record()?)?)?;
                file.sync_all()?;
            }
            let durable: arkret::MlsGroupStateRecord =
                serde_json::from_slice(&std::fs::read(durable_state_path)?)?;
            *agent_group = arkret::ArkretMlsGroup::restore_from_state_record(&durable)?;
            ensure!(arkret_wire::ErrorCode::Conflict.http_status() == 409);
            crate::harness::expect_api_error(
                write_with_read
                    .post("/_arkret/self/events")
                    .canonical_json(&arkret_wire::EventAdmissionSubmission::new(
                        pending_write.clone(),
                    ))?,
                StatusCode::CONFLICT,
                arkret_wire::ErrorCode::CONFLICT,
            )
            .await?;
            crate::harness::expect_api_error(
                controller.client.get(&format!(
                    "/_arkret/self/committed-events/{}",
                    pending_write.event_id
                )),
                StatusCode::NOT_FOUND,
                arkret_wire::ErrorCode::NOT_FOUND,
            )
            .await?;
        }
        let still_pending = controller
            .client
            .sdk()
            .agent_sidecar_get(sidecar_id)
            .await?;
        ensure!(
            still_pending.desired_agent_ids == vec![agent.agent_account.principal_id.clone()]
                && still_pending.effective_agent_ids.is_empty()
        );
        if self.read_positive_only {
            println!(
                "[agent-sidecar-pending-read] actual_read_only_material=1 original_genesis_target_refused=1 exact_add_target_allowed=1 write_only_welcome_read_refused=1 queued_original_retained=1 native_private_reply_authority=1 business_write_fixture_not_executed=1"
            );
        } else {
            println!(
                "[agent-sidecar-pending-grant] actual_write_only_ceiling=1 same_queued_welcome_read_positive=1 write_does_not_read_welcome=1 queued_original_retained=1 read_and_write_ceiling_for_payload=1 valid_agent_ciphertext_durable_before_attempt=1 effective_missing_write_refused=1 effective_conflict_409=1 no_committed_original=1 pending_endpoint_still_ineffective=1"
            );
        }
        Ok(())
    }
}

pub async fn run_agent_content_sidecar_production()
-> Result<crate::conformance::SuiteExecutionResult> {
    crate::harness::heap_future(|| run_sidecar_production(SidecarCase::Content)).await?;
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: REVIEWED_SIDECAR_CONTENT_CASES
            .iter()
            .map(|name| crate::conformance::CaseExecutionResult {
                case_id: (*name).to_owned(),
                assertions: 1,
            })
            .collect(),
    })
}

pub async fn run_agent_content_sidecar_read_production() -> Result<()> {
    crate::harness::heap_future(|| run_sidecar_production(SidecarCase::LocalRead)).await
}

async fn join_controller_agent(
    client: &TestActorClient,
    controller: &AccountId,
    realm: &RealmId,
    generation: EventId,
    agent_account: &AccountId,
) -> Result<arkret_wire::RealmCommit> {
    let mut membership = MembershipPayload::join(
        realm.clone(),
        ActorId::account(agent_account.clone()),
        "Private Sidecar membership",
    );
    membership.agent_controller_binding = Some(AgentControllerMembershipBinding {
        controller_account_id: controller.clone(),
        controller_membership_generation_ref: generation,
        controller_terminal_event_ref: None,
    });
    let joined = client
        .author_event(realm.as_str(), "ak.member.state", membership.to_value()?)
        .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        client,
        controller,
        &client.device_id,
        &joined,
    )
    .await
}

pub async fn run_agent_membership_discovery() -> Result<()> {
    use arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeParameters;
    use arkret_models_collaboration::sync_frames::demand_sync::RealmListMembership;
    let deployment =
        coauth_session_evidence::actual_agent_deployment("agent-membership-discovery").await?;
    let client = &deployment.controller;
    let operations = arkret_schema::agent_runtime_scope::complete_agent_runtime_scope([
        ServiceOperationId::SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1,
        ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE_V1,
    ])?;
    let operations = operations.iter().map(String::as_str).collect::<Vec<_>>();
    let agent = AgentRuntimeSession::establish_observed(
        &deployment.station,
        AgentSessionIssuer::Coauth {
            base: deployment.coauth.base_url(),
            database_url: &deployment.coauth.pg.connect_url,
        },
        client,
        &deployment.account,
        "membership-only-agent",
        requested_scope(&operations)?,
        None,
    )
    .await?;
    let runtime = agent.runtime.sdk();
    let request = AccountSubscribeParameters::default();
    let before = runtime.account_subscribe_batch(&request).await?;
    // The service grant predates the new Realm and has no content selector.
    // Only the controller sends requests while the Agent is disconnected.
    let created = client.create_realm_with(json!({"title":"Offline membership discovery",
        "public":false,"join_rule":"invite","plaintext_visible_services":[deployment.station.service_id()]})).await?;
    let realm = RealmId::new(created["realm_id"].as_str().context("new parent Realm")?)?;
    let generation = EventId::new(
        created["event_response"]["commits"]
            .as_array()
            .and_then(|v| v.last())
            .and_then(|v| v["event_ref"].as_str())
            .context("controller membership generation")?,
    )?;
    join_controller_agent(
        client,
        &deployment.account,
        &realm,
        generation,
        &agent.agent_account,
    )
    .await?;
    let cold = runtime.account_subscribe_batch(&request).await?;
    let resume = |cursor: String| AccountSubscribeParameters {
        after: Some(cursor),
        ..Default::default()
    };
    let delta = runtime
        .account_subscribe_batch(&resume(before.cursor.clone()))
        .await?;
    for batch in [&cold, &delta] {
        ensure!(batch.frames.iter().all(|f| f.realms.is_none()
            && f.account_data.is_none()
            && f.device_lists.is_none()
            && f.agent_draft_pending_intents.is_none()
            && f.to_device.is_none()
            && f.notifications.is_none()));
        ensure!(
            batch
                .frames
                .iter()
                .flat_map(|f| f
                    .realm_list
                    .iter()
                    .flat_map(|p| &p.items)
                    .chain(f.realm_list_changes.iter().flat_map(|c| &c.upserts)))
                .any(|item| item.realm_id == realm
                    && item.membership == RealmListMembership::Join
                    && item.title.is_none()
                    && item.default_strand_id.is_none()),
            "fresh and resumed Agent-only sessions must discover the accepted join"
        );
    }
    let leave = client
        .author_event(
            realm.as_str(),
            "ak.member.state",
            json!({
        "member_id":ActorId::account(agent.agent_account.clone()),"membership":"leave"}),
        )
        .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        client,
        &deployment.account,
        &client.device_id,
        &leave,
    )
    .await?;
    let removed = runtime
        .account_subscribe_batch(&resume(delta.cursor))
        .await?;
    ensure!(
        removed
            .frames
            .iter()
            .flat_map(|f| &f.realm_list_changes)
            .flat_map(|c| &c.removals)
            .any(|r| r.realm_id == realm)
    );
    let missed = runtime
        .account_subscribe_batch(&resume(before.cursor))
        .await?;
    ensure!(missed.frames.iter().all(|f| {
        f.realm_list_changes.as_ref().is_none_or(|c| {
            c.upserts.iter().all(|r| r.realm_id != realm)
                && c.removals.iter().all(|r| r.realm_id != realm)
        }) && f
            .realm_invalidations
            .as_ref()
            .is_none_or(|v| v.iter().all(|r| r.realm_id != realm))
    }));
    Ok(())
}

async fn await_history_dispatch(
    listener: &tokio::net::TcpListener,
) -> Result<tokio::net::TcpStream> {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(Duration::from_secs(45), async {
        let (mut stream, address) = listener.accept().await?;
        ensure!(
            address.ip().is_loopback() && stream.read_u8().await? == 1,
            "unexpected dispatch observation"
        );
        Ok(stream)
    })
    .await
    .context("H did not reach the history handoff")?
}

async fn verify_queued_history_loss(
    listener: &tokio::net::TcpListener,
    home: &ActualAgentDeployment,
    governor: &ActualAgentDeployment,
    reader: &TestActorClient,
    agent: &AccountId,
    realm: &RealmId,
    query: &arkret_wire::StreamScanRequestBody,
    generation: &EventId,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    use crate::scenarios::human_device_producer_live::{
        ensure_commit_signed_by, ensure_same_commit, submit_and_expect_commit, wait_for_committed,
    };
    let database = home
        .station
        .owned_database_url()
        .context("home storage")?
        .to_owned();
    let read_checkpoint = || {
        let database = database.clone();
        let realm = realm.to_string();
        let member = json!(agent);
        let stream = json!(query.stream_ref);
        tokio::task::spawn_blocking(move || -> Result<_> {
            let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
            let row = db.query_one("SELECT
                (SELECT snapshot_json FROM realm_state_snapshots s JOIN realm_state_snapshot_issuances i USING(snapshot_id)
                 WHERE s.realm_id=$1 AND snapshot_json->>'purpose'='stream_history'
                 AND snapshot_json->'history_basis'->'account_id'=$2 AND snapshot_json->'history_basis'->'stream_ref'=$3
                 ORDER BY i.issued_at DESC,s.snapshot_id LIMIT 1),
                jsonb_build_object('head',(SELECT commit_id FROM realm_commits WHERE realm_id=$1 AND stream_ref=$3 ORDER BY stream_position DESC LIMIT 1),
                'anchors',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY a.stream_key),'[]'::jsonb)
                  FROM replica_stream_anchors a JOIN realm_commits c ON c.commit_id=a.join_commit_id
                  WHERE a.realm_id=$1 AND c.stream_ref=$3))",
                &[&realm,&member,&stream])?;
            Ok((
                serde_json::from_value::<arkret_wire::RealmStateSnapshot>(row.try_get(0)?)?,
                row.try_get::<_, serde_json::Value>(1)?,
            ))
        })
    };
    let original = read_checkpoint().await??;
    ensure!(
        reader
            .sdk()
            .realm_state_snapshot_by_ref(realm, &original.0.snapshot_id)
            .await?
            == original.0,
        "the original narrow snapshot must be held and readable before departure"
    );
    let expected_membership = original
        .0
        .active_realm_member_revision(&ActorId::account(agent.clone()))
        .context("original signed membership")?
        .commit_id
        .clone();
    let request = reader
        .post("/_arkret/self/streams/scan")
        .canonical_json(query)?;
    let pending = async {
        let response = request.send().await;
        if let Ok(mut response) = response {
            ensure!(
                response.status().is_success(),
                "history had not been accepted for queued delivery"
            );
            ensure!(
                response.chunk().await.is_err(),
                "a queued read produced a body after withdrawal"
            );
        }
        Ok::<(), anyhow::Error>(())
    };
    let withdraw = async {
        let mut gate = await_history_dispatch(listener).await?;
        let event = home
            .controller
            .author_event(
                realm.as_str(),
                "ak.member.state",
                json!({"member_id":ActorId::account(agent.clone()),"membership":"leave"}),
            )
            .await?;
        let accepted = submit_and_expect_commit(
            &home.controller,
            &home.account,
            &home.controller.device_id,
            &event,
        )
        .await?;
        ensure_commit_signed_by(&accepted, &governor.station)?;
        ensure_same_commit(
            &accepted,
            &wait_for_committed(&home.controller, &event.event_id).await?,
        )?;
        // Withdrawal itself legitimately advances the shared Realm stream.
        // Record its accepted cut while the queued delivery is still paused.
        let after_withdrawal = read_checkpoint().await??;
        ensure!(after_withdrawal.0 == original.0);
        gate.write_u8(1).await?;
        Ok(after_withdrawal)
    };
    let ((), after_withdrawal) = tokio::try_join!(pending, withdraw)?;
    println!(
        "[project-history] G accepted withdrawal before H released the queued response; zero body bytes"
    );
    crate::harness::expect_json(reader.get("/_arkret/self/device-messages"), StatusCode::OK)
        .await?;
    crate::harness::expect_api_error(
        reader
            .post("/_arkret/self/streams/scan")
            .canonical_json(query)?,
        StatusCode::FORBIDDEN,
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
    )
    .await?;
    ensure!(
        read_checkpoint().await?? == after_withdrawal,
        "refused delivery advanced the home history checkpoint"
    );
    let joined = join_controller_agent(
        &home.controller,
        &home.account,
        realm,
        generation.clone(),
        agent,
    )
    .await?;
    ensure_commit_signed_by(&joined, &governor.station)?;
    ensure!(joined.commit_id != expected_membership);
    let after_rejoin = read_checkpoint().await??;
    ensure!(after_rejoin.0 == original.0);
    let bootstrap=arkret_models_collaboration::governance::realm_join_intake::PeerRealmJoinBootstrapRequestBody {
        request_id:RequestId::new_v7_at(Utc::now().timestamp_millis().max(0) as u64),
        realm_id:realm.clone(), member_account_id:agent.clone(),membership_commit_id:joined.commit_id.clone(),content_intent:None,history_stream_ref:Some(query.stream_ref.clone()),
    };
    ensure!(
        bootstrap.validate_history_snapshot(&original.0).is_err(),
        "old signed history accepted for new join"
    );
    crate::harness::expect_api_error(
        reader
            .get(&format!(
                "/_arkret/self/realm-state-snapshot/{}",
                original.0.snapshot_id
            ))
            .query(&[("realm_id", realm.as_str())]),
        StatusCode::SERVICE_UNAVAILABLE,
        arkret_wire::ErrorCode::REALM_STATE_SNAPSHOT_UNAVAILABLE,
    )
    .await?;
    ensure!(
        read_checkpoint().await?? == after_rejoin,
        "old history changed accepted history or replication progress"
    );
    println!(
        "[project-history] rejoin received a different membership Commit; old signed snapshot refused and checkpoint preserved"
    );
    Ok(())
}

pub async fn run_cross_station_project_history() -> Result<()> {
    crate::harness::heap_future(|| run_sidecar_production(SidecarCase::ProjectHistory)).await
}

async fn verify_private_federation_absent(
    database: String,
    sidecar: String,
    create: String,
    foreign: bool,
) -> Result<()> {
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut db=postgres::Client::connect(&database,postgres::NoTls)?;
        let row=db.query_one("SELECT
            EXISTS(SELECT 1 FROM canonical_events e WHERE e.envelope->>'event_id'=$2 OR e.envelope->'scope_ref'->>'sidecar_id'=$1),
            EXISTS(SELECT 1 FROM authority_forward_attempts f JOIN canonical_events e ON e.pk=f.event_pk
                 WHERE e.envelope->>'event_id'=$2 OR e.envelope->'scope_ref'->>'sidecar_id'=$1),
            EXISTS(SELECT 1 FROM event_federation_outbox f JOIN canonical_events e ON e.pk=f.event_pk
                 WHERE e.envelope->>'event_id'=$2 OR e.envelope->'scope_ref'->>'sidecar_id'=$1),
            EXISTS(SELECT 1 FROM federation_outbox f WHERE strpos(to_jsonb(f)::text,$1)>0 OR strpos(to_jsonb(f)::text,$2)>0)",
            &[&sidecar,&create])?;
        ensure!(row.get::<_,bool>(0)!=foreign && !(1..=3).any(|i|row.get::<_,bool>(i)),
            "private Sidecar originals, forwarding attempts or outbox rows crossed their home boundary");
        Ok(())
    }).await?
}

async fn recover_on_new_device(
    device: &TestActorClient,
    expected: &arkret_wire::CommittedEventView,
    recovery_mnemonic: &str,
    producer: arkret_models_crypto::ContentEndpoint,
    expected_reply: &arkret_wire::CommittedEventView,
    reply_producer: arkret_models_crypto::ContentEndpoint,
    backup_verifier: &ed25519_dalek::VerifyingKey,
) -> Result<(Vec<u8>, Vec<u8>)> {
    use arkret_models_crypto::*;
    use ed25519_dalek::Signer as _;
    let sdk = device.sdk();
    let commit = expected.commit();
    let held = sdk.committed_event_get(&commit.event_ref).await?;
    ensure!(&held == expected);
    let event = held
        .reducer_input()
        .context("recovery requires the full accepted original")?;
    let envelope: EncryptedEnvelope =
        serde_json::from_value(event.payload["encrypted_content"].clone())?;
    let EncryptedEnvelopeEncryptionContext::EpochContent {
        root_ref,
        protection,
        ..
    } = &envelope.encryption_context;
    let [backup_id] = protection.backup_refs.as_slice() else {
        bail!("expected the original controller backup")
    };
    let access = ContentHistoryBackupAccess {
        source: arkret_wire::CommittedEventRef {
            event_id: commit.event_ref.clone(),
            commit_id: commit.commit_id.clone(),
            stream_ref: commit.stream_ref.clone(),
            stream_position: commit.stream_position,
        },
        root_refs: vec![root_ref.clone()],
    };
    let encoded = |bytes: &[u8]| {
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(bytes))
            .map_err(anyhow::Error::msg)
    };
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).context("generate backup challenge request")?;
    let challenge = sdk
        .issue_key_backup_unlock_challenge(
            backup_id,
            &KeysBackupsIssueUnlockChallengeRequestBody {
                request_id: encoded(&nonce)?,
                subject_actor_id: None,
                custody_authorization_ref: None,
                content_history: Some(access.clone()),
            },
        )
        .await?;
    challenge.validate_at(Utc::now())?;
    let principal = device.principal.as_ref().context("new authorized device")?;
    ensure!(
        challenge.requesting_device_id == principal.device_id
            && challenge.content_history.as_ref() == Some(&access)
    );
    let mut proof = KeyBackupUnlockProof {
        schema: KeyBackupUnlockProof::SCHEMA.into(),
        authority: KeyBackupUnlockAuthority::CurrentDevice {
            challenge_id: challenge.challenge_id.clone(),
        },
        account_id: challenge.account_id.clone(),
        requesting_device_id: principal.device_id.clone(),
        backup_id: backup_id.clone(),
        backup_kind: BackupKind::SecretStorage,
        series_id: challenge.series_id.clone(),
        ciphertext_digest: challenge.ciphertext_digest.clone(),
        challenge: challenge.challenge.clone(),
        service_id: challenge.service_id.clone(),
        audience: challenge.audience.clone(),
        issued_at: challenge.issued_at,
        expires_at: challenge.expires_at,
        content_history: Some(access),
        subject_actor_id: None,
        custody_authorization_ref: None,
        signature_proof: KeyBackupUnlockSignatureProof {
            verification_method: DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
                .map_err(anyhow::Error::msg)?,
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            signature: encoded(&[0; 64])?,
        },
    };
    proof.signature_proof.signature = encoded(
        &principal
            .device_signing_key
            .sign(&proof.signing_payload_bytes()?)
            .to_bytes(),
    )?;
    proof.validate_for_challenge(&challenge)?;
    let backup = sdk
        .unlock_key_backup(backup_id, &KeysBackupsUnlockRequestBody { proof })
        .await?;
    ensure!(
        backup.signature_proof.device_authorize_event_id.as_ref()
            == Some(&producer.authorization_event_ref)
    );
    let recovery = arkret::identity_root::derive_identity_recovery_key_material_from_bip39(
        recovery_mnemonic,
        "",
        0,
    )?;
    let bag = arkret_crypto::content_history::open_content_root_backup(
        &backup,
        &recovery.backup_hpke_serialized_private_key,
        |bytes, proof| {
            let raw = arkret_canonical::base64url_decode(proof.signature.as_str())
                .map_err(|e| arkret_crypto::Error::Protocol(e.to_string()))?;
            let signature = ed25519_dalek::Signature::from_slice(&raw)
                .map_err(|e| arkret_crypto::Error::Protocol(e.to_string()))?;
            backup_verifier
                .verify_strict(bytes, &signature)
                .map_err(|e| arkret_crypto::Error::Protocol(e.to_string()))
        },
    )?;
    let root = bag
        .items
        .into_iter()
        .find_map(|entry| match entry {
            SecretStorageEntry::ContentRoot(root) if &root.root_ref == root_ref => Some(root),
            _ => None,
        })
        .context("recovered backup omitted the original epoch root")?;
    let decrypt = |event: &Event,
                   envelope: &arkret_models_crypto::EncryptedEnvelope,
                   producer: arkret_models_crypto::ContentEndpoint|
     -> Result<Vec<u8>> {
        let EncryptedEnvelopeEncryptionContext::EpochContent {
            root_ref: held_root,
            ..
        } = &envelope.encryption_context;
        ensure!(held_root == &root.root_ref);
        let material = EventContentMaterial::from_original(
            event,
            envelope,
            root.root_context.clone(),
            producer,
        )?;
        let domain = arkret::mls_basic_credential_identity(event.actual_signer())?;
        let header = envelope.reconstruct_pre_encryption_header(
            arkret::EncryptedPayloadScheme::EpochContentAead,
            event.scope_ref.clone(),
            event.kind.as_str(),
            std::str::from_utf8(&domain)?,
            None,
            material,
        )?;
        Ok(arkret_crypto::content_history::open_content(
            &root.root_base64url,
            &header,
            &envelope.ciphertext,
        )?)
    };
    let restored_reply = sdk
        .committed_event_get(&expected_reply.commit().event_ref)
        .await?;
    ensure!(
        &restored_reply == expected_reply
            && restored_reply.commit().stream_ref == commit.stream_ref
    );
    let reply = restored_reply
        .reducer_input()
        .context("recovery requires the signed Agent reply")?;
    let reply_envelope = serde_json::from_value(reply.payload["encrypted_content"].clone())?;
    Ok((
        decrypt(event, &envelope, producer)?,
        decrypt(reply, &reply_envelope, reply_producer)?,
    ))
}

pub async fn run_home_sidecar_offline() -> Result<()> {
    crate::harness::heap_future(|| run_sidecar_production(SidecarCase::OfflineHome)).await
}

enum SidecarCase {
    Content,
    LocalRead,
    ProjectHistory,
    OfflineHome,
}

async fn run_sidecar_production(case: SidecarCase) -> Result<()> {
    let read_positive_only = matches!(case, SidecarCase::LocalRead);
    let fixture = crate::conformance::load_fixture_value("agent-vectors-fixture.json")?;
    let contract = &fixture["session_content_authority_contract"];
    ensure!(
        arkret_canonical::sha256_hex(arkret_canonical::canonical_json_bytes(
            &contract["defaults"]
        )?) == "49fad7028393f37d28ca1a4ee06c376d6b16be0a16e4bfa35b77826a53130665"
    );
    let path = json!([{"kind":"sidecar_read","actions":["ak.event.read"],"resources":["A"],"complete":true,"active":true}]);
    for (name, input, expected) in [
        (
            "sidecar_read_without_literal_grant",
            json!({"paths":path,"resource_profile":"sidecar"}),
            "allow",
        ),
        (
            "sidecar_read_does_not_grant_write",
            json!({"action":"ak.message.create","paths":[{"kind":"sidecar_read","actions":["ak.message.create"],"resources":["A"],"complete":true,"active":true}],"resource_profile":"sidecar"}),
            "deny",
        ),
        (
            "bootstrap_desired_not_yet_effective",
            json!({"phase":"bootstrap","effective":false,"mls_ready":false,"paths":path,"resource_profile":"sidecar"}),
            "allow",
        ),
        (
            "bootstrap_wrong_endpoint",
            json!({"phase":"bootstrap","effective":false,"exact_endpoint":false,"paths":path,"resource_profile":"sidecar"}),
            "deny",
        ),
        (
            "bootstrap_missing_add_welcome_claim_lineage",
            json!({"phase":"bootstrap","accepted_lineage":false,"paths":path,"resource_profile":"sidecar"}),
            "deny",
        ),
        (
            "desired_cannot_read_payload",
            json!({"phase":"payload","effective":false,"paths":path,"resource_profile":"sidecar"}),
            "deny",
        ),
        (
            "effective_sidecar_payload",
            json!({"phase":"payload","paths":path,"resource_profile":"sidecar"}),
            "allow",
        ),
        (
            "issue_pending_mls_is_only_ceiling",
            json!({"mls_ready":false,"effective":false,"paths":path,"resource_profile":"sidecar"}),
            "allow",
        ),
        (
            "project_grant_cannot_authorize_private_reply",
            json!({"resource_profile":"sidecar","action":"ak.message.create","paths":[{"kind":"capability_grant","actions":["ak.message.create"],"resources":["A"],"complete":true,"active":true}],"phase":"payload"}),
            "deny",
        ),
        (
            "sidecar_explicit_write_grant",
            json!({"resource_profile":"sidecar","action":"ak.message.create","paths":[{"kind":"sidecar_private_reply","actions":["ak.message.create"],"resources":["A"],"complete":true,"active":true}],"phase":"payload"}),
            "allow",
        ),
        (
            "sidecar_write_grant_after_desired_loss",
            json!({"resource_profile":"sidecar","action":"ak.message.create","paths":[{"kind":"sidecar_private_reply","actions":["ak.message.create"],"resources":["A"],"complete":true,"active":true}],"phase":"payload","desired":false}),
            "deny",
        ),
        (
            "sidecar_write_grant_without_effective",
            json!({"resource_profile":"sidecar","action":"ak.message.create","paths":[{"kind":"sidecar_private_reply","actions":["ak.message.create"],"resources":["A"],"complete":true,"active":true}],"phase":"payload","effective":false}),
            "deny",
        ),
        (
            "sidecar_material_not_a_write_grant_operation",
            json!({"resource_profile":"sidecar","action":"ak.message.create","paths":[{"kind":"sidecar_private_reply","actions":["ak.message.create"],"resources":["A"],"complete":true,"active":true}],"phase":"bootstrap"}),
            "deny",
        ),
        (
            "queued_welcome_after_desired_revoke",
            json!({"phase":"bootstrap","desired":false,"paths":path,"resource_profile":"sidecar"}),
            "deny",
        ),
        (
            "future_epoch_material_after_desired_revoke",
            json!({"phase":"future_material","desired":false,"paths":path,"resource_profile":"sidecar"}),
            "deny",
        ),
        (
            "valid_future_epoch_material",
            json!({"phase":"future_material","paths":path,"resource_profile":"sidecar"}),
            "allow",
        ),
        (
            "wrong_sidecar_binding",
            json!({"phase":"payload","same_account_scope":false,"paths":path,"resource_profile":"sidecar"}),
            "deny",
        ),
        (
            "realm_grant_cannot_replace_sidecar_authority",
            json!({"resource_profile":"sidecar","paths":[{"kind":"capability_grant","actions":["ak.event.read"],"resources":["A"],"complete":true,"active":true}]}),
            "deny",
        ),
    ] {
        let rows = contract["cases"]
            .as_array()
            .context("Sidecar contract")?
            .iter()
            .filter(|v| v["name"] == name)
            .collect::<Vec<_>>();
        ensure!(
            rows.len() == 1 && rows[0]["input"] == input && rows[0]["expected"] == expected,
            "review changed Sidecar case {name}"
        );
    }
    let mut observer = None;
    let (deployment, mut governor) = match case {
        SidecarCase::ProjectHistory => {
            let listener =
                tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let (home, governor) =
                super::cross_station_agent_join::independent_stations(Some(listener.local_addr()?))
                    .await?;
            observer = Some(listener);
            (home, Some(governor))
        }
        SidecarCase::OfflineHome => {
            let (h, g) = super::cross_station_agent_join::independent_stations(None).await?;
            (h, Some(g))
        }
        _ => (
            coauth_session_evidence::actual_agent_deployment("agent-content-sidecar").await?,
            None,
        ),
    };
    let client = &deployment.controller;
    let principal = client.principal.as_ref().context("actual controller")?;
    let controller = Member {
        client: client.clone(),
        account: deployment.account.clone(),
        actor: ActorId::account(deployment.account.clone()),
        device: principal.device_id.clone(),
        method: DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
            .map_err(anyhow::Error::msg)?,
        key: principal.device_signing_key.clone(),
        authorize_event_id: principal.founding_authorize_event_id.clone(),
    };
    let realm_owner = governor.as_ref().unwrap_or(&deployment);
    let mut visible_stations = vec![deployment.station.service_id()];
    if let Some(remote) = &governor {
        visible_stations.push(remote.station.service_id());
    }
    let created = realm_owner
        .controller
        .create_realm_with(
            json!({"title":"Real issuer Sidecar", "public":false,"join_rule":"public",
            "plaintext_visible_services":visible_stations}),
        )
        .await?;
    let realm = RealmId::new(created["realm_id"].as_str().context("Sidecar parent")?)?;
    let strand = arkret_wire::StrandId::new(
        created["default_strand_id"]
            .as_str()
            .context("Sidecar context")?,
    )?;
    let generation = if let Some(remote) = &governor {
        super::cross_station_agent_join::controller_join(&deployment, remote, &realm)
            .await?
            .event_ref
    } else {
        EventId::new(
            created["event_response"]["commits"]
                .as_array()
                .and_then(|v| v.last())
                .and_then(|v| v["event_ref"].as_str())
                .context("controller current generation")?,
        )?
    };
    if !matches!(case, SidecarCase::OfflineHome) {
        realm_owner
            .controller
            .grant_realm_actions_to_client(
                realm.as_str(),
                client,
                &["ak.event.read", "ak.message.create"],
            )
            .await?;
    }
    if matches!(case, SidecarCase::OfflineHome) {
        let remote = governor.as_mut().context("independent project Station")?;
        let known =
            crate::scenarios::human_device_producer_live::wait_for_member_snapshot(client, &realm)
                .await
                .context("owner opens the project Strand before G goes offline")?;
        ensure!(
            known.current_state_entries.iter().any(|row| matches!(row,
                arkret_wire::CurrentState::Value {
                    selector: arkret_wire::CurrentSelector::Strand { strand_id },
                    source_stream_ref: arkret_wire::CommitStreamRef::Realm { realm_id }, ..
                } if strand_id == &strand && realm_id == &realm
            )),
            "the owner's G snapshot must actually identify the ordinary project Strand"
        );
        remote.station.stop_external_process().await?;
        remote.coauth.kill_immediately()?;
    }
    let operations = arkret_schema::agent_runtime_scope::complete_agent_runtime_scope([
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE_V1,
        ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
        ServiceOperationId::SELF_COMMITTED_EVENT_RESOURCE_GET_V1,
        ServiceOperationId::SELF_REALM_READ_STREAMS_V1,
        ServiceOperationId::SELF_REALM_STATE_SNAPSHOT_READ_MANIFEST_HEAD_V1,
        ServiceOperationId::SELF_REALM_STATE_SNAPSHOT_READ_BY_REF_V1,
        ServiceOperationId::SELF_MLS_READ_ROSTER_AUTHORITY_V1,
        ServiceOperationId::SELF_MLS_READ_GROUP_STATE_MATERIAL_V1,
        ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM_V1,
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_READ_CLAIM_V1,
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1,
        ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1,
        ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_ACK_V1,
        "ak.event.read",
        "ak.object.read",
        "ak.message.create",
    ])?;
    let actions = operations.iter().map(String::as_str).collect::<Vec<_>>();
    let mut provision_scope = requested_scope(&actions)?;
    if !matches!(case, SidecarCase::OfflineHome) {
        provision_scope.resources.push(serde_json::from_value(
            json!({"kind":"realm","realm_id":realm}),
        )?);
    }
    if !matches!(case, SidecarCase::ProjectHistory) {
        provision_scope.resources.push(serde_json::from_value(
            json!({"kind":"realm","realm_id":principal.pcr_realm_id}),
        )?);
    }
    let mut agent = AgentRuntimeSession::establish_observed(
        &deployment.station,
        AgentSessionIssuer::Coauth {
            base: deployment.coauth.base_url(),
            database_url: &deployment.coauth.pg.connect_url,
        },
        client,
        &deployment.account,
        "actual-sidecar-agent",
        provision_scope,
        None,
    )
    .await?;
    if matches!(case, SidecarCase::ProjectHistory) {
        let remote = governor.as_ref().context("G")?;
        let timing = observer.as_ref().context("H transport observer")?;
        let joined = join_controller_agent(
            client,
            &deployment.account,
            &realm,
            generation.clone(),
            &agent.agent_account,
        )
        .await?;
        let read_grant = client.author_event(realm.as_str(), "ak.capability.grant", json!({"grant":{
            "schema":"ak.schema.capability.v1","realm_id":realm,"issuer_id":controller.actor,
            "subject":ActorId::account(agent.agent_account.clone()),"actions":["ak.event.read"],
            "resources":[{"kind":"realm","realm_id":realm,"match_scope":"realm_wide"}],
            "constraints":[{"constraint_kind":"authority_control","effect":"allow","max_authority_depth":0,"authority_regrant_allowed":false}],
            "issuer_authority_refs":[arkret::IssuerAuthorityRef::OwnedAgent{
                realm_id:realm.clone(), controller_account_id:deployment.account.clone(),
                controller_join_event_id:generation.clone(),agent_join_event_id:joined.event_ref.clone()}],
            "issued_at":arkret_canonical::format_timestamp_canonical(Utc::now())
        }})).await?;
        use crate::scenarios::human_device_producer_live::{
            ensure_commit_signed_by, submit_and_expect_commit, wait_for_committed,
        };
        ensure_commit_signed_by(
            &submit_and_expect_commit(client, &deployment.account, &client.device_id, &read_grant)
                .await?,
            &remote.station,
        )?;
        let message=remote.controller.author_event(realm.as_str(),"ak.message.create", json!({"strand_id":strand,"track_name":"discussion","content":arkret::ContentBlock::text("G authorized project history")})).await?;
        let commit = submit_and_expect_commit(
            &remote.controller,
            &remote.account,
            &remote.controller.device_id,
            &message,
        )
        .await?;
        ensure_commit_signed_by(&commit, &remote.station)?;
        let expected = wait_for_committed(&remote.controller, &message.event_id).await?;
        // The immutable provision selects the mandatory service operations.
        // Issue a read-only content ceiling on the project while retaining those operations.
        let read_actions = actions
            .iter()
            .copied()
            .filter(|action| *action != "ak.message.create")
            .collect::<Vec<_>>();
        let (reader, _) =
            content_direct_evidence::issue(&deployment, &agent, &read_actions, &realm)
                .await
                .context("issue the project Agent's read-only session")?;
        let query = arkret_wire::StreamScanRequestBody {
            realm_id: realm.clone(),
            stream_ref: commit.stream_ref.clone(),
            direction: arkret_wire::StreamScanDirection::After(None),
            limit: 100,
        };
        let sdk = reader.sdk();
        let (page, ()) = tokio::try_join!(
            async {
                sdk.scan_commit_stream(&query)
                    .await
                    .context("G original via H")
            },
            async {
                use tokio::io::AsyncWriteExt;
                await_history_dispatch(timing).await?.write_u8(1).await?;
                Ok(())
            }
        )?;
        page.validate_for_request(&query)?;
        ensure!(
            expected.reducer_input() == Some(&message) && page.committed_events.contains(&expected)
        );
        println!("[project-history] Agent read the exact G-signed project message through H");
        return verify_queued_history_loss(
            timing,
            &deployment,
            remote,
            &reader,
            &agent.agent_account,
            &realm,
            &query,
            &generation,
        )
        .await;
    }
    let source_realm = realm;
    let realm = principal.pcr_realm_id.clone();
    let operation = ProtocolOperationId::new(format!("ak:operation:{}", unique_uuid7()))
        .map_err(anyhow::Error::msg)?;
    let prepare = SidecarEnsureRequestBody::Prepare(SidecarEnsurePrepareRequestBody {
        phase: SidecarEnsurePreparePhase::Prepare,
        operation_id: operation.clone(),
        idempotency_key: IdempotencyKey::new(format!("sidecar-prepare-{}", unique_uuid7()))
            .map_err(anyhow::Error::msg)?,
        source_realm_id: source_realm.clone(),
        controller_account_id: deployment.account.clone(),
        context_ref: SidecarContextRef::Strand {
            strand_id: strand.clone(),
        },
    });
    let SidecarEnsureResponseBody::PreparedNew(prepared) = client
        .sdk()
        .agent_sidecar_ensure(&client.verify_publication(prepare)?)
        .await
        .context("prepare the controller Sidecar and context")?
    else {
        bail!("Sidecar new preparation required")
    };
    let create = client.sign_prepared_contact_event(
        &prepared.create_event_draft,
        arkret_wire::EventKind::SidecarCreate.as_str(),
    )?;
    let attach = client.sign_prepared_contact_event(
        &prepared.context_attach_event_draft,
        arkret_wire::EventKind::SidecarContextAttach.as_str(),
    )?;
    let attach_id = attach.event_id.clone();
    let request = SidecarEnsureRequestBody::Commit(SidecarEnsureCommitRequestBody {
        phase: SidecarEnsureCommitPhase::Commit,
        operation_id: operation,
        idempotency_key: IdempotencyKey::new(format!("sidecar-commit-{}", unique_uuid7()))
            .map_err(anyhow::Error::msg)?,
        reservation_handle: prepared.reservation_handle,
        create_event: create.clone(),
        context_attach_event: attach,
    });
    let signed_request = client.verify_publication(request.clone())?;
    let sdk = client.sdk();
    let outcome = sdk
        .agent_sidecar_ensure(&signed_request)
        .await
        .context("H atomically accepts create and attach")?;
    let SidecarEnsureResponseBody::Accepted(accepted) = outcome else {
        bail!("Sidecar acceptance required")
    };
    if governor.is_some() {
        let replay = client
            .sdk()
            .agent_sidecar_ensure(&client.verify_publication(request.clone())?)
            .await?;
        ensure!(
            serde_json::to_value(replay)? == serde_json::to_value(&accepted)?,
            "exact first ensure replay changed its outcome"
        );
        let SidecarEnsureRequestBody::Commit(unit) = &request else {
            unreachable!()
        };
        let mut receipts = Vec::new();
        for original in [&unit.create_event, &unit.context_attach_event] {
            let held = crate::scenarios::human_device_producer_live::wait_for_committed(
                client,
                &original.event_id,
            )
            .await?;
            ensure!(
                held.reducer_input() == Some(original),
                "controller did not recover the signed original"
            );
            crate::scenarios::human_device_producer_live::ensure_commit_signed_by(
                held.commit(),
                &deployment.station,
            )?;
            receipts.push(held.commit().clone());
        }
        ensure!(
            receipts[0].authority_ref == receipts[1].authority_ref
                && receipts[0].governance_generation == receipts[1].governance_generation
                && receipts[0].stream_ref != receipts[1].stream_ref
                && receipts[1].stream_position == 0
        );
    }
    let sidecar = accepted.sidecar_id;
    ensure!(sidecar == arkret_wire::SidecarId::from_event_id(&create.event_id));
    let view = client.sdk().agent_sidecar_get(&sidecar).await?;
    ensure!(
        view.sidecar.id == sidecar
            && view.sidecar.realm_id == realm
            && view.sidecar.controller_account_id == deployment.account
    );
    ensure!(view.sidecar.source_realm_id == source_realm && view.desired_agent_ids.is_empty());
    let mut enroll = client
        .author_event(
            realm.as_str(),
            "ak.sidecar.member.state",
            json!({"agent_account_id":agent.agent_account,"membership":"join","private_reply_allowed":true}),
        )
        .await?;
    enroll.scope_ref = ScopeRef::Sidecar {
        realm_id: realm.clone(),
        sidecar_id: sidecar.clone(),
    };
    crate::harness::refresh_typed_event_proof_with_signing_seed(
        &mut enroll,
        controller.key.to_bytes(),
    )?;
    let enrolled = crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        client,
        &deployment.account,
        &client.device_id,
        &enroll,
    )
    .await?;
    crate::scenarios::human_device_producer_live::ensure_commit_signed_by(
        &enrolled,
        &deployment.station,
    )?;
    let view = client.sdk().agent_sidecar_get(&sidecar).await?;
    ensure!(
        view.desired_agent_ids == vec![agent.agent_account.principal_id.clone()]
            && view.effective_agent_ids.is_empty()
            && view.mls_context.mls_group_id.is_none()
    );
    let read_actions = actions
        .iter()
        .copied()
        .filter(|v| *v != "ak.message.create")
        .collect::<Vec<_>>();
    let (read, claims) =
        content_direct_evidence::issue(&deployment, &agent, &read_actions, &realm).await?;
    ensure!(
        claims
            .scope_details
            .as_ref()
            .context("Sidecar frozen ceiling")?
            .capability_grant_refs
            .is_empty()
    );
    ensure!(
        claims.scopes.iter().any(|v| v == "ak.event.read")
            && !claims.scopes.iter().any(|v| v == "ak.message.create")
    );
    agent.runtime = read.clone();
    let scope = ScopeRef::Sidecar {
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
    )?;
    let mut group = controller
        .mls_identity()?
        .create_group_with_governance_binding(&scope, &binding)?;
    let leaf = crate::scenarios::cross_station_mls_welcome::genesis_creator_leaf_authority(
        &mut group,
        &controller,
    )?;
    let (info, tree) = group.public_group_state_bytes()?;
    let info = upload_public_blob(client, &realm, &info).await?;
    let tree = upload_public_blob(client, &realm, &tree).await?;
    let mut genesis = client.author_event(realm.as_str(), "ak.mls.genesis", json!({
        "cipher_suite":ACTIVE_SUITE,"group_info_ref":info,"ratchet_tree_ref":tree,"governance_binding":binding,"creator_leaf_authority":leaf,
        "created_at":arkret_canonical::format_timestamp_canonical(Utc::now())})).await?;
    genesis.scope_ref = scope.clone();
    crate::harness::refresh_typed_event_proof_with_signing_seed(
        &mut genesis,
        controller.key.to_bytes(),
    )?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        client,
        &deployment.account,
        &client.device_id,
        &genesis,
    )
    .await?;
    if let Some(remote) = &mut governor {
        let (state, mut receiver) = Box::pin(private_reply::join_agent_and_consume(
            &controller,
            &agent,
            &mut group,
            &genesis,
            None,
            true,
        ))
        .await?;
        println!(
            "[home-sidecar] first create, KeyPackage claim, Add, Welcome and consume accepted with G offline"
        );
        let (message, plaintext) =
            controller_message(&controller, &mut group, &state, &strand).await?;
        let from_home = agent
            .runtime
            .sdk()
            .committed_event_get(&message.event_id)
            .await?;
        ensure!(from_home.reducer_input() == Some(&message));
        ensure!(
            open_message(
                &agent.runtime,
                &mut receiver,
                from_home
                    .reducer_input()
                    .context("private question from H")?
            )
            .await?
                == plaintext
        );
        let (write, claims) =
            content_direct_evidence::issue(&deployment, &agent, &actions, &realm).await?;
        ensure!(
            claims
                .scopes
                .iter()
                .any(|scope| scope == "ak.message.create")
        );
        agent.runtime = write;
        let basis =
            crate::harness::content::root_context(&agent.runtime, &receiver, &state.event.event_id)
                .await?;
        let (response, response_bytes) = agent_message(
            &agent,
            &mut receiver,
            &state,
            &strand,
            from_home.reducer_input().context("private question")?,
            basis,
        )
        .await?;
        let accepted: AuthoritySubmitResponseBody = serde_json::from_value(
            expect_json(
                agent.runtime.post("/_arkret/self/events").canonical_json(
                    &arkret_wire::EventAdmissionSubmission::new(response.clone()),
                )?,
                StatusCode::OK,
            )
            .await?,
        )?;
        ensure!(
            matches!(accepted, AuthoritySubmitResponseBody::Accepted {status:AuthorityCommitStatus::Committed, commit}
            if commit.event_ref == response.event_id && commit.stream_ref == state.commit.stream_ref)
        );
        let original_reply = client.sdk().committed_event_get(&response.event_id).await?;
        ensure!(original_reply.reducer_input() == Some(&response));
        ensure!(open_message(client, &mut group, &response).await? == response_bytes);
        let expected = client.sdk().committed_event_get(&message.event_id).await?;
        crate::scenarios::human_device_producer_live::ensure_commit_signed_by(
            expected.commit(),
            &deployment.station,
        )?;
        let recovery_mnemonic = arkret::identity_root::format_bip39_identity_recovery_mnemonic(
            &principal.root_key_seed,
        )?;
        let producer = group.original_content_endpoint(&message)?;
        let reply_producer = group.original_content_endpoint(&response)?;
        let verifier = principal.device_signing_key.verifying_key();
        drop(group);
        drop(receiver);
        let fixture = crate::scenarios::_helpers::canonical_api::CanonicalApiFixture::from_owned(
            deployment.station,
            deployment.controller,
            deployment.http,
            deployment.endpoints,
            deployment.oidc_client_id,
        );
        let second = fixture.pair_sibling().await?;
        ensure!(second.device_id != fixture.client.device_id);
        ensure!(
            recover_on_new_device(
                &second,
                &expected,
                &recovery_mnemonic,
                producer,
                &original_reply,
                reply_producer,
                &verifier
            )
            .await?
                == (plaintext, response_bytes),
            "new device could not recover the original private request and reply"
        );
        let restored = second.sdk().agent_sidecar_get(&sidecar).await?;
        ensure!(restored.sidecar == view.sidecar);
        let held_attach = second.sdk().committed_event_get(&attach_id).await?;
        ensure!(held_attach.reducer_input().is_some_and(
            |e| e.payload["source_context_ref"] == json!({"kind":"strand","strand_id":strand})
        ));
        let h = fixture
            .server
            .owned_database_url()
            .context("H durable store")?
            .to_owned();
        let g = remote
            .station
            .owned_database_url()
            .context("G durable store")?
            .to_owned();
        verify_private_federation_absent(
            h.clone(),
            sidecar.to_string(),
            create.event_id.to_string(),
            false,
        )
        .await?;
        remote.station.start_external_process().await?;
        remote.coauth.restart_same_config().await?;
        verify_private_federation_absent(
            h,
            sidecar.to_string(),
            create.event_id.to_string(),
            false,
        )
        .await?;
        verify_private_federation_absent(g, sidecar.to_string(), create.event_id.to_string(), true)
            .await?;
        println!(
            "[home-sidecar] new authorized device decrypted the question and reply before G restarted; no private originals or outbox rows at G"
        );
        return Ok(());
    }
    let observer = PendingPayload {
        read: &read,
        strand: &strand,
        deployment: &deployment,
        actions: &actions,
        genesis: &genesis,
        read_positive_only,
        pending_message: Default::default(),
    };
    let (state, mut agent_group) = Box::pin(private_reply::join_agent_with_observer(
        &controller,
        &agent,
        &mut group,
        &genesis,
        Some(&observer),
    ))
    .await?;
    let (_, narrowed) =
        content_direct_evidence::issue(&deployment, &agent, &read_actions, &realm).await?;
    ensure!(
        narrowed
            .scopes
            .iter()
            .any(|action| action == "ak.event.read")
            && !narrowed
                .scopes
                .iter()
                .any(|action| action == "ak.message.create"),
        "Sidecar read produced write authority: {:?}",
        narrowed.scopes
    );
    ensure!(
        narrowed
            .scope_details
            .as_ref()
            .context("narrowed ceiling")?
            .capability_grant_refs
            .is_empty()
    );
    let (fresh_read, fresh_claims) =
        content_direct_evidence::issue(&deployment, &agent, &read_actions, &realm).await?;
    ensure!(
        fresh_claims
            .scope_details
            .as_ref()
            .context("effective Sidecar ceiling")?
            .capability_grant_refs
            .is_empty()
    );
    if read_positive_only {
        let expected = observer
            .pending_message
            .lock()
            .unwrap()
            .clone()
            .context("pending controller business original was not retained")?;
        let query = arkret_wire::StreamScanRequestBody {
            realm_id: realm.clone(),
            stream_ref: state.commit.stream_ref.clone(),
            direction: arkret_wire::StreamScanDirection::After(None),
            limit: 100,
        };
        let page = fresh_read.sdk().scan_commit_stream(&query).await?;
        page.validate_for_request(&query)?;
        ensure!(
            !page.truncated,
            "effective Sidecar history was unexpectedly truncated"
        );
        let original = page
            .committed_events
            .iter()
            .find(|row| row.commit().event_ref == expected.commit().event_ref)
            .context("effective Agent history omitted the formerly withheld original")?;
        ensure!(
            original.reducer_input().is_some() && original == &expected,
            "effective Agent history changed the accepted Event or covering Commit"
        );
        let exact = fresh_read
            .sdk()
            .committed_event_get(&original.commit().event_ref)
            .await?;
        ensure!(
            exact == expected,
            "effective Agent exact GET changed the scanned original"
        );
        println!(
            "[agent-sidecar-effective-read] actual_coauth=1 original_signed_claim=1 actual_add_and_welcome=1 durable_mls_state=1 signed_consume=1 effective_endpoint=1 fresh_read_only_session=1 no_literal_read_or_write_grant=1 pending_controller_original_refused=1 same_historical_event_and_commit_received_by_scan=1 exact_get_matches_scan=1 business_write_not_executed=1 decryption_not_claimed=1"
        );
        return Ok(());
    }
    let (message, plaintext) = controller_message(&controller, &mut group, &state, &strand).await?;
    let received = fresh_read
        .sdk()
        .committed_event_get(&message.event_id)
        .await?;
    ensure!(received.reducer_input() == Some(&message));
    let envelope: arkret::EncryptedEnvelope =
        serde_json::from_value(message.payload["encrypted_content"].clone())?;
    let domain = arkret::mls_basic_credential_identity(message.actual_signer())?;
    let header = envelope.reconstruct_pre_encryption_header(
        arkret::EncryptedPayloadScheme::EpochContentAead,
        scope.clone(),
        message.kind.as_str(),
        std::str::from_utf8(&domain)?,
        None,
        crate::harness::content::original_material(
            &agent.runtime,
            &agent_group,
            &message,
            &envelope,
        )
        .await?,
    )?;
    let payload =
        arkret::mls::encrypted_envelope_to_payload_with_verified_header(&envelope, header)?;
    ensure!(agent_group.decrypt_payload(&payload)? == plaintext);
    println!(
        "[agent-sidecar-content] actual_coauth=1 no_literal_read_or_write_grant=1 issued_before_mls_ready=1 accepted_add_welcome_claim=1 durable_before_consume=1 pending_payload_refused=1 effective_payload_full_and_decrypted=1 mixed_request_read_only_ceiling=1"
    );
    let enrolled_original = client.sdk().committed_event_get(&enroll.event_id).await?;
    ensure!(enrolled_original.reducer_input() == Some(&enroll));
    let (write, write_claims) =
        content_direct_evidence::issue(&deployment, &agent, &actions, &realm).await?;
    ensure!(
        write_claims
            .scopes
            .iter()
            .any(|action| action == "ak.message.create")
    );
    ensure!(
        write_claims
            .scope_details
            .as_ref()
            .context("explicit write ceiling")?
            .capability_grant_refs
            .is_empty()
    );
    let basis =
        crate::harness::content::root_context(&fresh_read, &agent_group, &state.event.event_id)
            .await?;
    let question = fresh_read
        .sdk()
        .committed_event_get(&message.event_id)
        .await?;
    let (reply, reply_plaintext) = agent_message(
        &agent,
        &mut agent_group,
        &state,
        &strand,
        question
            .reducer_input()
            .context("effective Agent question")?,
        basis,
    )
    .await?;
    let outcome: AuthoritySubmitResponseBody = serde_json::from_value(
        expect_json(
            write
                .post("/_arkret/self/events")
                .canonical_json(&arkret_wire::EventAdmissionSubmission::new(reply.clone()))?,
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(&outcome, AuthoritySubmitResponseBody::Accepted {status:AuthorityCommitStatus::Committed,commit}
        if commit.event_ref == reply.event_id && commit.stream_ref == state.commit.stream_ref),
        "Sidecar granted write did not commit: {outcome:?}"
    );
    ensure!(
        client
            .sdk()
            .committed_event_get(&reply.event_id)
            .await?
            .reducer_input()
            == Some(&reply)
    );
    ensure!(open_message(client, &mut group, &reply).await? == reply_plaintext);
    let future_state = advance_epoch_material(
        &controller,
        &agent,
        &fresh_read,
        &mut group,
        &mut agent_group,
        &state.event.scope_ref,
    )
    .await?;
    let (future_message, future_plaintext) =
        controller_message(&controller, &mut group, &future_state, &strand).await?;
    ensure!(
        fresh_read
            .sdk()
            .committed_event_get(&future_message.event_id)
            .await?
            .reducer_input()
            == Some(&future_message)
    );
    ensure!(
        open_message(&agent.runtime, &mut agent_group, &future_message).await? == future_plaintext
    );
    other_controller_content(
        &deployment,
        &agent,
        &fresh_read,
        &source_realm,
        &strand,
        &future_message,
    )
    .await?;
    let (queued_before_loss, _) =
        crate::scenarios::mls_lifecycle_live::recipient_welcomes(&fresh_read).await?;
    ensure!(
        queued_before_loss.len() == 1
            && queued_before_loss[0].commit_event_ref == state.event.event_id
            && queued_before_loss[0].effective_scope == state.event.scope_ref,
        "the accepted Welcome must still be queued without ACK after consume"
    );
    use arkret_models_collaboration::agent_interaction::{
        AgentInteractionExactCurrentSelector, AgentInteractionMode,
        agent_interaction_from_verified_exact_read,
    };
    use arkret_models_collaboration::exact_current_state::{
        ExactCurrentStateReadRequestBody, ExactCurrentStateSelector,
    };
    let mode_generation = future_state.commit.governance_generation;
    join_controller_agent(
        client,
        &deployment.account,
        &source_realm,
        generation.clone(),
        &agent.agent_account,
    )
    .await?;
    let mode_request = ExactCurrentStateReadRequestBody {
        realm_id: source_realm.clone(),
        selector: ExactCurrentStateSelector::AgentInteraction(
            AgentInteractionExactCurrentSelector::new(agent.agent_account.clone()),
        ),
    };
    // This Realm was created here and has never changed governance tenure.
    // Snapshot omission does not prove the default mode or its CAS basis.
    let mode_before = client
        .sdk()
        .exact_current_state(&mode_request, mode_generation)
        .await?;
    let (prior_mode, expected_commit_id) = agent_interaction_from_verified_exact_read(
        &mode_before,
        &source_realm,
        &agent.agent_account,
        &deployment.account,
        mode_generation,
    )?;
    ensure!(prior_mode == AgentInteractionMode::Private && expected_commit_id.is_none());
    let set = arkret_models_collaboration::agent_interaction::AgentInteractionSetPayload {
        agent_account_id: agent.agent_account.clone(),
        controller_account_id: deployment.account.clone(),
        interaction_mode:
            arkret_models_collaboration::agent_interaction::AgentInteractionMode::Public,
        expected_commit_id: expected_commit_id.map(|revision| revision.commit_id),
    };
    let change = client
        .author_event(
            source_realm.as_str(),
            "ak.agent.interaction.set",
            serde_json::to_value(set)?,
        )
        .await?;
    let mode_submission = crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        client,
        &deployment.account,
        &client.device_id,
        &change,
    )
    .await;
    if mode_submission.is_err() {
        diagnose_first_mode_failure(
            &deployment.station,
            client,
            &source_realm,
            &agent.agent_account,
            future_state.commit.governance_generation,
        )
        .await;
    }
    let mode_commit = mode_submission?;
    let mode_after = client
        .sdk()
        .exact_current_state(&mode_request, mode_generation)
        .await?;
    let (current_mode, revision) = agent_interaction_from_verified_exact_read(
        &mode_after,
        &source_realm,
        &agent.agent_account,
        &deployment.account,
        mode_generation,
    )?;
    ensure!(
        current_mode == AgentInteractionMode::Public
            && revision
                == Some(arkret_wire::CurrentRevision {
                    commit_id: mode_commit.commit_id,
                    stream_position: mode_commit.stream_position,
                })
    );
    let retained = client.sdk().agent_sidecar_get(&sidecar).await?;
    ensure!(
        retained.desired_agent_ids == vec![agent.agent_account.principal_id.clone()]
            && retained.effective_agent_ids == vec![agent.agent_account.principal_id.clone()],
        "mode changed Sidecar roster: desired={:?} effective={:?}",
        retained.desired_agent_ids,
        retained.effective_agent_ids
    );
    let basis = crate::harness::content::root_context(
        &fresh_read,
        &agent_group,
        &future_state.event.event_id,
    )
    .await?;
    let question = fresh_read
        .sdk()
        .committed_event_get(&future_message.event_id)
        .await?;
    let (denied, _) = agent_message(
        &agent,
        &mut agent_group,
        &future_state,
        &strand,
        question
            .reducer_input()
            .context("queued private question")?,
        basis,
    )
    .await?;
    let mut leave = client.author_event(realm.as_str(),"ak.sidecar.member.state",json!({
        "agent_account_id":agent.agent_account, "membership":"leave","predecessor_event_ref":enroll.event_id
    })).await?;
    leave.scope_ref = scope.clone();
    crate::harness::refresh_typed_event_proof_with_signing_seed(
        &mut leave,
        controller.key.to_bytes(),
    )?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        client,
        &deployment.account,
        &client.device_id,
        &leave,
    )
    .await?;
    let revoked = client.sdk().agent_sidecar_get(&sidecar).await?;
    ensure!(revoked.desired_agent_ids.is_empty() && revoked.effective_agent_ids.is_empty());
    let submit = ServiceOperationId::from_wire(ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1)
        .context("registered self events operation")?;
    ensure!(
        submit
            .operation_specific_errors()
            .iter()
            .any(|entry| matches!(
                entry,
                arkret_wire::OperationSpecificError::Code(
                    arkret_wire::ErrorCode::FailedPrecondition
                )
            ))
    );
    ensure!(arkret_wire::ErrorCode::FailedPrecondition.http_status() == 409);
    ensure!(
        arkret_wire::ReasonCode::from_wire(arkret_wire::ReasonCode::EPOCH_UPDATE_REQUIRED)
            .descriptor()
            .is_some()
    );
    let rejected = crate::harness::expect_api_error(
        write
            .post("/_arkret/self/events")
            .canonical_json(&arkret_wire::EventAdmissionSubmission::new(denied.clone()))?,
        StatusCode::CONFLICT,
        arkret_wire::ErrorCode::FAILED_PRECONDITION,
    )
    .await?;
    ensure!(
        rejected
            .extensions
            .get("reason_code")
            .and_then(serde_json::Value::as_str)
            == Some(arkret_wire::ReasonCode::EPOCH_UPDATE_REQUIRED)
    );
    crate::harness::expect_api_error(
        client.get(&format!(
            "/_arkret/self/committed-events/{}",
            denied.event_id
        )),
        StatusCode::NOT_FOUND,
        arkret_wire::ErrorCode::NOT_FOUND,
    )
    .await?;
    ensure!(client.sdk().committed_event_get(&enroll.event_id).await? == enrolled_original);
    crate::harness::expect_api_error(
        fresh_read.get("/_arkret/self/device-messages"),
        StatusCode::FORBIDDEN,
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
    )
    .await?;
    crate::harness::expect_api_error(
        fresh_read.get(&format!(
            "/_arkret/self/committed-events/{}",
            future_state.event.event_id
        )),
        StatusCode::NOT_FOUND,
        arkret_wire::ErrorCode::NOT_FOUND,
    )
    .await?;
    ensure!(
        client
            .sdk()
            .committed_event_get(&future_state.event.event_id)
            .await?
            .reducer_input()
            == Some(&future_state.event)
    );
    println!(
        "[agent-sidecar-future] actual_governed_update_epoch_two=1 accepted_lineage_read=1 current_effective_endpoint=1 update_installed_and_durable=1 new_epoch_message_decrypted=1 accepted_desired_loss=1 old_read_ceiling_retained=1 update_material_new_delivery_denied=1 controller_original_retained=1 prior_knowledge_not_retracted=1"
    );
    println!(
        "[agent-sidecar-revoked-welcome] actual_unacked_welcome_present_after_consume=1 exact_scope_and_add=1 accepted_membership_loss=1 old_read_ceiling_retained=1 queued_welcome_new_delivery_denied=1 no_retroactive_knowledge_claim=1"
    );
    println!(
        "[agent-sidecar-write] accepted_private_enrollment=1 fresh_real_coauth_write_ceiling=1 explicit_agent_message_committed=1 controller_decrypted=1 accepted_private_to_public=1 mode_preserves_roster=1 accepted_agent_leave=1 desired_and_effective_lost=1 old_write_credential_refused=1 required_rotation_checkpoint_denied=1 rejected_event_not_stored=1 enrollment_original_retained=1"
    );
    Ok(())
}
