//! Real signed Sidecar ensure and independent private stream reads.

use anyhow::{Result, anyhow, bail, ensure};
use arkret_models_collaboration::sidecar_operations::{
    SidecarContextRef, SidecarEnsureCommitPhase, SidecarEnsureCommitRequestBody,
    SidecarEnsureOutcome, SidecarEnsurePreparePhase, SidecarEnsurePrepareRequestBody,
    SidecarEnsureRequestBody,
};
use arkret_wire::{CommitStreamRef, EventKind, RealmId, StreamScanDirection, StreamScanRequest};
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

pub async fn run() -> Result<()> {
    let Some(database) = database(GROUP)? else {
        return Ok(());
    };
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(servers) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[station_env(&database.connect_url, &coauth)],
    )
    .await?
    else {
        return skip_or_fail(GROUP, "prebuilt Soland unavailable");
    };
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
        .agent_sidecar_ensure(&prepare)
        .await?;
    let SidecarEnsureOutcome::PreparedNew(prepared) = prepared else {
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
        .agent_sidecar_ensure(&request)
        .await?;
    let SidecarEnsureOutcome::Accepted(accepted) = accepted else {
        bail!("signed Sidecar unit was not accepted");
    };
    ensure!(accepted.sidecar_id == arkret_wire::SidecarId::from_event_id(&create.event_id));
    let view = controller
        .client
        .sdk()
        .agent_sidecar_get(&accepted.sidecar_id)
        .await?;
    ensure!(view.desired_agent_ids.is_empty() && view.effective_agent_ids.is_empty());
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
        .agent_sidecar_ensure(&request)
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
                arkret_wire::TypedCurrentResult::Value {
                    selector: arkret_wire::CurrentSelector::Sidecar { .. }
                        | arkret_wire::CurrentSelector::SidecarContext { .. },
                    ..
                }
            )),
        "another Realm member received private Sidecar typed currents"
    );
    let parent_query = StreamScanRequest {
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
        let query = StreamScanRequest {
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
    let accepted_genesis = submit_and_expect_commit(
        &controller.client,
        &controller.account,
        controller.device.as_str(),
        &genesis,
    )
    .await?;
    ensure!(
        accepted_genesis.stream_ref == stream && accepted_genesis.stream_position == 1,
        "Sidecar MLS Genesis reused parent coordinates"
    );
    let ready = controller.client.sdk().agent_sidecar_get(&sidecar).await?;
    ensure!(
        ready.mls_context.current_controller_device_ready
            && ready.mls_context.epoch == Some(0)
            && ready.desired_agent_ids.is_empty()
            && ready.effective_agent_ids.is_empty(),
        "native Genesis creator is not ready at its accepted empty-agent cut"
    );
    let material=arkret_models_collaboration::mls_group_state_material::MlsMemberGroupStateMaterialReadRequestBody{
        realm_id:realm.clone(),effective_scope:scope.clone(),mls_group_id:scope.canonical_mls_group_id()?,epoch:Default::default(),
        group_state_event_id:genesis.event_id.clone(),caller_actor_id:controller.actor.clone(),target_commit_event_ref:genesis.event_id.clone(),target_epoch:0,
        group_info_ref:arkret_wire::BlobRef::new(group_info_ref)?,ratchet_tree_ref:arkret_wire::BlobRef::new(tree_ref)?,max_response_bytes:None,
    };
    let response = expect_json(
        controller
            .client
            .post("/_arkret/self/mls/group-state-material/query")
            .canonical_json(&material)?,
        reqwest::StatusCode::OK,
    )
    .await?;
    let response:arkret_models_collaboration::mls_group_state_material::MlsGroupStateMaterialOutcome=serde_json::from_value(response)?;
    let validated = response.validate_for_request(&material.as_peer_request())?;
    ensure!(
        validated.group_info_bytes == group_info && validated.ratchet_tree_bytes == tree,
        "native Sidecar material changed accepted bytes"
    );
    let roster =
        arkret_models_collaboration::mls_roster_authority::MlsRosterAuthorityReadRequestBody {
            realm_id: realm,
            effective_scope: scope,
            mls_group_id: material.mls_group_id,
            genesis_event_ref: genesis.event_id.clone(),
            target_commit_event_ref: genesis.event_id,
            target_epoch: 0,
            caller_actor_id: controller.actor,
            cursor: None,
        };
    let roster_response = expect_json(
        controller
            .client
            .post(arkret_wire::PATH_SELF_MLS_ROSTER_AUTHORITY)
            .canonical_json(&roster)?,
        reqwest::StatusCode::OK,
    )
    .await?;
    let roster_response:arkret_models_collaboration::mls_roster_authority::MlsRosterAuthorityReadOutcome=serde_json::from_value(roster_response)?;
    roster_response.manifest.validate_for_request(&roster)?;
    ensure!(
        roster_response.records.len() == 1 && roster_response.manifest.total_records == 1,
        "native Sidecar Genesis roster is partial"
    );
    Ok(())
}
