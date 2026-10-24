//! Actual Realm ciphertext stays unavailable until its target epoch is installed.

use super::content_grant_evidence::GrantFixture;
use super::*;
use crate::scenarios::mls_lifecycle_live::{Member, accepted_full_view, upload_public_blob};
use crate::scenarios::sidecar_authority_live::private_reply;

pub const REVIEWED_MLS_CONTENT_CASES: [&str; 1] = ["mls_not_ready_for_payload"];

fn durable_group(group: &mut arkret::ArkretMlsGroup, path: &std::path::Path) -> Result<()> {
    use std::io::Write as _;
    let record = group.export_state_record()?;
    let mut file = std::fs::File::create(path)?;
    file.write_all(&serde_json::to_vec(&record)?)?;
    file.sync_all()?;
    let restored = serde_json::from_slice(&std::fs::read(path)?)?;
    *group = arkret::ArkretMlsGroup::restore_from_state_record(&restored)?;
    Ok(())
}

async fn current(scene: &GrantFixture, scope: &ScopeRef) -> Result<arkret_wire::MlsGroupValue> {
    let snapshot = scene
        .deployment
        .controller
        .sdk()
        .realm_state_snapshot_head(&scene.realm)
        .await?;
    snapshot
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
        .context("accepted Realm MLS current")?
        .map_err(Into::into)
}

async fn install_roster(
    client: &TestActorClient,
    actor: ActorId,
    group: &mut arkret::ArkretMlsGroup,
    state: &arkret_wire::CommittedEventFullView,
    expected: usize,
) -> Result<()> {
    let scope = state.event.scope_ref.clone();
    let request = arkret::MlsMemberRosterAuthorityReadRequestBody {
        realm_id: state.event.realm_id.clone(),
        effective_scope: scope.clone(),
        mls_group_id: scope.canonical_mls_group_id()?,
        target_commit_event_ref: state.event.event_id.clone(),
        target_epoch: group.epoch(),
        caller_actor_id: actor,
        cursor: None,
    };
    let page = client.sdk().self_mls_roster_authority(&request).await?;
    ensure!(page.roster.records.len() == expected && page.roster.next_cursor.is_none());
    let peer =
        arkret::verify_mls_member_roster_authority_pages(std::slice::from_ref(&page), &request)?;
    let material = client
        .sdk()
        .self_mls_group_state_material(&arkret::mls_roster_genesis_material_request(
            &peer,
            &page.roster.manifest,
        ))
        .await?;
    arkret::install_verified_mls_self_roster_bindings(group, &[page], &request, &material)
        .map_err(anyhow::Error::msg)?;
    Ok(())
}

pub async fn run_agent_content_mls_production() -> Result<crate::conformance::SuiteExecutionResult>
{
    let fixture = crate::conformance::load_fixture_value("agent-vectors-fixture.json")?;
    let rows = fixture["session_content_authority_contract"]["cases"]
        .as_array()
        .context("canonical payload MLS cases")?
        .iter()
        .filter(|row| row["name"] == "mls_not_ready_for_payload")
        .collect::<Vec<_>>();
    ensure!(
        rows.len() == 1
            && rows[0]["input"] == json!({"phase":"payload","mls_ready":false})
            && rows[0]["expected"] == "deny",
        "review changed payload MLS contract"
    );
    let mut scene = GrantFixture::establish_with_mls().await?;
    let client = scene.deployment.controller.clone();
    let principal = client
        .principal
        .as_ref()
        .context("actual controller principal")?;
    let controller = Member {
        client: client.clone(),
        account: scene.deployment.account.clone(),
        actor: ActorId::account(scene.deployment.account.clone()),
        device: principal.device_id.clone(),
        method: DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
            .map_err(anyhow::Error::msg)?,
        key: principal.device_signing_key.clone(),
        authorize_event_id: principal.founding_authorize_event_id.clone(),
    };
    let scope = ScopeRef::Realm {
        realm_id: scene.realm.clone(),
    };
    let operations = scene
        .operations
        .iter()
        .map(String::as_str)
        .filter(|action| *action != "ak.message.create")
        .collect::<Vec<_>>();
    let (read, claims) = scene
        .issue_for(
            &operations,
            arkret_models_collaboration::session_grants::RequestedAgentSessionGrantScope {
                realm_ids: vec![scene.realm.clone()],
                strand_ids: vec![],
                track_names: vec![],
            },
        )
        .await?;
    ensure!(
        claims.scopes.iter().any(|action| action == "ak.event.read")
            && !claims
                .scopes
                .iter()
                .any(|action| action == "ak.message.create")
    );
    ensure!(
        claims.scope_details.as_ref().context("membership source")?["capability_grant_refs"]
            == json!([])
    );
    scene.agent.runtime = read.clone();
    let binding = arkret::MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mut group = controller
        .mls_identity()?
        .create_group_with_governance_binding(&scope, &binding)?;
    let leaf = crate::scenarios::cross_station_mls_welcome::genesis_creator_leaf_authority(
        &mut group,
        &controller,
    )?;
    let (info, tree) = group.public_group_state_bytes()?;
    let info = upload_public_blob(&client, &scene.realm, &info).await?;
    let tree = upload_public_blob(&client, &scene.realm, &tree).await?;
    let genesis = client.author_event(scene.realm.as_str(), "ak.mls.genesis", json!({
        "cipher_suite":crate::scenarios::mls_lifecycle_live::ACTIVE_SUITE,
        "group_info_ref":info,"ratchet_tree_ref":tree,"governance_binding":binding,
        "creator_leaf_authority":leaf,"created_at":arkret_canonical::format_timestamp_canonical(Utc::now())
    })).await?;
    let journal = tempfile::tempdir()?;
    durable_group(&mut group, &journal.path().join("controller-genesis.json"))?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &client,
        &controller.account,
        controller.device.as_str(),
        &genesis,
    )
    .await?;
    let genesis_full = accepted_full_view(&client, &genesis.event_id).await?;
    install_roster(
        &client,
        controller.actor.clone(),
        &mut group,
        &genesis_full,
        1,
    )
    .await?;
    let (joined, mut recipient) = Box::pin(private_reply::join_agent(
        &controller,
        &scene.agent,
        &mut group,
        &genesis,
    ))
    .await?;
    let (first, first_plain) = super::content_sidecar_evidence::controller_message(
        &controller,
        &mut group,
        &joined,
        &scene.a,
    )
    .await?;
    ensure!(
        read.sdk()
            .committed_event_get(&first.event_id)
            .await?
            .reducer_input()
            == Some(&first)
    );
    ensure!(super::content_sidecar_evidence::open_message(&mut recipient, &first)? == first_plain);
    let recipient_path = journal.path().join("recipient-epoch-one.json");
    durable_group(&mut recipient, &recipient_path)?;
    let base = current(&scene, &scope).await?;
    ensure!(base.epoch == 1 && group.epoch() == 1 && recipient.epoch() == 1);
    let binding = arkret::MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(base.current_mls_commit_event_ref.clone()),
        1,
        2,
        base.current_key_access_revision,
    )?;
    let update = group.self_update_commit_with_governance_binding(&binding)?;
    let event = client
        .author_event(
            scene.realm.as_str(),
            "ak.mls.commit",
            serde_json::to_value(arkret::MlsCommitPayload::new(
                base.current_mls_commit_event_ref.clone(),
                base.current_key_access_revision,
                &update,
                binding,
            )?)?,
        )
        .await?;
    durable_group(
        &mut group,
        &journal.path().join("controller-pending-update.json"),
    )?;
    let submission =
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::MlsCommit(
            arkret_wire::MlsCommitSubmission {
                commit_event: event.clone(),
                welcomes: vec![],
                idempotency_key: arkret_wire::UuidV7::new(
                    crate::scenarios::mls_lifecycle_live::fresh_uuid_v7().parse()?,
                )?,
            },
        );
    let (status, outcome) =
        crate::scenarios::mls_lifecycle_live::post_json(&client, &submission).await?;
    ensure!(
        status == StatusCode::OK,
        "actual Realm Update refused: {status} {outcome}"
    );
    let accepted = accepted_full_view(&client, &event.event_id).await?;
    ensure!(group.install_accepted_commit(&accepted, &base)? == 2);
    install_roster(&client, controller.actor.clone(), &mut group, &accepted, 2).await?;
    let (target, plaintext) = super::content_sidecar_evidence::controller_message(
        &controller,
        &mut group,
        &accepted,
        &scene.a,
    )
    .await?;
    let delivered = read.sdk().committed_event_get(&target.event_id).await?;
    ensure!(delivered.reducer_input() == Some(&target));
    let before = recipient.export_state_record()?;
    let durable = std::fs::read(&recipient_path)?;
    ensure!(
        super::content_sidecar_evidence::open_message(&mut recipient, &target).is_err(),
        "epoch-one recipient exposed actual epoch-two payload"
    );
    let after = recipient.export_state_record()?;
    ensure!(
        before.serialized_state == after.serialized_state
            && before.epoch == after.epoch
            && before.group_id == after.group_id
            && before.actor_id == after.actor_id
            && before.endpoint == after.endpoint
    );
    ensure!(std::fs::read(&recipient_path)? == durable);
    let received = read
        .sdk()
        .committed_event_get(&accepted.event.event_id)
        .await?;
    let arkret_wire::CommittedEventView::Full(received) = received else {
        bail!("actual Update original required");
    };
    ensure!(received == accepted && recipient.install_accepted_commit(&received, &base)? == 2);
    install_roster(
        &read,
        ActorId::account(scene.agent.agent_account.clone()),
        &mut recipient,
        &received,
        2,
    )
    .await?;
    durable_group(
        &mut recipient,
        &journal.path().join("recipient-epoch-two.json"),
    )?;
    ensure!(super::content_sidecar_evidence::open_message(&mut recipient, &target)? == plaintext);
    println!(
        "[agent-payload-mls] actual_coauth_membership_read=1 ordinary_realm_scope=1 real_add_welcome_durable_consume=1 epoch_one_payload_decrypted=1 actual_epoch_two_ciphertext_cached=1 stale_private_epoch_returns_no_plaintext=1 complete_crypto_state_and_durable_checkpoint_unchanged=1 actual_accepted_update_installed_and_durable=1 exact_original_ciphertext_decrypted=1"
    );
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: vec![crate::conformance::CaseExecutionResult {
            case_id: "mls_not_ready_for_payload".to_owned(),
            assertions: 1,
        }],
    })
}
