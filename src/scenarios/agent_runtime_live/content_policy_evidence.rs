//! Accepted management Policies, global refusals and safe resource correlation.
use arkret_models_collaboration::governance::grant_constraint::{
    GrantConstraint, GrantConstraintEffect, GrantConstraintKind,
};
use arkret_models_collaboration::governance::operation_wire::{Policy, PolicySetStatePayload};
use arkret_wire::EventKind;

use super::content_grant_evidence::GrantFixture;
use super::*;
use crate::harness::{CanonicalJsonBody, expect_api_error};

pub const REVIEWED_POLICY_CONTENT_CASES: [&str; 7] = [
    "policy_unknown_is_not_absent",
    "explicit_policy_allow",
    "policy_deny",
    "unsafe_flat_cross_product",
    "management_read_denied",
    "global_deny_overrides_complete_allow",
    "participation_current_denied",
];

async fn unavailable_policy_source(
    scene: &GrantFixture,
    operations: &[&str],
    runtime: &TestActorClient,
) -> Result<()> {
    use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;
    let database = scene
        .deployment
        .station
        .owned_database_url()
        .context("owned Station database")?
        .to_owned();
    let before = acceptance_rows_with_agent_stores(&database, true).await?;
    let lock_database = database.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let blocker = tokio::task::spawn_blocking(move || -> Result<()> {
        let mut connection = postgres::Client::connect(&lock_database, postgres::NoTls)?;
        let backend: i32 = connection.query_one("SELECT pg_backend_pid()", &[])?.get(0);
        let mut transaction = connection.transaction()?;
        transaction.batch_execute("SET LOCAL lock_timeout='5s'; LOCK TABLE policy_current_states IN ACCESS EXCLUSIVE MODE")?;
        let _ = ready_tx.send(backend);
        let _ = release_rx.recv_timeout(Duration::from_secs(30));
        transaction.rollback()?;
        Ok(())
    });
    let blocker_pid = ready_rx
        .await
        .context("Policy source lock was not established")?;
    let observe_database = database.clone();
    let observed = tokio::task::spawn_blocking(move || -> Result<()> {
        let mut connection = postgres::Client::connect(&observe_database, postgres::NoTls)?;
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        loop {
            let waiting: bool = connection.query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_locks l WHERE NOT l.granted AND l.relation='policy_current_states'::regclass AND $1=ANY(pg_blocking_pids(l.pid)))",
                &[&blocker_pid],
            )?.get(0);
            if waiting {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                let diagnostic: serde_json::Value = connection.query_one(
                    "SELECT COALESCE(jsonb_agg(jsonb_build_object('pid',l.pid,'mode',l.mode,'granted',l.granted,'relation',COALESCE(c.relname,''),'blockers',pg_blocking_pids(l.pid),'query',a.query)),'[]'::jsonb) FROM pg_locks l LEFT JOIN pg_class c ON c.oid=l.relation LEFT JOIN pg_stat_activity a ON a.pid=l.pid WHERE l.database=(SELECT oid FROM pg_database WHERE datname=current_database())",
                    &[],
                )?.get(0);
                if let Some(directory) = std::env::var_os("COTEST_SERVICE_LOG_DIR") {
                    std::fs::write(
                        std::path::PathBuf::from(directory)
                            .join("policy-lock-private-diagnostic.json"),
                        serde_json::to_vec_pretty(&diagnostic)?,
                    )?;
                }
                bail!("real issuer did not attempt the unavailable current Policy read");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    });
    let refusal = refused_issue(
        scene,
        operations,
        scene.selectors(),
        arkret_wire::ErrorCode::SERVICE_UNAVAILABLE,
    );
    let (refused, observed) = tokio::join!(refusal, observed);
    let _ = release_tx.send(());
    let released = blocker.await.context("Policy blocker task")?;
    refused?;
    observed.context("Policy read observation task")??;
    released?;
    ensure!(
        acceptance_rows_with_agent_stores(&database, true).await? == before,
        "unavailable Policy issue altered accepted/current/Agent/delivery state"
    );
    scene.read_exact(runtime).await?;
    let (restored, claims) = scene.issue_for(operations, scene.selectors()).await?;
    ensure!(
        claims
            .scope_details
            .as_ref()
            .context("restored absence proof")?["policy_refs"]
            == json!([])
    );
    scene.read_exact(&restored).await?;
    println!(
        "[agent-policy-unknown] real_current_policy_read_observed_waiting=1 only_policy_table_temporarily_locked=1 no_business_data_mutated=1 actual_issue_503_service_unavailable=1 complete_issuer_noop=1 complete_station_business_noop=1 original_read_retained_after_release=1 fresh_issue_with_complete_absence_restored=1"
    );
    Ok(())
}

async fn current_reply_selection(
    scene: &GrantFixture,
    runtime: &TestActorClient,
    read: &TestActorClient,
    grant: &arkret_wire::GrantId,
) -> Result<()> {
    use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;
    let controller = &scene.deployment.controller;
    let selection = arkret::ParticipationReplaceRequestBody {
        target_scope: arkret::ParticipationScope::Realm {
            realm_id: scene.realm.clone(),
        },
        selection: arkret::ParticipationBits::NONE,
        expected_version: 1,
    };
    let changed = controller
        .sdk()
        .agent_participation_replace(scene.agent.agent_account.principal_id.as_str(), &selection)
        .await?;
    ensure!(changed.participation_entries.len() == 1);
    let entry = &changed.participation_entries[0];
    ensure!(
        entry.target_scope == selection.target_scope
            && entry.version == 2
            && entry.selection == arkret::ParticipationBits::NONE
    );
    let message =
        arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::MessageCreate>::new(
            ScopeRef::Realm {
                realm_id: scene.realm.clone(),
            },
            ActorId::account(scene.agent.agent_account.clone()),
            arkret_models_collaboration::events_payloads::MessageCreatePayload::with_content(
                scene.b.clone(),
                "discussion",
                arkret_models_collaboration::events_payloads::ContentBlock::text(
                    "Current reply selection must be checked",
                ),
            ),
        )?
        .with_semantic_ref(arkret_wire::SemanticRef::new(
            grant.to_string(),
            arkret_wire::SEMANTIC_REF_ROLE_AUTHORIZED_BY,
        ))
        .author_with_digest_suite(Utc::now(), arkret_canonical::DigestSuite::Sha256)?;
    let message = sign(
        message,
        &scene.agent.verification_method,
        scene.agent.runtime_key.to_bytes(),
    )?;
    let submission = arkret_wire::EventAdmissionSubmission::new(message.clone());
    let url = scene
        .deployment
        .station
        .owned_database_url()
        .context("owned Station database")?;
    let before = acceptance_rows_with_agent_stores(url, true).await?;
    let problem = expect_api_error(
        runtime
            .post("/_arkret/self/events")
            .canonical_json(&submission)?,
        StatusCode::CONFLICT,
        arkret_wire::ErrorCode::FAILED_PRECONDITION,
    )
    .await?;
    ensure!(
        problem.detail.contains("agent_reply_not_permitted"),
        "reply denial did not reach current selection gate"
    );
    ensure!(
        acceptance_rows_with_agent_stores(url, true).await? == before,
        "denied reply altered accepted/current/Agent/delivery business state"
    );
    scene.read_exact(read).await?;
    let restored = controller
        .sdk()
        .agent_participation_replace(
            scene.agent.agent_account.principal_id.as_str(),
            &arkret::ParticipationReplaceRequestBody {
                target_scope: selection.target_scope,
                selection: arkret::ParticipationBits {
                    message_creation_allowed: true,
                    ..arkret::ParticipationBits::NONE
                },
                expected_version: 2,
            },
        )
        .await?;
    ensure!(
        restored.participation_entries.len() == 1
            && restored.participation_entries[0].version == 3
            && restored.participation_entries[0]
                .selection
                .message_creation_allowed
    );
    let accepted: AuthoritySubmitResponseBody = serde_json::from_value(
        expect_json(
            runtime
                .post("/_arkret/self/events")
                .canonical_json(&submission)?,
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(matches!(accepted, AuthoritySubmitResponseBody::Accepted {
        status: AuthorityCommitStatus::Committed, commit,
    } if commit.event_ref == message.event_id));
    ensure!(
        controller
            .sdk()
            .committed_event_get(&message.event_id)
            .await?
            .reducer_input()
            == Some(&message)
    );
    println!(
        "[agent-current-participation] original_write_credential_and_grant_retained=1 normal_reply_selection_removed=1 actual_current_selection_refusal=1 complete_business_noop=1 normal_selection_restored=1 exact_same_signed_message_committed=1 independent_read_retained=1"
    );
    Ok(())
}

async fn publish_policy(
    scene: &GrantFixture,
    policy: &Policy,
    previous: Option<arkret_wire::CurrentRevision>,
) -> Result<arkret_wire::CurrentRevision> {
    let payload: PolicySetStatePayload = serde_json::from_value(json!({
        "policy_id":policy.id,"expected_revision":previous,"value":policy,
    }))?;
    payload.validate()?;
    let controller = &scene.deployment.controller;
    let event = controller
        .author_event(
            scene.realm.as_str(),
            EventKind::PolicySet.as_str(),
            serde_json::to_value(payload)?,
        )
        .await?;
    let commit = crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        controller,
        &scene.deployment.account,
        &controller.device_id,
        &event,
    )
    .await?;
    let accepted = controller
        .sdk()
        .committed_event_get(&event.event_id)
        .await?;
    ensure!(accepted.reducer_input() == Some(&event));
    Ok(arkret_wire::CurrentRevision {
        commit_id: commit.commit_id,
        stream_position: commit.stream_position,
    })
}

fn read_policy(scene: &GrantFixture, effect: arkret_wire::PolicyEffect) -> Result<Policy> {
    let id = arkret_wire::PolicyId::new_v7_at(Utc::now().timestamp_millis() as u64);
    let policy: Policy = serde_json::from_value(json!({
        "schema":"ak.schema.policy.v1", "id":id, "realm_id":scene.realm,
        "policy_kind":"agent", "default_effect":"allow",
        "created_by":ActorId::account(scene.deployment.account.clone()),
        "created_at":arkret_canonical::format_timestamp_canonical(Utc::now()),
        "rules":[{"rule_id":"exact_agent_read", "kind":"agent", "effect":effect,
            "agent_target":{"kind":"agent","agent_account_id":scene.agent.agent_account},
            "agent_operations":["read"]}],
    }))?;
    policy.validate()?;
    Ok(policy)
}

async fn refused_issue(
    scene: &GrantFixture,
    operations: &[&str],
    selectors: arkret_models_collaboration::session_grants::RequestedAgentSessionGrantScope,
    code: &str,
) -> Result<()> {
    let request = coauth_session_evidence::build_runtime_session_request(
        &scene.deployment.station,
        scene.deployment.coauth.base_url(),
        &scene.agent.agent_account.principal_id,
        &scene.agent.key_authorization,
        &scene.agent.verification_method,
        &scene.agent.runtime_key,
        operations,
        selectors,
    )?;
    let url = format!(
        "{}/_arkret/gate/account/session-grants",
        scene.deployment.coauth.base_url()
    );
    coauth_session_evidence::expect_issue_refusal(
        &scene.deployment.station,
        &scene.deployment.coauth.pg.connect_url,
        &url,
        &request,
        &scene.agent.runtime_key,
        None,
        code,
        None,
    )
    .await
}

async fn read_denied(scene: &GrantFixture, runtime: &TestActorClient) -> Result<()> {
    expect_api_error(
        runtime.get(&format!(
            "/_arkret/self/committed-events/{}",
            scene.message.event_id
        )),
        StatusCode::FORBIDDEN,
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
    )
    .await?;
    scene.read_exact(&scene.deployment.controller).await
}

pub async fn run_agent_content_policy_production()
-> Result<crate::conformance::SuiteExecutionResult> {
    let fixture = crate::conformance::load_fixture_value("agent-vectors-fixture.json")?;
    let contract = &fixture["session_content_authority_contract"];
    ensure!(
        arkret_canonical::sha256_hex(arkret_canonical::canonical_json_bytes(
            &contract["defaults"]
        )?) == "49fad7028393f37d28ca1a4ee06c376d6b16be0a16e4bfa35b77826a53130665",
        "review changed current Policy baseline"
    );
    let declared = contract["cases"]
        .as_array()
        .context("canonical Policy cases")?;
    for (name, input, expected) in [
        (
            "policy_unknown_is_not_absent",
            json!({"policy_state":"unknown"}),
            "deny",
        ),
        (
            "explicit_policy_allow",
            json!({"policy_state":"allow"}),
            "allow",
        ),
        ("policy_deny", json!({"policy_state":"deny"}), "deny"),
        (
            "management_read_denied",
            json!({"management_allows":false}),
            "deny",
        ),
        (
            "unsafe_flat_cross_product",
            json!({"flat_encoding_safe":false}),
            "deny",
        ),
        (
            "global_deny_overrides_complete_allow",
            json!({"global_deny":true}),
            "deny",
        ),
        (
            "participation_current_denied",
            json!({"phase":"payload","action":"ak.message.create","participation_allows":false,
                "paths":[{"kind":"capability_grant","actions":["ak.message.create"],"resources":["A"],"complete":true,"active":true}]}),
            "deny",
        ),
    ] {
        let rows = declared
            .iter()
            .filter(|case| case["name"] == name)
            .collect::<Vec<_>>();
        ensure!(
            rows.len() == 1 && rows[0]["input"] == input && rows[0]["expected"] == expected,
            "review changed Policy case {name}"
        );
    }
    let scene = GrantFixture::establish().await?;
    let read_operations = scene
        .operations
        .iter()
        .map(String::as_str)
        .filter(|action| *action != "ak.message.create")
        .collect::<Vec<_>>();
    let (runtime, initial_claims) = scene.issue_for(&read_operations, scene.selectors()).await?;
    ensure!(
        initial_claims
            .scope_details
            .as_ref()
            .context("complete initial Policy absence")?["policy_refs"]
            == json!([])
    );
    scene.read_exact(&runtime).await?;
    unavailable_policy_source(&scene, &read_operations, &runtime).await?;
    let allow = read_policy(&scene, arkret_wire::PolicyEffect::Allow)?;
    publish_policy(&scene, &allow, None).await?;
    let (runtime, claims) = scene.issue_for(&read_operations, scene.selectors()).await?;
    ensure!(
        claims
            .scope_details
            .as_ref()
            .context("policy scope details")?["policy_refs"]
            .as_array()
            .context("actual current policy refs")?
            .iter()
            .any(|value| value.as_str() == Some(allow.id.as_str()))
    );
    scene.read_exact(&runtime).await?;
    let mut deny = read_policy(&scene, arkret_wire::PolicyEffect::Deny)?;
    let revision = publish_policy(&scene, &deny, None).await?;
    refused_issue(
        &scene,
        &read_operations,
        scene.selectors(),
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
    )
    .await?;
    read_denied(&scene, &runtime).await?;
    println!(
        "[agent-management-read] accepted_exact_agent_read_deny=1 existing_read_credential_denied=1 complete_membership_retained=1 controller_original_retained=1"
    );
    deny.rules[0].effect = arkret_wire::PolicyEffect::Allow;
    publish_policy(&scene, &deny, Some(revision)).await?;
    let (runtime, _) = scene.issue_for(&read_operations, scene.selectors()).await?;
    scene.read_exact(&runtime).await?;

    // The independent membership source is complete before this accepted deny.
    let mut constraint =
        GrantConstraint::new(GrantConstraintKind::Temporal, GrantConstraintEffect::Deny);
    constraint.not_before = Some(Utc::now() - chrono::Duration::hours(1));
    constraint.expires_at = Some(Utc::now() + chrono::Duration::hours(1));
    let refusal = scene
        .grant_with_constraints(&scene.a, &["ak.event.read"], vec![constraint])
        .await?;
    refused_issue(
        &scene,
        &read_operations,
        scene.selectors(),
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
    )
    .await?;
    read_denied(&scene, &runtime).await?;
    scene.revoke(&refusal).await?;
    let (runtime, _) = scene.issue_for(&read_operations, scene.selectors()).await?;
    scene.read_exact(&runtime).await?;

    scene.grant(&scene.a, &["ak.event.read"]).await?;
    let write_b = scene.grant(&scene.b, &["ak.message.create"]).await?;
    let operations = scene
        .operations
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let (on_a, claims) = scene.issue_for(&operations, scene.selectors()).await?;
    ensure!(
        !claims
            .scopes
            .iter()
            .any(|action| action == "ak.message.create")
    );
    scene.read_exact(&on_a).await?;
    let mut on_b = scene.selectors();
    on_b.strand_ids = vec![scene.b.clone()];
    let (on_b, claims) = scene.issue_for(&operations, on_b).await?;
    ensure!(
        claims
            .scopes
            .iter()
            .any(|action| action == "ak.message.create")
    );
    scene
        .commit_message(
            &on_b,
            &scene.b,
            &write_b,
            "Exact B write before mixed resource request",
        )
        .await?;
    let mut mixed = scene.selectors();
    mixed.strand_ids.push(scene.b.clone());
    mixed.strand_ids.sort();
    refused_issue(
        &scene,
        &operations,
        mixed,
        arkret_wire::ErrorCode::CAPABILITY_DENIED,
    )
    .await?;
    println!(
        "[agent-policy-content] accepted_allow=1 accepted_current_deny=1 original_credential_rechecked=1 exact_cas_restore=1 global_deny_beats_membership=1 controller_still_reads=1 safe_A_read_and_B_write=1 mixed_resources_refused=1"
    );
    current_reply_selection(&scene, &on_b, &on_a, &write_b).await?;
    Ok(crate::conformance::SuiteExecutionResult {
        entrypoint: "ak.suite.agent.vectors.v1",
        fixture: "agent-vectors-fixture.json",
        cases: declared
            .iter()
            .filter_map(|case| {
                let name = case["name"].as_str()?;
                REVIEWED_POLICY_CONTENT_CASES.contains(&name).then(|| {
                    crate::conformance::CaseExecutionResult {
                        case_id: name.to_owned(),
                        assertions: 1,
                    }
                })
            })
            .collect(),
    })
}
