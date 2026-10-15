//! Accepted management Policies, global refusals and safe resource correlation.
use arkret_models_collaboration::governance::grant_constraint::{
    GrantConstraint, GrantConstraintEffect, GrantConstraintKind,
};
use arkret_models_collaboration::governance::operation_wire::{Policy, PolicySetStatePayload};
use arkret_wire::EventKind;

use super::content_grant_evidence::GrantFixture;
use super::*;
use crate::harness::expect_api_error;

pub const REVIEWED_POLICY_CONTENT_CASES: [&str; 4] = [
    "explicit_policy_allow",
    "policy_deny",
    "unsafe_flat_cross_product",
    "global_deny_overrides_complete_allow",
];

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
    selectors: arkret_models_collaboration::session_grants::SessionGrantAgentScopeRequest,
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
            "explicit_policy_allow",
            json!({"policy_state":"allow"}),
            "allow",
        ),
        ("policy_deny", json!({"policy_state":"deny"}), "deny"),
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
    let (runtime, _) = scene.issue_for(&read_operations, scene.selectors()).await?;
    scene.read_exact(&runtime).await?;
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
