//! Admission-producer contract audit for Direct Conversation Realms.
//!
//! This module deliberately does not claim service execution. The canonical
//! suite requires calls through the public Event-submit and Direct Conversation
//! resolver operations, but the current Station/SDK pair does not yet expose a
//! complete public setup path for all seven negative pre-states. Keeping that
//! distinction explicit prevents a fixture walk from being reported as E2E
//! coverage.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, ensure};
use serde_json::Value;

use super::{fixture_runner_entrypoint, load_fixture_value, required_array, required_str};

const FIXTURE: &str = "direct-conversation-admission-fixture.json";
const ENTRYPOINT: &str = "ak.suite.direct_conversation.admission_producers.v1";
const WRITE_OPERATION: &str = "ak.self.events.command.submit.v1";
const READ_OPERATION: &str = "ak.self.direct_conversation.read.resolve.v1";

const REASONS: [&str; 7] = [
    "direct_conversation_binding_invalid",
    "direct_conversation_terminal_forbidden",
    "direct_conversation_member_count_invalid",
    "direct_conversation_third_party_member_forbidden",
    "direct_conversation_invite_forbidden",
    "direct_conversation_root_mask_violation",
    "direct_conversation_participant_authority_denied",
];

const PRODUCER_PATHS: [&str; 7] = [
    "ak.direct_conversation.admission.binding_integrity.v1",
    "ak.direct_conversation.admission.terminal_guard.v1",
    "ak.direct_conversation.admission.exact_two_projection.v1",
    "ak.direct_conversation.admission.third_party_member_guard.v1",
    "ak.direct_conversation.admission.invite_guard.v1",
    "ak.direct_conversation.admission.root_phase_mask.v1",
    "ak.direct_conversation.admission.participant_authority.v1",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectConversationAdmissionCoverage {
    pub canonical_named_suite: String,
    pub write_operation_id: String,
    pub read_operation_id: String,
    pub audited_reason_codes: Vec<String>,
    pub audited_negative_cases: usize,
    pub service_e2e_status: &'static str,
    pub blockers: Vec<&'static str>,
}

/// Audit the closed canonical producer mapping without presenting it as a live
/// operation run. `service_e2e_status` stays `unwired` until Cotest can create
/// every required pre-state through public operations and then observe the
/// write and read outcomes from a spawned Station.
pub fn audit_direct_conversation_admission_contract() -> Result<DirectConversationAdmissionCoverage>
{
    let fixture = load_fixture_value(FIXTURE)?;
    ensure!(fixture_runner_entrypoint(&fixture)? == ENTRYPOINT);
    ensure!(required_str(&fixture, "write_operation_id")? == WRITE_OPERATION);
    ensure!(required_str(&fixture, "read_operation_id")? == READ_OPERATION);

    let rules = required_array(&fixture, "rules")?;
    ensure!(
        rules.len() == REASONS.len(),
        "fixture must contain seven rules"
    );
    let mut observed_reasons = Vec::with_capacity(rules.len());
    let mut observed_paths = Vec::with_capacity(rules.len());
    let mut negative_cases = 0usize;
    for rule in rules {
        let reason = required_str(rule, "reason_code")?;
        observed_reasons.push(reason.to_owned());
        observed_paths.push(required_str(rule, "producer_path_id")?.to_owned());
        let negatives = required_array(rule, "negative")?;
        ensure!(!negatives.is_empty(), "{reason} has no negative case");
        for case in negatives {
            ensure!(
                required_str(case, "expected_reason_code")? == reason,
                "{} does not produce its owning reason {reason}",
                required_str(case, "case_id")?
            );
            negative_cases += 1;
        }
    }
    ensure!(
        observed_reasons == REASONS,
        "reason precedence/order drifted"
    );
    ensure!(
        observed_paths == PRODUCER_PATHS,
        "producer-path mapping drifted"
    );
    ensure!(
        observed_reasons.iter().collect::<BTreeSet<_>>().len() == REASONS.len(),
        "reason codes must be unique"
    );

    let precedence = required_array(&fixture, "precedence")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("precedence members must be strings"))
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(precedence == REASONS, "closed precedence order drifted");

    let all_rejections = fixture
        .get("all_rejections")
        .ok_or_else(|| anyhow!("fixture omits all_rejections"))?;
    ensure!(required_str(all_rejections, "status")? == "rejected");
    for field in [
        "realm_commit_count",
        "event_write_count",
        "projection_write_count",
        "outbox_write_count",
        "durable_effect_count",
    ] {
        ensure!(
            all_rejections.get(field).and_then(Value::as_u64) == Some(0),
            "{field} must remain zero for every rejection"
        );
    }

    assert_special_precedence_cases(&fixture)?;
    assert_member_count_read_suspension(&fixture)?;
    assert_participant_denial_privacy(&fixture)?;

    Ok(DirectConversationAdmissionCoverage {
        canonical_named_suite: ENTRYPOINT.to_owned(),
        write_operation_id: WRITE_OPERATION.to_owned(),
        read_operation_id: READ_OPERATION.to_owned(),
        audited_reason_codes: observed_reasons,
        audited_negative_cases: negative_cases,
        service_e2e_status: "unwired",
        blockers: vec![
            "station_producer_for_all_seven_reasons_not_yet_available",
            "public_operation_setup_for_all_negative_pre_states_not_yet_available",
            "sdk_read_blocker_member_count_invalid_not_yet_available",
        ],
    })
}

fn assert_special_precedence_cases(fixture: &Value) -> Result<()> {
    let third_party = negative_case(
        fixture,
        "third_party_invite_dual_match_uses_third_party_reason",
    )?;
    ensure!(third_party["also_matches_invite_guard"] == true);
    ensure!(
        required_str(third_party, "expected_reason_code")?
            == "direct_conversation_third_party_member_forbidden"
    );

    let terminal = negative_case(fixture, "root_terminal_action_rejects")?;
    ensure!(
        required_str(terminal, "expected_reason_code")?
            == "direct_conversation_root_mask_violation"
    );
    ensure!(
        terminal
            .get("precedence_note")
            .and_then(Value::as_str)
            .is_some_and(|note| note.contains("direct_conversation_terminal_forbidden")),
        "root terminal-family case must preserve concrete terminal-event precedence"
    );
    Ok(())
}

fn assert_member_count_read_suspension(fixture: &Value) -> Result<()> {
    let case = negative_case(fixture, "binding_membership_disagreement_rejects")?;
    ensure!(case["expected_read_state"] == "suspended");
    ensure!(case["expected_read_blocker"] == "member_count_invalid");
    Ok(())
}

fn assert_participant_denial_privacy(fixture: &Value) -> Result<()> {
    let rule = rule(fixture, "direct_conversation_participant_authority_denied")?;
    let observable = required_array(rule, "observable_failure_fields")?;
    ensure!(observable == &[Value::from("status"), Value::from("reason_code")]);
    let forbidden = required_array(rule, "forbidden_observable_fields")?;
    ensure!(
        forbidden
            == &[
                Value::from("failed_input"),
                Value::from("missing_dependency"),
                Value::from("target_exists"),
            ]
    );
    Ok(())
}

fn rule<'a>(fixture: &'a Value, reason: &str) -> Result<&'a Value> {
    required_array(fixture, "rules")?
        .iter()
        .find(|rule| rule.get("reason_code").and_then(Value::as_str) == Some(reason))
        .ok_or_else(|| anyhow!("fixture omits rule {reason}"))
}

fn negative_case<'a>(fixture: &'a Value, case_id: &str) -> Result<&'a Value> {
    required_array(fixture, "rules")?
        .iter()
        .filter_map(|rule| rule.get("negative").and_then(Value::as_array))
        .flatten()
        .find(|case| case.get("case_id").and_then(Value::as_str) == Some(case_id))
        .ok_or_else(|| anyhow!("fixture omits negative case {case_id}"))
}
