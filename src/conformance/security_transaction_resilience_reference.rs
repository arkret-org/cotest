//! Independent security-transaction resilience reference runner.
//!
//! This module intentionally does not import Arkret wire, state, Garth, or
//! Soland code. It interprets only the fixture vocabulary and emits the five
//! canonical comparison fields.

use std::collections::BTreeSet;
use std::fmt::Write;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecurityTransactionResilienceFixture {
    profile: String,
    version: String,
    suite: String,
    runner: FixtureRunner,
    covers_vectors: Vec<String>,
    /// Free-form instances validated by their referenced JSON Schemas.
    schema_validation_cases: Vec<Value>,
    fault_matrix: Value,
    assertions: Vec<String>,
    rotation_cases: Vec<Value>,
    pub(crate) continue_cases: Vec<Value>,
    recovery_terminal_commit_cases: Vec<Value>,
    equivalence_output: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRunner {
    kind: String,
    entrypoint: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceProjection {
    pub scenario: String,
    pub transaction_id: String,
    pub request_digest: String,
    pub prepared_plan_digest: String,
    pub accepted_steps: Vec<String>,
    pub terminal_outcome: String,
}

fn canonical_write(value: &Value, output: &mut String) -> Result<(), String> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(value) => output.push_str(&value.to_string()),
        Value::String(value) => output.push_str(
            &serde_json::to_string(value)
                .map_err(|error| format!("canonical string encode failed: {error}"))?,
        ),
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                canonical_write(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(
                    &serde_json::to_string(key)
                        .map_err(|error| format!("canonical key encode failed: {error}"))?,
                );
                output.push(':');
                canonical_write(value, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn digest(value: &Value) -> Result<String, String> {
    let mut canonical = String::new();
    canonical_write(value, &mut canonical)?;
    let digest = Sha256::digest(canonical.as_bytes());
    let mut encoded = String::with_capacity(71);
    encoded.push_str("sha256:");
    for byte in digest {
        write!(&mut encoded, "{byte:02x}")
            .map_err(|error| format!("digest encode failed: {error}"))?;
    }
    Ok(encoded)
}

fn strings_at<'a>(fixture: &'a Value, pointer: &str) -> Result<Vec<&'a str>, String> {
    fixture
        .pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{pointer} must be an array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| format!("{pointer} must contain strings"))
        })
        .collect()
}

/// A RecoveryTransaction has exactly one step. The two-step
/// `submit_reanchor_unit` / `issue_terminal_receipt` shape is gone: both
/// Events, the first new-generation reanchor commit and the terminal outcome
/// now enter through the single `commit_recovery_unit` continue.
fn steps(kind: &str) -> Result<Vec<String>, String> {
    let values = match kind {
        "recovery" => vec!["commit_recovery_unit"],
        "security_rotation" => vec![
            "revoke",
            "upload_new_material",
            "switch_authoritative_pointer",
            "erase_old_material",
            "local_commit",
        ],
        _ => return Err(format!("unknown transaction kind {kind}")),
    };
    Ok(values.into_iter().map(str::to_owned).collect())
}

fn transaction_id(kind: &str) -> Result<String, String> {
    let suffix = match kind {
        "recovery" => "000000000001",
        "security_rotation" => "000000000003",
        _ => return Err(format!("unknown transaction kind {kind}")),
    };
    Ok(format!("ak:transaction:019a7400-0000-7000-8000-{suffix}"))
}

fn projection(
    scenario: String,
    kind: &str,
    accepted_steps: Vec<String>,
    terminal_outcome: &str,
) -> Result<ReferenceProjection, String> {
    let transaction_id = transaction_id(kind)?;
    Ok(ReferenceProjection {
        scenario,
        request_digest: digest(&json!({
            "kind": kind,
            "suite": "security_transaction_resilience",
            "transaction_id": transaction_id,
        }))?,
        prepared_plan_digest: digest(&json!({
            "kind": kind,
            "steps": steps(kind)?,
            "suite": "security_transaction_resilience",
        }))?,
        transaction_id,
        accepted_steps,
        terminal_outcome: terminal_outcome.to_owned(),
    })
}

fn is_digest(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|value| {
        value.len() == 71
            && value.starts_with("sha256:")
            && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn validate_schema_cases(fixture: &SecurityTransactionResilienceFixture) -> Result<(), String> {
    let cases = &fixture.schema_validation_cases;
    if cases.len() != 2 {
        return Err("fixture must contain two schema cases".to_owned());
    }
    let binding_value = cases[0]
        .get("instance")
        .ok_or_else(|| "backup binding schema instance is missing".to_owned())?;
    let binding = binding_value
        .as_object()
        .ok_or_else(|| "backup binding schema instance is not an object".to_owned())?;
    for field in [
        "backup_kind",
        "previous_series_id",
        "new_series_id",
        "new_backups",
        "active_series_event_id",
        "old_backups",
    ] {
        if !binding.contains_key(field) {
            return Err(format!("backup binding is missing {field}"));
        }
    }
    if binding.len() != 6
        || binding.get("previous_series_id") == binding.get("new_series_id")
        || !binding
            .get("new_backups")
            .and_then(Value::as_array)
            .is_some_and(|values| values.len() == 1)
        || !binding
            .get("old_backups")
            .and_then(Value::as_array)
            .is_some_and(|values| values.len() == 1)
        || !is_digest(binding_value.pointer("/new_backups/0/ciphertext_digest"))
        || !is_digest(binding_value.pointer("/old_backups/0/ciphertext_digest"))
    {
        return Err("backup binding schema case is not closed".to_owned());
    }

    let outcome_value = cases[1]
        .get("instance")
        .ok_or_else(|| "erase outcome schema instance is missing".to_owned())?;
    let outcome = outcome_value
        .as_object()
        .ok_or_else(|| "erase outcome schema instance is not an object".to_owned())?;
    // `partial` is the status that must not carry a confirmation: the per-series
    // records are the whole answer. A record that reports an erased series has
    // to name the pointer it moved off and leave nothing behind on the old one.
    if outcome.get("status").and_then(Value::as_str) != Some("partial")
        || outcome.contains_key("confirmation")
        || !is_digest(outcome.get("request_digest"))
        || !outcome
            .get("series_records")
            .and_then(Value::as_array)
            .is_some_and(|records| {
                records.len() == 1
                    && records[0].get("backup_kind").and_then(Value::as_str)
                        == Some("secret_storage")
                    && records[0].get("status").and_then(Value::as_str) == Some("erased")
                    && records[0].get("previous_series_id") != records[0].get("new_series_id")
                    && records[0]
                        .get("erased_backups")
                        .and_then(Value::as_array)
                        .is_some_and(|values| values.len() == 1)
                    && is_digest(records[0].pointer("/erased_backups/0/ciphertext_digest"))
                    && records[0]
                        .get("remaining_backups")
                        .and_then(Value::as_array)
                        .is_some_and(|values| values.is_empty())
            })
    {
        return Err("partial erase outcome schema case is invalid".to_owned());
    }
    Ok(())
}

fn validate_fixture(fixture: &SecurityTransactionResilienceFixture) -> Result<(), String> {
    if fixture.suite != "security_transaction_resilience"
        || fixture.runner.kind != "named_suite"
        || fixture.runner.entrypoint != "ak.suite.security_transaction.resilience.v1"
        || fixture
            .equivalence_output
            .get("minimum_independent_runners")
            .and_then(Value::as_u64)
            != Some(2)
        || fixture.profile.trim().is_empty()
        || fixture.version.trim().is_empty()
        || fixture.covers_vectors.is_empty()
        || fixture.fault_matrix.is_null()
        || fixture.assertions.is_empty()
    {
        return Err("resilience fixture metadata changed".to_owned());
    }
    let fields = strings_at(&fixture.equivalence_output, "/canonical_fields")?;
    if fields
        != [
            "transaction_id",
            "request_digest",
            "prepared_plan_digest",
            "accepted_steps",
            "terminal_outcome",
        ]
    {
        return Err("resilience equivalence fields changed".to_owned());
    }
    // Pinned by name rather than by count: a count alone reports "incomplete"
    // for an added assertion as loudly as for a deleted one, and says nothing
    // about which.
    const EXPECTED_ASSERTIONS: &[&str] = &[
        "accepted_webvh_entry_resumes_the_same_reanchor_unit",
        "conflicting_replay_returns_duplicate_conflict",
        "continue_accepts_only_a_terminal_ready_client_attestation",
        "coordinator_owned_prefix_is_advanced_only_by_the_durable_worker",
        "device_attestation_readiness_is_derived_from_canonical_next_step",
        "erased_series_never_becomes_active_again",
        "exact_replay_returns_the_stored_outcome",
        "one_transaction_id_and_one_reserved_id_set",
        "only_the_atomic_generation_cas_winner_commits_a_reanchor_commit",
        "pointer_switch_precedes_every_old_series_erase",
        "public_store_log_telemetry_and_crash_artifact_contain_no_secret_material",
        "recovery_authoritative_results_are_all_invisible_before_the_commit_and_all_visible_after",
        "recovery_create_freezes_one_unsigned_commit_body_with_no_recovery_effect",
        "recovery_reanchor_commit_enters_only_through_commit_recovery_unit",
        "recovery_stored_outcome_is_checked_before_consumed_session_refusal",
        "request_plan_step_outputs_and_first_terminal_outcome_are_durable",
    ];
    let assertions = fixture
        .assertions
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected = EXPECTED_ASSERTIONS.iter().copied().collect::<BTreeSet<_>>();
    if assertions != expected {
        let missing = expected
            .difference(&assertions)
            .copied()
            .collect::<Vec<_>>();
        let extra = assertions
            .difference(&expected)
            .copied()
            .collect::<Vec<_>>();
        return Err(format!(
            "resilience assertion set drifted: missing {missing:?}, unregistered {extra:?}"
        ));
    }
    validate_schema_cases(fixture)
}

fn run_rotation_cases(
    fixture: &SecurityTransactionResilienceFixture,
) -> Result<Vec<ReferenceProjection>, String> {
    let cases = &fixture.rotation_cases;
    if cases.len() != 2
        || cases[0].get("name").and_then(Value::as_str)
            != Some("partial_secret_storage_erase_then_restart")
        || cases[0]
            .pointer("/expected_after_restart/confirmation_emitted_once")
            .and_then(Value::as_bool)
            != Some(true)
        || cases[0]
            .pointer("/expected_after_restart/accepted_erase_step_count")
            .and_then(Value::as_u64)
            != Some(1)
        || cases[1].get("name").and_then(Value::as_str)
            != Some("erase_before_both_pointer_switches")
        || cases[1]
            .pointer("/expected/old_backup_deleted")
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("rotation resilience cases changed".to_owned());
    }
    Ok(vec![
        projection(
            "rotation/partial_secret_storage_erase_then_restart".to_owned(),
            "security_rotation",
            steps("security_rotation")?,
            "completed",
        )?,
        projection(
            "rotation/erase_before_both_pointer_switches".to_owned(),
            "security_rotation",
            steps("security_rotation")?.into_iter().take(2).collect(),
            "failed_precondition",
        )?,
    ])
}

/// Every authoritative result of a RecoveryTransaction. The atomic boundary is
/// the whole list: all of it is invisible before the single commit and all of
/// it is visible after, so a case that shows one of them early is a broken
/// boundary, not a partial success.
const RECOVERY_AUTHORITATIVE_RESULTS: [&str; 7] = [
    "accepted_reanchor_event",
    "accepted_authorize_event",
    "committed_reanchor_commit",
    "advanced_device_generation",
    "active_verified_replacement_device",
    "consumed_recovery_session",
    "completed_terminal_outcome",
];

fn members<'a>(case: &'a Value, key: &str) -> Vec<&'a str> {
    case.get(key)
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn case_text<'a>(case: &'a Value, name: &str, key: &str) -> Result<&'a str, String> {
    case.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("recovery terminal commit case {name} needs a string {key}"))
}

/// A refusal label, when the fixture names one, is the canonical outcome.
///
/// The fixture spells a recovery refusal either as an operation-specific
/// `reason_code` or as a top-level `expected_reason_code`; this runner owns no
/// error registry (the dependency fence forbids importing one), so it accepts
/// both keys and leaves registration to the SDK runner it is compared against.
fn recovery_case_outcome(case: &Value, expected: &str) -> String {
    for key in ["reason_code", "expected_reason_code"] {
        if let Some(code) = case.get(key).and_then(Value::as_str) {
            return code.to_owned();
        }
    }
    expected.to_owned()
}

fn validate_recovery_terminal_commit_case(case: &Value, name: &str) -> Result<(), String> {
    match name {
        "create_freezes_the_only_signable_commit_body" => {
            if !members(case, "observable_recovery_effects").is_empty()
                || members(case, "committed_command_result_unit_event_digests")
                    != ["reanchor_digest", "authorize_digest"]
                || !members(case, "frozen_plan_members").contains(&"reanchor_commit_body")
            {
                return Err(
                    "recovery create must freeze one unsigned reanchor commit body over the exact [reanchor, authorize] unit and leave no recovery effect"
                        .to_owned(),
                );
            }
        }
        // Same caveat as the race case below: the fixture contract is the
        // atomic boundary, which the Station has not closed yet.
        "terminal_commit_is_one_atomic_commit" => {
            let invisible = members(case, "invisible_before_commit");
            let visible = members(case, "visible_after_commit");
            if RECOVERY_AUTHORITATIVE_RESULTS
                .iter()
                .any(|result| !invisible.contains(result) || !visible.contains(result))
                || !visible.contains(&"accepted_terminal_step")
            {
                return Err(
                    "the terminal commit must hide every authoritative result before it and show all of them after"
                        .to_owned(),
                );
            }
        }
        "receipt_completed_at_later_than_the_linearized_commit_time" => {
            let zero = members(case, "zero_effects");
            if RECOVERY_AUTHORITATIVE_RESULTS
                .iter()
                .any(|result| !zero.contains(result))
                || !zero.contains(&"accepted_terminal_step")
                || case.get("retry_with_a_new_receipt").and_then(Value::as_str) != Some("accepted")
                || case
                    .get("retry_with_different_bytes_for_a_frozen_step_outcome")
                    .and_then(Value::as_str)
                    != Some("duplicate_conflict")
            {
                return Err(
                    "an authoring time later than the linearized commit must reject with zero authoritative writes and stay retryable with a new receipt"
                        .to_owned(),
                );
            }
        }
        // KNOWN UNCLOSED on the Station side: the seven steps of the terminal
        // commit do not share one local database transaction yet - both Events
        // still land through the ordinary batch submit before the reanchor
        // commit is accepted. So "the loser leaves no residue" and "a crash
        // before the commit rolls the whole thing back" hold in the contract this
        // runner checks, and do NOT hold end to end in a joint run. This stays
        // the contract, not a relaxed one: the joint acceptance is an open
        // implementation item, not a reason to weaken the check here.
        "two_units_race_the_same_previous_generation" => {
            if !members(case, "loser_residue").is_empty()
                || case.get("winner_quarantined").and_then(Value::as_bool) != Some(false)
            {
                return Err(
                    "only the atomic CAS winner may commit a reanchor commit, and it is never quarantined"
                        .to_owned(),
                );
            }
        }
        "raw_recovery_commit_without_a_completed_transaction" => {
            if members(case, "attempted_paths")
                != ["ordinary_commit_submit", "federation", "history_replay"]
                || case.get("expected_finality").and_then(Value::as_str) != Some("none")
            {
                return Err(
                    "a raw recovery commit must reach no finality through submit, federation or history replay"
                        .to_owned(),
                );
            }
        }
        _ => {}
    }
    Ok(())
}

/// The recovery terminal-commit cases, pinned by name for the same reason the
/// assertion set is: a count alone cannot say *which* case left the fixture,
/// and a case that quietly disappears takes its arm in
/// [`validate_recovery_terminal_commit_case`] out of service without a word.
const EXPECTED_RECOVERY_TERMINAL_COMMIT_CASES: &[&str] = &[
    "byte_identical_create_replays_the_same_frozen_material",
    "commit_body_differs_from_the_frozen_body",
    "create_freezes_the_only_signable_commit_body",
    "raw_recovery_commit_without_a_completed_transaction",
    "receipt_completed_at_later_than_the_linearized_commit_time",
    "receipt_omits_or_rebinds_reanchor_commit_id",
    "same_transaction_id_with_different_intent_bytes",
    "signing_slot_fence_is_not_released_by_expiry_or_restart",
    "terminal_commit_is_one_atomic_commit",
    "terminal_response_lost_then_byte_identical_continue",
    "two_units_race_the_same_previous_generation",
];

fn run_recovery_terminal_commit_cases(
    fixture: &SecurityTransactionResilienceFixture,
) -> Result<Vec<ReferenceProjection>, String> {
    let declared = fixture
        .recovery_terminal_commit_cases
        .iter()
        .filter_map(|case| case.get("name").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let expected = EXPECTED_RECOVERY_TERMINAL_COMMIT_CASES
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    if declared != expected {
        let missing = expected.difference(&declared).copied().collect::<Vec<_>>();
        let extra = declared.difference(&expected).copied().collect::<Vec<_>>();
        return Err(format!(
            "recovery terminal commit case set drifted: missing {missing:?}, unregistered {extra:?}"
        ));
    }
    let terminal_step = steps("recovery")?;
    let mut projections = Vec::with_capacity(fixture.recovery_terminal_commit_cases.len());
    for case in &fixture.recovery_terminal_commit_cases {
        let name = case_text(case, "<unnamed>", "name")?;
        let phase = case_text(case, name, "phase")?;
        if !matches!(phase, "create" | "commit_recovery_unit" | "post_commit") {
            return Err(format!(
                "recovery terminal commit case {name} declares unknown phase {phase}"
            ));
        }
        let expected = case_text(case, name, "expected")?;
        validate_recovery_terminal_commit_case(case, name)?;
        // Recovery owns no coordinator prefix, so the accepted ledger is either
        // the single terminal step or empty; nothing in between is reachable.
        let accepted_terminal = phase != "create"
            && (members(case, "visible_after_commit").contains(&"accepted_terminal_step")
                || matches!(
                    expected,
                    "replay_stored_outcome" | "single_atomic_cas_winner"
                ));
        projections.push(projection(
            format!("recovery_terminal_commit/{phase}/{name}"),
            "recovery",
            if accepted_terminal {
                terminal_step.clone()
            } else {
                Vec::new()
            },
            &recovery_case_outcome(case, expected),
        )?);
    }
    Ok(projections)
}

pub fn run(
    fixture: &SecurityTransactionResilienceFixture,
) -> Result<Vec<ReferenceProjection>, String> {
    validate_fixture(fixture)?;
    let kinds = strings_at(&fixture.fault_matrix, "/transaction_kinds")?;
    let positions = strings_at(&fixture.fault_matrix, "/fault_positions")?;
    let faults = strings_at(&fixture.fault_matrix, "/faults")?;
    if kinds != ["recovery", "security_rotation"] || positions.len() != 3 || faults.len() != 7 {
        return Err("resilience fault matrix cardinality changed".to_owned());
    }

    let mut projections = Vec::with_capacity(kinds.len() * positions.len() * faults.len() + 2);
    for kind in kinds {
        let all_steps = steps(kind)?;
        for position in &positions {
            if !matches!(
                *position,
                "before_remote_side_effect"
                    | "after_remote_side_effect_before_local_commit"
                    | "after_local_commit_before_response"
            ) {
                return Err(format!("unknown fault position {position}"));
            }
            for fault in &faults {
                if !matches!(
                    *fault,
                    "crash"
                        | "response_lost"
                        | "coordinator_restart"
                        | "exact_request_replay"
                        | "conflicting_request_replay"
                        | "staged_secret_lost"
                        | "terminal_replay"
                ) {
                    return Err(format!("unknown resilience fault {fault}"));
                }
                let staged_secret_lost = *fault == "staged_secret_lost";
                projections.push(projection(
                    format!("{kind}/{position}/{fault}"),
                    kind,
                    if staged_secret_lost {
                        all_steps
                            .iter()
                            .take(all_steps.len().saturating_sub(1))
                            .cloned()
                            .collect()
                    } else {
                        all_steps.clone()
                    },
                    if staged_secret_lost {
                        "staged_secret_lost"
                    } else {
                        "completed"
                    },
                )?);
            }
        }
    }
    projections.extend(run_rotation_cases(fixture)?);
    projections.extend(run_recovery_terminal_commit_cases(fixture)?);
    Ok(projections)
}

#[cfg(test)]
mod tests {
    use serde_json::Map;

    use super::*;

    #[test]
    fn canonical_writer_sorts_object_keys() {
        let mut object = Map::new();
        object.insert("z".to_owned(), json!(1));
        object.insert("a".to_owned(), json!(2));
        let mut encoded = String::new();
        canonical_write(&Value::Object(object), &mut encoded).unwrap();
        assert_eq!(encoded, r#"{"a":2,"z":1}"#);
    }
}
