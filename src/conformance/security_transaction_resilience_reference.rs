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
    let named = |name: &str| {
        cases
            .iter()
            .find(|case| case.get("name").and_then(Value::as_str) == Some(name))
            .ok_or_else(|| format!("fixture is missing schema case {name}"))
    };
    let binding_value = named("backup_rotation_binding_is_closed_per_kind")?
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

    // `accepted_steps[]` records only the accepted position and participant;
    // the effect proof lives in the durable results the worker re-checks, so a
    // redundant output digest on the step must be refused by the schema.
    let accepted_step = named("accepted_step_has_only_acceptor_and_time")?;
    let redundant = named("accepted_step_rejects_redundant_output_evidence")?;
    fn step_fields(case: &Value) -> Option<BTreeSet<&str>> {
        case.get("instance")
            .and_then(Value::as_object)
            .map(|instance| instance.keys().map(String::as_str).collect())
    }
    if accepted_step.get("expect_valid").and_then(Value::as_bool) != Some(true)
        || step_fields(accepted_step) != Some(BTreeSet::from(["acceptor", "accepted_at"]))
        || redundant.get("expect_valid").and_then(Value::as_bool) != Some(false)
        || !step_fields(redundant).is_some_and(|fields| {
            fields.contains("acceptor") && fields.contains("accepted_at") && fields.len() > 2
        })
    {
        return Err("accepted step schema cases are not closed to acceptor and time".to_owned());
    }

    let confirmation_value = named("durable_worker_erase_confirmation_is_closed")?
        .get("instance")
        .ok_or_else(|| "erase confirmation schema instance is missing".to_owned())?;
    let confirmation = confirmation_value
        .as_object()
        .ok_or_else(|| "erase confirmation schema instance is not an object".to_owned())?;
    // The durable worker's complete confirmation is the only erase evidence:
    // it binds the create-time transaction, request and plan digests and the
    // exact planned `secret_storage` series bytes.
    if confirmation.get("schema").and_then(Value::as_str)
        != Some("ak.schema.backup_series_erase_confirmation.v1")
        || confirmation.len() != 5
        || !confirmation
            .get("transaction_id")
            .and_then(Value::as_str)
            .is_some_and(|value| value.starts_with("ak:transaction:"))
        || !is_digest(confirmation.get("transaction_request_digest"))
        || !is_digest(confirmation.get("prepared_plan_digest"))
        || !confirmation
            .get("series")
            .and_then(Value::as_array)
            .is_some_and(|series| {
                series.len() == 1
                    && series[0].get("backup_kind").and_then(Value::as_str)
                        == Some("secret_storage")
                    && series[0].get("previous_series_id") != series[0].get("new_series_id")
                    && is_digest(series[0].pointer("/new_backups/0/ciphertext_digest"))
                    && is_digest(series[0].pointer("/old_backups/0/ciphertext_digest"))
            })
    {
        return Err("durable worker erase confirmation schema case is not closed".to_owned());
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
        "accepted_or_rejected_revoke_outcome_is_atomic_with_step_or_abort_expiry",
        "accepted_revoke_proposal_has_exact_covering_commit_and_pending_without_outcome",
        "accepted_step_contains_only_acceptor_and_accepted_at",
        "accepted_webvh_entry_resumes_the_same_reanchor_unit",
        "authorization_lease_is_not_issued_or_accepted",
        "backup_envelopes_are_signed_digest_checked_and_match_binding_in_canonical_backup_id_order",
        "client_attestation_method_resolves_current_device_key_at_same_accepted_pcr_cut",
        "conflicting_replay_returns_duplicate_conflict",
        "continue_accepts_only_a_terminal_ready_client_attestation",
        "coordinator_owned_prefix_is_advanced_only_by_the_durable_worker",
        "device_attestation_readiness_is_derived_from_canonical_next_step",
        "erase_is_only_worker_executed_and_has_no_public_self_operation",
        "erase_rechecks_live_transaction_active_account_non_revoked_authorizing_device_current_pointer_and_generation",
        "erased_series_never_becomes_active_again",
        "exact_replay_returns_the_stored_outcome",
        "governance_station_issues_both_recovery_realm_commits_only_inside_commit_recovery_unit",
        "one_transaction_id_and_one_reserved_id_set",
        "only_the_atomic_generation_cas_winner_commits_a_reanchor_commit",
        "pointer_switch_precedes_every_old_series_erase",
        "public_store_log_telemetry_and_crash_artifact_contain_no_secret_material",
        "recovery_authoritative_results_are_all_invisible_before_the_commit_and_all_visible_after",
        "recovery_create_freezes_two_signed_events_current_predecessor_and_ordered_digests_with_no_recovery_effect",
        "recovery_stored_outcome_is_checked_before_consumed_session_refusal",
        "request_plan_effect_results_accepted_positions_and_first_terminal_outcome_are_durable",
        "reserved_plan_ids_and_digests_alone_never_prove_a_completed_effect",
        "security_rotation_create_requires_fresh_high_risk_authentication_and_binds_the_authenticated_authorizing_device",
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

/// The rotation cases, pinned by name for the same reason the assertion set
/// is. Each entry is the accepted prefix length the case leaves behind: the
/// fixture states which step is refused or not appended, and the fixed step
/// table turns that into the accepted ledger.
const EXPECTED_ROTATION_CASES: &[(&str, usize)] = &[
    // Reserved upload ids alone prove nothing: only revoke is accepted.
    (
        "reserved_upload_ids_without_durable_envelopes_do_not_accept_step",
        1,
    ),
    // Upload is refused before it appends: only revoke is accepted.
    ("backup_envelope_digest_or_order_mismatch_rejected", 1),
    // The switch is accepted and erase is worker-only: a client cannot drive it.
    ("self_erase_attempt_cannot_drive_worker_step", 3),
    // The coordinator prefix is complete; the client-attested local commit is refused.
    ("local_commit_method_uses_wrong_device_fragment", 4),
    ("local_commit_method_key_revoked_at_accepted_pcr_cut", 4),
    ("partial_secret_storage_erase_then_restart", 5),
    // An unrelated PCR Commit between attempts does not stale the frozen
    // old-backup manifest: the resume reuses the first request bytes.
    ("partial_erase_resumes_after_unrelated_pcr_commit", 5),
    // The secret_storage pointer changed between attempts: the resume stops
    // before any further old backup is deleted.
    ("erase_resume_after_secret_storage_pointer_changed", 3),
    // The pointer switch has not been accepted: revoke and upload only.
    ("erase_before_secret_storage_pointer_switch", 2),
    // The switch was accepted, then the authorizing device stopped being
    // current: erase is refused before any old backup is deleted.
    ("erase_after_authorizing_device_revoked", 3),
];

fn validate_rotation_case(case: &Value, name: &str) -> Result<String, String> {
    let rejects_without_delete = |case: &Value| {
        case.pointer("/expected/decision").and_then(Value::as_str) == Some("reject")
            && case.pointer("/expected/reason").and_then(Value::as_str)
                == Some("failed_precondition")
            && case
                .pointer("/expected/old_backup_deleted")
                .and_then(Value::as_bool)
                == Some(false)
            && members(case, "authoritative_new_pointers") == ["secret_storage"]
    };
    let expected_label = |label: &str| case.get("expected").and_then(Value::as_str) == Some(label);
    let valid = match name {
        "reserved_upload_ids_without_durable_envelopes_do_not_accept_step" => {
            case.get("prepared_plan_has_reserved_new_backups")
                .and_then(Value::as_bool)
                == Some(true)
                && case
                    .get("durable_uploaded_envelopes")
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty)
                && expected_label("do_not_append_accepted_step")
        }
        "backup_envelope_digest_or_order_mismatch_rejected" => {
            case.get("new_backup_envelopes_match_binding")
                .and_then(Value::as_bool)
                == Some(false)
                && expected_label("reject_without_side_effect")
        }
        "self_erase_attempt_cannot_drive_worker_step" => {
            case.get("driver").and_then(Value::as_str) == Some("external_client")
                && expected_label("no_public_operation")
        }
        "local_commit_method_uses_wrong_device_fragment" => {
            case.get("verification_method_device_matches_artifact")
                .and_then(Value::as_bool)
                == Some(false)
                && expected_label("reject_without_side_effect")
        }
        "local_commit_method_key_revoked_at_accepted_pcr_cut" => {
            case.get("device_current_at_accepted_pcr_cut")
                .and_then(Value::as_bool)
                == Some(false)
                && expected_label("reject_without_side_effect")
        }
        "partial_secret_storage_erase_then_restart" => {
            members(case, "authoritative_new_pointers") == ["secret_storage"]
                && case
                    .pointer("/first_outcome/secret_storage")
                    .and_then(Value::as_str)
                    == Some("failed_retryable")
                && case
                    .pointer("/expected_after_restart/secret_storage")
                    .and_then(Value::as_str)
                    == Some("erased")
                && case
                    .pointer("/expected_after_restart/mls_history")
                    .is_none()
                && case
                    .pointer("/expected_after_restart/confirmation_emitted_once")
                    .and_then(Value::as_bool)
                    == Some(true)
                && case
                    .pointer("/expected_after_restart/accepted_erase_step_count")
                    .and_then(Value::as_u64)
                    == Some(1)
        }
        "partial_erase_resumes_after_unrelated_pcr_commit" => {
            members(case, "authoritative_new_pointers") == ["secret_storage"]
                && case
                    .pointer("/first_outcome/secret_storage")
                    .and_then(Value::as_str)
                    == Some("failed_retryable")
                && case
                    .pointer("/between_attempts/unrelated_pcr_commit_accepted")
                    .and_then(Value::as_bool)
                    == Some(true)
                && case
                    .pointer("/between_attempts/secret_storage_pointer_changed")
                    .and_then(Value::as_bool)
                    == Some(false)
                && case
                    .pointer("/between_attempts/device_generation_changed")
                    .and_then(Value::as_bool)
                    == Some(false)
                && case
                    .pointer("/expected_after_restart/secret_storage")
                    .and_then(Value::as_str)
                    == Some("erased")
                && case
                    .pointer("/expected_after_restart/request_bytes_reused")
                    .and_then(Value::as_bool)
                    == Some(true)
                && case
                    .pointer("/expected_after_restart/confirmation_emitted_once")
                    .and_then(Value::as_bool)
                    == Some(true)
                && case
                    .pointer("/expected_after_restart/accepted_erase_step_count")
                    .and_then(Value::as_u64)
                    == Some(1)
        }
        "erase_resume_after_secret_storage_pointer_changed" => {
            members(case, "authoritative_new_pointers") == ["secret_storage"]
                && case
                    .pointer("/first_outcome/secret_storage")
                    .and_then(Value::as_str)
                    == Some("failed_retryable")
                && case
                    .pointer("/between_attempts/secret_storage_pointer_changed")
                    .and_then(Value::as_bool)
                    == Some(true)
                && case.pointer("/expected/decision").and_then(Value::as_str) == Some("reject")
                && case.pointer("/expected/reason").and_then(Value::as_str)
                    == Some("failed_precondition")
                && case
                    .pointer("/expected/further_old_backup_deleted")
                    .and_then(Value::as_bool)
                    == Some(false)
        }
        "erase_before_secret_storage_pointer_switch" => rejects_without_delete(case),
        "erase_after_authorizing_device_revoked" => {
            rejects_without_delete(case)
                && case
                    .get("authorizing_device_current")
                    .and_then(Value::as_bool)
                    == Some(false)
        }
        _ => false,
    };
    if !valid {
        return Err(format!("rotation resilience case {name} changed"));
    }
    // A refusal names its reason; a case with no terminal decision keeps its
    // fixture label, as the recovery cases do.
    Ok(match name {
        "partial_secret_storage_erase_then_restart"
        | "partial_erase_resumes_after_unrelated_pcr_commit" => "completed".to_owned(),
        _ => case
            .pointer("/expected/reason")
            .or_else(|| case.get("expected"))
            .and_then(Value::as_str)
            .ok_or_else(|| format!("rotation resilience case {name} has no expectation"))?
            .to_owned(),
    })
}

fn run_rotation_cases(
    fixture: &SecurityTransactionResilienceFixture,
) -> Result<Vec<ReferenceProjection>, String> {
    let declared = fixture
        .rotation_cases
        .iter()
        .filter_map(|case| case.get("name").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    let expected = EXPECTED_ROTATION_CASES
        .iter()
        .map(|(name, _)| *name)
        .collect::<BTreeSet<_>>();
    if declared != expected || fixture.rotation_cases.len() != expected.len() {
        let missing = expected.difference(&declared).copied().collect::<Vec<_>>();
        let extra = declared.difference(&expected).copied().collect::<Vec<_>>();
        return Err(format!(
            "rotation case set drifted: missing {missing:?}, unregistered {extra:?}"
        ));
    }
    let all_steps = steps("security_rotation")?;
    let mut projections = Vec::with_capacity(fixture.rotation_cases.len());
    for case in &fixture.rotation_cases {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "rotation case needs a string name".to_owned())?;
        let accepted = EXPECTED_ROTATION_CASES
            .iter()
            .find_map(|(expected, accepted)| (*expected == name).then_some(*accepted))
            .ok_or_else(|| format!("rotation case {name} is not registered"))?;
        let outcome = validate_rotation_case(case, name)?;
        projections.push(projection(
            format!("rotation/{name}"),
            "security_rotation",
            all_steps.iter().take(accepted).cloned().collect(),
            &outcome,
        )?);
    }
    Ok(projections)
}

/// Every authoritative result of a RecoveryTransaction. The atomic boundary is
/// the whole list: all of it is invisible before the single commit and all of
/// it is visible after, so a case that shows one of them early is a broken
/// boundary, not a partial success.
const RECOVERY_AUTHORITATIVE_RESULTS: [&str; 8] = [
    "accepted_reanchor_event",
    "accepted_authorize_event",
    "committed_reanchor_realm_commit",
    "committed_authorize_realm_commit",
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

/// A refusal's `reason_code`, when the fixture names one, is the canonical
/// outcome; otherwise the fixture's expectation label is. This runner owns no
/// error registry (the dependency fence forbids importing one).
fn recovery_case_outcome(case: &Value, expected: &str) -> String {
    case.get("reason_code")
        .and_then(Value::as_str)
        .unwrap_or(expected)
        .to_owned()
}

/// A rejected commit attempt leaves every authoritative result, the accepted
/// terminal step and the completion attestation at zero.
fn has_zero_recovery_effects(case: &Value) -> bool {
    let zero = members(case, "zero_effects");
    RECOVERY_AUTHORITATIVE_RESULTS
        .iter()
        .all(|result| zero.contains(result))
        && zero.contains(&"accepted_terminal_step")
        && zero.contains(&"recovery_completion_attestation")
}

fn validate_recovery_terminal_commit_case(case: &Value, name: &str) -> Result<(), String> {
    match name {
        "create_freezes_events_predecessor_and_ordered_digests" => {
            let frozen = members(case, "frozen_plan_members");
            if !members(case, "observable_recovery_effects").is_empty()
                || members(case, "committed_command_result_unit_event_digests")
                    != ["reanchor_digest", "authorize_digest"]
                || [
                    "binding.reanchor_event_id",
                    "binding.authorize_event_id",
                    "binding.terminal_receipt_id",
                    "reanchor_unit",
                    "reanchor_commit_intent",
                    "reanchor_commit_intent.predecessor_ref",
                    "reanchor_commit_intent.unit_event_digests",
                ]
                .iter()
                .any(|member| !frozen.contains(member))
            {
                return Err(
                    "recovery create must freeze both signed Events, the current predecessor and the ordered [reanchor, authorize] digests and leave no recovery effect"
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
                || !visible.contains(&"recovery_completion_attestation")
            {
                return Err(
                    "the terminal commit must hide every authoritative result before it and show all of them after"
                        .to_owned(),
                );
            }
        }
        "swapped_event_digest_order_differs_from_the_frozen_plan" => {
            let frozen = members(case, "frozen_order");
            let submitted = members(case, "submitted_order");
            if frozen != ["reanchor_digest", "authorize_digest"]
                || submitted == frozen
                || submitted.iter().collect::<BTreeSet<_>>()
                    != frozen.iter().collect::<BTreeSet<_>>()
                || !has_zero_recovery_effects(case)
            {
                return Err(
                    "a reordered commit unit must be refused against the frozen digest order with zero authoritative writes"
                        .to_owned(),
                );
            }
        }
        // The Station issues both recovery RealmCommits itself; the terminal
        // artifact never carries commit material.
        "terminal_artifact_attempts_to_carry_realm_commit_material" => {
            let forbidden = members(case, "forbidden_members");
            if ["realm_commit", "realm_commit_id", "authority_signature"]
                .iter()
                .any(|member| !forbidden.contains(member))
            {
                return Err(
                    "the recovery terminal artifact must refuse every RealmCommit member"
                        .to_owned(),
                );
            }
        }
        "receipt_completed_at_later_than_the_linearized_commit_time" => {
            if !has_zero_recovery_effects(case)
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
        "terminal_response_lost_then_byte_identical_continue" => {
            if case
                .get("stored_outcome_checked_before_live_state_refusal")
                .and_then(Value::as_bool)
                != Some(true)
                || members(case, "replayed_members")
                    != [
                        "terminal_outcome",
                        "terminal_outcome.receipt_id",
                        "terminal_outcome.completion_attestation",
                    ]
            {
                return Err(
                    "a lost terminal response must replay the stored outcome before any live-state refusal"
                        .to_owned(),
                );
            }
        }
        // KNOWN UNCLOSED on the Station side: the terminal commit does not yet
        // share one local database transaction end to end. So "the loser leaves
        // no residue" and "a crash before the commit rolls the whole thing back"
        // hold in the contract this runner checks, and do NOT hold end to end in
        // a joint run. This stays the contract, not a relaxed one: the joint
        // acceptance is an open implementation item, not a reason to weaken the
        // check here.
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
    "create_freezes_events_predecessor_and_ordered_digests",
    "ordered_event_digests_differ_from_the_frozen_intent",
    "raw_recovery_commit_without_a_completed_transaction",
    "receipt_completed_at_later_than_the_linearized_commit_time",
    "same_transaction_id_with_different_intent_bytes",
    "swapped_event_digest_order_differs_from_the_frozen_plan",
    "terminal_artifact_attempts_to_carry_realm_commit_material",
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

    let mut projections = Vec::with_capacity(
        kinds.len() * positions.len() * faults.len()
            + fixture.rotation_cases.len()
            + fixture.recovery_terminal_commit_cases.len(),
    );
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
