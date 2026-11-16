//! Independent security-transaction resilience reference runner.
//!
//! This module intentionally does not import Arkret wire, state, Garth, or
//! Coland code. It interprets only the fixture vocabulary and emits the five
//! canonical comparison fields.

use std::collections::BTreeSet;
use std::fmt::Write;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

mod recovery;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecurityTransactionResilienceFixture {
    profile: String,

    runner: FixtureRunner,
    covers_vectors: Vec<String>,
    /// Free-form instances validated by their referenced JSON Schemas.
    schema_validation_cases: Vec<Value>,
    fault_matrix: Value,
    assertions: Vec<String>,
    rotation_cases: Vec<Value>,
    pub(crate) continue_cases: Vec<Value>,
    single_submit_recovery_kat: Value,
    recovery_submit_cases: Vec<Value>,
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
    #[serde(flatten)]
    result: ReferenceOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ReferenceOutcome {
    SecurityRotation {
        transaction_id: String,
        request_digest: String,
        prepared_plan_digest: String,
        accepted_steps: Vec<String>,
        terminal_outcome: String,
    },
    Recovery {
        transaction_id: Value,
        receipt_digest: String,
        native_commits: Vec<Value>,
        completion_attestation: Option<Value>,
        outcome: String,
    },
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

/// Only Rotation has an accepted-step ledger. Recovery publishes one immutable
/// closure at create; it must never enter this prefix/continue derivation.
fn steps(kind: &str) -> Result<Vec<String>, String> {
    let values = match kind {
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
        result: ReferenceOutcome::SecurityRotation {
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
        },
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
    if fixture.runner.kind != "named_suite"
        || fixture.runner.entrypoint != "ak.suite.security_transaction.resilience.v1"
        || fixture
            .equivalence_output
            .get("minimum_independent_runners")
            .and_then(Value::as_u64)
            != Some(2)
        || fixture.profile.trim().is_empty()
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
        "Recovery is one exact signed receipt containing two EventAdmissionSubmission slots; it has no prepare plan or outer terminal signature.",
        "Recovery success atomically creates distinct consecutive Commits, device/generation/session terminal and native content-recovery fence.",
        "The existing completion operation obtains the original success closure server-side and verifies a fresh accepted-device PoP for the new holder.",
        "accepted_or_rejected_revoke_outcome_is_atomic_with_step_or_abort_expiry",
        "accepted_revoke_proposal_has_exact_covering_commit_and_pending_without_outcome",
        "accepted_step_contains_only_acceptor_and_accepted_at",
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
        "one_transaction_id_and_one_reserved_id_set",
        "pointer_switch_precedes_every_old_series_erase",
        "public_store_log_telemetry_and_crash_artifact_contain_no_secret_material",
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

fn members<'a>(case: &'a Value, key: &str) -> Vec<&'a str> {
    case.get(key)
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

pub fn run(
    fixture: &SecurityTransactionResilienceFixture,
) -> Result<Vec<ReferenceProjection>, String> {
    validate_fixture(fixture)?;
    recovery::check_freeze_and_atomic_effects(&fixture.single_submit_recovery_kat)?;
    let kinds = strings_at(&fixture.fault_matrix, "/transaction_kinds")?;
    let positions = strings_at(&fixture.fault_matrix, "/fault_positions")?;
    let faults = strings_at(&fixture.fault_matrix, "/faults")?;
    if kinds != ["recovery", "security_rotation"] || positions.len() != 3 || faults.len() != 7 {
        return Err("resilience fault matrix cardinality changed".to_owned());
    }

    let mut projections = Vec::with_capacity(
        kinds.len() * positions.len() * faults.len()
            + fixture.rotation_cases.len()
            + fixture.recovery_submit_cases.len(),
    );
    for kind in kinds {
        let all_steps = if kind == "security_rotation" {
            steps(kind)?
        } else {
            Vec::new()
        };
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
                if kind == "recovery" {
                    projections.push(recovery::fault(
                        &fixture.single_submit_recovery_kat,
                        format!("{kind}/{position}/{fault}"),
                        position,
                        fault,
                    )?);
                    continue;
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
    projections.extend(recovery::cases(
        &fixture.single_submit_recovery_kat,
        &fixture.recovery_submit_cases,
    )?);
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
