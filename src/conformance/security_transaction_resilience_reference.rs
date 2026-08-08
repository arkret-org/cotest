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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceProjection {
    pub scenario: String,
    pub transaction_id: String,
    pub request_digest: String,
    pub prepared_plan_digest: String,
    pub accepted_steps: Vec<String>,
    pub terminal_result: String,
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

fn steps(kind: &str) -> Result<Vec<String>, String> {
    let values = match kind {
        "recovery_root_anchored" => vec![
            "publish_did_entry",
            "submit_reanchor_unit",
            "issue_terminal_receipt",
        ],
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
        "recovery_root_anchored" => "000000000001",
        "security_rotation" => "000000000003",
        _ => return Err(format!("unknown transaction kind {kind}")),
    };
    Ok(format!("ak:transaction:019a7400-0000-7000-8000-{suffix}"))
}

fn projection(
    scenario: String,
    kind: &str,
    accepted_steps: Vec<String>,
    terminal_result: &str,
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
        terminal_result: terminal_result.to_owned(),
    })
}

fn is_digest(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|value| {
        value.len() == 71
            && value.starts_with("sha256:")
            && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
    })
}

fn validate_schema_cases(fixture: &Value) -> Result<(), String> {
    let cases = fixture
        .get("schema_validation_cases")
        .and_then(Value::as_array)
        .ok_or_else(|| "schema_validation_cases must be an array".to_owned())?;
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

    let outcome = cases[1]
        .get("instance")
        .and_then(Value::as_object)
        .ok_or_else(|| "erase outcome schema instance is missing".to_owned())?;
    if outcome.get("status").and_then(Value::as_str) != Some("partial")
        || outcome.contains_key("confirmation")
        || !outcome
            .get("series_results")
            .and_then(Value::as_array)
            .is_some_and(|results| {
                results.len() == 2
                    && results[0].get("backup_kind").and_then(Value::as_str)
                        == Some("secret_storage")
                    && results[0].get("status").and_then(Value::as_str) == Some("erased")
                    && results[1].get("backup_kind").and_then(Value::as_str) == Some("mls_history")
                    && results[1].get("status").and_then(Value::as_str) == Some("failed_retryable")
                    && results[1].get("reason_code").and_then(Value::as_str)
                        == Some("storage_temporarily_unavailable")
            })
    {
        return Err("partial erase outcome schema case is invalid".to_owned());
    }
    Ok(())
}

fn validate_fixture(fixture: &Value) -> Result<(), String> {
    if fixture.get("suite").and_then(Value::as_str) != Some("security_transaction_resilience")
        || fixture
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            != Some("ak.suite.security_transaction.resilience.v1")
        || fixture
            .pointer("/equivalence_output/minimum_independent_runners")
            .and_then(Value::as_u64)
            != Some(2)
    {
        return Err("resilience fixture metadata changed".to_owned());
    }
    let fields = strings_at(fixture, "/equivalence_output/canonical_fields")?;
    if fields
        != [
            "transaction_id",
            "request_digest",
            "prepared_plan_digest",
            "accepted_steps",
            "terminal_result",
        ]
    {
        return Err("resilience equivalence fields changed".to_owned());
    }
    let assertions = strings_at(fixture, "/assertions")?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if assertions.len() != 8 {
        return Err("resilience assertion set is incomplete".to_owned());
    }
    validate_schema_cases(fixture)
}

fn run_rotation_cases(fixture: &Value) -> Result<Vec<ReferenceProjection>, String> {
    let cases = fixture
        .get("rotation_cases")
        .and_then(Value::as_array)
        .ok_or_else(|| "rotation_cases must be an array".to_owned())?;
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

pub fn run(fixture: &Value) -> Result<Vec<ReferenceProjection>, String> {
    validate_fixture(fixture)?;
    let kinds = strings_at(fixture, "/fault_matrix/transaction_kinds")?;
    let positions = strings_at(fixture, "/fault_matrix/fault_positions")?;
    let faults = strings_at(fixture, "/fault_matrix/faults")?;
    if kinds.len() != 3 || positions.len() != 3 || faults.len() != 7 {
        return Err("resilience fault matrix cardinality changed".to_owned());
    }

    let mut projections = Vec::with_capacity(65);
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
