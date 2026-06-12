//! CBA dual-plane lattice fixture suite.
//!
//! Validates the `cba-lattice-fixture.json` profile's normative vectors. Data
//! events use `effects + seal_ref + auth_context` and stay data-plane local or
//! observed until control-plane seals cover the relevant state. Control moves
//! use `effects + seal_basis`, may carry preconditions, and only become sealed
//! after valid seal coverage.

use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value, json};

use super::{load_fixture_value, required_str, validate_profile};
use crate::transcripts::record_vector_event;

pub fn run_state_resolution_fixture_suite() -> Result<()> {
    run_cba_lattice_fixture_suite()
}

pub fn run_cba_lattice_fixture_suite() -> Result<()> {
    let value = load_fixture_value("cba-lattice-fixture.json")?;
    validate_profile(&value, "ck.profile.cba_lattice_vectors.v1")?;

    let vectors = value
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("cba lattice fixture missing vectors[]"))?;
    if vectors.is_empty() {
        bail!("cba lattice fixture has no vectors");
    }

    let mut seen_data_local = false;
    let mut seen_observation = false;
    let mut seen_control_seal = false;
    let mut seen_same_batch = false;
    let mut seen_data_bottom = false;
    let mut seen_delta_plane_guard = false;
    let mut seen_compaction = false;

    for vector in vectors {
        let name = required_str(vector, "name")?;
        match name {
            "data_event_accepts_without_seal_finality" => {
                require_str_eq(vector, "/event/plane", "data", name)?;
                require_non_empty_array(vector, "/event/effects", name)?;
                require_field(required_object(vector, "/event", name)?, "seal_ref", name)?;
                require_field(
                    required_object(vector, "/event", name)?,
                    "auth_context",
                    name,
                )?;
                require_str_eq(vector, "/expected/event_state", "data_local", name)?;
                require_bool_eq(vector, "/expected/fanout_allowed", true, name)?;
                require_bool_eq(vector, "/expected/seal_required_for_accept", false, name)?;
                require_str_eq(
                    vector,
                    "/expected/query_grade_before_observation",
                    "local",
                    name,
                )?;
                seen_data_local = true;
                record_vector_event(
                    "state_resolution.cba.data_event_accepts_without_seal_finality",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "plane": "data",
                        "event_state": "data_local",
                        "seal_required_for_accept": false,
                    }),
                    &json!({
                        "plane": pointer_str(vector, "/event/plane"),
                        "event_state": pointer_str(vector, "/expected/event_state"),
                        "seal_required_for_accept": pointer_bool(vector, "/expected/seal_required_for_accept"),
                    }),
                );
            }
            "data_event_observation_does_not_seal" => {
                require_field(required_object(vector, "/seal", name)?, "id", name)?;
                require_non_empty_array(vector, "/seal/delta", name)?;
                require_field(
                    required_object(vector, "/seal", name)?,
                    "data_event_set_root",
                    name,
                )?;
                require_str_eq(vector, "/expected/data_event_state", "data_observed", name)?;
                require_str_eq(vector, "/expected/query_grade", "observed", name)?;
                require_bool_eq(vector, "/expected/must_not_report_sealed", true, name)?;
                seen_observation = true;
                record_vector_event(
                    "state_resolution.cba.data_event_observation_does_not_seal",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "data_event_state": "data_observed",
                        "query_grade": "observed",
                        "must_not_report_sealed": true,
                    }),
                    &json!({
                        "data_event_state": pointer_str(vector, "/expected/data_event_state"),
                        "query_grade": pointer_str(vector, "/expected/query_grade"),
                        "must_not_report_sealed": pointer_bool(vector, "/expected/must_not_report_sealed"),
                    }),
                );
            }
            "control_move_requires_seal_basis_and_seal" => {
                require_non_empty_array(vector, "/basis/leaves", name)?;
                require_field(
                    required_object(vector, "/basis", name)?,
                    "control_event_set_root",
                    name,
                )?;
                require_field(required_object(vector, "/basis", name)?, "state_root", name)?;
                require_str_eq(vector, "/control_move/plane", "control", name)?;
                require_non_empty_array(vector, "/control_move/preconditions", name)?;
                require_non_empty_array(vector, "/control_move/effects", name)?;
                require_str_eq(
                    vector,
                    "/expected_before_seal/event_state",
                    "control_pending",
                    name,
                )?;
                require_str_eq(vector, "/expected_before_seal/query_grade", "seen", name)?;
                require_str_eq(
                    vector,
                    "/expected_after_valid_seal/event_state",
                    "control_sealed",
                    name,
                )?;
                require_str_eq(
                    vector,
                    "/expected_after_valid_seal/query_grade",
                    "sealed",
                    name,
                )?;
                seen_control_seal = true;
                record_vector_event(
                    "state_resolution.cba.control_move_requires_seal_basis_and_seal",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "plane": "control",
                        "before": "control_pending",
                        "after": "control_sealed",
                    }),
                    &json!({
                        "plane": pointer_str(vector, "/control_move/plane"),
                        "before": pointer_str(vector, "/expected_before_seal/event_state"),
                        "after": pointer_str(vector, "/expected_after_valid_seal/event_state"),
                    }),
                );
            }
            "same_batch_does_not_advance_authorization_basis" => {
                let batch = required_array(vector, "/batch", name)?;
                if batch.len() < 2 {
                    bail!("vector {name} requires at least two batch events");
                }
                require_str_eq(vector, "/batch/0/plane", "control", name)?;
                require_str_eq(vector, "/batch/0/state", "control_pending", name)?;
                require_str_eq(vector, "/batch/1/plane", "data", name)?;
                require_str_eq(
                    vector,
                    "/expected/second_event_result",
                    "reject_or_quarantine",
                    name,
                )?;
                require_str_eq(vector, "/expected/reason", "capability_denied", name)?;
                require_bool_eq(vector, "/expected/same_batch_resolution_only", true, name)?;
                seen_same_batch = true;
                record_vector_event(
                    "state_resolution.cba.same_batch_does_not_advance_authorization_basis",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "first_state": "control_pending",
                        "second_result": "reject_or_quarantine",
                        "reason": "capability_denied",
                    }),
                    &json!({
                        "first_state": pointer_str(vector, "/batch/0/state"),
                        "second_result": pointer_str(vector, "/expected/second_event_result"),
                        "reason": pointer_str(vector, "/expected/reason"),
                    }),
                );
            }
            "data_plane_conflict_returns_bottom_without_winner" => {
                require_str_eq(vector, "/cell_lattice/plane", "data", name)?;
                require_str_eq(vector, "/cell_lattice/lattice", "cas_register", name)?;
                require_str_eq(vector, "/cell_lattice/bottom", "reject", name)?;
                require_array_len_at_least(vector, "/data_events", 2, name)?;
                require_str_eq(vector, "/expected/query/status", "bottom", name)?;
                require_str_eq(vector, "/expected/query/bottom/kind", "conflict", name)?;
                require_array_len_at_least(vector, "/expected/query/bottom/event_ids", 2, name)?;
                require_str_eq(
                    vector,
                    "/expected/dependent_write_result",
                    "failed_bottom",
                    name,
                )?;
                seen_data_bottom = true;
                record_vector_event(
                    "state_resolution.cba.data_plane_conflict_returns_bottom_without_winner",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "plane": "data",
                        "lattice": "cas_register",
                        "query_status": "bottom",
                    }),
                    &json!({
                        "plane": pointer_str(vector, "/cell_lattice/plane"),
                        "lattice": pointer_str(vector, "/cell_lattice/lattice"),
                        "query_status": pointer_str(vector, "/expected/query/status"),
                    }),
                );
            }
            "seal_delta_excludes_data_event_digest" => {
                require_non_empty_array(vector, "/seal/delta", name)?;
                let first_delta = required_array(vector, "/seal/delta", name)?
                    .first()
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        anyhow!("vector {name} first seal.delta entry must be string")
                    })?;
                let member_plane = vector
                    .pointer(&format!(
                        "/seal/delta_member_plane/{}",
                        escape_pointer(first_delta)
                    ))
                    .and_then(Value::as_str);
                if member_plane != Some("data") {
                    bail!("vector {name} first seal.delta member must be marked as data plane");
                }
                require_str_eq(vector, "/expected/seal_result", "reject", name)?;
                require_str_eq(vector, "/expected/event_state", "rejected_seal", name)?;
                require_str_eq(
                    vector,
                    "/expected/reason",
                    "delta_contains_data_event",
                    name,
                )?;
                seen_delta_plane_guard = true;
                record_vector_event(
                    "state_resolution.cba.seal_delta_excludes_data_event_digest",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "delta_member_plane": "data",
                        "seal_result": "reject",
                        "reason": "delta_contains_data_event",
                    }),
                    &json!({
                        "delta_member_plane": member_plane,
                        "seal_result": pointer_str(vector, "/expected/seal_result"),
                        "reason": pointer_str(vector, "/expected/reason"),
                    }),
                );
            }
            "open_set_compaction_preserves_control_roots" => {
                require_array_len_at_least(vector, "/predecessor_refs", 2, name)?;
                require_field(
                    required_object(vector, "/compaction_seal", name)?,
                    "control_event_set_root_must_equal",
                    name,
                )?;
                require_field(
                    required_object(vector, "/compaction_seal", name)?,
                    "state_root_must_equal",
                    name,
                )?;
                let delta = required_array(vector, "/compaction_seal/delta", name)?;
                if !delta.is_empty() {
                    bail!("vector {name} compaction seal delta must be empty");
                }
                require_str_eq(
                    vector,
                    "/expected/seal_result",
                    "accept_when_equivalent_else_reject",
                    name,
                )?;
                require_bool_eq(vector, "/expected/preserves_bottom_diagnostics", true, name)?;
                require_bool_eq(vector, "/expected/preserves_signature_chain", true, name)?;
                require_str_eq(
                    vector,
                    "/expected/compaction_without_signature",
                    "reject",
                    name,
                )?;
                seen_compaction = true;
                record_vector_event(
                    "state_resolution.cba.open_set_compaction_preserves_control_roots",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "seal_result": "accept_when_equivalent_else_reject",
                        "preserves_bottom_diagnostics": true,
                        "compaction_without_signature": "reject",
                    }),
                    &json!({
                        "seal_result": pointer_str(vector, "/expected/seal_result"),
                        "preserves_bottom_diagnostics": pointer_bool(vector, "/expected/preserves_bottom_diagnostics"),
                        "compaction_without_signature": pointer_str(vector, "/expected/compaction_without_signature"),
                    }),
                );
            }
            _ => bail!("unknown cba lattice vector: {name}"),
        }
    }

    if !(seen_data_local
        && seen_observation
        && seen_control_seal
        && seen_same_batch
        && seen_data_bottom
        && seen_delta_plane_guard
        && seen_compaction)
    {
        bail!(
            "cba lattice fixture must cover all 7 normative vectors \
             (data_local / observation / control_seal / same_batch / data_bottom / \
              delta_plane_guard / compaction)"
        );
    }

    Ok(())
}

fn required_object<'a>(
    value: &'a Value,
    pointer: &str,
    vector_name: &str,
) -> Result<&'a Map<String, Value>> {
    value
        .pointer(pointer)
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("vector {vector_name} missing object at {pointer}"))
}

fn required_array<'a>(
    value: &'a Value,
    pointer: &str,
    vector_name: &str,
) -> Result<&'a Vec<Value>> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("vector {vector_name} missing array at {pointer}"))
}

fn require_non_empty_array(value: &Value, pointer: &str, vector_name: &str) -> Result<()> {
    let array = required_array(value, pointer, vector_name)?;
    if array.is_empty() {
        bail!("vector {vector_name} array at {pointer} must not be empty");
    }
    Ok(())
}

fn require_array_len_at_least(
    value: &Value,
    pointer: &str,
    min_len: usize,
    vector_name: &str,
) -> Result<()> {
    let array = required_array(value, pointer, vector_name)?;
    if array.len() < min_len {
        bail!("vector {vector_name} array at {pointer} must have at least {min_len} items");
    }
    Ok(())
}

fn require_str_eq(value: &Value, pointer: &str, expected: &str, vector_name: &str) -> Result<()> {
    let actual = value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("vector {vector_name} missing string at {pointer}"))?;
    if actual != expected {
        bail!("vector {vector_name} field {pointer} must be {expected:?}, got {actual:?}");
    }
    Ok(())
}

fn require_bool_eq(value: &Value, pointer: &str, expected: bool, vector_name: &str) -> Result<()> {
    let actual = value
        .pointer(pointer)
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("vector {vector_name} missing bool at {pointer}"))?;
    if actual != expected {
        bail!("vector {vector_name} field {pointer} must be {expected}, got {actual}");
    }
    Ok(())
}

fn require_field<'a>(
    obj: &'a Map<String, Value>,
    field: &str,
    vector_name: &str,
) -> Result<&'a Value> {
    obj.get(field)
        .ok_or_else(|| anyhow!("vector {vector_name} object missing field {field}"))
}

fn pointer_str(value: &Value, pointer: &str) -> Option<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn pointer_bool(value: &Value, pointer: &str) -> Option<bool> {
    value.pointer(pointer).and_then(Value::as_bool)
}

fn escape_pointer(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}
