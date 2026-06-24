//! CBA dual-plane lattice fixture suite.
//!
//! Validates the `cba-lattice-fixture.json` profile's normative vectors. Data
//! events use `effects + seal_ref + auth_context` and stay data-plane local or
//! observed until control-plane seals cover the relevant state. Control moves
//! use `effects + seal_basis`, may carry preconditions, and only become sealed
//! after valid seal coverage.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use serde_json::{Map, Value, json};

use super::{
    canonical_json, load_fixture_value, looks_like_sha256_digest, required_str, sha256_prefixed,
    validate_profile,
};
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
    let mut seen_seal_canonical = false;
    let mut seen_cas_mixed_basis = false;
    let mut seen_auth_epoch = false;
    let mut seen_compaction_interval = false;
    let mut seen_inclusion_list = false;
    let mut seen_notary_fault = false;
    let mut seen_threshold_forensics = false;
    let mut seen_concurrent_revocation = false;
    let mut seen_conflict_recovery = false;

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
            "seal_canonical_no_self_reference" => {
                validate_seal_canonical_no_self_reference(vector, name)?;
                seen_seal_canonical = true;
                record_vector_event(
                    "state_resolution.cba.seal_canonical_no_self_reference",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "valid_result": "accept",
                        "reject_reasons": ["digest_mismatch", "schema_violation"],
                    }),
                    &json!({
                        "valid_result": pointer_str(vector, "/expected/valid_result"),
                        "attack_count": required_array(vector, "/attacks", name)?.len(),
                    }),
                );
            }
            "cas_mixed_basis" => {
                validate_cas_mixed_basis(vector, name)?;
                seen_cas_mixed_basis = true;
                record_vector_event(
                    "state_resolution.cba.cas_mixed_basis",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "blind_write": "failed_precondition",
                        "valid_basis": "accept_after_valid_seal",
                    }),
                    &json!({
                        "pre_state": pointer_str(vector, "/pre_state/settled_value"),
                        "case_count": required_array(vector, "/cases", name)?.len(),
                    }),
                );
            }
            "auth_context_epoch_pinning_reject" => {
                validate_auth_context_epoch_pinning_reject(vector, name)?;
                seen_auth_epoch = true;
                record_vector_event(
                    "state_resolution.cba.auth_context_epoch_pinning_reject",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "outside_window": "reject_or_hide",
                        "inside_window_grade": "stale",
                        "epoch_mismatch": "failed_precondition",
                    }),
                    &json!({
                        "window_ms": pointer_u64(vector, "/revocation_freshness_window_ms"),
                        "case_count": required_array(vector, "/cases", name)?.len(),
                    }),
                );
            }
            "seal_compaction_interval_enforced" => {
                validate_seal_compaction_interval_enforced(vector, name)?;
                seen_compaction_interval = true;
                record_vector_event(
                    "state_resolution.cba.seal_compaction_interval_enforced",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "valid_compaction": "accept",
                        "coverage_mismatch": "reject",
                        "overdue": "governance_health_alarm",
                    }),
                    &json!({
                        "max_interval_ms": pointer_u64(vector, "/realm/seal_compaction_max_interval_ms"),
                        "case_count": required_array(vector, "/cases", name)?.len(),
                    }),
                );
            }
            "inclusion_list_obligation" => {
                validate_inclusion_list_obligation(vector, name)?;
                seen_inclusion_list = true;
                record_vector_event(
                    "state_resolution.cba.inclusion_list_obligation",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "discharged": ["include", "signed_reject", "pre_state_failure_proof"],
                        "omitted": "inclusion_list_violation",
                        "same_slot_conflict": "equivocation",
                    }),
                    &json!({
                        "single_did_profile_expected": pointer_str(vector, "/single_did_profile_expected"),
                        "case_count": required_array(vector, "/cases", name)?.len(),
                    }),
                );
            }
            "notary_fault_equivocation_quarantine" => {
                validate_notary_fault_equivocation_quarantine(vector, name)?;
                seen_notary_fault = true;
                record_vector_event(
                    "state_resolution.cba.notary_fault_equivocation_quarantine",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "fault_move_result": "accept",
                        "later_seal_from_signer": "reject",
                        "branch_grade": "forked",
                    }),
                    &json!({
                        "fault_move_result": pointer_str(vector, "/expected/fault_move_result"),
                        "later_seal_from_signer": pointer_str(vector, "/expected/later_seal_from_signer"),
                        "branch_grade": pointer_str(vector, "/expected/affected_branch_query_grade"),
                    }),
                );
            }
            "threshold_forensic_attribution" => {
                validate_threshold_forensic_attribution(vector, name)?;
                seen_threshold_forensics = true;
                record_vector_event(
                    "state_resolution.cba.threshold_forensic_attribution",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "n5_k3_quorum_intersection": "accept",
                        "mismatched_arithmetic": "reject",
                        "missing_field": "schema_violation",
                    }),
                    &json!({
                        "case_count": required_array(vector, "/cases", name)?.len(),
                    }),
                );
            }
            "open_set_concurrent_revocation_fail_closed" => {
                validate_open_set_concurrent_revocation_fail_closed(vector, name)?;
                seen_concurrent_revocation = true;
                record_vector_event(
                    "state_resolution.cba.open_set_concurrent_revocation_fail_closed",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "concurrent_revoke": "reject_or_hide",
                        "authorization_cell_bottom": "fail_closed",
                        "light_client": "pending_or_fail_closed",
                    }),
                    &json!({
                        "notary_profile": pointer_str(vector, "/notary_profile"),
                        "case_count": required_array(vector, "/cases", name)?.len(),
                    }),
                );
            }
            "conflict_recovery_move" => {
                validate_conflict_recovery_move(vector, name)?;
                seen_conflict_recovery = true;
                record_vector_event(
                    "state_resolution.cba.conflict_recovery_move",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "valid_recovery": "accept_after_valid_seal",
                        "unsealed_recovery": "control_pending",
                    }),
                    &json!({
                        "cell": pointer_str(vector, "/cell"),
                        "case_count": required_array(vector, "/cases", name)?.len(),
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
        && seen_compaction
        && seen_seal_canonical
        && seen_cas_mixed_basis
        && seen_auth_epoch
        && seen_compaction_interval
        && seen_inclusion_list
        && seen_notary_fault
        && seen_threshold_forensics
        && seen_concurrent_revocation
        && seen_conflict_recovery)
    {
        bail!(
            "cba lattice fixture must cover all 16 normative vectors \
             (data_local / observation / control_seal / same_batch / data_bottom / \
              delta_plane_guard / compaction / seal_canonical / cas_mixed_basis / \
              auth_epoch / compaction_interval / inclusion_list / notary_fault / \
              threshold_forensics / concurrent_revocation / conflict_recovery)"
        );
    }

    Ok(())
}

fn validate_seal_canonical_no_self_reference(vector: &Value, vector_name: &str) -> Result<()> {
    let body_value = vector
        .pointer("/seal_body")
        .ok_or_else(|| anyhow!("vector {vector_name} missing object at /seal_body"))?;
    let body = required_object(vector, "/seal_body", vector_name)?;
    for forbidden in ["id", "notary_signature"] {
        if body.contains_key(forbidden) {
            bail!("vector {vector_name} seal_body must exclude {forbidden}");
        }
    }
    for field in [
        "realm_id",
        "predecessor_refs",
        "delta",
        "control_event_set_root",
        "state_root",
        "sealed_at",
        "hlc",
    ] {
        require_field(body, field, vector_name)?;
    }
    require_non_empty_array(vector, "/seal_body/predecessor_refs", vector_name)?;
    for digest in string_vec_at(vector, "/seal_body/delta", vector_name)? {
        require_sha256_digest(digest, "/seal_body/delta", vector_name)?;
    }

    let canonical = canonical_json(body_value)?;
    let digest = sha256_prefixed(canonical.as_bytes());
    let expected_id = required_pointer_str(vector, "/expected/id", vector_name)?;
    let computed_id = format!("ck:seal:{digest}");
    if expected_id != computed_id.as_str() {
        bail!("vector {vector_name} expected id must be {computed_id}, got {expected_id}");
    }
    let payload_digest = required_pointer_str(
        vector,
        "/expected/notary_signature_payload_digest",
        vector_name,
    )?;
    if payload_digest != digest.as_str() {
        bail!(
            "vector {vector_name} signature payload digest must be {digest}, got {payload_digest}"
        );
    }
    require_str_eq(vector, "/expected/valid_result", "accept", vector_name)?;

    let attacks = required_array(vector, "/attacks", vector_name)?;
    let mut seen = BTreeSet::new();
    for attack in attacks {
        let attack_name = required_pointer_str(attack, "/name", vector_name)?;
        seen.insert(attack_name.to_owned());
        match attack_name {
            "id_in_canonical_bytes" => {
                require_str_eq(attack, "/inject_field", "id", vector_name)?;
                require_str_eq(attack, "/expected_result", "reject", vector_name)?;
                require_str_eq(attack, "/reason", "digest_mismatch", vector_name)?;
            }
            "signature_in_canonical_bytes" => {
                require_str_eq(attack, "/inject_field", "notary_signature", vector_name)?;
                require_str_eq(attack, "/expected_result", "reject", vector_name)?;
                require_str_eq(attack, "/reason", "digest_mismatch", vector_name)?;
            }
            "wire_key_reorder" => {
                require_str_eq(
                    attack,
                    "/expected_result",
                    "accept_after_canonical_reencode",
                    vector_name,
                )?;
            }
            "extra_proof_injection" => {
                require_str_eq(attack, "/inject_field", "extra_proof", vector_name)?;
                require_str_eq(attack, "/expected_result", "reject", vector_name)?;
                require_str_eq(attack, "/reason", "schema_violation", vector_name)?;
            }
            "non_digest_delta_value" => {
                let values = string_vec_at(attack, "/delta", vector_name)?;
                if values.iter().all(|value| looks_like_sha256_digest(value)) {
                    bail!("vector {vector_name} non_digest_delta_value must carry a bad digest");
                }
                require_str_eq(attack, "/expected_result", "reject", vector_name)?;
                require_str_eq(attack, "/reason", "schema_violation", vector_name)?;
            }
            _ => bail!("vector {vector_name} unknown canonical attack {attack_name}"),
        }
    }
    require_seen(
        vector_name,
        &seen,
        &[
            "id_in_canonical_bytes",
            "signature_in_canonical_bytes",
            "wire_key_reorder",
            "extra_proof_injection",
            "non_digest_delta_value",
        ],
    )
}

fn validate_cas_mixed_basis(vector: &Value, vector_name: &str) -> Result<()> {
    let cell = required_pointer_str(vector, "/cell", vector_name)?;
    require_str_eq(vector, "/cell_lattice/lattice", "cas_register", vector_name)?;
    require_str_eq(vector, "/cell_lattice/bottom", "reject", vector_name)?;
    if !vector
        .pointer("/cell_lattice/initial_value")
        .is_some_and(Value::is_null)
    {
        bail!("vector {vector_name} cas_register initial_value must be null");
    }
    require_str_eq(vector, "/pre_state/settled_value", "v1", vector_name)?;

    let mut seen = BTreeSet::new();
    for case in required_array(vector, "/cases", vector_name)? {
        let case_name = required_pointer_str(case, "/name", vector_name)?;
        seen.insert(case_name.to_owned());
        match case_name {
            "blind_write_without_basis" => {
                require_str_eq(case, "/event/plane", "data", vector_name)?;
                require_str_eq(case, "/event/effects/0/cell", cell, vector_name)?;
                if !case.pointer("/event/basis").is_some_and(Value::is_null) {
                    bail!("vector {vector_name} blind write must carry a null basis");
                }
                require_str_eq(case, "/event/effects/0/op/kind", "set", vector_name)?;
                require_str_eq(case, "/event/effects/0/op/value", "v2", vector_name)?;
                require_str_eq(case, "/expected/result", "failed_precondition", vector_name)?;
                require_str_eq(case, "/expected/cell_value", "v1", vector_name)?;
                require_bool_eq(
                    case,
                    "/expected/atomic_rejects_all_effects",
                    true,
                    vector_name,
                )?;
                require_str_eq(
                    case,
                    "/expected/defensive_join_result",
                    "bottom",
                    vector_name,
                )?;
            }
            "control_move_with_head_eq_basis" => {
                require_str_eq(case, "/control_move/plane", "control", vector_name)?;
                require_str_eq(
                    case,
                    "/control_move/preconditions/0/cell",
                    cell,
                    vector_name,
                )?;
                require_str_eq(
                    case,
                    "/control_move/preconditions/0/predicate/op",
                    "head_eq",
                    vector_name,
                )?;
                require_str_eq(
                    case,
                    "/control_move/preconditions/0/predicate/value",
                    "v1",
                    vector_name,
                )?;
                require_str_eq(case, "/control_move/effects/0/cell", cell, vector_name)?;
                require_str_eq(case, "/control_move/effects/0/op/kind", "set", vector_name)?;
                require_str_eq(case, "/control_move/effects/0/op/value", "v2", vector_name)?;
                require_str_eq(
                    case,
                    "/expected/result",
                    "accept_after_valid_seal",
                    vector_name,
                )?;
                require_str_eq(case, "/expected/cell_value", "v2", vector_name)?;
                require_bool_eq(
                    case,
                    "/expected/replay_order_independent",
                    true,
                    vector_name,
                )?;
            }
            _ => bail!("vector {vector_name} unknown cas mixed basis case {case_name}"),
        }
    }
    require_seen(
        vector_name,
        &seen,
        &[
            "blind_write_without_basis",
            "control_move_with_head_eq_basis",
        ],
    )
}

fn validate_auth_context_epoch_pinning_reject(vector: &Value, vector_name: &str) -> Result<()> {
    let window = required_u64(vector, "/revocation_freshness_window_ms", vector_name)?;
    let mut seen = BTreeSet::new();
    for case in required_array(vector, "/cases", vector_name)? {
        let case_name = required_pointer_str(case, "/name", vector_name)?;
        seen.insert(case_name.to_owned());
        match case_name {
            "revoked_key_old_seal_ref_outside_window" => {
                let distance = required_u64(case, "/seal_ref_distance_ms", vector_name)?;
                if distance <= window {
                    bail!("vector {vector_name} outside-window case must exceed freshness window");
                }
                require_str_eq(case, "/expected/result", "reject_or_hide", vector_name)?;
                require_str_eq(case, "/expected/reason", "stale_seal_ref", vector_name)?;
            }
            "revoked_key_within_freshness_window" => {
                let distance = required_u64(case, "/seal_ref_distance_ms", vector_name)?;
                if distance > window {
                    bail!("vector {vector_name} within-window case exceeds freshness window");
                }
                require_str_eq(case, "/expected/result", "accept_temporarily", vector_name)?;
                require_str_eq(case, "/expected/query_grade", "stale", vector_name)?;
            }
            "epoch_not_valid_at_seal_ref" => {
                require_bool_eq(
                    case,
                    "/current_did_document_contains_key",
                    true,
                    vector_name,
                )?;
                require_str_eq(case, "/expected/result", "failed_precondition", vector_name)?;
                require_bool_eq(
                    case,
                    "/expected/must_not_use_current_did_document_fallback",
                    true,
                    vector_name,
                )?;
            }
            _ => bail!("vector {vector_name} unknown auth epoch case {case_name}"),
        }
    }
    require_seen(
        vector_name,
        &seen,
        &[
            "revoked_key_old_seal_ref_outside_window",
            "revoked_key_within_freshness_window",
            "epoch_not_valid_at_seal_ref",
        ],
    )
}

fn validate_seal_compaction_interval_enforced(vector: &Value, vector_name: &str) -> Result<()> {
    require_str_eq(vector, "/realm/notary_type", "open_set", vector_name)?;
    let interval = required_u64(
        vector,
        "/realm/seal_compaction_max_interval_ms",
        vector_name,
    )?;
    let mut seen = BTreeSet::new();
    for case in required_array(vector, "/cases", vector_name)? {
        let case_name = required_pointer_str(case, "/name", vector_name)?;
        seen.insert(case_name.to_owned());
        match case_name {
            "compaction_within_interval" => {
                let expected_covered = union_digest_sets(
                    string_set_at(case, "/predecessor_covered_event_digests", vector_name)?,
                    string_set_at(case, "/delta", vector_name)?,
                );
                let covered = string_set_at(case, "/covered_event_digests", vector_name)?;
                if covered != expected_covered {
                    bail!(
                        "vector {vector_name} valid compaction coverage is not recursive closure"
                    );
                }
                if required_u64(case, "/elapsed_since_previous_compaction_ms", vector_name)?
                    > interval
                {
                    bail!("vector {vector_name} valid compaction case exceeds interval");
                }
                require_str_eq(case, "/expected/seal_result", "accept", vector_name)?;
                require_bool_eq(
                    case,
                    "/expected/bootstrap_from_compaction",
                    true,
                    vector_name,
                )?;
            }
            "covered_set_mismatch" => {
                let expected_covered = union_digest_sets(
                    string_set_at(case, "/predecessor_covered_event_digests", vector_name)?,
                    string_set_at(case, "/delta", vector_name)?,
                );
                let covered = string_set_at(case, "/covered_event_digests", vector_name)?;
                if covered == expected_covered {
                    bail!("vector {vector_name} mismatch case accidentally matches closure");
                }
                require_str_eq(case, "/expected/seal_result", "reject", vector_name)?;
                require_str_eq(
                    case,
                    "/expected/reason",
                    "covered_set_mismatch",
                    vector_name,
                )?;
            }
            "live_chain_exceeds_interval_without_compaction" => {
                if required_u64(case, "/elapsed_since_previous_compaction_ms", vector_name)?
                    <= interval
                {
                    bail!("vector {vector_name} overdue case must exceed compaction interval");
                }
                require_bool_eq(case, "/expected/governance_health_alarm", true, vector_name)?;
                require_bool_eq(
                    case,
                    "/expected/existing_seals_remain_valid",
                    true,
                    vector_name,
                )?;
                require_bool_eq(
                    case,
                    "/expected/bootstrap_degraded_to_chain_walk",
                    true,
                    vector_name,
                )?;
            }
            _ => bail!("vector {vector_name} unknown compaction interval case {case_name}"),
        }
    }
    require_seen(
        vector_name,
        &seen,
        &[
            "compaction_within_interval",
            "covered_set_mismatch",
            "live_chain_exceeds_interval_without_compaction",
        ],
    )
}

fn validate_inclusion_list_obligation(vector: &Value, vector_name: &str) -> Result<()> {
    require_str_eq(vector, "/notary_profile/type", "threshold", vector_name)?;
    let proposer = required_pointer_str(vector, "/notary_profile/proposer_id", vector_name)?;
    let signer = required_pointer_str(vector, "/notary_profile/signer_id", vector_name)?;
    if proposer == signer {
        bail!("vector {vector_name} inclusion list signer must be non-proposer");
    }
    require_str_eq(vector, "/inclusion_list/signer_id", signer, vector_name)?;
    if required_u64(vector, "/inclusion_list/expiry_seal_count", vector_name)? == 0 {
        bail!("vector {vector_name} inclusion list expiry must be positive");
    }
    let event_digests = string_set_at(vector, "/inclusion_list/event_digests", vector_name)?;
    if event_digests.is_empty() {
        bail!("vector {vector_name} inclusion list must carry event digests");
    }
    require_str_eq(
        vector,
        "/inclusion_list/signature/kind",
        "detached_jws",
        vector_name,
    )?;
    require_str_eq(
        vector,
        "/inclusion_list/signature/alg",
        "EdDSA",
        vector_name,
    )?;
    let payload_digest = required_pointer_str(
        vector,
        "/inclusion_list/signature/payload_digest",
        vector_name,
    )?;
    require_sha256_digest(
        payload_digest,
        "/inclusion_list/signature/payload_digest",
        vector_name,
    )?;

    let mut seen = BTreeSet::new();
    for case in required_array(vector, "/cases", vector_name)? {
        let case_name = required_pointer_str(case, "/name", vector_name)?;
        seen.insert(case_name.to_owned());
        match case_name {
            "next_seal_includes_digest" => {
                require_str_eq(case, "/seal_action", "include", vector_name)?;
                require_str_eq(case, "/expected/seal_result", "accept", vector_name)?;
            }
            "next_seal_signed_rejects_digest" => {
                require_str_eq(case, "/seal_action", "signed_reject", vector_name)?;
                require_str_eq(case, "/expected/seal_result", "accept", vector_name)?;
            }
            "next_seal_proves_pre_state_failure" => {
                require_str_eq(case, "/seal_action", "pre_state_failure_proof", vector_name)?;
                require_str_eq(case, "/expected/seal_result", "accept", vector_name)?;
            }
            "next_seal_omits_obligation" => {
                require_str_eq(case, "/seal_action", "omit", vector_name)?;
                require_str_eq(case, "/expected/seal_result", "reject", vector_name)?;
                require_str_eq(
                    case,
                    "/expected/reason",
                    "inclusion_list_violation",
                    vector_name,
                )?;
            }
            "same_signer_seq_different_contents" => {
                let conflicting = string_set_at(case, "/conflicting_event_digests", vector_name)?;
                if conflicting == event_digests {
                    bail!("vector {vector_name} inclusion-list conflict must change contents");
                }
                require_str_eq(
                    case,
                    "/expected/fault_evidence",
                    "equivocation",
                    vector_name,
                )?;
            }
            _ => bail!("vector {vector_name} unknown inclusion-list case {case_name}"),
        }
    }
    require_str_eq(
        vector,
        "/single_did_profile_expected",
        "unavailable",
        vector_name,
    )?;
    require_seen(
        vector_name,
        &seen,
        &[
            "next_seal_includes_digest",
            "next_seal_signed_rejects_digest",
            "next_seal_proves_pre_state_failure",
            "next_seal_omits_obligation",
            "same_signer_seq_different_contents",
        ],
    )
}

fn validate_notary_fault_equivocation_quarantine(vector: &Value, vector_name: &str) -> Result<()> {
    let signer = required_pointer_str(vector, "/fault_pair/signer_id", vector_name)?;
    let notary_seq = required_u64(vector, "/fault_pair/notary_seq", vector_name)?;
    let seal_a_id = required_pointer_str(vector, "/fault_pair/seal_a/id", vector_name)?;
    let seal_b_id = required_pointer_str(vector, "/fault_pair/seal_b/id", vector_name)?;
    if !seal_a_id.starts_with("ck:seal:sha256:") || !seal_b_id.starts_with("ck:seal:sha256:") {
        bail!("vector {vector_name} fault seals must use ck:seal:sha256 typed ids");
    }
    let seal_a_digest = required_pointer_str(
        vector,
        "/fault_pair/seal_a/canonical_body_digest",
        vector_name,
    )?;
    let seal_b_digest = required_pointer_str(
        vector,
        "/fault_pair/seal_b/canonical_body_digest",
        vector_name,
    )?;
    require_sha256_digest(
        seal_a_digest,
        "/fault_pair/seal_a/canonical_body_digest",
        vector_name,
    )?;
    require_sha256_digest(
        seal_b_digest,
        "/fault_pair/seal_b/canonical_body_digest",
        vector_name,
    )?;
    if seal_a_digest == seal_b_digest {
        bail!("vector {vector_name} equivocation seals must have different canonical bodies");
    }

    require_str_eq(
        vector,
        "/fault_move/event_kind",
        "ck.notary.fault.equivocation",
        vector_name,
    )?;
    let capability_refs =
        required_array(vector, "/fault_move/submitter_capability_refs", vector_name)?;
    if !capability_refs.is_empty() {
        bail!("vector {vector_name} public fault move must not require submitter capability refs");
    }
    require_str_eq(vector, "/fault_move/payload/signer_id", signer, vector_name)?;
    require_str_eq(vector, "/fault_move/payload/seal_a", seal_a_id, vector_name)?;
    require_str_eq(vector, "/fault_move/payload/seal_b", seal_b_id, vector_name)?;
    require_str_eq(vector, "/expected/fault_move_result", "accept", vector_name)?;
    require_bool_eq(
        vector,
        "/expected/authorized_by_signature_evidence",
        true,
        vector_name,
    )?;
    require_bool_eq(
        vector,
        "/expected/requires_submitter_capability",
        false,
        vector_name,
    )?;
    require_str_eq(
        vector,
        "/expected/fault_cell",
        "ck.component.notary_fault.v1",
        vector_name,
    )?;
    require_str_eq(
        vector,
        "/expected/later_seal_from_signer",
        "reject",
        vector_name,
    )?;
    require_str_eq(
        vector,
        "/expected/affected_branch_query_grade",
        "forked",
        vector_name,
    )?;
    require_str_eq(
        vector,
        "/expected/remaining_signer_policy",
        "continue_if_quorum_else_notary_paused",
        vector_name,
    )?;

    let invalid_signer =
        required_pointer_str(vector, "/invalid_parallel_leaf_case/signer_id", vector_name)?;
    let invalid_seq = required_u64(
        vector,
        "/invalid_parallel_leaf_case/notary_seq",
        vector_name,
    )?;
    if invalid_signer == signer && invalid_seq == notary_seq {
        bail!("vector {vector_name} invalid parallel leaf case must not reuse the fault slot");
    }
    require_str_eq(
        vector,
        "/invalid_parallel_leaf_case/expected/result",
        "failed_precondition",
        vector_name,
    )
}

fn validate_threshold_forensic_attribution(vector: &Value, vector_name: &str) -> Result<()> {
    let mut seen = BTreeSet::new();
    for case in required_array(vector, "/cases", vector_name)? {
        let case_name = required_pointer_str(case, "/name", vector_name)?;
        seen.insert(case_name.to_owned());
        require_str_eq(case, "/notary/type", "threshold", vector_name)?;
        let member_count = required_array(case, "/notary/members", vector_name)?.len() as u64;
        let threshold = required_u64(case, "/notary/threshold", vector_name)?;
        if threshold == 0 || threshold > member_count {
            bail!("vector {vector_name} threshold must be within member set");
        }
        let attribution = case
            .pointer("/notary/forensic_attribution")
            .and_then(Value::as_str);
        let derived_result = match attribution {
            None => "schema_violation",
            Some("quorum_intersection") if 2 * threshold > member_count => "accept",
            Some("waived") if 2 * threshold <= member_count => "accept",
            Some("quorum_intersection" | "waived") => "reject",
            Some(other) => {
                bail!("vector {vector_name} invalid forensic_attribution value {other}");
            }
        };
        let expected = required_pointer_str(case, "/expected/result", vector_name)?;
        if expected != derived_result {
            bail!(
                "vector {vector_name} case {case_name} expected {expected}, \
                 arithmetic derives {derived_result}"
            );
        }
        if derived_result == "reject" {
            require_str_eq(
                case,
                "/expected/reason",
                "forensic_attribution_mismatch",
                vector_name,
            )?;
        }
    }
    require_seen(
        vector_name,
        &seen,
        &[
            "n5_k3_quorum_intersection",
            "n5_k3_waived_reject",
            "n4_k2_quorum_intersection_reject",
            "threshold_missing_forensic_attribution",
        ],
    )
}

/// Vector `ck.vector.cba_lattice.open_set_concurrent_revocation_fail_closed.v1`.
///
/// A DataEvent with a locally valid `seal_ref` MUST be re-evaluated against the
/// joined multi-leaf control view of an open-set notary. When a concurrent
/// revocation branch is observed (capability no longer live, or the
/// authorization cell is bottom) the event MUST fail closed / be hidden rather
/// than trusting the lone seal_ref, and a light client that cannot verify the
/// joined view MUST NOT fan out or treat the seal_ref as sufficient.
fn validate_open_set_concurrent_revocation_fail_closed(
    vector: &Value,
    vector_name: &str,
) -> Result<()> {
    require_str_eq(vector, "/notary_profile", "open_set", vector_name)?;
    require_array_len_at_least(vector, "/joined_leaf_set", 2, vector_name)?;
    require_str_eq(vector, "/data_event/plane", "data", vector_name)?;

    let mut seen = BTreeSet::new();
    for case in required_array(vector, "/cases", vector_name)? {
        let case_name = required_pointer_str(case, "/name", vector_name)?;
        seen.insert(case_name.to_owned());
        match case_name {
            "concurrent_revoke_branch" => {
                require_bool_eq(
                    case,
                    "/joined_control_view/capability_grant_live",
                    false,
                    vector_name,
                )?;
                require_str_eq(
                    case,
                    "/expected/data_event_result",
                    "reject_or_hide",
                    vector_name,
                )?;
                require_str_eq(case, "/expected/reason", "stale_seal_ref", vector_name)?;
                require_bool_eq(
                    case,
                    "/expected/freshness_window_applies",
                    false,
                    vector_name,
                )?;
            }
            "authorization_cell_bottom" => {
                require_str_eq(
                    case,
                    "/joined_control_view/cell_status",
                    "bottom",
                    vector_name,
                )?;
                require_str_eq(
                    case,
                    "/expected/data_event_result",
                    "fail_closed",
                    vector_name,
                )?;
                require_str_eq(case, "/expected/reason", "stale_seal_ref", vector_name)?;
                require_bool_eq(
                    case,
                    "/expected/freshness_window_applies",
                    false,
                    vector_name,
                )?;
            }
            "light_client_without_joined_view" => {
                require_bool_eq(case, "/verifiable_joined_view", false, vector_name)?;
                require_str_eq(
                    case,
                    "/expected/data_event_result",
                    "pending_or_fail_closed",
                    vector_name,
                )?;
                require_bool_eq(case, "/expected/must_not_fanout", true, vector_name)?;
                require_bool_eq(
                    case,
                    "/expected/must_not_treat_seal_ref_as_sufficient",
                    true,
                    vector_name,
                )?;
            }
            other => {
                bail!("vector {vector_name} unknown concurrent revocation case {other}");
            }
        }
    }
    require_seen(
        vector_name,
        &seen,
        &[
            "concurrent_revoke_branch",
            "authorization_cell_bottom",
            "light_client_without_joined_view",
        ],
    )
}

/// Vector `ck.vector.cba_lattice.conflict_recovery_move.v1`.
///
/// A `bottom=reject` control cell that has gone to bottom-by-conflict recovers
/// ONLY through a sealed Control Move that carries a critical
/// `recovery_capability` ref and a critical `state_witness` ref taken from
/// before the conflict. Missing / post-conflict / unsealed witnesses, an
/// unsealed recovery capability, and a lagging revoke all fail precondition;
/// an unsealed recovery move stays `control_pending` and the cell remains
/// bottom.
fn validate_conflict_recovery_move(vector: &Value, vector_name: &str) -> Result<()> {
    require_str_eq(vector, "/bottom_state/status", "bottom", vector_name)?;
    require_str_eq(vector, "/bottom_state/reason", "conflict", vector_name)?;
    require_str_eq(vector, "/valid_recovery_move/plane", "control", vector_name)?;

    let refs = required_array(vector, "/valid_recovery_move/refs", vector_name)?;
    for required_role in ["recovery_capability", "state_witness"] {
        if !refs.iter().any(|reference| {
            reference.get("role").and_then(Value::as_str) == Some(required_role)
                && reference.get("critical").and_then(Value::as_bool) == Some(true)
        }) {
            bail!("vector {vector_name} valid_recovery_move missing critical {required_role} ref");
        }
    }

    let mut seen = BTreeSet::new();
    for case in required_array(vector, "/cases", vector_name)? {
        let case_name = required_pointer_str(case, "/name", vector_name)?;
        seen.insert(case_name.to_owned());
        match case_name {
            "valid_recovery" => {
                require_str_eq(
                    case,
                    "/expected/result",
                    "accept_after_valid_seal",
                    vector_name,
                )?;
                require_str_eq(case, "/expected/cell_status", "value", vector_name)?;
            }
            "missing_state_witness" => {
                require_str_eq(case, "/expected/result", "failed_precondition", vector_name)?;
                require_str_eq(
                    case,
                    "/expected/reason",
                    "recovery_witness_missing",
                    vector_name,
                )?;
            }
            "post_conflict_witness" => {
                require_str_eq(case, "/expected/result", "failed_precondition", vector_name)?;
                require_str_eq(
                    case,
                    "/expected/reason",
                    "recovery_witness_post_conflict",
                    vector_name,
                )?;
            }
            "recovery_capability_not_sealed" => {
                require_str_eq(case, "/expected/result", "failed_precondition", vector_name)?;
                require_str_eq(
                    case,
                    "/expected/reason",
                    "recovery_capability_not_sealed",
                    vector_name,
                )?;
            }
            "witness_revoke_lagging" => {
                require_str_eq(case, "/expected/result", "failed_precondition", vector_name)?;
                require_str_eq(
                    case,
                    "/expected/reason",
                    "recovery_witness_revoke_lagging",
                    vector_name,
                )?;
            }
            "unsealed_recovery_move" => {
                require_str_eq(case, "/expected/result", "control_pending", vector_name)?;
                require_str_eq(case, "/expected/cell_remains", "bottom", vector_name)?;
                require_str_eq(case, "/expected/query_result", "failed_bottom", vector_name)?;
            }
            other => bail!("vector {vector_name} unknown conflict recovery case {other}"),
        }
    }
    require_seen(
        vector_name,
        &seen,
        &[
            "valid_recovery",
            "missing_state_witness",
            "post_conflict_witness",
            "recovery_capability_not_sealed",
            "witness_revoke_lagging",
            "unsealed_recovery_move",
        ],
    )
}

fn union_digest_sets(mut left: BTreeSet<String>, right: BTreeSet<String>) -> BTreeSet<String> {
    left.extend(right);
    left
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

fn required_pointer_str<'a>(value: &'a Value, pointer: &str, vector_name: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("vector {vector_name} missing string at {pointer}"))
}

fn required_u64(value: &Value, pointer: &str, vector_name: &str) -> Result<u64> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("vector {vector_name} missing unsigned integer at {pointer}"))
}

fn string_vec_at<'a>(value: &'a Value, pointer: &str, vector_name: &str) -> Result<Vec<&'a str>> {
    required_array(value, pointer, vector_name)?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| anyhow!("vector {vector_name} entries at {pointer} must be strings"))
        })
        .collect()
}

fn string_set_at(value: &Value, pointer: &str, vector_name: &str) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for item in string_vec_at(value, pointer, vector_name)? {
        require_sha256_digest(item, pointer, vector_name)?;
        if !out.insert(item.to_owned()) {
            bail!("vector {vector_name} duplicate digest {item} at {pointer}");
        }
    }
    Ok(out)
}

fn require_sha256_digest(value: &str, pointer: &str, vector_name: &str) -> Result<()> {
    if !looks_like_sha256_digest(value) {
        bail!("vector {vector_name} value at {pointer} must be sha256:<64 lowercase hex>");
    }
    Ok(())
}

fn require_seen(vector_name: &str, seen: &BTreeSet<String>, required: &[&str]) -> Result<()> {
    let missing = required
        .iter()
        .filter(|name| !seen.contains::<str>(*name))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!(
            "vector {vector_name} missing required cases: {}",
            missing.join(", ")
        );
    }
    Ok(())
}

fn pointer_str(value: &Value, pointer: &str) -> Option<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn pointer_u64(value: &Value, pointer: &str) -> Option<u64> {
    value.pointer(pointer).and_then(Value::as_u64)
}

fn pointer_bool(value: &Value, pointer: &str) -> Option<bool> {
    value.pointer(pointer).and_then(Value::as_bool)
}

fn escape_pointer(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}
