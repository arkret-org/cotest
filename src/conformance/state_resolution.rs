//! CBA dual-plane lattice fixture suite.
//!
//! Validates the `cba-lattice-fixture.json` profile's normative vectors. Data
//! events use registry-derived projected writes plus `seal_ref + auth_context` and stay data-plane
//! local or observed until control-plane seals cover the relevant state. Control moves
//! use registry-derived projected writes plus `seal_basis`, may carry preconditions, and only
//! become sealed after valid seal coverage.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use arkret_wire::{Did, PayloadProof, Seal, project_did_to_core_id};
use serde_json::{Map, Value, json};

use super::{
    load_fixture_value, looks_like_sha256_digest, required_str, sha256_prefixed, validate_profile,
};
use crate::transcripts::record_vector_event;

const CONFLICT_RECOVERY_VECTOR_ID: &str = "ak.vector.cba_lattice.conflict_recovery_move.v1";

pub fn run_state_resolution_fixture_suite() -> Result<()> {
    run_cba_lattice_fixture_suite()
}

pub fn run_cba_lattice_fixture_suite() -> Result<()> {
    let value = load_fixture_value("cba-lattice-fixture.json")?;
    validate_profile(&value, "ak.vector_group.cba_lattice.v1")?;

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
    let mut seen_sealed_control_collision = false;
    let mut seen_threshold_forensics = false;
    let mut seen_concurrent_revocation = false;
    let mut seen_actor_chain_realm_scope = false;
    let mut seen_conflict_recovery = false;
    let mut seen_same_seal_bottom_serialization = false;
    let mut seen_realm_create_projection_closure = false;
    let mut seen_null_cell_subject_wire_form = false;
    let mut seen_realm_alias_single_carrier = false;
    let mut seen_fork_resolution_peer_alignment = false;
    let mut seen_vector_ids = BTreeSet::new();

    for vector in vectors {
        let name = required_str(vector, "name")?;
        let vector_id = required_str(vector, "vector_id")?;
        if !seen_vector_ids.insert(vector_id) {
            bail!("cba lattice fixture repeats vector_id {vector_id}");
        }
        match name {
            "data_event_accepts_without_seal_finality" => {
                require_str_eq(vector, "/event/plane", "data", name)?;
                require_non_empty_array(vector, "/event/projected_writes", name)?;
                require_field(required_object(vector, "/event", name)?, "seal_ref", name)?;
                require_field(
                    required_object(vector, "/event", name)?,
                    "auth_context",
                    name,
                )?;
                require_str_eq(vector, "/expected/event_state", "data_local", name)?;
                require_bool_eq(vector, "/expected/fanout_allowed", true, name)?;
                require_bool_eq(vector, "/expected/seal_required_for_accept", false, name)?;
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
                require_bool_eq(vector, "/expected/must_not_report_sealed", true, name)?;
                seen_observation = true;
                record_vector_event(
                    "state_resolution.cba.data_event_observation_does_not_seal",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "data_event_state": "data_observed",
                        "must_not_report_sealed": true,
                    }),
                    &json!({
                        "data_event_state": pointer_str(vector, "/expected/data_event_state"),
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
                require_non_empty_array(vector, "/control_move/projected_writes", name)?;
                require_str_eq(
                    vector,
                    "/expected_before_seal/event_state",
                    "control_pending",
                    name,
                )?;
                require_str_eq(
                    vector,
                    "/expected_after_valid_seal/event_state",
                    "control_sealed",
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
                        "single_signer_profile_expected": pointer_str(vector, "/single_signer_profile_expected"),
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
                        "branch_disposition": "fork_quarantine",
                    }),
                    &json!({
                        "fault_move_result": pointer_str(vector, "/expected/fault_move_result"),
                        "later_seal_from_signer": pointer_str(vector, "/expected/later_seal_from_signer"),
                        "branch_disposition": pointer_str(vector, "/expected/affected_branch_disposition"),
                    }),
                );
            }
            "sealed_control_move_full_digest_collision" => {
                validate_sealed_control_move_full_digest_collision(vector, name)?;
                seen_sealed_control_collision = true;
                record_vector_event(
                    "state_resolution.cba.sealed_control_move_full_digest_collision",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "quarantine_scope": "entire_collision_group",
                        "accepted_seal_commitments": "unchanged",
                        "digest_only_resolution": "reject",
                        "canonical_bytes_resolution": "accept_and_project_exact_scope",
                    }),
                    &json!({
                        "quarantine_group": vector.pointer("/expected/quarantine_group"),
                        "accepted_seal_commitments": pointer_str(vector, "/expected/accepted_seal_commitments"),
                        "resolution_case_count": required_array(vector, "/resolution_cases", name)?.len(),
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
                        "notary_kind": pointer_str(vector, "/notary_kind"),
                        "case_count": required_array(vector, "/cases", name)?.len(),
                    }),
                );
            }
            "actor_chain_realm_scope" => {
                validate_actor_chain_realm_scope(vector, name)?;
                seen_actor_chain_realm_scope = true;
                record_vector_event(
                    "state_resolution.cba.actor_chain_realm_scope",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "cross_realm_same_sequence": "independent",
                        "same_realm_siblings": "fork",
                        "cross_realm_predecessor": "reject",
                    }),
                    &json!({
                        "actor_id": pointer_str(vector, "/actor_id"),
                        "case_count": required_array(vector, "/cases", name)?.len(),
                    }),
                );
            }
            "conflict_recovery_move" => {
                if vector_id != CONFLICT_RECOVERY_VECTOR_ID {
                    bail!("vector {name} must use the canonical id {CONFLICT_RECOVERY_VECTOR_ID}");
                }
                validate_conflict_recovery_move(vector, name)?;
                seen_conflict_recovery = true;
                record_vector_event(
                    "state_resolution.cba.conflict_recovery_move",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "valid_recovery": "accept_after_valid_seal",
                        "unsealed_recovery": "control_pending",
                        "ordinary_mls_commit": "failed_bottom",
                    }),
                    &json!({
                        "cell": pointer_str(vector, "/cell"),
                        "case_count": required_array(vector, "/cases", name)?.len(),
                    }),
                );
            }
            "same_seal_bottom_reject_serialization" => {
                validate_same_seal_bottom_reject_serialization(vector, name)?;
                seen_same_seal_bottom_serialization = true;
                record_vector_event(
                    "state_resolution.cba.same_seal_bottom_reject_serialization",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "one_included_one_rejected": "accept_seal",
                        "both_in_same_seal": "rejected_seal",
                        "unreachable_leaves": "bottom_conflict",
                    }),
                    &json!({
                        "cell": pointer_str(vector, "/cell/id"),
                        "case_count": required_array(vector, "/cases", name)?.len(),
                    }),
                );
            }
            "realm_create_projection_closure" => {
                validate_realm_create_projection_closure(vector, name)?;
                seen_realm_create_projection_closure = true;
                record_vector_event(
                    "state_resolution.cba.realm_create_projection_closure",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "required_projection_count": 5,
                        "genesis_state_root": "byte_identical_across_independent_implementations",
                    }),
                    &json!({
                        "required_projection_count": required_array(vector, "/required_projected_writes", name)?.len(),
                        "genesis_state_root": pointer_str(vector, "/expected/genesis_state_root"),
                    }),
                );
            }
            "null_cell_subject_wire_form" => {
                validate_null_cell_subject_wire_form(vector, name)?;
                seen_null_cell_subject_wire_form = true;
                record_vector_event(
                    "state_resolution.cba.null_cell_subject_wire_form",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "wire_subject_segment": "null",
                        "state_root": "byte_identical_across_independent_implementations",
                    }),
                    &json!({
                        "wire_subject_segment": pointer_str(vector, "/expected/wire_subject_segment"),
                        "state_root": pointer_str(vector, "/expected/state_root"),
                    }),
                );
            }
            "realm_alias_single_carrier" => {
                validate_realm_alias_single_carrier(vector, name)?;
                seen_realm_alias_single_carrier = true;
                record_vector_event(
                    "state_resolution.cba.realm_alias_single_carrier",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "carrier_cell": "ak:cell:ak.component.realm.alias.v1:null",
                        "authorized_by": ["ak.realm.alias", "ak.realm.admin"],
                    }),
                    &json!({
                        "carrier_cell": pointer_str(vector, "/required_projected_writes/0/cell"),
                        "authorized_by": vector
                            .pointer("/expected/authorized_by")
                            .cloned()
                            .unwrap_or(Value::Null),
                    }),
                );
            }
            "fork_resolution_peer_alignment" => {
                validate_fork_resolution_peer_alignment(vector, name)?;
                seen_fork_resolution_peer_alignment = true;
                record_vector_event(
                    "state_resolution.cba.fork_resolution_peer_alignment",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "sibling_position_face": "ak.peer.events.read.sibling_positions.v1",
                        "collision_face": "ak.peer.events.read.resolve.v1",
                        "contradicting_disclosure": "peer_stale_retained_without_new_fork_evidence",
                    }),
                    &json!({
                        "sibling_position_face": pointer_str(
                            vector,
                            "/disclosure_faces/event_sibling_position",
                        ),
                        "collision_face": pointer_str(
                            vector,
                            "/disclosure_faces/event_id_collision",
                        ),
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
        && seen_sealed_control_collision
        && seen_threshold_forensics
        && seen_concurrent_revocation
        && seen_actor_chain_realm_scope
        && seen_conflict_recovery
        && seen_same_seal_bottom_serialization
        && seen_realm_create_projection_closure
        && seen_null_cell_subject_wire_form
        && seen_realm_alias_single_carrier
        && seen_fork_resolution_peer_alignment)
    {
        bail!(
            "cba lattice fixture must cover all 23 normative vectors \
             (data_local / observation / control_seal / same_batch / data_bottom / \
              delta_plane_guard / compaction / seal_canonical / cas_mixed_basis / \
              auth_epoch / compaction_interval / inclusion_list / notary_fault / sealed_control_collision / \
              threshold_forensics / concurrent_revocation / actor_chain_realm_scope / \
              conflict_recovery / same_seal_bottom_serialization / realm_create_projection_closure / \
              null_cell_subject_wire_form / realm_alias_single_carrier / \
              fork_resolution_peer_alignment)"
        );
    }

    Ok(())
}

/// `sync/federation.md` §4.5.3 second phase: local normalization alone never
/// clears `peer_stale`.
///
/// The two things this pins that a reader would otherwise get wrong: holding
/// the winner is *not* alignment, because the verdict's negative half has to
/// hold too; and a disclosure that contradicts the verdict keeps the peer stale
/// rather than becoming new fork evidence. An undisclosed position is a
/// fail-closed answer, not a peer failure.
fn validate_fork_resolution_peer_alignment(vector: &Value, vector_name: &str) -> Result<()> {
    require_str_eq(
        vector,
        "/disclosure_faces/event_sibling_position",
        "ak.peer.events.read.sibling_positions.v1",
        vector_name,
    )?;
    require_str_eq(
        vector,
        "/disclosure_faces/event_id_collision",
        "ak.peer.events.read.resolve.v1",
        vector_name,
    )?;
    require_str_eq(
        vector,
        "/subject/kind",
        "event_sibling_position",
        vector_name,
    )?;
    let cases = required_array(vector, "/cases", vector_name)?;
    let mut aligned = BTreeSet::new();
    let mut not_aligned = BTreeSet::new();
    for case in cases {
        let case_name = required_str(case, "name")?;
        let alignment = case
            .pointer("/expected/alignment")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                anyhow!("vector {vector_name} case {case_name} must declare expected.alignment")
            })?;
        match alignment {
            "aligned" => {
                if case.pointer("/expected/peer_stale").and_then(Value::as_str) != Some("cleared") {
                    bail!(
                        "vector {vector_name} case {case_name} aligns but does not clear peer_stale"
                    );
                }
                aligned.insert(case_name.to_owned());
            }
            "not_aligned" => {
                if case.pointer("/expected/peer_stale").and_then(Value::as_str) != Some("retained")
                {
                    bail!(
                        "vector {vector_name} case {case_name} does not align but drops peer_stale"
                    );
                }
                if case.pointer("/expected/fork_evidence").and_then(Value::as_str)
                    == Some("witness_disagreement")
                {
                    bail!(
                        "vector {vector_name} case {case_name} must not turn a contradicting \
                         disclosure into fork evidence"
                    );
                }
                not_aligned.insert(case_name.to_owned());
            }
            other => bail!(
                "vector {vector_name} case {case_name} declares unknown alignment {other}"
            ),
        }
    }
    for required in [
        "winner_single_element_aligns",
        "void_all_empty_set_aligns",
        "collision_subject_aligns_on_exact_point_resolve",
    ] {
        if !aligned.contains(required) {
            bail!("vector {vector_name} must cover the aligning case {required}");
        }
    }
    for required in [
        "extra_sibling_does_not_align",
        "missing_winner_does_not_align",
        "undisclosed_position_does_not_align",
        "actor_wide_scan_page_is_not_an_alignment_face",
        "another_peer_alignment_does_not_clear_this_peer",
    ] {
        if !not_aligned.contains(required) {
            bail!("vector {vector_name} must cover the non-aligning case {required}");
        }
    }
    Ok(())
}

fn validate_sealed_control_move_full_digest_collision(
    vector: &Value,
    vector_name: &str,
) -> Result<()> {
    let event_id = required_pointer_str(vector, "/colliding_identity/event_id", vector_name)?;
    let event_id = arkret_wire::EventId::new(event_id.to_owned())
        .map_err(|error| anyhow!("vector {vector_name} collision event_id is invalid: {error}"))?;
    require_str_eq(
        vector,
        "/colliding_identity/digest_suite",
        "sha256",
        vector_name,
    )?;
    if event_id.identity_key().suite().as_str() != "sha256" {
        bail!("vector {vector_name} collision event_id must carry the sha256 suite code");
    }
    require_str_eq(
        vector,
        "/sealed_state/seal_covered_variant",
        "variant_a",
        vector_name,
    )?;
    require_str_eq(
        vector,
        "/sealed_state/materialized_reducer_output_from",
        "variant_a_canonical_bytes",
        vector_name,
    )?;

    let quarantine_group = string_vec_at(vector, "/expected/quarantine_group", vector_name)?
        .into_iter()
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    if quarantine_group.len()
        != required_array(vector, "/expected/quarantine_group", vector_name)?.len()
    {
        bail!("vector {vector_name} collision quarantine group contains duplicates");
    }
    let required_group = BTreeSet::from([
        "variant_a".to_owned(),
        "variant_b".to_owned(),
        "event_derived_objects_of_either_variant".to_owned(),
        "non_final_writes_of_either_variant".to_owned(),
        "successors_referencing_the_event_id".to_owned(),
    ]);
    if quarantine_group != required_group {
        bail!("vector {vector_name} must quarantine the entire collision group");
    }
    for (path, expected) in [
        (
            "/expected/subsequent_control_moves_for_actor",
            "fail_closed",
        ),
        ("/expected/accepted_seal_commitments", "unchanged"),
        ("/expected/recompute_sealed_state_root", "forbidden"),
        (
            "/expected/receiver_without_retained_canonical_bytes",
            "range_unverifiable_fail_closed",
        ),
        ("/expected/compaction_across_unresolved_range", "forbidden"),
    ] {
        require_str_eq(vector, path, expected, vector_name)?;
    }

    let mut cases = std::collections::BTreeMap::new();
    for case in required_array(vector, "/resolution_cases", vector_name)? {
        let name = required_str(case, "name")?;
        if cases.insert(name, case).is_some() {
            bail!("vector {vector_name} repeats resolution case {name}");
        }
    }
    // Every accepted resolution projects its exact scope and nothing wider, so
    // one accept spelling covers the whole family. Anything not listed here is
    // an unreviewed case rather than a passing one.
    let expectations: &[(&str, &str, Option<&str>)] = &[
        (
            "resolution_names_winner_by_digest_only",
            "reject",
            Some(arkret_wire::ReasonCode::WITNESS_DISAGREEMENT),
        ),
        (
            "resolution_names_winner_by_canonical_bytes",
            "accept_and_project_exact_scope",
            None,
        ),
        (
            "resolution_names_winner_by_variant_record_reference",
            "accept_and_project_exact_scope",
            None,
        ),
        (
            "resolution_collision_missing_variant_record_is_dependency_missing",
            "reject",
            Some(arkret_wire::ErrorCode::DEPENDENCY_MISSING),
        ),
        (
            "resolution_voids_complete_sibling_position",
            "accept_and_project_exact_scope",
            None,
        ),
        (
            "resolution_cross_bucket_overflow_uses_sixty_five_siblings",
            "accept_and_project_exact_scope",
            None,
        ),
        (
            "resolution_bucket_overflow_below_minimal_evidence_rejected",
            "reject",
            Some(arkret_wire::ErrorCode::SCHEMA_VIOLATION),
        ),
        (
            "resolution_domain_non_joinable_reruns_registered_cell_family",
            "accept_and_project_exact_scope",
            None,
        ),
        (
            "resolution_winner_outside_evidence_set_rejected",
            "reject",
            Some(arkret_wire::ErrorCode::FAILED_PRECONDITION),
        ),
        (
            "resolution_subject_carrying_bucket_digest_rejected",
            "reject",
            Some(arkret_wire::ErrorCode::SCHEMA_VIOLATION),
        ),
        (
            "resolution_scope_mismatch_does_not_clear",
            "accepted_cell_but_no_peer_state_transition",
            None,
        ),
        (
            "resolution_without_peer_alignment_does_not_clear_peer",
            "accepted_cell_but_no_peer_state_transition",
            None,
        ),
        (
            "resolution_missing_recovery_capability",
            "reject",
            Some(arkret_wire::ReasonCode::RECOVERY_CAPABILITY_NOT_SEALED),
        ),
        (
            "resolution_state_witness_role_rejected",
            "reject",
            Some(arkret_wire::ErrorCode::SCHEMA_VIOLATION),
        ),
        (
            "witness_disagreement_single_source_does_not_clear",
            "retain_confirmed_evidence",
            None,
        ),
        (
            "witness_disagreement_quorum_reagreement_does_not_clear",
            "retain_confirmed_evidence",
            None,
        ),
        (
            "cross_suite_discriminator_is_diagnostic_only",
            "reject",
            Some(arkret_wire::ReasonCode::WITNESS_DISAGREEMENT),
        ),
        (
            "resolution_near_one_mib_collision_requires_variant_record",
            "reject",
            Some(arkret_wire::ErrorCode::PAYLOAD_TOO_LARGE),
        ),
        (
            "resolution_near_one_mib_collision_accepts_variant_record",
            "accept_and_project_exact_scope",
            None,
        ),
        (
            "resolution_variant_record_digest_mismatch_rejected",
            "reject",
            Some(arkret_wire::ErrorCode::DIGEST_MISMATCH),
        ),
        (
            "resolution_variant_record_size_mismatch_rejected",
            "reject",
            Some(arkret_wire::ErrorCode::SCHEMA_VIOLATION),
        ),
        (
            "resolution_variant_record_foreign_realm_rejected",
            "reject",
            Some(arkret_wire::ErrorCode::SCHEMA_VIOLATION),
        ),
        (
            "resolution_variant_record_proof_controller_mismatch_rejected",
            "reject",
            Some(arkret_wire::ErrorCode::SCHEMA_VIOLATION),
        ),
        (
            "resolution_variant_record_event_id_recompute_mismatch_rejected",
            "reject",
            Some(arkret_wire::ReasonCode::EVENT_ID_DIGEST_MISMATCH),
        ),
        (
            "resolution_cross_realm_winner_outside_event_realm_rejected",
            "reject",
            Some(arkret_wire::ErrorCode::SCHEMA_VIOLATION),
        ),
        (
            "resolution_cross_realm_verdict_does_not_govern_other_realm",
            "accept_and_project_exact_scope",
            None,
        ),
        (
            "resolution_peer_alignment_clears_only_exact_evidence_key",
            "clear_exact_evidence_scope",
            None,
        ),
        (
            "resolution_peer_alignment_mismatch_keeps_peer_stale",
            "retain_confirmed_evidence",
            None,
        ),
        (
            "resolution_cell_bottom_refails_closed_after_clear",
            "requarantine_peer",
            None,
        ),
        (
            "recovery_seal_covering_only_fork_resolution_accepted",
            "accept_and_project_exact_scope",
            None,
        ),
        (
            "recovery_seal_mixing_an_ordinary_move_rejected",
            "reject",
            Some(arkret_wire::ErrorCode::SEAL_SIGNER_UNAUTHORIZED),
        ),
    ];
    for (name, expected, reason) in expectations {
        let case = cases
            .get(name)
            .ok_or_else(|| anyhow!("vector {vector_name} missing resolution case {name}"))?;
        require_str_eq(case, "/expected", expected, vector_name)?;
        match reason {
            Some(reason) => require_str_eq(case, "/reason_code", reason, vector_name)?,
            None if case.get("reason_code").is_some() => {
                bail!("vector {vector_name} case {name} accepts but carries a rejection reason")
            }
            None => {}
        }
    }
    let reviewed = expectations
        .iter()
        .map(|(name, ..)| *name)
        .chain(["resolution_idempotent_replay"])
        .collect::<BTreeSet<_>>();
    for name in cases.keys() {
        if !reviewed.contains(name) {
            bail!("vector {vector_name} carries unreviewed resolution case {name}");
        }
    }

    for (name, discriminator) in [
        ("resolution_names_winner_by_digest_only", "event_digest"),
        (
            "resolution_names_winner_by_canonical_bytes",
            "canonical_bytes",
        ),
        (
            "cross_suite_discriminator_is_diagnostic_only",
            "blake3_digest_of_same_preimage",
        ),
    ] {
        require_str_eq(
            cases[name],
            "/fork_resolution_identifies_winner_by",
            discriminator,
            vector_name,
        )?;
    }

    // A collision has no digest-only identity. The evidence carries both
    // complete canonical-byte locators and the verdict selects one by index,
    // avoiding a third copy of the winning preimage.
    let canonical_case = cases["resolution_names_winner_by_canonical_bytes"];
    require_str_eq(
        canonical_case,
        "/payload/subject/kind",
        "event_id_collision",
        vector_name,
    )?;
    require_str_eq(
        canonical_case,
        "/payload/conflict_evidence/kind",
        "full_hash_collision",
        vector_name,
    )?;
    let variants = required_array(
        canonical_case,
        "/payload/conflict_evidence/variants",
        vector_name,
    )?;
    if variants.len() != 2 {
        bail!("vector {vector_name} collision evidence must carry exactly two variants");
    }
    require_str_eq(
        canonical_case,
        "/payload/verdict/kind",
        "canonical_winner",
        vector_name,
    )?;
    let winner_index = canonical_case
        .pointer("/payload/verdict/winner_index")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("vector {vector_name} collision winner must carry winner_index"))?;
    if winner_index >= variants.len() as u64 {
        bail!("vector {vector_name} collision winner_index is outside its own evidence variants");
    }

    // The reference arm exists because two preimages near the 1 MiB ceiling
    // cannot both be inlined into a resolution Event bounded by the same limit.
    let record_case = cases["resolution_names_winner_by_variant_record_reference"];
    require_u64_eq(record_case, "/payload/verdict/winner_index", 0, vector_name)?;
    require_str_eq(
        record_case,
        "/payload/conflict_evidence/variants/0/kind",
        "collision_variant_record",
        vector_name,
    )?;
    require_str_eq(
        cases["resolution_near_one_mib_collision_requires_variant_record"],
        "/locator_kind",
        "inline_canonical_bytes",
        vector_name,
    )?;
    require_str_eq(
        cases["resolution_near_one_mib_collision_accepts_variant_record"],
        "/locator_kind",
        "collision_variant_record",
        vector_name,
    )?;

    // 17 and 65 are the bounded minimal proofs that the v1 single-bucket and
    // cumulative ceilings were passed. Both land on one position cell, so a
    // bucket-scoped and a cross-bucket verdict can never disagree.
    let void_case = cases["resolution_voids_complete_sibling_position"];
    require_str_eq(
        void_case,
        "/payload/subject/kind",
        "event_sibling_position",
        vector_name,
    )?;
    if void_case
        .pointer("/payload/subject/prev_frontier_digest")
        .is_some()
    {
        bail!("vector {vector_name} position subject must not carry a bucket digest");
    }
    require_str_eq(
        void_case,
        "/payload/conflict_evidence/kind",
        "bucket_overflow",
        vector_name,
    )?;
    require_array_len(
        void_case,
        "/payload/conflict_evidence/event_ids",
        17,
        vector_name,
    )?;
    require_str_eq(void_case, "/payload/verdict/kind", "void_all", vector_name)?;
    let cross_bucket = cases["resolution_cross_bucket_overflow_uses_sixty_five_siblings"];
    require_array_len(
        cross_bucket,
        "/payload/conflict_evidence/event_ids",
        65,
        vector_name,
    )?;
    require_str_eq(
        cross_bucket,
        "/expected_cell_subject_equals_case",
        "resolution_voids_complete_sibling_position",
        vector_name,
    )?;
    if void_case.pointer("/payload/subject") != cross_bucket.pointer("/payload/subject") {
        bail!(
            "vector {vector_name} single-bucket and cross-bucket overflow must share one cell subject"
        );
    }
    require_array_len(
        cases["resolution_bucket_overflow_below_minimal_evidence_rejected"],
        "/payload/conflict_evidence/event_ids",
        16,
        vector_name,
    )?;

    // A domain conflict is re-derived from the registered family's own lattice;
    // there is no conflict-rule registry to trust instead.
    let domain_case = cases["resolution_domain_non_joinable_reruns_registered_cell_family"];
    let family = required_pointer_str(
        domain_case,
        "/payload/conflict_evidence/cell_family",
        vector_name,
    )?;
    if !family.starts_with("ak.component.") {
        bail!("vector {vector_name} domain conflict must name a registered cell family");
    }

    // Exactly one critical recovery capability, and never a state_witness: the
    // fork-resolution cell is `__unset__` before its first write, so the role
    // that attests a pre-Bottom value has no referent here.
    for name in [
        "resolution_voids_complete_sibling_position",
        "resolution_cross_bucket_overflow_uses_sixty_five_siblings",
        "resolution_domain_non_joinable_reruns_registered_cell_family",
        "resolution_names_winner_by_variant_record_reference",
    ] {
        let roles = string_vec_at(cases[name], "/critical_ref_roles", vector_name)?
            .into_iter()
            .collect::<Vec<_>>();
        if roles
            .iter()
            .filter(|role| **role == "recovery_capability")
            .count()
            != 1
        {
            bail!("vector {vector_name} case {name} must bind exactly one recovery capability");
        }
        if roles.contains(&"state_witness") {
            bail!("vector {vector_name} case {name} must not carry a state_witness role");
        }
    }
    if !string_vec_at(
        cases["resolution_state_witness_role_rejected"],
        "/critical_ref_roles",
        vector_name,
    )?
    .contains(&"state_witness")
    {
        bail!("vector {vector_name} state_witness negative must actually carry the role");
    }

    // Two phases that must not be merged: an accepted resolution normalizes
    // local state, and only that peer's own exact-scope alignment clears it.
    if cases["resolution_without_peer_alignment_does_not_clear_peer"]
        .pointer("/peer_exact_scope_challenge_completed")
        != Some(&Value::Bool(false))
    {
        bail!("vector {vector_name} unaligned case must leave the peer challenge incomplete");
    }
    let aligned = cases["resolution_peer_alignment_clears_only_exact_evidence_key"];
    for path in [
        "/peer_exact_scope_challenge_completed",
        "/peer_sibling_set_equals_verdict",
    ] {
        if aligned.pointer(path) != Some(&Value::Bool(true)) {
            bail!("vector {vector_name} alignment case must complete a matching challenge");
        }
    }
    for path in [
        "/other_peer_confirmed_evidence",
        "/other_subject_confirmed_evidence",
    ] {
        require_str_eq(aligned, path, "retained", vector_name)?;
    }
    require_str_eq(
        aligned,
        "/ordinary_failure_window",
        "unchanged",
        vector_name,
    )?;
    if cases["resolution_peer_alignment_mismatch_keeps_peer_stale"]
        .pointer("/peer_sibling_set_equals_verdict")
        != Some(&Value::Bool(false))
    {
        bail!("vector {vector_name} alignment mismatch must not match the verdict");
    }
    require_str_eq(
        cases["resolution_cell_bottom_refails_closed_after_clear"],
        "/resolution_cell_status_after_clear",
        "bottom",
        vector_name,
    )?;

    // The step 2b recovery exception is per Seal: a recovery signer must not
    // attach an ordinary Control Move to a fork-resolution Seal.
    for (name, expect_fork_only) in [
        ("recovery_seal_covering_only_fork_resolution_accepted", true),
        ("recovery_seal_mixing_an_ordinary_move_rejected", false),
    ] {
        let case = cases[name];
        require_str_eq(
            case,
            "/seal_signer_descriptor",
            "recovery_members",
            vector_name,
        )?;
        let kinds = string_vec_at(case, "/seal_delta_kinds", vector_name)?;
        if kinds.len() < 2 {
            bail!("vector {vector_name} case {name} must cover more than one delta item");
        }
        let fork_only = kinds.iter().all(|kind| *kind == "ak.fork.resolution");
        if fork_only != expect_fork_only {
            bail!("vector {vector_name} case {name} delta does not match its own claim");
        }
    }

    // One Realm's verdict never rewrites another Realm's projection.
    require_str_eq(
        cases["resolution_cross_realm_winner_outside_event_realm_rejected"],
        "/winner_variant_realm_relation",
        "other_realm",
        vector_name,
    )?;
    require_str_eq(
        cases["resolution_cross_realm_verdict_does_not_govern_other_realm"],
        "/other_realm_projection",
        "unchanged_and_still_quarantined",
        vector_name,
    )?;

    // Replaying one accepted Event is idempotent rather than a second write.
    let replay = cases["resolution_idempotent_replay"];
    if required_u64(replay, "/replay_count", vector_name)? < 2
        || required_u64(replay, "/expected_store_transitions", vector_name)? != 1
    {
        bail!("vector {vector_name} replay case must prove one transition for repeated delivery");
    }
    Ok(())
}

fn validate_null_cell_subject_wire_form(vector: &Value, vector_name: &str) -> Result<()> {
    require_str_eq(
        vector,
        "/expected/wire_subject_segment",
        "null",
        vector_name,
    )?;
    for path in ["/expected/leaf_sequence", "/expected/state_root"] {
        require_str_eq(
            vector,
            path,
            "byte_identical_across_independent_implementations",
            vector_name,
        )?;
    }

    let negatives = required_array(vector, "/negative_cases", vector_name)?;
    let mut negative_names = BTreeSet::new();
    for case in negatives {
        let name = required_str(case, "name")?;
        if !negative_names.insert(name) {
            bail!("vector {vector_name} repeats negative case {name}");
        }
        let family = required_str(case, "cell_family")?;
        if !family.starts_with("ak.component.") {
            bail!("vector {vector_name} negative case {name} has invalid cell family");
        }
        if required_str(case, "bad_subject_segment")? == "null" {
            bail!("vector {vector_name} negative case {name} is not a malformed subject");
        }
        if required_str(case, "expected")? != "schema_violation" {
            bail!("vector {vector_name} negative case {name} must be a schema violation");
        }
    }
    let expected_names = BTreeSet::from([
        "realm_id_encoded_into_subject",
        "realm_role_classification_encoded_into_subject",
        "empty_trailing_segment",
    ]);
    if negative_names != expected_names {
        bail!("vector {vector_name} null-subject negative coverage drifted");
    }

    Ok(())
}

/// A Realm alias has exactly one wire carrier: `ak.realm.alias` setting the
/// `cas_register` cell `ak.component.realm.alias.v1:null`
/// (object-addressing.md §3.3). The closed Realm object, the create/update
/// payloads and every other input shape MUST be rejected, and concurrent
/// distinct declarations MUST reach `⊥` rather than picking a winner.
fn validate_realm_alias_single_carrier(vector: &Value, vector_name: &str) -> Result<()> {
    let projected_writes = required_array(vector, "/required_projected_writes", vector_name)?;
    if projected_writes.len() != 1 {
        bail!("vector {vector_name} must define exactly one realm-alias projected write");
    }
    let write = &projected_writes[0];
    if required_str(write, "cell")? != "ak:cell:ak.component.realm.alias.v1:null" {
        bail!("vector {vector_name} must project the null-subject realm alias cell");
    }
    if required_str(write, "op_kind")? != "set" {
        bail!("vector {vector_name} realm alias projection must be a cas_register set");
    }
    require_str_eq(
        vector,
        "/expected/declaration_payload/alias",
        "general:acme.example",
        vector_name,
    )?;
    let authorized_by = vector
        .pointer("/expected/authorized_by")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("vector {vector_name} must declare expected.authorized_by[]"))?;
    for action in ["ak.realm.alias", "ak.realm.admin"] {
        if !authorized_by
            .iter()
            .any(|value| value.as_str() == Some(action))
        {
            bail!("vector {vector_name} must authorize the alias write through {action}");
        }
    }

    let negatives = required_array(vector, "/negative_cases", vector_name)?;
    let mut by_name = std::collections::BTreeMap::new();
    for negative in negatives {
        by_name.insert(required_str(negative, "name")?, negative);
    }
    // Every forbidden alias input shape and every namespace / concurrency rule
    // MUST stay covered; dropping one is how a second carrier creeps back in.
    for (name, expected_fragment) in [
        ("alias_on_realm_object", "schema_violation"),
        ("alias_in_realm_profile", "schema_violation"),
        ("alias_at_payload_top_level", "schema_violation"),
        ("foreign_authority_domain", "realm_alias_authority_mismatch"),
        ("alias_held_by_another_realm", "realm_alias_taken"),
        ("same_string_occupied_in_handle_namespace", "accepted"),
        ("concurrent_distinct_alias_declarations", "bottom_conflict"),
        (
            "alias_in_principal_control_realm",
            "principal_control_event_kind_forbidden",
        ),
    ] {
        let negative = by_name
            .get(name)
            .ok_or_else(|| anyhow!("vector {vector_name} missing negative case {name}"))?;
        let expected = required_str(negative, "expected")?;
        if !expected.contains(expected_fragment) {
            bail!(
                "vector {vector_name} negative case {name} must expect {expected_fragment}, got {expected}"
            );
        }
    }
    Ok(())
}

fn validate_realm_create_projection_closure(vector: &Value, vector_name: &str) -> Result<()> {
    let projected_writes = required_array(vector, "/required_projected_writes", vector_name)?;
    if projected_writes.len() != 5 {
        bail!("vector {vector_name} must define exactly five realm-create projected writes");
    }

    let mut effect_kinds = std::collections::BTreeMap::new();
    for write in projected_writes {
        let cell = required_str(write, "cell")?;
        let op_kind = required_str(write, "op_kind")?;
        if effect_kinds.insert(cell, op_kind).is_some() {
            bail!("vector {vector_name} repeats realm-create projected cell {cell}");
        }
    }
    for (cell, op_kind) in [
        ("ak:cell:ak.component.realm.genesis.v1:null", "set"),
        ("ak:cell:ak.component.realm.create.v1:null", "append"),
        ("ak:cell:ak.component.notary.v1:null", "set"),
        ("ak:cell:ak.component.realm.reducer_profile.v1:null", "set"),
        ("ak:cell:ak.component.realm.authority_root.v1:null", "set"),
    ] {
        if effect_kinds.get(cell) != Some(&op_kind) {
            bail!("vector {vector_name} must bind realm-create cell {cell} to op_kind={op_kind}");
        }
    }
    let create_effect = projected_writes
        .iter()
        .find(|effect| {
            effect.get("cell").and_then(Value::as_str)
                == Some("ak:cell:ak.component.realm.create.v1:null")
        })
        .expect("realm-create effect checked above");
    if required_u64(create_effect, "/issuer_seq", vector_name)? != 0 {
        bail!("vector {vector_name} realm-create ordered-log issuer_seq must be zero");
    }

    require_str_eq(
        vector,
        "/expected/genesis_state_root",
        "byte_identical_across_independent_implementations",
        vector_name,
    )?;
    require_str_eq(
        vector,
        "/expected/creator_member_cell_proof",
        "inclusion from the explicit final ak.member.state bootstrap facet",
        vector_name,
    )?;
    require_bool_eq(
        vector,
        "/expected/realm_genesis_and_profile_cells_present_in_genesis_leaf_set",
        true,
        vector_name,
    )?;
    let branches: BTreeSet<&str> =
        required_array(vector, "/expected/branches_covered", vector_name)?
            .iter()
            .filter_map(Value::as_str)
            .collect();
    let expected_branches =
        BTreeSet::from(["collaboration", "principal_control", "direct_conversation"]);
    if branches != expected_branches {
        bail!("vector {vector_name} realm-create branch coverage drifted");
    }

    let negative_names: BTreeSet<&str> = required_array(vector, "/negative_cases", vector_name)?
        .iter()
        .map(|case| required_str(case, "name"))
        .collect::<Result<_>>()?;
    let expected_negative_names = BTreeSet::from([
        "implicit_member_state_projection",
        "creator_non_membership_proof",
        "profile_cell_after_bootstrap",
        "extra_unregistered_projection",
    ]);
    if negative_names != expected_negative_names {
        bail!("vector {vector_name} realm-create negative coverage drifted");
    }

    Ok(())
}

fn validate_same_seal_bottom_reject_serialization(vector: &Value, vector_name: &str) -> Result<()> {
    require_str_eq(vector, "/cell/lattice", "cas_register", vector_name)?;
    require_str_eq(vector, "/cell/bottom", "reject", vector_name)?;
    let frozen_revision = required_u64(
        vector,
        "/cell/frozen_predecessor_value/revision",
        vector_name,
    )?;
    let moves = required_array(vector, "/moves", vector_name)?;
    if moves.len() != 2 {
        bail!("vector {vector_name} must define exactly two competing moves");
    }
    let mut move_ids = BTreeSet::new();
    let mut revisions = BTreeSet::new();
    for movement in moves {
        let id = required_pointer_str(movement, "/id", vector_name)?;
        if !move_ids.insert(id.to_owned())
            || required_u64(movement, "/precondition/head_eq", vector_name)? != frozen_revision
            || !revisions.insert(required_u64(movement, "/set/revision", vector_name)?)
        {
            bail!("vector {vector_name} competing move definitions drifted");
        }
    }

    let mut seen = BTreeSet::new();
    for case in required_array(vector, "/cases", vector_name)? {
        let case_name = required_pointer_str(case, "/name", vector_name)?;
        seen.insert(case_name.to_owned());
        match case_name {
            "one_included_one_rejected" => {
                let included = string_vec_at(case, "/same_seal_included", vector_name)?
                    .into_iter()
                    .map(ToOwned::to_owned)
                    .collect::<BTreeSet<_>>();
                let rejected = required_array(case, "/signed_rejected", vector_name)?;
                if included.len() != 1
                    || rejected.len() != 1
                    || !move_ids.contains(required_pointer_str(&rejected[0], "/id", vector_name)?)
                    || included.contains(required_pointer_str(&rejected[0], "/id", vector_name)?)
                {
                    bail!("vector {vector_name} serialized acceptance inputs drifted");
                }
                require_str_eq(&rejected[0], "/reason_code", "cas_conflict", vector_name)?;
                require_str_eq(case, "/expected", "accept_seal", vector_name)?;
            }
            "both_in_same_seal" => {
                let included = string_vec_at(case, "/same_seal_included", vector_name)?
                    .into_iter()
                    .map(ToOwned::to_owned)
                    .collect::<BTreeSet<_>>();
                if included != move_ids {
                    bail!("vector {vector_name} invalid same-Seal case must include both moves");
                }
                require_str_eq(case, "/expected", "rejected_seal", vector_name)?;
            }
            "moves_on_unreachable_seal_leaves" => {
                let leaves = required_array(case, "/unreachable_leaf_included", vector_name)?;
                let leaf_moves = leaves
                    .iter()
                    .flat_map(|leaf| leaf.as_array().into_iter().flatten())
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect::<BTreeSet<_>>();
                if leaves.len() != 2 || leaf_moves != move_ids {
                    bail!("vector {vector_name} unreachable leaf inputs drifted");
                }
                require_str_eq(case, "/expected", "bottom_conflict", vector_name)?;
            }
            _ => bail!("vector {vector_name} unknown same-Seal serialization case {case_name}"),
        }
    }
    require_seen(
        vector_name,
        &seen,
        &[
            "one_included_one_rejected",
            "both_in_same_seal",
            "moves_on_unreachable_seal_leaves",
        ],
    )
}

fn validate_actor_chain_realm_scope(vector: &Value, vector_name: &str) -> Result<()> {
    super::value_field_actor(vector, "actor_id")?.validate()?;

    let mut seen = BTreeSet::new();
    for case in required_array(vector, "/cases", vector_name)? {
        let case_name = required_pointer_str(case, "/name", vector_name)?;
        seen.insert(case_name.to_owned());
        match case_name {
            "same_actor_and_seq_across_realms" => {
                let events = required_array(case, "/events", vector_name)?;
                if events.len() != 2 {
                    bail!("vector {vector_name} cross-Realm sequence case needs two Events");
                }
                let left_realm = required_pointer_str(&events[0], "/realm_id", vector_name)?;
                let right_realm = required_pointer_str(&events[1], "/realm_id", vector_name)?;
                if left_realm == right_realm
                    || required_u64(&events[0], "/actor_seq", vector_name)?
                        != required_u64(&events[1], "/actor_seq", vector_name)?
                    || required_pointer_str(&events[0], "/event_digest", vector_name)?
                        == required_pointer_str(&events[1], "/event_digest", vector_name)?
                {
                    bail!("vector {vector_name} cross-Realm sequence inputs drifted");
                }
                require_bool_eq(case, "/expected/sibling_fork", false, vector_name)?;
                require_bool_eq(
                    case,
                    "/expected/sequence_counters_are_independent",
                    true,
                    vector_name,
                )?;
            }
            "same_actor_and_seq_in_one_realm" => {
                let events = required_array(case, "/events", vector_name)?;
                if events.len() != 2
                    || required_pointer_str(&events[0], "/realm_id", vector_name)?
                        != required_pointer_str(&events[1], "/realm_id", vector_name)?
                    || required_u64(&events[0], "/actor_seq", vector_name)?
                        != required_u64(&events[1], "/actor_seq", vector_name)?
                    || events[0].pointer("/prev_refs") != events[1].pointer("/prev_refs")
                    || required_pointer_str(&events[0], "/event_digest", vector_name)?
                        == required_pointer_str(&events[1], "/event_digest", vector_name)?
                {
                    bail!("vector {vector_name} same-Realm sibling inputs drifted");
                }
                require_bool_eq(case, "/expected/sibling_fork", true, vector_name)?;
                if case.pointer("/expected/bucket_key")
                    != Some(&json!([
                        "realm_id",
                        "actor_id",
                        "actor_seq",
                        "prev_refs_digest"
                    ]))
                {
                    bail!("vector {vector_name} sibling bucket key drifted");
                }
            }
            "realm_bootstrap_transaction_chain" => {
                let events = required_array(case, "/events", vector_name)?;
                let expected_kinds = [
                    "ak.realm.create",
                    "ak.realm.profile",
                    "ak.realm.policy_bundle",
                    "ak.realm.join_rule",
                    "ak.realm.history_access",
                    "ak.realm.discovery",
                    "ak.member.state",
                ];
                if events.len() != expected_kinds.len() {
                    bail!("vector {vector_name} Realm bootstrap chain cardinality drifted");
                }
                let realm_id = required_pointer_str(&events[0], "/realm_id", vector_name)?;
                for (index, (event, expected_kind)) in events.iter().zip(expected_kinds).enumerate()
                {
                    let expected_prev = if index == 0 {
                        json!([])
                    } else {
                        json!([required_pointer_str(
                            &events[index - 1],
                            "/event_id",
                            vector_name,
                        )?])
                    };
                    if required_pointer_str(event, "/kind", vector_name)? != expected_kind
                        || required_u64(event, "/actor_seq", vector_name)? != index as u64
                        || event.pointer("/prev_refs") != Some(&expected_prev)
                        || required_pointer_str(event, "/realm_id", vector_name)? != realm_id
                    {
                        bail!("vector {vector_name} Realm bootstrap actor chain drifted");
                    }
                }
                require_str_eq(case, "/expected/result", "accept", vector_name)?;
                require_str_eq(
                    case,
                    "/expected/authoring_sequence",
                    "genesis_then_same_transaction",
                    vector_name,
                )?;
            }
            "cross_realm_predecessor" => {
                if required_pointer_str(case, "/event_realm_id", vector_name)?
                    == required_pointer_str(case, "/predecessor_realm_id", vector_name)?
                {
                    bail!("vector {vector_name} cross-Realm predecessor must cross Realms");
                }
                require_str_eq(case, "/expected/result", "reject", vector_name)?;
                require_str_eq(case, "/expected/reason", "schema_violation", vector_name)?;
            }
            _ => bail!("vector {vector_name} unknown actor-chain scope case {case_name}"),
        }
    }
    require_seen(
        vector_name,
        &seen,
        &[
            "same_actor_and_seq_across_realms",
            "same_actor_and_seq_in_one_realm",
            "realm_bootstrap_transaction_chain",
            "cross_realm_predecessor",
        ],
    )
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
        "completeness_root",
        "notary_seq",
        "sealed_at",
        "hlc",
    ] {
        require_field(body, field, vector_name)?;
    }
    require_non_empty_array(vector, "/seal_body/predecessor_refs", vector_name)?;
    for digest in string_vec_at(vector, "/seal_body/delta", vector_name)? {
        require_sha256_digest(digest, "/seal_body/delta", vector_name)?;
    }

    let expected_id = required_pointer_str(vector, "/expected/id", vector_name)?;
    let mut seal_value = body_value.clone();
    let seal_object = seal_value
        .as_object_mut()
        .ok_or_else(|| anyhow!("vector {vector_name} seal_body must be an object"))?;
    seal_object.insert("id".to_owned(), json!(expected_id));
    seal_object.insert(
        "notary_signature".to_owned(),
        json!({
            "verification_method": "did:web:notary.example#k1",
            "payload_digest": required_pointer_str(
                vector,
                "/expected/notary_signature_payload_digest",
                vector_name,
            )?,
            "jws": "AAAA.BBBB.CCCC"
        }),
    );
    let seal: Seal = serde_json::from_value(seal_value)
        .map_err(|error| anyhow!("vector {vector_name} seal_body is not a typed Seal: {error}"))?;
    let canonical = seal
        .canonical_bytes_for_id()
        .map_err(|error| anyhow!("vector {vector_name} Seal canonicalization failed: {error}"))?;
    let digest = sha256_prefixed(&canonical);
    let computed_id = seal
        .derive_id(arkret_canonical::DigestSuite::Sha256)
        .map_err(|error| anyhow!("vector {vector_name} Seal id derivation failed: {error}"))?;
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
                require_str_eq(case, "/event/projected_writes/0/cell", cell, vector_name)?;
                if !case.pointer("/event/basis").is_some_and(Value::is_null) {
                    bail!("vector {vector_name} blind write must carry a null basis");
                }
                require_str_eq(
                    case,
                    "/event/projected_writes/0/op/kind",
                    "set",
                    vector_name,
                )?;
                require_str_eq(
                    case,
                    "/event/projected_writes/0/op/value",
                    "v2",
                    vector_name,
                )?;
                require_str_eq(case, "/expected/result", "failed_precondition", vector_name)?;
                require_str_eq(case, "/expected/cell_value", "v1", vector_name)?;
                require_bool_eq(
                    case,
                    "/expected/atomic_rejects_all_projected_writes",
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
                require_str_eq(
                    case,
                    "/control_move/projected_writes/0/cell",
                    cell,
                    vector_name,
                )?;
                require_str_eq(
                    case,
                    "/control_move/projected_writes/0/op/kind",
                    "set",
                    vector_name,
                )?;
                require_str_eq(
                    case,
                    "/control_move/projected_writes/0/op/value",
                    "v2",
                    vector_name,
                )?;
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
                require_str_eq(case, "/expected/reason", "seal_ref_stale", vector_name)?;
            }
            "revoked_key_within_freshness_window" | "revoked_key_at_freshness_window_boundary" => {
                let distance = required_u64(case, "/seal_ref_distance_ms", vector_name)?;
                if distance > window {
                    bail!("vector {vector_name} within-window case exceeds freshness window");
                }
                if case_name == "revoked_key_at_freshness_window_boundary" && distance != window {
                    bail!("vector {vector_name} boundary case must equal freshness window");
                }
                require_str_eq(case, "/expected/result", "accept", vector_name)?;
                require_bool_eq(
                    case,
                    "/expected/included_in_data_cell_join",
                    true,
                    vector_name,
                )?;
            }
            "rejecting_revoked_key_within_freshness_window_is_nonconformant" => {
                let distance = required_u64(case, "/seal_ref_distance_ms", vector_name)?;
                if distance > window {
                    bail!("vector {vector_name} nonconformance control exceeds freshness window");
                }
                require_str_eq(case, "/implementation_result", "reject", vector_name)?;
                require_str_eq(case, "/expected/conformance", "fail", vector_name)?;
                require_str_eq(case, "/expected/required_result", "accept", vector_name)?;
                require_bool_eq(
                    case,
                    "/expected/required_included_in_data_cell_join",
                    true,
                    vector_name,
                )?;
            }
            "first_delivery_thirty_days_after_revocation_keeps_same_historical_grace_result" => {
                require_str_eq(case, "/risk_tier", "medium", vector_name)?;
                let distance = required_u64(case, "/seal_ref_distance_ms", vector_name)?;
                if distance > window {
                    bail!("vector {vector_name} delayed-delivery case exceeds freshness window");
                }
                let basis_committed_at =
                    required_pointer_str(case, "/basis_seal_committed_at", vector_name)?
                        .parse::<chrono::DateTime<chrono::Utc>>()?;
                let revocation_committed_at =
                    required_pointer_str(case, "/revocation_seal_committed_at", vector_name)?
                        .parse::<chrono::DateTime<chrono::Utc>>()?;
                let first_delivery_at =
                    required_pointer_str(case, "/first_delivery_at", vector_name)?
                        .parse::<chrono::DateTime<chrono::Utc>>()?;
                let committed_distance =
                    (revocation_committed_at - basis_committed_at).num_milliseconds();
                if committed_distance < 0 || committed_distance as u64 != distance {
                    bail!(
                        "vector {vector_name} delayed-delivery distance must come from the two Seal commit times"
                    );
                }
                if first_delivery_at <= revocation_committed_at {
                    bail!(
                        "vector {vector_name} delayed-delivery control must arrive after revocation"
                    );
                }
                require_str_eq(case, "/expected/result", "accept", vector_name)?;
                for pointer in [
                    "/expected/same_as_immediate_delivery",
                    "/expected/same_across_receivers",
                    "/expected/same_under_offline_replay",
                    "/expected/first_delivery_at_is_not_an_input",
                ] {
                    require_bool_eq(case, pointer, true, vector_name)?;
                }
            }
            "high_risk_has_zero_historical_grace_even_on_immediate_delivery" => {
                require_str_eq(case, "/risk_tier", "high", vector_name)?;
                let distance = required_u64(case, "/seal_ref_distance_ms", vector_name)?;
                if distance == 0 {
                    bail!("vector {vector_name} high-risk control must use an older basis Seal");
                }
                require_str_eq(case, "/expected/result", "reject_or_hide", vector_name)?;
                require_str_eq(case, "/expected/reason", "seal_ref_stale", vector_name)?;
                if required_u64(case, "/expected/effective_window_ms", vector_name)? != 0 {
                    bail!("vector {vector_name} high-risk effective freshness window must be zero");
                }
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
            "revoked_key_at_freshness_window_boundary",
            "rejecting_revoked_key_within_freshness_window_is_nonconformant",
            "first_delivery_thirty_days_after_revocation_keeps_same_historical_grace_result",
            "high_risk_has_zero_historical_grace_even_on_immediate_delivery",
            "epoch_not_valid_at_seal_ref",
        ],
    )
}

fn validate_seal_compaction_interval_enforced(vector: &Value, vector_name: &str) -> Result<()> {
    require_str_eq(vector, "/realm/notary/kind", "open_set", vector_name)?;
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
    require_str_eq(vector, "/notary_kind", "threshold", vector_name)?;
    let proposer = required_pointer_str(vector, "/notary_proposer_id", vector_name)?;
    let signer = required_pointer_str(vector, "/notary_signer_id", vector_name)?;
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
    let signature_value = vector
        .pointer("/inclusion_list/signature")
        .cloned()
        .ok_or_else(|| anyhow!("vector {vector_name} missing inclusion-list signature"))?;
    let signature: PayloadProof = serde_json::from_value(signature_value).map_err(|error| {
        anyhow!("vector {vector_name} inclusion-list signature is not a PayloadProof: {error}")
    })?;
    signature.validate_production().map_err(|error| {
        anyhow!("vector {vector_name} inclusion-list signature is invalid: {error}")
    })?;
    if signature.domain.is_some()
        || signature.audience.is_some()
        || signature.proof_purpose.is_some()
    {
        bail!(
            "vector {vector_name} inclusion-list signature contains members outside its closed schema"
        );
    }
    let (verification_controller, _) = signature
        .verification_method
        .as_str()
        .rsplit_once('#')
        .ok_or_else(|| {
            anyhow!("vector {vector_name} inclusion-list verification method has no fragment")
        })?;
    let verification_controller = Did::new(verification_controller).map_err(|error| {
        anyhow!("vector {vector_name} inclusion-list verification controller is not a DID: {error}")
    })?;
    let verification_signer = project_did_to_core_id(&verification_controller).map_err(|error| {
        anyhow!(
            "vector {vector_name} inclusion-list verification controller has no active method adapter: {error}"
        )
    })?;
    if verification_signer.as_str() != signer {
        bail!("vector {vector_name} inclusion-list signature is not bound to signer {signer}");
    }
    if signature.jws.is_empty() {
        bail!("vector {vector_name} inclusion-list signature JWS must be non-empty");
    }
    let payload_digest = signature.payload_digest.as_str();
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
        "/single_signer_profile_expected",
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
    if !seal_a_id.starts_with("ak:seal:sha256:") || !seal_b_id.starts_with("ak:seal:sha256:") {
        bail!("vector {vector_name} fault seals must use ak:seal:sha256 typed ids");
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
        "ak.notary.fault.equivocation",
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
        "ak.component.notary_fault.v1",
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
        "/expected/affected_branch_disposition",
        "fork_quarantine",
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
        require_str_eq(case, "/notary/kind", "threshold", vector_name)?;
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

/// Vector `ak.vector.cba_lattice.open_set_concurrent_revocation_fail_closed.v1`.
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
    require_str_eq(vector, "/notary_kind", "open_set", vector_name)?;
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
                require_str_eq(case, "/expected/reason", "seal_ref_stale", vector_name)?;
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
                require_str_eq(case, "/expected/reason", "seal_ref_stale", vector_name)?;
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
            "late_revocation_leaf_retroactive_removal" => {
                let source_event_id = required_pointer_str(vector, "/data_event/id", vector_name)?;
                require_str_eq(case, "/dependent_data_event/plane", "data", vector_name)?;
                require_str_eq(
                    case,
                    "/dependent_data_event/critical_causal_ref",
                    source_event_id,
                    vector_name,
                )?;
                let sequence = required_array(case, "/sequence", vector_name)?;
                if sequence.len() != 2 {
                    bail!(
                        "vector {vector_name} late-revocation sequence must contain exactly two steps"
                    );
                }
                let accepted = &sequence[0];
                require_str_eq(accepted, "/step", "accept_before_revocation", vector_name)?;
                require_str_eq(
                    accepted,
                    "/expected/data_event_result",
                    "accept",
                    vector_name,
                )?;
                require_bool_eq(
                    accepted,
                    "/expected/data_cell_x_contains_event_projection",
                    true,
                    vector_name,
                )?;
                require_str_eq(
                    accepted,
                    "/expected/dependent_event_result",
                    "accept",
                    vector_name,
                )?;
                require_bool_eq(
                    accepted,
                    "/expected/data_cell_y_contains_dependent_projection",
                    true,
                    vector_name,
                )?;

                let revoked = &sequence[1];
                require_str_eq(
                    revoked,
                    "/step",
                    "revocation_leaf_arrives_late",
                    vector_name,
                )?;
                require_str_eq(
                    revoked,
                    "/expected/data_event_result",
                    "reject_or_hide",
                    vector_name,
                )?;
                require_str_eq(revoked, "/expected/reason", "seal_ref_stale", vector_name)?;
                require_bool_eq(
                    revoked,
                    "/expected/data_cell_x_projection_retroactively_removed",
                    true,
                    vector_name,
                )?;
                require_str_eq(
                    revoked,
                    "/expected/dependent_event_result",
                    "pending",
                    vector_name,
                )?;
                require_str_eq(
                    revoked,
                    "/expected/dependent_event_reason",
                    "dependency_missing",
                    vector_name,
                )?;
                for path in [
                    "/expected/dependent_event_projection_retroactively_removed",
                    "/expected/recursive_dependency_closure_revalidated",
                    "/expected/projection_recomputed",
                    "/expected/converges_with_from_start_joiner",
                    "/expected/order_independent",
                ] {
                    require_bool_eq(revoked, path, true, vector_name)?;
                }

                require_str_eq(
                    case,
                    "/expected/final_data_event_result",
                    "reject_or_hide",
                    vector_name,
                )?;
                require_str_eq(
                    case,
                    "/expected/final_reason",
                    "seal_ref_stale",
                    vector_name,
                )?;
                require_str_eq(
                    case,
                    "/expected/dependent_event_final_result",
                    "pending",
                    vector_name,
                )?;
                require_str_eq(
                    case,
                    "/expected/dependent_event_final_reason",
                    "dependency_missing",
                    vector_name,
                )?;
                for path in [
                    "/expected/data_cell_x_projection_retroactively_removed",
                    "/expected/data_cell_y_dependent_projection_retroactively_removed",
                    "/expected/accepted_set_is_authorized_dependency_closed",
                    "/expected/order_independent",
                ] {
                    require_bool_eq(case, path, true, vector_name)?;
                }
                if case.pointer("/expected/final_state_equals_from_start_joiner_of_leaf_set")
                    != vector.pointer("/joined_leaf_set")
                {
                    bail!(
                        "vector {vector_name} late-revocation final leaf set must equal the joined open-set view"
                    );
                }
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
            "late_revocation_leaf_retroactive_removal",
        ],
    )
}

/// Vector `ak.vector.cba_lattice.conflict_recovery_move.v1`.
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
            "reset_on_a_cell_not_in_bottom" => {
                require_str_eq(case, "/expected/result", "failed_precondition", vector_name)?;
                require_str_eq(
                    case,
                    "/expected/reason",
                    "recovery_target_not_in_bottom",
                    vector_name,
                )?;
            }
            "target_cell_mismatch" => {
                require_str_eq(case, "/expected/result", "failed_precondition", vector_name)?;
                require_str_eq(
                    case,
                    "/expected/reason",
                    "recovery_witness_invalid",
                    vector_name,
                )?;
            }
            "legacy_target_cell_alias_rejected" => {
                // event-auth-state-resolution.md section 9.5: `target_cell_id`
                // is the only registered recovery target field; the retired
                // `target_cell` alias is a closed-schema violation.
                require_str_eq(case, "/payload_field_name", "target_cell", vector_name)?;
                require_str_eq(case, "/expected/result", "reject", vector_name)?;
                require_str_eq(case, "/expected/reason", "schema_violation", vector_name)?;
            }
            "duplicate_target_cell_fields_rejected" => {
                require_str_eq(case, "/payload_extra_field", "target_cell", vector_name)?;
                require_str_eq(case, "/expected/result", "reject", vector_name)?;
                require_str_eq(case, "/expected/reason", "schema_violation", vector_name)?;
            }
            "ordinary_mls_commit_cannot_recover_bottom" => {
                require_str_eq(
                    case,
                    "/target_cell_family",
                    "ak.component.mls.epoch.v1",
                    vector_name,
                )?;
                require_str_eq(case, "/cell_status_before", "bottom", vector_name)?;
                require_str_eq(case, "/operation", "ak.mls.commit", vector_name)?;
                let base_epoch = required_u64(case, "/base_epoch", vector_name)?;
                let next_epoch = required_u64(case, "/next_epoch", vector_name)?;
                if next_epoch <= base_epoch + 1 {
                    bail!(
                        "vector {vector_name} ordinary MLS commit bypass must attempt a later epoch"
                    );
                }
                require_str_eq(case, "/expected/result", "failed_bottom", vector_name)?;
                require_str_eq(case, "/expected/cell_remains", "bottom", vector_name)?;
                require_str_eq(
                    case,
                    "/expected/application_send_gate",
                    "blocked",
                    vector_name,
                )?;
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
            "reset_on_a_cell_not_in_bottom",
            "target_cell_mismatch",
            "legacy_target_cell_alias_rejected",
            "duplicate_target_cell_fields_rejected",
            "ordinary_mls_commit_cannot_recover_bottom",
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

/// Exact cardinality. The fork-resolution evidence bounds are the claim, not a
/// floor: 17 proves the single-bucket ceiling was passed and 16 does not.
fn require_array_len(value: &Value, pointer: &str, len: usize, vector_name: &str) -> Result<()> {
    let array = required_array(value, pointer, vector_name)?;
    if array.len() != len {
        bail!(
            "vector {vector_name} array at {pointer} must have exactly {len} items, found {}",
            array.len()
        );
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

fn require_u64_eq(value: &Value, pointer: &str, expected: u64, vector_name: &str) -> Result<()> {
    let actual = value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("vector {vector_name} missing integer {pointer}"))?;
    if actual != expected {
        bail!("vector {vector_name} {pointer} = {actual}, expected {expected}");
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
