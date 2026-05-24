//! Move / Anchor / Lattice fixture suite (spec 2026-05-08).
//!
//! Validates the `move-anchor-lattice-fixture.json` profile's normative
//! vectors. The legacy state-slot winner-reconstruction validator that this
//! file used to host (against `state-resolution-fixture.json`) was removed
//! when the spec replaced state-slot winner reconstruction with the Move /
//! Anchor / Lattice three-primitive model. Conformance for state convergence
//! now lives entirely on this suite plus the per-Lattice reference-impl
//! sections in `event-auth-state-resolution.md` §5.3.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{load_fixture_value, required_str, validate_profile};
use crate::transcripts::record_vector_event;

/// Public entry point retained so the release-gate cargo_filter list can
/// reference both `state_resolution_fixture_suite_matches_reference_semantics`
/// and `move_anchor_lattice_fixture_suite_matches_reference_semantics` —
/// both delegate here.
pub fn run_state_resolution_fixture_suite() -> Result<()> {
    run_move_anchor_lattice_fixture_suite()
}

/// Structural validator for `move-anchor-lattice-fixture.json`.
///
/// The fixture is a profile with normative vectors for Move precondition
/// validation, Anchor batch semantics, cas-register conflict bottom, MLS
/// commit covered_frontier, anchorer cell ⊥ recovery, signed compaction
/// equivalence, and Anchor DAG genesis / multi-leaf cases. This suite
/// runs a static well-formedness check; deeper deterministic re-execution
/// lives in the SDK's lattice / state-res crates (root C10.A) and in
/// scenario-level integration tests once a Move/Anchor SUT is wired
/// through cotest's harness.
pub fn run_move_anchor_lattice_fixture_suite() -> Result<()> {
    let value = load_fixture_value("move-anchor-lattice-fixture.json")?;
    validate_profile(&value, "cx.profile.move_anchor_lattice_vectors.v1")?;

    let vectors = value
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("move-anchor-lattice fixture missing vectors[]"))?;
    if vectors.is_empty() {
        bail!("move-anchor-lattice fixture has no vectors");
    }

    let mut seen_atomic = false;
    let mut seen_cas_bottom = false;
    let mut seen_anchor_batch_pre_state = false;
    let mut seen_mls_covered_frontier = false;
    let mut seen_anchorer_recovery = false;
    let mut seen_signed_compaction = false;
    let mut seen_genesis_multi_leaf = false;

    for vector in vectors {
        let name = required_str(vector, "name")?;
        match name {
            "multi_cell_ban_revokes_grants_atomically" => {
                let m = vector
                    .get("move")
                    .and_then(Value::as_object)
                    .ok_or_else(|| anyhow!("vector {name} missing move"))?;
                require_field(m, "id", name)?;
                require_field(m, "issuer", name)?;
                require_field(m, "anchor_ref", name)?;
                let preconditions = m
                    .get("preconditions")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} move missing preconditions"))?;
                let effects = m
                    .get("effects")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} move missing effects"))?;
                if preconditions.len() < 2 {
                    bail!("vector {name} requires multi-cell precondition set (>=2)");
                }
                if effects.len() < 2 {
                    bail!("vector {name} requires multi-cell atomic effects (>=2)");
                }
                let atomicity = vector
                    .pointer("/expected/atomicity")
                    .and_then(Value::as_str);
                if atomicity != Some("all_effects_or_none") {
                    bail!("vector {name} expected.atomicity must be 'all_effects_or_none'");
                }
                seen_atomic = true;
                record_vector_event(
                    "state_resolution.multi_cell_ban_revokes_grants_atomically",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "min_preconditions": 2,
                        "min_effects": 2,
                        "atomicity": "all_effects_or_none",
                    }),
                    &json!({
                        "preconditions": preconditions.len(),
                        "effects": effects.len(),
                        "atomicity": atomicity,
                    }),
                );
            }
            "cas_register_conflict_returns_bottom" => {
                let lat = vector
                    .pointer("/lattice/type")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("vector {name} missing lattice.type"))?;
                if lat != "cas_register" {
                    bail!("vector {name} lattice.type must be cas-register");
                }
                let bot_status = vector
                    .pointer("/expected/query/status")
                    .and_then(Value::as_str);
                if bot_status != Some("bottom") {
                    bail!("vector {name} expected.query.status must be 'bottom'");
                }
                let dep = vector
                    .pointer("/expected/dependent_move_result")
                    .and_then(Value::as_str);
                if dep != Some("fail_bottom") {
                    bail!("vector {name} dependent_move_result must be 'fail_bottom'");
                }
                seen_cas_bottom = true;
                record_vector_event(
                    "state_resolution.cas_register_conflict_returns_bottom",
                    &json!({"vector": vector.clone()}),
                    &json!({
                        "lattice_type": "cas_register",
                        "query_status": "bottom",
                        "dependent_move_result": "fail_bottom",
                    }),
                    &json!({
                        "lattice_type": lat,
                        "query_status": bot_status,
                        "dependent_move_result": dep,
                    }),
                );
            }
            "anchor_batch_pre_state_prevents_self_satisfaction" => {
                let anchor_result = vector
                    .pointer("/expected/anchor_result")
                    .and_then(Value::as_str);
                if anchor_result != Some("reject") {
                    bail!("vector {name} expected.anchor_result must be 'reject'");
                }
                seen_anchor_batch_pre_state = true;
                record_vector_event(
                    "state_resolution.anchor_batch_pre_state_prevents_self_satisfaction",
                    &json!({"vector": vector.clone()}),
                    &json!({"anchor_result": "reject"}),
                    &json!({"anchor_result": anchor_result}),
                );
            }
            "mls_commit_move_requires_covered_frontier" => {
                let verify = vector
                    .pointer("/expected/verify_move")
                    .and_then(Value::as_str);
                if verify != Some("fail_precondition") {
                    bail!("vector {name} expected.verify_move must be 'fail_precondition'");
                }
                seen_mls_covered_frontier = true;
                record_vector_event(
                    "state_resolution.mls_commit_move_requires_covered_frontier",
                    &json!({"vector": vector.clone()}),
                    &json!({"verify_move": "fail_precondition"}),
                    &json!({"verify_move": verify}),
                );
            }
            "anchorer_cell_bottom_pauses_space_until_recovery" => {
                let space_state = vector
                    .pointer("/expected/space_state")
                    .and_then(Value::as_str);
                if space_state != Some("anchorer_paused") {
                    bail!("vector {name} expected.space_state must be 'anchorer_paused'");
                }
                seen_anchorer_recovery = true;
                record_vector_event(
                    "state_resolution.anchorer_cell_bottom_pauses_space_until_recovery",
                    &json!({"vector": vector.clone()}),
                    &json!({"space_state": "anchorer_paused"}),
                    &json!({"space_state": space_state}),
                );
            }
            "signed_compaction_anchor_equals_effective_view" => {
                let preserves = vector
                    .pointer("/expected/preserves_bottom_diagnostics")
                    .and_then(Value::as_bool);
                if preserves != Some(true) {
                    bail!("vector {name} expected.preserves_bottom_diagnostics must be true");
                }
                seen_signed_compaction = true;
                record_vector_event(
                    "state_resolution.signed_compaction_anchor_equals_effective_view",
                    &json!({"vector": vector.clone()}),
                    &json!({"preserves_bottom_diagnostics": true}),
                    &json!({"preserves_bottom_diagnostics": preserves}),
                );
            }
            "anchor_dag_genesis_and_multi_leaf_join" => {
                let cases = vector
                    .get("cases")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing cases[]"))?;
                if cases.len() < 4 {
                    bail!(
                        "vector {name} requires at least 4 cases (genesis / non-genesis-empty / multi-leaf-view / signed-compaction)"
                    );
                }
                seen_genesis_multi_leaf = true;
                record_vector_event(
                    "state_resolution.anchor_dag_genesis_and_multi_leaf_join",
                    &json!({"vector": vector.clone()}),
                    &json!({"min_cases": 4}),
                    &json!({"cases": cases.len()}),
                );
            }
            _ => bail!("unknown move-anchor-lattice vector: {name}"),
        }
    }

    if !(seen_atomic
        && seen_cas_bottom
        && seen_anchor_batch_pre_state
        && seen_mls_covered_frontier
        && seen_anchorer_recovery
        && seen_signed_compaction
        && seen_genesis_multi_leaf)
    {
        bail!(
            "move-anchor-lattice fixture must cover all 7 normative vectors \
             (atomic / cas_bottom / anchor_batch_pre_state / mls_covered_frontier / \
              anchorer_recovery / signed_compaction / genesis_multi_leaf)"
        );
    }

    Ok(())
}

fn require_field<'a>(
    obj: &'a serde_json::Map<String, Value>,
    field: &str,
    vector_name: &str,
) -> Result<&'a Value> {
    obj.get(field)
        .ok_or_else(|| anyhow!("vector {vector_name} move missing field {field}"))
}
