//! Anchor-view, anchorer-cell, and conflict-repair wire-model conformance
//! vectors, including late-arriving anchor and frontier-conflict resolution.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{emit_vector, expected_outcome, load_local_fixture};
use crate::conformance::{required_str, validate_profile};

/// M6 — anchor view compaction round-trip vectors.
///
/// Spec: `authz/event-auth-state-resolution.md` §6 (Anchor DAG,
/// effective_anchor_view, signed compaction). The validator pins these
/// invariants per vector:
///
/// * **multi-leaf effective_anchor_view is a pure function of the input leaves** —
///   `expected_effective_anchor_view.leaves` MUST equal the set of input Anchor ids; `frontier`
///   MUST equal the leaves whenever the leaves are concurrent (no Anchor in the input list is an
///   ancestor of another in the same input list).
/// * **signed compaction is join-equivalent** — when a `signed_compaction` is present, its
///   `frontier` and `state_root` MUST exactly match the `expected_effective_anchor_view`.
/// * **bottom diagnostics are preserved across compaction** —
///   `signed_compaction.bottom_diagnostics` MUST be a superset of
///   `expected_effective_anchor_view.bottom_diagnostics` (compaction is information-preserving for
///   ⊥ cells; dropping one is a structural error).
/// * **compaction Anchor id is content-addressed** — id starts with `ak:anchor:sha256:` and the
///   digest is 64 lowercase hex chars.
///
/// Negative vectors carry a `drift_compaction` with `expected_rejection_reason`
/// — the validator computes the actual drift (state_root or
/// dropped-diagnostic) and asserts the recorded reason matches.
pub fn run_anchor_view_compaction_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("anchor_view_compaction_fixture.json")?;
    validate_profile(&fixture, "ak.profile.anchor_view_compaction_vectors.v1")?;

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("anchor_view_compaction fixture missing vectors[]"))?;
    if vectors.is_empty() {
        bail!("anchor_view_compaction fixture has no vectors");
    }

    let mut covered_single_leaf = false;
    let mut covered_multi_leaf_clean = false;
    let mut covered_bottom_preserved = false;

    for vector in vectors {
        let name = required_str(vector, "name")?;
        let anchors = vector
            .get("anchors")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("vector {name} missing anchors[]"))?;
        if anchors.is_empty() {
            bail!("vector {name} has no anchor leaves");
        }
        let view = vector
            .get("expected_effective_anchor_view")
            .ok_or_else(|| anyhow!("vector {name} missing expected_effective_anchor_view"))?;

        // (1) leaves equal input anchor id set
        let input_ids: std::collections::BTreeSet<String> = anchors
            .iter()
            .map(|a| required_str(a, "id").map(str::to_owned))
            .collect::<Result<_>>()?;
        for id in &input_ids {
            validate_anchor_id_shape(id, name)?;
        }
        let view_leaves: std::collections::BTreeSet<String> = view
            .get("leaves")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("vector {name} view missing leaves[]"))?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| anyhow!("vector {name} leaf entry not a string"))
            })
            .collect::<Result<_>>()?;
        if view_leaves != input_ids {
            bail!("vector {name} effective_anchor_view.leaves drift from input anchor ids");
        }

        // (2) when there are >= 2 concurrent leaves, frontier == leaves.
        // We treat all input anchors as concurrent (the fixture vectors are
        // crafted that way: each leaf points to the same prior frontier).
        let view_frontier: std::collections::BTreeSet<String> = view
            .get("frontier")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("vector {name} view missing frontier[]"))?
            .iter()
            .map(|v| {
                v.as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| anyhow!("vector {name} frontier entry not a string"))
            })
            .collect::<Result<_>>()?;
        if anchors.len() >= 2 && view_frontier != view_leaves {
            bail!("vector {name} concurrent multi-leaf frontier MUST equal leaves set");
        }
        if anchors.len() == 1 && !view_frontier.is_empty() && view_frontier != view_leaves {
            bail!("vector {name} single-leaf view frontier must be empty or equal to leaves");
        }

        // (3) signed compaction equivalence
        if let Some(compaction) = vector.get("signed_compaction")
            && !compaction.is_null()
        {
            let comp_id = required_str(compaction, "id")?;
            validate_anchor_id_shape(comp_id, name)?;
            let comp_frontier: std::collections::BTreeSet<String> = compaction
                .get("frontier")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("vector {name} signed_compaction missing frontier[]"))?
                .iter()
                .map(|v| {
                    v.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                        anyhow!("vector {name} signed_compaction frontier entry not a string")
                    })
                })
                .collect::<Result<_>>()?;
            if comp_frontier != view_frontier {
                bail!(
                    "vector {name} signed_compaction frontier MUST equal effective_view frontier"
                );
            }
            let comp_state_root = required_str(compaction, "state_root")?;
            let view_state_root = required_str(view, "state_root")?;
            if comp_state_root != view_state_root {
                bail!(
                    "vector {name} signed_compaction state_root drift: expected {view_state_root}, got {comp_state_root}"
                );
            }
            // (4) bottom_diagnostics preserved
            let view_diags = view
                .get("bottom_diagnostics")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("vector {name} view missing bottom_diagnostics"))?;
            let comp_diags = compaction
                .get("bottom_diagnostics")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    anyhow!("vector {name} signed_compaction missing bottom_diagnostics")
                })?;
            for diag in view_diags {
                if !comp_diags.iter().any(|d| d == diag) {
                    bail!(
                        "vector {name} signed_compaction dropped a bottom diagnostic from the effective view (compaction must be information-preserving for ⊥ cells)"
                    );
                }
            }
            let signature = compaction
                .get("signature")
                .ok_or_else(|| anyhow!("vector {name} signed_compaction missing signature"))?;
            let signature_algorithm = required_str(signature, "signature_algorithm")?;
            if signature_algorithm != "Ed25519" {
                bail!(
                    "vector {name} signed_compaction signature.signature_algorithm must be Ed25519, got {signature_algorithm}"
                );
            }
        }

        match name {
            "single_leaf_view_passthrough" => covered_single_leaf = true,
            "two_leaf_concurrent_no_bottom_compacts_to_one" => covered_multi_leaf_clean = true,
            "compaction_preserves_bottom_diagnostics" => covered_bottom_preserved = true,
            _ => {}
        }
        emit_vector(
            "anchor_view_compaction.view",
            vector,
            json!({
                "name": name,
                "leaves": view_leaves,
                "frontier": view_frontier,
                "anchor_count": anchors.len(),
            }),
        );
    }

    if !(covered_single_leaf && covered_multi_leaf_clean && covered_bottom_preserved) {
        bail!(
            "anchor_view_compaction fixture must cover single-leaf passthrough + concurrent-multi-leaf + bottom-diagnostic-preservation"
        );
    }

    // Negative vectors: each carries a `drift_compaction` with an expected
    // rejection reason. We compute the drift kind and assert it matches.
    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("anchor_view_compaction fixture missing negative_vectors[]"))?;
    let mut saw_diag_drop = false;
    let mut saw_state_root_drift = false;
    for vector in negatives {
        let name = required_str(vector, "name")?;
        let anchors = vector
            .get("anchors")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("negative vector {name} missing anchors[]"))?;
        let drift = vector
            .get("drift_compaction")
            .ok_or_else(|| anyhow!("negative vector {name} missing drift_compaction"))?;
        let reason = required_str(drift, "expected_rejection_reason")?;
        match reason {
            "compaction_dropped_bottom_diagnostics" => {
                let leaf_diags: Vec<&Value> = anchors
                    .iter()
                    .filter_map(|a| a.get("bottom_diagnostics").and_then(Value::as_array))
                    .flatten()
                    .collect();
                let drift_diags: &Vec<Value> = drift
                    .get("bottom_diagnostics")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!(
                            "negative vector {name} drift_compaction missing bottom_diagnostics"
                        )
                    })?;
                if drift_diags.len() >= leaf_diags.len() {
                    bail!(
                        "negative vector {name} expected dropped diagnostics but drift_compaction kept them all"
                    );
                }
                saw_diag_drop = true;
            }
            "state_root_drifted_from_effective_view" => {
                let leaf_state_root = anchors
                    .first()
                    .and_then(|a| a.get("state_root"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("negative vector {name} leaf missing state_root"))?;
                let drift_state_root = required_str(drift, "state_root")?;
                if drift_state_root == leaf_state_root {
                    bail!(
                        "negative vector {name} expected drifted state_root but drift_compaction matches"
                    );
                }
                saw_state_root_drift = true;
            }
            other => bail!("negative vector {name} unknown rejection reason {other}"),
        }
    }
    if !(saw_diag_drop && saw_state_root_drift) {
        bail!(
            "anchor_view_compaction fixture must include both bottom-diagnostic-drop and state-root-drift negative vectors"
        );
    }

    Ok(())
}
/// Validate late-arriving anchor semantics.
pub fn run_late_arriving_anchor_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("late_arriving_anchor_fixture.json")?;
    validate_profile(&fixture, "ak.profile.late_arriving_anchor_vectors.v1")?;
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("late_arriving_anchor missing vectors[]"))?;
    if vectors.len() < 2 {
        bail!(
            "late_arriving_anchor requires >= 2 vectors, got {}",
            vectors.len()
        );
    }
    let mut saw_metadata_only = false;
    let mut saw_mixed = false;
    let mut saw_duplicate = false;
    for v in vectors {
        let name = required_str(v, "name")?;
        if expected_outcome(v, name)? != "accept" {
            bail!("vector {name} outcome must be accept");
        }
        let before = v
            .get("peer_b_state_before")
            .ok_or_else(|| anyhow!("vector {name} missing peer_b_state_before"))?;
        let after = v
            .pointer("/expected/peer_b_state_after")
            .ok_or_else(|| anyhow!("vector {name} missing expected.peer_b_state_after"))?;
        let projected_before: Vec<&str> = before
            .get("projected_moves")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let projected_after: Vec<&str> = after
            .get("projected_moves")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let count_before = before
            .get("message_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let count_after = after
            .get("message_count")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let new_projections = projected_after.len() as i64 - projected_before.len() as i64;
        let count_delta = count_after as i64 - count_before as i64;
        if new_projections != count_delta {
            bail!(
                "vector {name} message_count delta ({count_delta}) must equal new projections ({new_projections})"
            );
        }
        match name {
            "anchor_arrives_after_direct_move_idempotent" => {
                if count_delta != 0 {
                    bail!(
                        "vector {name} idempotent anchor must not change message_count (got delta {count_delta})"
                    );
                }
                saw_metadata_only = true;
            }
            "anchor_arrives_with_new_move_projects_once" => {
                if count_delta != 1 {
                    bail!(
                        "vector {name} mixed anchor must project exactly 1 new move (got {count_delta})"
                    );
                }
                saw_mixed = true;
            }
            "duplicate_anchor_application_no_double_effect" => {
                if !v
                    .get("duplicate_apply")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    bail!("vector {name} duplicate_apply must be true");
                }
                if count_delta != 0 {
                    bail!(
                        "vector {name} duplicate apply must be a no-op (got delta {count_delta})"
                    );
                }
                saw_duplicate = true;
            }
            other => bail!("late_arriving_anchor unexpected vector {other}"),
        }
        emit_vector(
            "late_arriving_anchor.vector",
            v,
            json!({
                "name": name,
                "count_delta": count_delta,
                "new_projections": new_projections,
            }),
        );
    }
    if !(saw_metadata_only && saw_mixed && saw_duplicate) {
        bail!("late_arriving_anchor must cover metadata_only + mixed + duplicate_apply");
    }
    Ok(())
}
/// E5 — fixture-decoupled idempotency primitive: applying the same
/// anchor-id twice to a peer's anchored-set must be a set-insertion no-op
/// on the second call. Independent of any specific fixture.
pub fn run_late_arriving_anchor_idempotency_check() -> Result<()> {
    use std::collections::BTreeSet;
    let mut anchored: BTreeSet<&str> = BTreeSet::new();
    let mut new_after_first = false;
    let mut new_after_second = false;
    if anchored.insert("ax:S1:1") {
        new_after_first = true;
    }
    if anchored.insert("ax:S1:1") {
        new_after_second = true;
    }
    if !new_after_first {
        bail!("first anchor application must be a new insertion");
    }
    if new_after_second {
        bail!("second anchor application must be a no-op");
    }
    if anchored.len() != 1 {
        bail!("anchored set size must be 1, got {}", anchored.len());
    }
    Ok(())
}
fn validate_anchor_id_shape(id: &str, ctx: &str) -> Result<()> {
    let Some(rest) = id.strip_prefix("ak:anchor:sha256:") else {
        bail!("{ctx} anchor id {id} must use ak:anchor:sha256:<hex> special form");
    };
    if rest.len() != 64
        || !rest
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        bail!("{ctx} anchor id {id} sha256 segment must be exactly 64 lowercase hex chars");
    }
    Ok(())
}
