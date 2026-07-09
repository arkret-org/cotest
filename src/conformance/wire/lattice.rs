//! Event-kind lattice dispatch, membership FSM, and constraint-family /
//! evaluation-class wire-model conformance vectors.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{emit_vector, expected_reason, load_local_fixture};
use crate::conformance::{required_str, validate_profile};

/// M7 — MLS covered_frontier cell vectors (round 20).
///
/// Stand-alone fixture (`tests/fixtures/mls_move_covered_frontier_fixture.json`)
/// validating the or-set behaviour of `ck.component.mls.covered_frontier.v1`
/// across MLS commit Moves, governance Moves, and rotation. Pins:
///
/// * accumulate vector adds three ops where two share the same tag (idempotent re-add);
///   `expected.active_tags` MUST be the unique-tag set;
/// * rotation vector adds two distinct tags then removes one; remaining active_tag MUST equal the
///   un-removed tag;
/// * governance Move vector declares zero preconditions (governance Moves are NOT blocked on
///   covered_frontier);
/// * mls_commit_three_cells declares three distinct cells in `effects[]` with one shared move_id;
/// * E2EE missing-precondition negative declares no `covered_frontier` precondition + reason_code
///   `fail_precondition`;
/// * E2EE stale-attestation negative declares an attests_to that's NOT in active_tags_at_send_time.
pub fn run_mls_move_covered_frontier_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("mls_move_covered_frontier_fixture.json")?;
    validate_profile(&fixture, "ak.profile.mls_covered_frontier_vectors.v1")?;

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("mls covered_frontier fixture missing vectors[]"))?;
    let mut covered: std::collections::BTreeSet<&str> = Default::default();
    for vector in vectors {
        let name = required_str(vector, "name")?;
        match name {
            "covered_frontier_accumulates_governance_refs_idempotent" => {
                let cell_id = required_str(vector, "cell_id")?;
                if !cell_id.starts_with("ak:cell:ck.component.mls.covered_frontier.v1:") {
                    bail!("vector {name} cell_id wrong family: {cell_id}");
                }
                let ops = vector
                    .get("anchored_ops")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing anchored_ops[]"))?;
                let mut tags_seen: Vec<&str> = Vec::new();
                for op in ops {
                    if required_str(op, "op")? != "or_set_add" {
                        bail!("vector {name} accumulate vector ops must all be or_set_add");
                    }
                    tags_seen.push(required_str(op, "tag")?);
                }
                let unique_tags: std::collections::BTreeSet<&str> =
                    tags_seen.iter().copied().collect();
                if unique_tags.len() == tags_seen.len() {
                    bail!(
                        "vector {name} must include at least one duplicate-tag re-add to test or-set idempotence"
                    );
                }
                let expected = vector
                    .get("expected")
                    .ok_or_else(|| anyhow!("vector {name} missing expected"))?;
                let active: std::collections::BTreeSet<&str> = expected
                    .get("active_tags")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} expected.active_tags missing"))?
                    .iter()
                    .filter_map(Value::as_str)
                    .collect();
                if active != unique_tags {
                    bail!(
                        "vector {name} expected.active_tags MUST equal the unique-tag set; got {active:?} vs {unique_tags:?}"
                    );
                }
                covered.insert(name);
            }
            "rotation_removes_old_ref_keeps_others" => {
                let ops = vector
                    .get("anchored_ops")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing anchored_ops[]"))?;
                let mut adds: Vec<&str> = Vec::new();
                let mut removes: Vec<&str> = Vec::new();
                for op in ops {
                    let kind = required_str(op, "op")?;
                    let tag = required_str(op, "tag")?;
                    match kind {
                        "or_set_add" => adds.push(tag),
                        "or_set_remove" => removes.push(tag),
                        other => bail!("vector {name} unknown op {other}"),
                    }
                }
                if removes.is_empty() {
                    bail!("vector {name} rotation must declare at least one or_set_remove");
                }
                let expected_active: std::collections::BTreeSet<&str> = vector
                    .pointer("/expected/active_tags")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} expected.active_tags missing"))?
                    .iter()
                    .filter_map(Value::as_str)
                    .collect();
                let computed_active: std::collections::BTreeSet<&str> = adds
                    .iter()
                    .filter(|tag| !removes.contains(tag))
                    .copied()
                    .collect();
                if expected_active != computed_active {
                    bail!(
                        "vector {name} expected.active_tags drift: declared {expected_active:?} computed {computed_active:?}"
                    );
                }
                covered.insert(name);
            }
            "governance_move_not_blocked_by_covered_frontier" => {
                let mv = vector
                    .get("governance_move")
                    .ok_or_else(|| anyhow!("vector {name} missing governance_move"))?;
                let preconds = mv
                    .get("preconditions")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!("vector {name} governance_move missing preconditions[]")
                    })?;
                if !preconds.is_empty() {
                    bail!(
                        "vector {name} governance_move MUST have empty preconditions[] (governance is NOT blocked on covered_frontier)"
                    );
                }
                if required_str(
                    vector
                        .get("expected")
                        .ok_or_else(|| anyhow!("vector {name} missing expected"))?,
                    "outcome",
                )? != "accept"
                {
                    bail!("vector {name} governance Move must accept");
                }
                covered.insert(name);
            }
            "mls_commit_attests_three_cells_in_one_move" => {
                let mv = vector
                    .get("mls_commit_move")
                    .ok_or_else(|| anyhow!("vector {name} missing mls_commit_move"))?;
                let _ = required_str(mv, "covered_frontier_attests_to")?;
                let effects = mv
                    .get("effects")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing effects[]"))?;
                if effects.len() != 3 {
                    bail!(
                        "vector {name} MLS commit Move MUST write exactly 3 cells (covered_frontier + epoch + group_state); got {} effects",
                        effects.len()
                    );
                }
                let mut cell_families: std::collections::BTreeSet<&str> = Default::default();
                for effect in effects {
                    let cell = required_str(effect, "cell")?;
                    let family = cell
                        .strip_prefix("ak:cell:")
                        .and_then(|tail| tail.split(':').next())
                        .ok_or_else(|| anyhow!("vector {name} cell {cell} malformed"))?;
                    cell_families.insert(family);
                }
                for required in [
                    "ak.component.mls.covered_frontier.v1",
                    "ak.component.mls.epoch.v1",
                    "ak.component.mls.group_state.v1",
                ] {
                    if !cell_families.contains(required) {
                        bail!("vector {name} MLS commit must write cell family {required}");
                    }
                }
                covered.insert(name);
            }
            other => bail!("vector {name}: unexpected name {other}"),
        }
        emit_vector("mls_covered_frontier.vector", vector, json!({"name": name}));
    }
    for required in [
        "covered_frontier_accumulates_governance_refs_idempotent",
        "rotation_removes_old_ref_keeps_others",
        "governance_move_not_blocked_by_covered_frontier",
        "mls_commit_attests_three_cells_in_one_move",
    ] {
        if !covered.contains(required) {
            bail!("mls covered_frontier fixture missing required vector {required}");
        }
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("mls covered_frontier fixture missing negative_vectors[]"))?;
    let mut covered_missing = false;
    let mut covered_stale = false;
    for vector in negatives {
        let name = required_str(vector, "name")?;
        let expected = vector
            .get("expected")
            .ok_or_else(|| anyhow!("negative vector {name} missing expected"))?;
        if required_str(expected, "outcome")? != "reject" {
            bail!("negative vector {name} must expect outcome=reject");
        }
        if required_str(expected, "reason_code")? != "fail_precondition" {
            bail!(
                "negative vector {name} reason_code must be fail_precondition (covered_frontier admission)"
            );
        }
        if required_str(expected, "missing_precondition")? != "covered_frontier" {
            bail!("negative vector {name} missing_precondition must be covered_frontier");
        }
        match name {
            "e2ee_message_missing_covered_frontier_precondition_rejected" => {
                let mv = vector
                    .get("e2ee_move")
                    .ok_or_else(|| anyhow!("negative vector {name} missing e2ee_move"))?;
                let preconds = mv
                    .get("preconditions")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!("negative vector {name} e2ee_move missing preconditions[]")
                    })?;
                let has_cf = preconds
                    .iter()
                    .any(|p| p.get("kind").and_then(Value::as_str) == Some("covered_frontier"));
                if has_cf {
                    bail!(
                        "negative vector {name} declared a covered_frontier precondition; this vector must omit it"
                    );
                }
                covered_missing = true;
            }
            "e2ee_message_with_stale_covered_frontier_ref_rejected" => {
                let active: std::collections::BTreeSet<&str> = vector
                    .get("active_tags_at_send_time")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect())
                    .unwrap_or_default();
                let mv = vector
                    .get("e2ee_move")
                    .ok_or_else(|| anyhow!("negative vector {name} missing e2ee_move"))?;
                let preconds = mv
                    .get("preconditions")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        anyhow!("negative vector {name} e2ee_move missing preconditions[]")
                    })?;
                let attests = preconds.iter().find_map(|p| {
                    if p.get("kind").and_then(Value::as_str) == Some("covered_frontier") {
                        p.get("attests_to").and_then(Value::as_str)
                    } else {
                        None
                    }
                });
                let attests = attests.ok_or_else(|| {
                    anyhow!(
                        "negative vector {name} stale variant must DECLARE a covered_frontier precondition"
                    )
                })?;
                if active.contains(attests) {
                    bail!(
                        "negative vector {name} attests_to ref {attests} IS in active_tags_at_send_time; this vector requires it to be stale"
                    );
                }
                covered_stale = true;
            }
            other => bail!("negative vector unexpected name {other}"),
        }
    }
    if !(covered_missing && covered_stale) {
        bail!(
            "mls covered_frontier fixture must cover both missing-precondition and stale-attestation negatives"
        );
    }
    Ok(())
}
/// Round 22 — event-kind ↔ LatticeKind dispatch consistency vectors.
///
/// Cross-checks `tests/fixtures/event_kind_lattice_dispatch_fixture.json`
/// against the LIVE event-kind-registry (registry/event-kind-registry.json).
/// The fixture declares EXPECTED canonical lattices per cell-family AND the
/// validator confirms the live registry matches. Drift from either side
/// fails loudly. Pattern mirrors `discovery_profile_fixture` cross-checking
/// operation-registry.surface_groups.
///
/// Validator pins:
/// * every active+reducer_input+durable_event kind that declares `cell_family` declares a `lattice`
///   in the core set {or-set, mv-register, cas-register, fsm, counter, ordered-log};
/// * cell_family namespace prefix is `ck.component.`;
/// * a single cell_family is bound to exactly one lattice across all kinds that declare it;
/// * bottom mode ∈ {reject, expose};
/// * every family in `expected_cell_family_lattice_bindings.<lattice>` MUST resolve to that lattice
///   in the live registry; conversely, every live cell_family that appears in the registry MUST be
///   listed under the correct lattice in the expected bindings.
pub fn run_event_kind_lattice_dispatch_fixture_suite() -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    let fixture = load_local_fixture("event_kind_lattice_dispatch_fixture.json")?;
    validate_profile(
        &fixture,
        "ak.profile.event_kind_lattice_dispatch_vectors.v1",
    )?;

    const CORE_LATTICES: &[&str] = &[
        "or_set",
        "mv_register",
        "cas_register",
        "fsm",
        "counter",
        "ordered_log",
    ];
    const VALID_BOTTOM_MODES: &[&str] = &["reject", "expose"];

    // Walk the live registry and build cell_family → set<lattice>.
    let registry = crate::conformance::load_artifact_json("registry/event-kind-registry.json")?;
    let event_kinds = registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event-kind-registry missing event_kinds[]"))?;
    let mut family_to_lattice: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut family_to_bottom: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut all_live_families: BTreeSet<String> = BTreeSet::new();
    for entry in event_kinds {
        let status = entry.get("status").and_then(Value::as_str).unwrap_or("");
        let wire_scope = entry
            .get("wire_scope")
            .and_then(Value::as_str)
            .unwrap_or("");
        if status != "active"
            || entry.get("reducer_input").and_then(Value::as_bool) != Some(true)
            || wire_scope != "durable_event"
        {
            continue;
        }
        let Some(family) = entry.get("cell_family").and_then(Value::as_str) else {
            continue;
        };
        if !family.starts_with("ak.component.") {
            bail!(
                "live event-kind-registry: cell_family {family} does not start with `ck.component.`"
            );
        }
        let lattice = required_str(entry, "lattice")?;
        if !CORE_LATTICES.contains(&lattice) {
            bail!(
                "live event-kind-registry: cell_family {family} declares non-core lattice {lattice}"
            );
        }
        let bottom = required_str(entry, "bottom")?;
        if !VALID_BOTTOM_MODES.contains(&bottom) {
            bail!(
                "live event-kind-registry: cell_family {family} declares invalid bottom={bottom}"
            );
        }
        family_to_lattice
            .entry(family.to_owned())
            .or_default()
            .insert(lattice.to_owned());
        family_to_bottom
            .entry(family.to_owned())
            .or_default()
            .insert(bottom.to_owned());
        all_live_families.insert(family.to_owned());
    }
    // Single-lattice-per-family invariant.
    for (family, lattices) in &family_to_lattice {
        if lattices.len() > 1 {
            bail!(
                "live event-kind-registry: cell_family {family} bound to multiple lattices {lattices:?} — only one allowed"
            );
        }
    }

    // Walk the expected bindings and confirm every declared family resolves
    // to the expected lattice in the live registry.
    let expected_bindings = fixture
        .get("expected_cell_family_lattice_bindings")
        .ok_or_else(|| anyhow!("fixture missing expected_cell_family_lattice_bindings"))?;
    let expected_pairs: &[(&str, &str)] = &[
        ("or_set_families", "or_set"),
        ("cas_register_families", "cas_register"),
        ("fsm_families", "fsm"),
        ("ordered_log_families", "ordered_log"),
        ("mv_register_families", "mv_register"),
    ];
    let mut all_expected_families: BTreeSet<String> = BTreeSet::new();
    for (group, expected_lattice) in expected_pairs {
        let arr = expected_bindings
            .get(*group)
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("expected_cell_family_lattice_bindings.{group} missing"))?;
        for v in arr {
            let family = v.as_str().ok_or_else(|| {
                anyhow!("expected_cell_family_lattice_bindings.{group} entry must be a string")
            })?;
            if !all_expected_families.insert(family.to_owned()) {
                bail!(
                    "expected_cell_family_lattice_bindings: cell_family {family} listed under multiple lattices"
                );
            }
            let live_lattices = family_to_lattice.get(family).ok_or_else(|| {
                anyhow!(
                    "expected family {family} (group={group}) not present in live event-kind-registry"
                )
            })?;
            // Single lattice already enforced above.
            let live = live_lattices
                .iter()
                .next()
                .expect("non-empty by construction");
            if live != *expected_lattice {
                bail!(
                    "cell_family {family}: live lattice={live} != expected lattice={expected_lattice} (group={group})"
                );
            }
        }
    }
    // Conversely: every live family covered by some expected group.
    for family in &all_live_families {
        if !all_expected_families.contains(family) {
            bail!(
                "live cell_family {family} not declared under any expected_cell_family_lattice_bindings group"
            );
        }
    }

    // Vectors — structural sanity (each scope is recognised, each outcome
    // matches the validator semantics already enforced above). Vectors are
    // descriptive; the live cross-check IS the validation.
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event_kind_lattice_dispatch fixture missing vectors[]"))?;
    let mut covered_invariants: BTreeSet<&str> = Default::default();
    for vector in vectors {
        let name = required_str(vector, "name")?;
        let scope = required_str(vector, "scope")?;
        let expected = vector
            .get("expected")
            .ok_or_else(|| anyhow!("vector {name} missing expected"))?;
        let outcome = required_str(expected, "outcome")?;
        match (name, scope, outcome) {
            (
                "every_active_reducer_input_durable_kind_with_cell_family_declares_one_lattice",
                "live_registry",
                "all_kinds_consistent",
            )
            | (
                "no_cell_family_appears_in_two_distinct_lattices",
                "live_registry",
                "single_lattice_per_cell_family",
            )
            | ("cell_family_namespace_is_cx_component", "live_registry", "namespace_ok")
            | ("bottom_mode_is_reject_or_expose", "live_registry", "bottom_mode_ok") => {
                covered_invariants.insert(name);
            }
            (
                "expected_or_set_families_resolve_to_or_set_in_live_registry",
                "expected_cell_family_lattice_bindings.or_set_families",
                "lattice_match",
            )
            | (
                "expected_cas_register_families_resolve_to_cas_register_in_live_registry",
                "expected_cell_family_lattice_bindings.cas_register_families",
                "lattice_match",
            )
            | (
                "expected_fsm_families_resolve_to_fsm_in_live_registry",
                "expected_cell_family_lattice_bindings.fsm_families",
                "lattice_match",
            )
            | (
                "expected_ordered_log_families_resolve_to_ordered_log_in_live_registry",
                "expected_cell_family_lattice_bindings.ordered_log_families",
                "lattice_match",
            )
            | (
                "expected_mv_register_families_resolve_to_mv_register_in_live_registry",
                "expected_cell_family_lattice_bindings.mv_register_families",
                "lattice_match",
            ) => {
                let lat = required_str(expected, "lattice")?;
                if !CORE_LATTICES.contains(&lat) {
                    bail!("vector {name} expected.lattice {lat} not in core set");
                }
                covered_invariants.insert(name);
            }
            (other_name, other_scope, other_outcome) => bail!(
                "event_kind_lattice_dispatch fixture unexpected vector ({other_name}, scope={other_scope}, outcome={other_outcome})"
            ),
        }
        emit_vector(
            "event_kind_lattice_dispatch.invariant",
            vector,
            json!({"name": name, "scope": scope, "outcome": outcome}),
        );
    }
    for required in [
        "every_active_reducer_input_durable_kind_with_cell_family_declares_one_lattice",
        "no_cell_family_appears_in_two_distinct_lattices",
        "cell_family_namespace_is_cx_component",
        "bottom_mode_is_reject_or_expose",
        "expected_or_set_families_resolve_to_or_set_in_live_registry",
        "expected_cas_register_families_resolve_to_cas_register_in_live_registry",
        "expected_fsm_families_resolve_to_fsm_in_live_registry",
        "expected_ordered_log_families_resolve_to_ordered_log_in_live_registry",
        "expected_mv_register_families_resolve_to_mv_register_in_live_registry",
    ] {
        if !covered_invariants.contains(required) {
            bail!("event_kind_lattice_dispatch fixture missing required vector {required}");
        }
    }

    // Negative vectors — pure structural / synthetic. Validator confirms each
    // declared drift name + reason_code maps to a known synthesised case.
    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event_kind_lattice_dispatch fixture missing negative_vectors[]"))?;
    let mut neg_non_core = false;
    let mut neg_wrong_ns = false;
    let mut neg_invalid_bottom = false;
    for vector in negatives {
        let name = required_str(vector, "name")?;
        let drift = vector
            .get("drift")
            .ok_or_else(|| anyhow!("negative vector {name} missing drift"))?;
        let drift_kind = required_str(drift, "kind")?;
        let expected = vector
            .get("expected")
            .ok_or_else(|| anyhow!("negative vector {name} missing expected"))?;
        if required_str(expected, "outcome")? != "reject" {
            bail!("negative vector {name} must expect outcome=reject");
        }
        let reason = required_str(expected, "reason_code")?;
        match (drift_kind, reason) {
            ("non_core_lattice", "lattice_not_in_core_set") => {
                let lat = required_str(drift, "lattice")?;
                if CORE_LATTICES.contains(&lat) {
                    bail!(
                        "negative vector {name} drift.lattice {lat} IS in core set — not a real drift"
                    );
                }
                neg_non_core = true;
            }
            ("wrong_namespace", "cell_family_invalid_namespace") => {
                let cf = required_str(drift, "cell_family")?;
                if cf.starts_with("ak.component.") {
                    bail!(
                        "negative vector {name} drift.cell_family {cf} IS in ck.component.* namespace — not a real drift"
                    );
                }
                neg_wrong_ns = true;
            }
            ("invalid_bottom", "bottom_invalid_value") => {
                let b = required_str(drift, "bottom")?;
                if VALID_BOTTOM_MODES.contains(&b) {
                    bail!("negative vector {name} drift.bottom {b} IS valid — not a real drift");
                }
                neg_invalid_bottom = true;
            }
            (k, r) => {
                bail!("negative vector {name} drift.kind={k} not paired with reason_code={r}")
            }
        }
    }
    if !(neg_non_core && neg_wrong_ns && neg_invalid_bottom) {
        bail!(
            "event_kind_lattice_dispatch fixture must cover (a) non-core lattice, (b) wrong cell_family namespace, (c) invalid bottom mode"
        );
    }

    Ok(())
}
/// A1 Round 23 — event-kind payload coverage.
pub fn run_event_kind_payload_coverage_fixture_suite() -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    let fixture = load_local_fixture("event_kind_payload_coverage_fixture.json")?;
    validate_profile(
        &fixture,
        "ak.profile.event_kind_payload_coverage_vectors.v1",
    )?;

    let registry = crate::conformance::load_artifact_json("registry/event-kind-registry.json")?;
    let event_kinds = registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event-kind-registry missing event_kinds[]"))?;
    type LiveKindMeta = (Option<String>, Option<String>, Option<String>, String);
    let mut live_kind_meta: BTreeMap<String, LiveKindMeta> = BTreeMap::new();
    for entry in event_kinds {
        let kind = required_str(entry, "event_kind")?;
        let status = entry.get("status").and_then(Value::as_str).unwrap_or("");
        let cell_family = entry
            .get("cell_family")
            .and_then(Value::as_str)
            .map(|s| s.to_owned());
        let lattice = entry
            .get("lattice")
            .and_then(Value::as_str)
            .map(|s| s.to_owned());
        let bottom = entry
            .get("bottom")
            .and_then(Value::as_str)
            .map(|s| s.to_owned());
        live_kind_meta.insert(
            kind.to_owned(),
            (cell_family, lattice, bottom, status.to_owned()),
        );
    }

    let positives = fixture
        .get("positive_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event_kind_payload_coverage fixture missing positive_vectors[]"))?;
    if positives.len() < 20 {
        bail!(
            "event_kind_payload_coverage fixture has {} positive vectors, expected >= 20",
            positives.len()
        );
    }

    let mut covered_tuples: BTreeSet<(String, String)> = BTreeSet::new();
    for v in positives {
        let name = required_str(v, "name")?;
        let kind = required_str(v, "event_kind")?;
        let claimed_family = required_str(v, "cell_family")?;
        let claimed_lattice = required_str(v, "lattice")?;
        let claimed_bottom = required_str(v, "bottom")?;

        let (live_family, live_lattice, live_bottom, status) =
            live_kind_meta.get(kind).ok_or_else(|| {
                anyhow!("vector {name} references event_kind {kind} not in live registry")
            })?;
        if status != "active" {
            bail!("vector {name} event_kind {kind} status={status} (expected active)");
        }
        let live_family = live_family.as_deref().ok_or_else(|| {
            anyhow!("vector {name} event_kind {kind} has no cell_family in registry")
        })?;
        let live_lattice = live_lattice
            .as_deref()
            .ok_or_else(|| anyhow!("vector {name} event_kind {kind} has no lattice in registry"))?;
        let live_bottom = live_bottom
            .as_deref()
            .ok_or_else(|| anyhow!("vector {name} event_kind {kind} has no bottom in registry"))?;
        if live_family != claimed_family {
            bail!(
                "vector {name} cell_family drift: claimed {claimed_family}, registry {live_family}"
            );
        }
        if live_lattice != claimed_lattice {
            bail!(
                "vector {name} lattice drift: claimed {claimed_lattice}, registry {live_lattice}"
            );
        }
        if live_bottom != claimed_bottom {
            bail!("vector {name} bottom drift: claimed {claimed_bottom}, registry {live_bottom}");
        }
        covered_tuples.insert((claimed_family.to_owned(), claimed_lattice.to_owned()));
        emit_vector(
            "event_kind_payload_coverage.kind",
            v,
            json!({
                "name": name,
                "event_kind": kind,
                "cell_family": claimed_family,
                "lattice": claimed_lattice,
                "bottom": claimed_bottom,
            }),
        );
    }
    if covered_tuples.len() < 6 {
        bail!(
            "event_kind_payload_coverage fixture covers only {} distinct (cell_family, lattice) tuples, expected >= 6",
            covered_tuples.len()
        );
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("event_kind_payload_coverage fixture missing negative_vectors[]"))?;
    let mut neg_unknown = false;
    let mut neg_family = false;
    let mut neg_lattice = false;
    for v in negatives {
        let name = required_str(v, "name")?;
        let outcome = v
            .pointer("/expected/outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("negative {name} missing expected.outcome"))?;
        if outcome != "reject" {
            bail!("negative {name} expected outcome=reject");
        }
        let drift = v
            .pointer("/drift/kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("negative {name} missing drift.kind"))?;
        match drift {
            "unknown_kind" => {
                let synth = required_str(v, "event_kind")?;
                if live_kind_meta.contains_key(synth) {
                    bail!("negative {name} synthetic event_kind {synth} actually exists");
                }
                neg_unknown = true;
            }
            "cell_family_mismatch" => {
                let claimed = required_str(v, "claimed_cell_family")?;
                let kind = required_str(v, "event_kind")?;
                let (live_family, ..) = live_kind_meta
                    .get(kind)
                    .ok_or_else(|| anyhow!("negative {name} event_kind {kind} not in registry"))?;
                if live_family.as_deref() == Some(claimed) {
                    bail!("negative {name} claimed_cell_family equals registry — not a real drift");
                }
                neg_family = true;
            }
            "lattice_mismatch" => {
                let claimed = required_str(v, "claimed_lattice")?;
                let kind = required_str(v, "event_kind")?;
                let (_, live_lattice, ..) = live_kind_meta
                    .get(kind)
                    .ok_or_else(|| anyhow!("negative {name} event_kind {kind} not in registry"))?;
                if live_lattice.as_deref() == Some(claimed) {
                    bail!("negative {name} claimed_lattice equals registry — not a real drift");
                }
                neg_lattice = true;
            }
            other => bail!("negative {name} unknown drift.kind {other}"),
        }
    }
    if !(neg_unknown && neg_family && neg_lattice) {
        bail!(
            "event_kind_payload_coverage fixture must cover unknown_kind, cell_family_mismatch, lattice_mismatch negatives"
        );
    }

    Ok(())
}
/// B1 Round 23 — quarantine-on-fork algorithm vectors.
pub fn run_state_resolution_quarantine_fixture_suite() -> Result<()> {
    use std::collections::BTreeSet;

    let fixture = load_local_fixture("state_resolution_quarantine_fixture.json")?;
    validate_profile(
        &fixture,
        "ak.profile.state_resolution_quarantine_vectors.v1",
    )?;

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("state_resolution_quarantine fixture missing vectors[]"))?;
    if vectors.len() < 5 {
        bail!(
            "state_resolution_quarantine fixture has {} vectors, expected >= 5",
            vectors.len()
        );
    }

    let mut covered_quarantine = 0usize;
    let mut covered_admin_escalation = false;
    let mut covered_or_set_no_quarantine = false;
    for v in vectors {
        let name = required_str(v, "name")?;
        let lattice = required_str(v, "lattice")?;
        let bottom = required_str(v, "bottom")?;
        let ops = v
            .get("ops")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("vector {name} missing ops[]"))?;
        let outcome = v
            .pointer("/expected/outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing expected.outcome"))?;

        match (lattice, bottom, outcome) {
            ("cas_register", "reject", "all_heads_quarantined")
            | ("fsm", "reject", "all_heads_quarantined") => {
                let picks = v
                    .pointer("/expected/reducer_picks_winner")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing expected.reducer_picks_winner")
                    })?;
                if picks {
                    bail!("vector {name} reducer_picks_winner must be false");
                }
                let admin = v
                    .pointer("/expected/admin_escalation_required")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing expected.admin_escalation_required")
                    })?;
                if !admin {
                    bail!("vector {name} admin_escalation_required must be true");
                }
                let quarantined = v
                    .pointer("/expected/quarantined_op_ids")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("vector {name} missing expected.quarantined_op_ids"))?;
                let q_set: BTreeSet<&str> = quarantined.iter().filter_map(Value::as_str).collect();
                let op_set: BTreeSet<&str> = ops
                    .iter()
                    .filter_map(|o| o.get("op_id").and_then(Value::as_str))
                    .collect();
                if q_set != op_set {
                    bail!(
                        "vector {name} quarantined_op_ids must equal full ops[] set; q={q_set:?} ops={op_set:?}"
                    );
                }
                covered_quarantine += 1;
            }
            ("cas_register", "reject", "repair_admits_winner") => {
                let escalation = v
                    .get("admin_escalation")
                    .ok_or_else(|| anyhow!("vector {name} missing admin_escalation"))?;
                let _ = required_str(escalation, "kind")?;
                let _ = required_str(escalation, "endorsed_winner_op_id")?;
                covered_admin_escalation = true;
                covered_quarantine += 1;
            }
            ("or_set", "expose", "or_set_union") => {
                let admin = v
                    .pointer("/expected/admin_escalation_required")
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        anyhow!("vector {name} missing expected.admin_escalation_required")
                    })?;
                if admin {
                    bail!("vector {name} or-set must NOT require admin escalation");
                }
                covered_or_set_no_quarantine = true;
            }
            (l, b, o) => bail!("vector {name} unexpected (lattice={l}, bottom={b}, outcome={o})"),
        }
        emit_vector(
            "state_resolution_quarantine.vector",
            v,
            json!({"name": name, "lattice": lattice, "bottom": bottom, "outcome": outcome}),
        );
    }

    if covered_quarantine < 4 {
        bail!("state_resolution_quarantine fixture must include >= 4 quarantine vectors");
    }
    if !covered_admin_escalation {
        bail!("state_resolution_quarantine fixture must cover admin escalation repair");
    }
    if !covered_or_set_no_quarantine {
        bail!("state_resolution_quarantine fixture must cover or-set non-quarantine union");
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("state_resolution_quarantine fixture missing negative_vectors[]"))?;
    let mut saw_hlc = false;
    let mut saw_actor = false;
    for v in negatives {
        let name = required_str(v, "name")?;
        let drift = v
            .pointer("/drift/kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("negative {name} missing drift.kind"))?;
        match drift {
            "hlc_tiebreak_attempt" => saw_hlc = true,
            "actor_priority_tiebreak_attempt" => saw_actor = true,
            other => bail!("negative {name} unknown drift.kind {other}"),
        }
    }
    if !(saw_hlc && saw_actor) {
        bail!(
            "state_resolution_quarantine fixture must cover HLC tiebreak + actor priority forbidden vectors"
        );
    }

    Ok(())
}
/// B5 Round 23 — membership transition FSM vectors.
pub fn run_membership_fsm_fixture_suite() -> Result<()> {
    use std::collections::BTreeSet;

    let fixture = load_local_fixture("membership_fsm_fixture.json")?;
    validate_profile(&fixture, "ak.profile.membership_fsm_vectors.v1")?;

    let valid_states: BTreeSet<&str> = ["invited", "join", "leave", "ban", "kick", "knock"]
        .into_iter()
        .collect();
    let legal_table: &[(&str, &str, bool)] = &[
        ("invited", "join", false),
        ("invited", "leave", false),
        ("invited", "ban", true),
        ("join", "leave", false),
        ("join", "ban", true),
        ("join", "kick", true),
        ("leave", "invited", false),
        ("leave", "ban", true),
        ("ban", "leave", true),
        ("kick", "invited", false),
        ("kick", "knock", false),
        ("knock", "invited", false),
        ("knock", "leave", false),
    ];
    let legal_set: BTreeSet<(&str, &str)> = legal_table.iter().map(|(f, t, _)| (*f, *t)).collect();

    let legal = fixture
        .get("legal_transitions")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("membership_fsm fixture missing legal_transitions[]"))?;
    if legal.len() < 8 {
        bail!(
            "membership_fsm fixture has {} legal_transitions, expected >= 8",
            legal.len()
        );
    }
    for v in legal {
        let name = required_str(v, "name")?;
        let from = required_str(v, "from")?;
        let to = required_str(v, "to")?;
        if !valid_states.contains(from) {
            bail!("legal {name}: from state {from} not in known set");
        }
        if !valid_states.contains(to) {
            bail!("legal {name}: to state {to} not in known set");
        }
        if !legal_set.contains(&(from, to)) {
            bail!("legal {name}: transition {from}→{to} is NOT in canonical FSM table");
        }
        let outcome = v
            .pointer("/expected/outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("legal {name} missing expected.outcome"))?;
        if outcome != "accept" {
            bail!("legal {name}: outcome must be accept, got {outcome}");
        }
        let next = v
            .pointer("/expected/next_state")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("legal {name} missing expected.next_state"))?;
        if next != to {
            bail!("legal {name}: next_state {next} != to {to}");
        }
        emit_vector(
            "membership_fsm.legal",
            v,
            json!({"name": name, "from": from, "to": to, "next_state": next}),
        );
    }

    let illegal = fixture
        .get("illegal_transitions")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("membership_fsm fixture missing illegal_transitions[]"))?;
    if illegal.len() < 7 {
        bail!(
            "membership_fsm fixture has {} illegal_transitions, expected >= 7",
            illegal.len()
        );
    }
    for v in illegal {
        let name = required_str(v, "name")?;
        let from = required_str(v, "from")?;
        let to = required_str(v, "to")?;
        let actor = required_str(v, "actor")?;
        if !valid_states.contains(from) {
            bail!("illegal {name}: from state {from} not in known set");
        }
        if !valid_states.contains(to) {
            bail!("illegal {name}: to state {to} not in known set");
        }
        let in_table = legal_set.contains(&(from, to));
        let admin_required = legal_table
            .iter()
            .find(|(f, t, _)| *f == from && *t == to)
            .map(|(_, _, a)| *a)
            .unwrap_or(false);
        let is_actually_illegal = !in_table || (admin_required && actor == "self");
        if !is_actually_illegal {
            bail!(
                "illegal {name}: transition {from}→{to} (actor={actor}) is actually legal in canonical table"
            );
        }
        let outcome = v
            .pointer("/expected/outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("illegal {name} missing expected.outcome"))?;
        if outcome != "reject" {
            bail!("illegal {name}: outcome must be reject");
        }
        let reason = v
            .pointer("/expected/reason_code")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("illegal {name} missing expected.reason_code"))?;
        if reason != "fsm_transition_forbidden" {
            bail!("illegal {name}: reason_code must be fsm_transition_forbidden, got {reason}");
        }
    }

    Ok(())
}
/// C1 Round 23 — constraint family × subtype coverage.
pub fn run_constraint_family_fixture_suite() -> Result<()> {
    use std::collections::BTreeSet;

    let fixture = load_local_fixture("constraint_family_fixture.json")?;
    validate_profile(&fixture, "ak.profile.constraint_family_vectors.v1")?;

    let valid_types: BTreeSet<&str> = [
        "temporal",
        "field_access",
        "type_restriction",
        "scope_limitation",
        "delegation_control",
        "quota",
        "claim_based",
        "confidentiality",
    ]
    .into_iter()
    .collect();
    let valid_classes: BTreeSet<&str> = ["stateless", "grant_local", "space_state", "external"]
        .into_iter()
        .collect();
    let valid_effects: BTreeSet<&str> = ["allow", "deny", "quarantine", "require_review"]
        .into_iter()
        .collect();

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("constraint_family fixture missing vectors[]"))?;

    let mut covered_types: BTreeSet<String> = BTreeSet::new();
    for v in vectors {
        let name = required_str(v, "name")?;
        let ct = required_str(v, "constraint_type")?;
        if !valid_types.contains(ct) {
            bail!("vector {name} constraint_type {ct} not in schema enum");
        }
        let constraint = v
            .get("constraint")
            .ok_or_else(|| anyhow!("vector {name} missing constraint object"))?;
        let body_ct = required_str(constraint, "constraint_type")?;
        if body_ct != ct {
            bail!("vector {name} constraint.constraint_type {body_ct} != outer {ct}");
        }
        let effect = required_str(constraint, "effect")?;
        if !valid_effects.contains(effect) {
            bail!("vector {name} effect {effect} not valid");
        }
        let class = required_str(constraint, "evaluation_class")?;
        if !valid_classes.contains(class) {
            bail!("vector {name} evaluation_class {class} not valid");
        }
        let outcome = v
            .pointer("/expected/outcome")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing expected.outcome"))?;
        if outcome != "shape_ok" {
            bail!("vector {name} expected.outcome must be shape_ok");
        }
        let exp_class = v
            .pointer("/expected/evaluation_class")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing expected.evaluation_class"))?;
        if exp_class != class {
            bail!(
                "vector {name} expected.evaluation_class {exp_class} != constraint.evaluation_class {class}"
            );
        }
        let fast = v
            .pointer("/expected/fast_path_eligible")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} missing expected.fast_path_eligible"))?;
        let expect_fast = matches!(class, "stateless" | "grant_local");
        if fast != expect_fast {
            bail!(
                "vector {name} fast_path_eligible={fast} but evaluation_class={class} (expected fast={expect_fast})"
            );
        }
        covered_types.insert(ct.to_owned());
        emit_vector(
            "constraint_family.shape",
            v,
            json!({"name": name, "constraint_type": ct, "evaluation_class": class, "effect": effect, "fast_path_eligible": fast}),
        );
    }

    for required in &valid_types {
        if !covered_types.contains(*required) {
            bail!("constraint_family fixture missing positive vector for family {required}");
        }
    }

    let fast_tests = fixture
        .get("fast_path_tests")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("constraint_family fixture missing fast_path_tests[]"))?;
    if fast_tests.len() < 4 {
        bail!(
            "constraint_family fixture has {} fast_path_tests, expected >= 4",
            fast_tests.len()
        );
    }
    let mut covered_classes: BTreeSet<String> = BTreeSet::new();
    for v in fast_tests {
        let name = required_str(v, "name")?;
        let class = required_str(v, "evaluation_class")?;
        if !valid_classes.contains(class) {
            bail!("fast_path_test {name} evaluation_class {class} invalid");
        }
        let cacheable = v
            .get("expected_cacheable")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("fast_path_test {name} missing expected_cacheable"))?;
        let expect = matches!(class, "stateless" | "grant_local");
        if cacheable != expect {
            bail!(
                "fast_path_test {name} expected_cacheable={cacheable}, evaluation_class={class}, expected {expect}"
            );
        }
        covered_classes.insert(class.to_owned());
    }
    if covered_classes.len() < 4 {
        bail!(
            "constraint_family fixture fast_path_tests must cover all 4 evaluation_classes; got {} ({:?})",
            covered_classes.len(),
            covered_classes
        );
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("constraint_family fixture missing negative_vectors[]"))?;
    let mut saw_unknown = false;
    let mut saw_loosen = false;
    let mut saw_unknown_subtype = false;
    for v in negatives {
        let name = required_str(v, "name")?;
        let drift = v
            .pointer("/drift/kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("negative {name} missing drift.kind"))?;
        match drift {
            "unknown_constraint_type" => {
                let body_ct = v
                    .pointer("/constraint/constraint_type")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("negative {name} missing constraint.constraint_type"))?;
                if valid_types.contains(body_ct) {
                    bail!("negative {name} constraint_type {body_ct} is actually valid");
                }
                saw_unknown = true;
            }
            "evaluation_class_loosened" => {
                let claimed = required_str(v, "claimed_evaluation_class")?;
                let ct = required_str(v, "constraint_type")?;
                let canonical = canonical_evaluation_class(ct);
                let canon_rank = class_strictness_rank(canonical);
                let claimed_rank = class_strictness_rank(claimed);
                if claimed_rank >= canon_rank {
                    bail!(
                        "negative {name} claimed class {claimed} is not strictly looser than canonical {canonical}"
                    );
                }
                saw_loosen = true;
            }
            "unknown_subtype" => {
                saw_unknown_subtype = true;
            }
            other => bail!("negative {name} unknown drift.kind {other}"),
        }
    }
    if !(saw_unknown && saw_loosen && saw_unknown_subtype) {
        bail!(
            "constraint_family fixture must cover unknown_constraint_type, evaluation_class loosen, unknown_subtype negatives"
        );
    }

    // C3-C6 — cross-family composition compositions: validate that the
    // combined_evaluation_class is the strictness-max of every member family
    // and fast_path_eligible follows accordingly.
    let compositions = fixture
        .get("cross_family_compositions")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("constraint_family fixture missing cross_family_compositions[]"))?;
    if compositions.len() < 4 {
        bail!(
            "constraint_family fixture cross_family_compositions has {} entries, expected >= 4",
            compositions.len()
        );
    }
    let mut covered_pairs: BTreeSet<(String, String)> = BTreeSet::new();
    for v in compositions {
        let name = required_str(v, "name")?;
        let families: Vec<&str> = v
            .get("families")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("composition {name} missing families[]"))?
            .iter()
            .filter_map(Value::as_str)
            .collect();
        if families.len() < 2 {
            bail!("composition {name} must have at least 2 families");
        }
        for f in &families {
            if !valid_types.contains(*f) {
                bail!("composition {name} family {f} not a valid constraint_type");
            }
        }
        // Combine class via strictness max; trust the fixture's declared
        // canonical_for_family hints if absent, fall back to per-family
        // canonical (subtype-blind).
        let mut max_rank: u8 = 0;
        let mut max_class: &str = "stateless";
        for f in &families {
            let class = canonical_evaluation_class(f);
            let rank = class_strictness_rank(class);
            if rank > max_rank {
                max_rank = rank;
                max_class = class;
            }
        }
        let declared_combined =
            required_str(v.pointer("/expected").unwrap(), "combined_evaluation_class")?;
        if declared_combined != max_class {
            bail!(
                "composition {name} declared combined_evaluation_class={declared_combined} but max-of-families is {max_class}"
            );
        }
        let declared_fast = v
            .pointer("/expected/fast_path_eligible")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("composition {name} missing fast_path_eligible"))?;
        let expect_fast = matches!(max_class, "stateless" | "grant_local");
        if declared_fast != expect_fast {
            bail!(
                "composition {name} fast_path_eligible={declared_fast} but combined={max_class} → expected {expect_fast}"
            );
        }
        // Pair coverage across distinct family pairs.
        let mut sorted = families.clone();
        sorted.sort();
        covered_pairs.insert((sorted[0].to_owned(), sorted[1].to_owned()));
    }
    if covered_pairs.len() < 4 {
        bail!(
            "constraint_family cross_family_compositions must cover at least 4 distinct family pairs; got {}",
            covered_pairs.len()
        );
    }

    Ok(())
}
/// C2 Round 26 — constraint evaluation_class fast-path classification.
///
/// Spec: `extensions/constraint-schema.md` §2.3 evaluation_class table. Each
/// (family, subtype) tuple maps to one canonical evaluation_class. The
/// validator re-derives the class from the family per the canonical mapping
/// and asserts fast/slow path classification matches.
pub fn run_constraint_evaluation_class_fixture_suite() -> Result<()> {
    let fixture = load_local_fixture("constraint_evaluation_class_fixture.json")?;
    validate_profile(
        &fixture,
        "ak.profile.constraint_evaluation_class_vectors.v1",
    )?;

    let mapping = fixture
        .get("canonical_mapping")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("constraint_evaluation_class fixture missing canonical_mapping"))?;
    // Cross-check the fixture's canonical_mapping against the implementation.
    for (family, declared) in mapping {
        let declared_str = declared
            .as_str()
            .ok_or_else(|| anyhow!("canonical_mapping[{family}] not a string"))?;
        let canonical = canonical_evaluation_class(family);
        if declared_str != canonical {
            bail!(
                "canonical_mapping[{family}]={declared_str} disagrees with implementation {canonical}"
            );
        }
    }

    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("constraint_evaluation_class fixture missing vectors[]"))?;
    if vectors.len() < 4 {
        bail!(
            "constraint_evaluation_class fixture has {} vectors, expected >= 4",
            vectors.len()
        );
    }

    let mut covered_families = std::collections::BTreeSet::<String>::new();
    let mut fast_seen = false;
    let mut slow_seen = false;
    for v in vectors {
        let name = required_str(v, "name")?;
        let family = required_str(v, "family")?;
        let class = required_str(v, "evaluation_class")?;
        let canonical = canonical_evaluation_class(family);
        if class != canonical {
            bail!(
                "vector {name} evaluation_class {class} disagrees with canonical {canonical} for family {family}"
            );
        }
        let fast = v
            .get("fast_path_eligible")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} missing fast_path_eligible"))?;
        let expect_fast = matches!(class, "stateless" | "grant_local");
        if fast != expect_fast {
            bail!(
                "vector {name} fast_path_eligible={fast} but class {class} → expected fast={expect_fast}"
            );
        }
        let needs_state = v
            .get("needs_space_state")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} missing needs_space_state"))?;
        let needs_external = v
            .get("needs_external_call")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("vector {name} missing needs_external_call"))?;
        let expected_state = class == "space_state";
        let expected_external = class == "external";
        if needs_state != expected_state {
            bail!(
                "vector {name} needs_space_state={needs_state} but class {class} (expected {expected_state})"
            );
        }
        if needs_external != expected_external {
            bail!(
                "vector {name} needs_external_call={needs_external} but class {class} (expected {expected_external})"
            );
        }
        let classification = v
            .pointer("/expected/classification")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("vector {name} missing expected.classification"))?;
        let expect_classification = if expect_fast {
            "fast_path"
        } else {
            "slow_path"
        };
        if classification != expect_classification {
            bail!(
                "vector {name} classification {classification} disagrees with class {class} (expected {expect_classification})"
            );
        }
        if expect_fast {
            fast_seen = true;
        } else {
            slow_seen = true;
        }
        covered_families.insert(family.to_owned());
        emit_vector(
            "constraint_evaluation_class.classify",
            v,
            json!({
                "name": name,
                "family": family,
                "evaluation_class": class,
                "fast_path_eligible": fast,
                "classification": classification,
            }),
        );
    }
    let required_families = [
        "temporal",
        "field_access",
        "type_restriction",
        "scope_limitation",
        "delegation_control",
        "quota",
        "claim_based",
        "confidentiality",
    ];
    for required in required_families {
        if !covered_families.contains(required) {
            bail!("constraint_evaluation_class fixture missing coverage for family {required}");
        }
    }
    if !(fast_seen && slow_seen) {
        bail!("constraint_evaluation_class fixture must cover both fast-path and slow-path");
    }

    let negatives = fixture
        .get("negative_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("constraint_evaluation_class fixture missing negative_vectors[]"))?;
    for v in negatives {
        let name = required_str(v, "name")?;
        let reason =
            expected_reason(v).ok_or_else(|| anyhow!("negative {name} missing reason_code"))?;
        if reason != "evaluation_class_mismatch" {
            bail!("negative {name} reason_code must be evaluation_class_mismatch");
        }
        let family = required_str(v, "family")?;
        let declared = required_str(v, "declared_evaluation_class")?;
        let canonical = canonical_evaluation_class(family);
        if declared == canonical {
            bail!(
                "negative {name} declared {declared} matches canonical {canonical} — not a drift"
            );
        }
        let expected = required_str(v.pointer("/expected").unwrap(), "expected_evaluation_class")?;
        if expected != canonical {
            bail!(
                "negative {name} expected_evaluation_class {expected} disagrees with canonical {canonical}"
            );
        }
    }

    Ok(())
}
fn canonical_evaluation_class(constraint_type: &str) -> &'static str {
    // Per `authz/constraint-schema.md` §2.3 evaluation_class table. Used by
    // both the C1 constraint_family suite (loosen-rejection check) and the
    // C2 constraint_evaluation_class suite (canonical_mapping lint).
    //
    // Subtype-specific deviations (e.g. field_access w/ condition →
    // space_state) are handled by the per-vector validators when needed.
    match constraint_type {
        "temporal" => "stateless",
        "field_access" => "stateless",
        "type_restriction" => "stateless",
        "scope_limitation" => "grant_local",
        "delegation_control" => "grant_local",
        "quota" => "space_state",
        "claim_based" => "external",
        "confidentiality" => "space_state",
        _ => "external",
    }
}
fn class_strictness_rank(class: &str) -> u8 {
    match class {
        "stateless" => 0,
        "grant_local" => 1,
        "space_state" => 2,
        "external" => 3,
        _ => 0,
    }
}
