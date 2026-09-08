//! Event-kind lattice dispatch, membership FSM, and constraint-family /
//! evaluation-class wire-model conformance vectors.

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{emit_vector, expected_reason, load_local_fixture};
use crate::conformance::{required_str, validate_profile};

/// Event-kind ↔ LatticeKind dispatch consistency vectors.
///
/// Cross-checks the SDK's generated event-kind descriptors against the
/// independently executable lattice registry. The fixture contains only
/// invariant and negative-mutation metadata; it does not mirror protocol
/// registry data.
///
/// Validator pins:
/// * every active+reducer_input+durable_event kind that declares `cell_family` declares a `lattice`
///   in the core set {or-set, mv-register, cas-register, fsm, counter, ordered-log};
/// * cell_family namespace prefix is `ak.component.`;
/// * a single cell_family is bound to exactly one lattice across all kinds that declare it;
/// * bottom mode ∈ {reject, expose, inert};
/// * the generated descriptor closure and executable registry closure match exactly.
pub fn run_event_kind_lattice_dispatch_fixture_suite() -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    let fixture = load_local_fixture("event-kind-lattice-dispatch-fixture.json")?;
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
    // `inert` is the registry's explicit mode for lattices whose join cannot
    // produce a Bottom diagnostic (for example an or-set).  It is distinct
    // from `reject` (quarantine on Bottom) and `expose` (surface conflict),
    // and is normative in event-kind-registry.json.
    const VALID_BOTTOM_MODES: &[&str] = &["reject", "expose", "inert"];

    // Walk the SDK-generated descriptors and build cell_family → set<lattice>.
    let mut family_to_lattice: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut family_to_bottom: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut all_live_families: BTreeSet<String> = BTreeSet::new();
    for descriptor in arkret_wire::EVENT_KIND_DESCRIPTORS {
        if !descriptor.reducer_input
            || descriptor.wire_scope != arkret_wire::EventWireScope::DurableEvent
        {
            continue;
        }
        for write in descriptor.cell_writes {
            let Some(family_id) = write.cell_family else {
                if descriptor.kind != "ak.conflict.recovery"
                    || write.cell_ref_rule.is_none()
                    || write.effect_projection_rule.is_none_or(|rule| {
                        rule.operator() != Some(arkret_wire::EventCellRuleOperator::Reset)
                    })
                {
                    bail!("dynamic cell write is not the closed conflict-recovery reset");
                }
                continue;
            };
            let family = family_id.as_str();
            if !family.starts_with("ak.component.") {
                bail!(
                    "SDK event-kind descriptor: cell_family {family} does not start with `ak.component.`"
                );
            }
            let lattice = write
                .lattice
                .ok_or_else(|| anyhow!("SDK cell write {family} omits lattice"))?
                .as_str();
            if !CORE_LATTICES.contains(&lattice) {
                bail!(
                    "SDK event-kind descriptor: cell_family {family} declares non-core lattice {lattice}"
                );
            }
            let bottom = write
                .bottom
                .ok_or_else(|| anyhow!("SDK cell write {family} omits bottom"))?
                .as_str();
            if !VALID_BOTTOM_MODES.contains(&bottom) {
                bail!(
                    "SDK event-kind descriptor: cell_family {family} declares invalid bottom={bottom}"
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
    }
    // Single-lattice-per-family invariant.
    for (family, lattices) in &family_to_lattice {
        if lattices.len() > 1 {
            bail!(
                "SDK event-kind descriptors bind cell_family {family} to multiple lattices {lattices:?}"
            );
        }
    }

    let executable_bindings = arkret_lattice_registry::lattice_bindings_for_sdk_registry();
    let executable_families = executable_bindings
        .iter()
        .map(|(family, ..)| *family)
        .collect::<BTreeSet<_>>();
    if executable_families != all_live_families.iter().map(String::as_str).collect() {
        bail!("SDK descriptor and executable lattice registry family closures differ");
    }
    for (family, lattice, bottom) in executable_bindings {
        let descriptor_lattice = family_to_lattice
            .get(family)
            .and_then(|values| values.iter().next())
            .ok_or_else(|| anyhow!("executable family {family} is absent from SDK descriptors"))?;
        let descriptor_bottom = family_to_bottom
            .get(family)
            .and_then(|values| values.iter().next())
            .ok_or_else(|| anyhow!("executable family {family} omits bottom mode"))?;
        if descriptor_lattice != lattice.as_wire_str()
            || descriptor_bottom
                != match bottom {
                    arkret_state::state::EventCellBottom::Reject => "reject",
                    arkret_state::state::EventCellBottom::Expose => "expose",
                    arkret_state::state::EventCellBottom::Inert => "inert",
                }
        {
            bail!("SDK descriptor and executable lattice binding differ for {family}");
        }
    }
    validate_canonical_fsm_contracts(&family_to_lattice)?;
    let registry = crate::conformance::load_artifact_json("registry/event-kind-registry.json")?;
    validate_actor_private_contracts(&registry, &all_live_families)?;

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
            | ("cell_family_namespace_is_ak_component", "live_registry", "namespace_ok")
            | ("bottom_mode_is_reject_or_expose", "live_registry", "bottom_mode_ok") => {
                covered_invariants.insert(name);
            }
            (
                "sdk_descriptors_match_executable_lattice_registry",
                "sdk_and_executable_registry",
                "exact_closure",
            ) => {
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
        "cell_family_namespace_is_ak_component",
        "bottom_mode_is_reject_or_expose",
        "sdk_descriptors_match_executable_lattice_registry",
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
                        "negative vector {name} drift.cell_family {cf} IS in ak.component.* namespace — not a real drift"
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

fn validate_actor_private_contracts(
    raw_registry: &Value,
    shared_families: &std::collections::BTreeSet<String>,
) -> Result<()> {
    use std::collections::BTreeSet;

    use arkret_lattice_registry::{
        ActorPrivateCandidate, ActorPrivateMergeOutcome, build_actor_private_registry,
    };

    let private = build_actor_private_registry()
        .map_err(|error| anyhow!("actor-private contract resolution failed: {error}"))?;
    let expected_families = raw_registry
        .pointer("/actor_private_contracts/cell_families")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("registry omits actor-private cell_families"))?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let expected_events = raw_registry
        .pointer("/actor_private_contracts/event_writes")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow!("registry omits actor-private event_writes"))?
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let actual_families = private
        .families()
        .map(|contract| contract.cell_family.as_str())
        .collect::<BTreeSet<_>>();
    let actual_events = private
        .event_writes()
        .map(|write| write.event_kind.as_str())
        .collect::<BTreeSet<_>>();
    if actual_families != expected_families || actual_events != expected_events {
        bail!("actor-private resolver is not an exact closure of the canonical registry");
    }
    if actual_families
        .iter()
        .any(|family| !family.starts_with("ak.private.") || shared_families.contains(*family))
    {
        bail!("shared and actor-private cell registries overlap");
    }
    for event_kind in &actual_events {
        let event =
            json!({"kind": event_kind, "actor_id": "ak:did_core:web:fixture", "payload": {}});
        private
            .validate_private_event_shape(&event)
            .map_err(|error| anyhow!("{event_kind} private shape rejected: {error}"))?;
        let mut shared = event;
        shared["effects"] = json!([]);
        if private.validate_private_event_shape(&shared).is_ok() {
            bail!("{event_kind} accepted shared CBS effects in an actor-private envelope");
        }
    }

    let current = ActorPrivateCandidate {
        value: json!({"route": "one"}),
        revision: Some(1),
        expected_revision: Some(0),
        causal_order: None,
        hlc: None,
        device_id: None,
    };
    let concurrent = ActorPrivateCandidate {
        value: json!({"route": "two"}),
        revision: Some(1),
        expected_revision: Some(0),
        causal_order: None,
        hlc: None,
        device_id: None,
    };
    if !matches!(
        private.apply(
            "ak.private.device.push_route.v1",
            Some(&current),
            concurrent
        )?,
        ActorPrivateMergeOutcome::Conflict
    ) {
        bail!("concurrent distinct actor-private push routes did not fail closed");
    }
    Ok(())
}

fn validate_canonical_fsm_contracts(
    family_to_lattice: &std::collections::BTreeMap<String, std::collections::BTreeSet<String>>,
) -> Result<()> {
    use std::collections::BTreeSet;

    let contracts = arkret_lattice_registry::canonical_fsm_contracts()
        .map_err(|error| anyhow!("canonical FSM contract resolution failed: {error}"))?;
    if contracts.is_empty() {
        bail!("canonical FSM contract resolver returned no contracts");
    }
    let mut families = BTreeSet::new();
    for contract in contracts {
        if !families.insert(contract.cell_family.clone()) {
            bail!("duplicate resolved FSM contract {}", contract.cell_family);
        }
        if family_to_lattice
            .get(&contract.cell_family)
            .is_none_or(|lattices| lattices.len() != 1 || !lattices.contains("fsm"))
        {
            bail!(
                "resolved FSM contract {} does not map to exactly one FSM lattice",
                contract.cell_family
            );
        }
        let states = contract.states.iter().collect::<BTreeSet<_>>();
        if states.len() != contract.states.len()
            || contract
                .initial_states
                .iter()
                .chain(contract.terminal_states.iter())
                .any(|state| !states.contains(state))
            || contract
                .allowed_transitions
                .iter()
                .any(|(from, to)| !states.contains(from) || !states.contains(to))
        {
            bail!(
                "resolved FSM contract {} is not an exact closed state machine",
                contract.cell_family
            );
        }
        for transition in &contract.allowed_transitions {
            let runtime = (
                Value::String(transition.0.clone()),
                Value::String(transition.1.clone()),
            );
            if !contract.runtime_transitions.contains(&runtime) {
                bail!(
                    "resolved FSM contract {} omitted runtime transition {:?}",
                    contract.cell_family,
                    transition
                );
            }
        }
        if contract
            .runtime_initial_state
            .as_ref()
            .is_some_and(Value::is_null)
        {
            for initial in &contract.initial_states {
                if !contract
                    .runtime_transitions
                    .contains(&(Value::Null, Value::String(initial.clone())))
                {
                    bail!(
                        "resolved FSM contract {} omitted null->{initial}",
                        contract.cell_family
                    );
                }
            }
        }
    }
    Ok(())
}
/// A1 — event-kind payload coverage.
pub fn run_event_kind_payload_coverage_fixture_suite() -> Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    let fixture = load_local_fixture("event-kind-payload-coverage-fixture.json")?;
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
        let contract_write = event_kinds
            .iter()
            .find(|entry| entry.get("event_kind").and_then(Value::as_str) == Some(kind))
            .and_then(|entry| entry.get("cell_writes"))
            .and_then(Value::as_array)
            .and_then(|writes| {
                writes.iter().find(|write| {
                    write.get("cell_family").and_then(Value::as_str) == Some(claimed_family)
                })
            });
        let live_family = live_family
            .as_deref()
            .or_else(|| contract_write.and_then(|write| write.get("cell_family")?.as_str()))
            .ok_or_else(|| {
                anyhow!("vector {name} event_kind {kind} has no matching cell_family in registry")
            })?;
        let live_lattice = live_lattice
            .as_deref()
            .or_else(|| contract_write.and_then(|write| write.get("lattice")?.as_str()))
            .ok_or_else(|| anyhow!("vector {name} event_kind {kind} has no lattice in registry"))?;
        let live_bottom = live_bottom
            .as_deref()
            .or_else(|| contract_write.and_then(|write| write.get("bottom")?.as_str()))
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
/// B1 — quarantine-on-fork algorithm vectors.
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
    if vectors.len() != 4 {
        bail!(
            "state_resolution_quarantine fixture has {} vectors, expected exactly 4",
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

    if covered_quarantine < 3 {
        bail!("state_resolution_quarantine fixture must include >= 3 quarantine vectors");
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
/// B5 — membership transition FSM vectors.
pub fn run_membership_fsm_fixture_suite() -> Result<()> {
    use std::collections::BTreeSet;

    let fixture = load_local_fixture("membership_fsm_fixture.json")?;
    validate_profile(&fixture, "ak.profile.membership_fsm_vectors.v1")?;

    let valid_states: BTreeSet<&str> = ["join", "knock", "leave", "ban"].into_iter().collect();
    let legal_table: &[(&str, &str)] = &[
        ("leave", "knock"),
        ("leave", "join"),
        ("knock", "join"),
        ("knock", "leave"),
        ("join", "leave"),
        ("leave", "ban"),
        ("knock", "ban"),
        ("join", "ban"),
        ("ban", "leave"),
    ];
    let legal_set: BTreeSet<(&str, &str)> = legal_table.iter().copied().collect();

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
        let is_actually_illegal = !legal_set.contains(&(from, to));
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
/// C1 — constraint family × constraint_subkind coverage.
pub fn run_constraint_family_fixture_suite() -> Result<()> {
    use std::collections::BTreeSet;

    let fixture = load_local_fixture("constraint_family_fixture.json")?;
    validate_profile(&fixture, "ak.profile.constraint_family_vectors.v1")?;

    let valid_types: BTreeSet<&str> = [
        "temporal",
        "field_access",
        "kind_restriction",
        "scope_limitation",
        "authority_control",
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
        let ct = required_str(v, "constraint_kind")?;
        if !valid_types.contains(ct) {
            bail!("vector {name} constraint_kind {ct} not in schema enum");
        }
        let constraint = v
            .get("constraint")
            .ok_or_else(|| anyhow!("vector {name} missing constraint object"))?;
        let body_ct = required_str(constraint, "constraint_kind")?;
        if body_ct != ct {
            bail!("vector {name} constraint.constraint_kind {body_ct} != outer {ct}");
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
            json!({"name": name, "constraint_kind": ct, "evaluation_class": class, "effect": effect, "fast_path_eligible": fast}),
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
    let mut saw_unknown_subkind = false;
    for v in negatives {
        let name = required_str(v, "name")?;
        let drift = v
            .pointer("/drift/kind")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("negative {name} missing drift.kind"))?;
        match drift {
            "unknown_constraint_kind" => {
                let body_ct = v
                    .pointer("/constraint/constraint_kind")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("negative {name} missing constraint.constraint_kind"))?;
                if valid_types.contains(body_ct) {
                    bail!("negative {name} constraint_kind {body_ct} is actually valid");
                }
                saw_unknown = true;
            }
            "evaluation_class_loosened" => {
                let claimed = required_str(v, "claimed_evaluation_class")?;
                let ct = required_str(v, "constraint_kind")?;
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
            "unknown_subkind" => {
                saw_unknown_subkind = true;
            }
            other => bail!("negative {name} unknown drift.kind {other}"),
        }
    }
    if !(saw_unknown && saw_loosen && saw_unknown_subkind) {
        bail!(
            "constraint_family fixture must cover unknown_constraint_kind, evaluation_class loosen, unknown_subkind negatives"
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
                bail!("composition {name} family {f} not a valid constraint_kind");
            }
        }
        // Combine class via strictness max; trust the fixture's declared
        // canonical_for_family hints if absent, fall back to per-family
        // canonical (constraint_subkind-blind).
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
/// C2 — constraint evaluation_class fast-path classification.
///
/// Spec: `extensions/constraint-schema.md` §2.3 evaluation_class table. Each
/// (family, constraint_subkind) tuple maps to one canonical evaluation_class. The
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
        "kind_restriction",
        "scope_limitation",
        "authority_control",
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
fn canonical_evaluation_class(constraint_kind: &str) -> &'static str {
    // Per `authz/constraint-schema.md` §2.3 evaluation_class table. Used by
    // both the C1 constraint_family suite (loosen-rejection check) and the
    // C2 constraint_evaluation_class suite (canonical_mapping lint).
    //
    // Subkind-specific deviations (e.g. field_access w/ condition →
    // space_state) are handled by the per-vector validators when needed.
    match constraint_kind {
        "temporal" => "stateless",
        "field_access" => "stateless",
        "kind_restriction" => "stateless",
        "scope_limitation" => "grant_local",
        "authority_control" => "grant_local",
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
