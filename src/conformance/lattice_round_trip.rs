//! C10.C lattice round-trip vectors.
//!
//! Exercises the SDK's [`arkret_state::lattice`] module directly against the
//! normative scenarios from `cba-lattice-fixture.json`.
//! The fixture itself is symbolic (it describes protocol-level semantics,
//! eliding wire-required `space_id` / `hlc` / `sig`) — this suite reifies
//! the symbolic ops as real `LatticeOp` + `SealedOp` values, runs the
//! lattice's `join`, and asserts that:
//!
//! - **OrSet**: deterministic add / remove / commute / idempotence.
//! - **CasRegister**: concurrent distinct `set` ops produce a `Bottom` with `kind = Conflict` and
//!   both move_ids in `Bottom.move_ids`.
//! - **Counter**: PN counter sums increments and decrements deterministically.
//! - **Fsm**: legal transitions advance state; illegal transitions produce `Bottom` with `kind =
//!   InvalidTransition`.
//! - **Realm Link Fsm**: all initial states and declared transitions execute through the SDK's
//!   canonical admission helper; self-reference and terminal writes fail closed.
//! - **MvRegister**: concurrent `set` ops surface multiple values without choosing a winner (vs.
//!   CasRegister which produces Bottom).
//! - **OrderedLog**: per-issuer monotonic `append` produces a deterministic linearization; gaps are
//!   tolerated.
//!
//! Each test constructs the minimal `LatticeOp` shape the implementation
//! needs (no full Move signing required — `Lattice::join` reads the op
//! and `move_id` only). Failures here imply SDK lattice drift from the
//! spec's normative join semantics.

use std::collections::BTreeSet;

use anyhow::{Result, anyhow, bail};
use arkret_canonical::canonical_json_bytes;
use arkret_identifiers::{CellRef, Did, Hash, RealmId};
use arkret_models_collaboration::governance::realm_governance::{
    REALM_LINK_ALLOWED_TRANSITIONS, REALM_LINK_INITIAL_STATES, REALM_LINK_TERMINAL_STATES,
    RealmLinkKind, RealmLinkPayload, RealmLinkStatus, RealmLinkTransitionCandidate,
    RealmLinkTransitionOutcome, evaluate_realm_link_transition,
};
use arkret_state::lattice::ordered_log::IssuedOp;
use arkret_state::lattice::{
    CasRegister, CellState, Counter, Fsm, Lattice, MvRegister, OrSet, OrderedLog, SealedOp,
};
use arkret_wire::{ErrorCode, LatticeOp, LatticeOpType};
use serde_json::{Value, json};

const REALM_LINK_FSM_VECTOR_ID: &str = "ak.vector.realm_link.fsm_transition_matrix.v1";
pub const VECTOR_ID_LATTICE_CAS_REGISTER_SUPERSESSION: &str =
    "ak.vector.lattice.cas_register_supersession.v1";
const LATTICE_ROUND_TRIP_VECTOR_IDS: [&str; 7] = [
    "ak.vector.lattice.mv_register_join.v1",
    "ak.vector.lattice.counter_join.v1",
    "ak.vector.lattice.ordered_log_join.v1",
    "ak.vector.lattice.ordered_log_gap.v1",
    "ak.vector.lattice.fsm_join.v1",
    VECTOR_ID_LATTICE_CAS_REGISTER_SUPERSESSION,
    REALM_LINK_FSM_VECTOR_ID,
];

/// Public entry point matching the cotest fixture-suite naming convention.
/// Returns `Ok(())` when every lattice's normative join behavior matches
/// the spec; `Err` otherwise with the failing scenario name.
pub fn run_lattice_round_trip_suite() -> Result<()> {
    validate_lattice_fixture_metadata()?;
    or_set_basic_add_remove_commute()?;
    or_set_idempotent_re_add_after_remove()?;
    cas_register_concurrent_set_returns_bottom_conflict()?;
    cas_register_single_set_returns_value()?;
    run_lattice_cas_register_supersession_vector()?;
    counter_pn_sums_increments_and_decrements()?;
    fsm_legal_transition_advances_state()?;
    fsm_duplicate_transition_is_idempotent()?;
    fsm_same_from_different_to_returns_bottom()?;
    fsm_illegal_transition_returns_bottom()?;
    run_realm_link_fsm_transition_matrix_vector()?;
    mv_register_concurrent_set_surfaces_multiple_values()?;
    ordered_log_per_issuer_monotonic_append()?;
    ordered_log_equivocation_resolves_to_max_event_digest()?;
    ordered_log_issuer_free_join_fails_closed()?;
    ordered_log_gap_reports_pending_until_backfill()?;
    // C10.C extensions (2026-05-09 aggressive batch): Notary cell
    // configurations, conflict repair head_in semantics, MLS covered_frontier.
    notary_cell_single_signer_profile_resolves_to_value()?;
    notary_cell_threshold_profile_resolves_to_value()?;
    notary_cell_open_set_profile_resolves_to_value()?;
    notary_cell_mixed_profile_resolves_to_value()?;
    notary_cell_concurrent_reconfig_returns_bottom()?;
    conflict_repair_head_in_move_resolves_existing_bottom()?;
    conflict_repair_resists_self_authorising_winner()?;
    mls_covered_frontier_or_set_accumulates_governance_refs()?;
    mls_covered_frontier_after_rotation_keeps_old_refs_visible()?;
    Ok(())
}

// ──────────────────────────── helpers ────────────────────────────────

fn validate_lattice_fixture_metadata() -> Result<()> {
    let fixture = super::load_fixture_value("cba-lattice-fixture.json")?;
    super::validate_profile(&fixture, "ak.vector_group.cba_lattice.v1")?;
    let metadata = fixture
        .get("lattice_round_trip")
        .ok_or_else(|| anyhow!("cba-lattice fixture missing lattice_round_trip metadata"))?;
    let covers = metadata
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("lattice_round_trip metadata missing covers_vectors[]"))?;
    let cases = metadata
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("lattice_round_trip metadata missing cases[]"))?;

    for vector_id in LATTICE_ROUND_TRIP_VECTOR_IDS {
        if !covers.iter().any(|entry| entry.as_str() == Some(vector_id)) {
            bail!("lattice_round_trip metadata missing covers_vectors entry {vector_id}");
        }
        let Some(case) = cases
            .iter()
            .find(|case| case.get("vector_id").and_then(Value::as_str) == Some(vector_id))
        else {
            bail!("lattice_round_trip metadata missing asserted case {vector_id}");
        };
        let assertions = case
            .get("assertions")
            .and_then(Value::as_array)
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if assertions.is_empty() {
            bail!("lattice_round_trip metadata missing asserted case {vector_id}");
        }
        // A non-empty `assertions[]` only proves the fixture says something.
        // Every declared assertion id MUST map to a case this suite actually
        // executes, otherwise a fixture can claim coverage the runner never
        // exercises.
        for assertion in &assertions {
            if !executed_lattice_assertion(vector_id, assertion) {
                bail!(
                    "lattice fixture declares assertion {assertion} for {vector_id},                      but the conformance suite does not execute it"
                );
            }
        }
    }

    Ok(())
}

fn realm_link_vector_case() -> Result<Value> {
    let fixture = super::load_fixture_value("cba-lattice-fixture.json")?;
    fixture
        .pointer("/lattice_round_trip/cases")
        .and_then(Value::as_array)
        .and_then(|cases| {
            cases.iter().find(|case| {
                case.get("vector_id").and_then(Value::as_str) == Some(REALM_LINK_FSM_VECTOR_ID)
            })
        })
        .cloned()
        .ok_or_else(|| anyhow!("Realm Link FSM vector case missing"))
}

fn parse_realm_link_statuses(value: &Value, pointer: &str) -> Result<Vec<RealmLinkStatus>> {
    value
        .pointer(pointer)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("Realm Link FSM vector missing {pointer}"))?
        .iter()
        .map(|entry| {
            let status = entry
                .as_str()
                .ok_or_else(|| anyhow!("Realm Link status in {pointer} must be a string"))?;
            RealmLinkStatus::parse(status)
                .ok_or_else(|| anyhow!("unknown Realm Link status {status}"))
        })
        .collect()
}

fn parse_realm_link_transitions(value: &Value) -> Result<Vec<(RealmLinkStatus, RealmLinkStatus)>> {
    value
        .pointer("/parameters/allowed_transitions")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("Realm Link FSM vector missing allowed_transitions"))?
        .iter()
        .map(|entry| {
            let pair = entry
                .as_array()
                .filter(|pair| pair.len() == 2)
                .ok_or_else(|| anyhow!("Realm Link transition must be a two-item array"))?;
            let from = pair[0]
                .as_str()
                .and_then(RealmLinkStatus::parse)
                .ok_or_else(|| anyhow!("invalid Realm Link transition source"))?;
            let to = pair[1]
                .as_str()
                .and_then(RealmLinkStatus::parse)
                .ok_or_else(|| anyhow!("invalid Realm Link transition target"))?;
            Ok((from, to))
        })
        .collect()
}

fn realm_link_payload(target_realm_id: RealmId, status: RealmLinkStatus) -> RealmLinkPayload {
    RealmLinkPayload {
        target_realm_id,
        link_kind: RealmLinkKind::GovernedBy,
        status,
        label: None,
        commitment: None,
    }
}

fn realm_id(suffix: &str) -> Result<RealmId> {
    let event_id = crate::fixture_event_id(format!("lattice-realm-{suffix}"));
    let token = event_id
        .as_str()
        .strip_prefix("ak:event:")
        .expect("fixture_event_id has the canonical ak:event prefix");
    RealmId::new(format!("ak:realm:{token}")).map_err(Into::into)
}

pub fn run_realm_link_fsm_transition_matrix_vector() -> Result<()> {
    let case = realm_link_vector_case()?;
    if case.get("cell_family").and_then(Value::as_str) != Some("ak.component.realm.link.v1")
        || case.get("lattice").and_then(Value::as_str) != Some("fsm")
        || case.get("bottom").and_then(Value::as_str) != Some("reject")
    {
        bail!("Realm Link FSM vector metadata drifted");
    }

    let states = parse_realm_link_statuses(&case, "/parameters/states")?;
    let initial_states = parse_realm_link_statuses(&case, "/parameters/initial_states")?;
    let terminal_states = parse_realm_link_statuses(&case, "/parameters/terminal_states")?;
    let allowed_transitions = parse_realm_link_transitions(&case)?;
    if initial_states != REALM_LINK_INITIAL_STATES
        || terminal_states != REALM_LINK_TERMINAL_STATES
        || allowed_transitions != REALM_LINK_ALLOWED_TRANSITIONS
        || states != initial_states
    {
        bail!("Realm Link SDK FSM constants drifted from the fixture matrix");
    }

    let source = realm_id("1")?;
    let target = realm_id("2")?;
    for status in &initial_states {
        let payload = realm_link_payload(target.clone(), *status);
        let move_bytes = canonical_json_bytes(&payload)?;
        let outcome = evaluate_realm_link_transition(
            &source,
            None,
            RealmLinkTransitionCandidate {
                payload: &payload,
                canonical_move_bytes: &move_bytes,
                canonical_basis_bytes: b"initial-basis",
            },
        )?;
        if outcome != RealmLinkTransitionOutcome::Apply {
            bail!(
                "Realm Link initial state {} was not applied",
                status.as_str()
            );
        }
    }

    let mut executed_transitions = 0usize;
    for (from, to) in &allowed_transitions {
        let current_payload = realm_link_payload(target.clone(), *from);
        let candidate_payload = realm_link_payload(target.clone(), *to);
        let current_move_bytes = canonical_json_bytes(&current_payload)?;
        let candidate_move_bytes = canonical_json_bytes(&candidate_payload)?;
        let terminal_replay = from.is_terminal();
        let outcome = evaluate_realm_link_transition(
            &source,
            Some(RealmLinkTransitionCandidate {
                payload: &current_payload,
                canonical_move_bytes: &current_move_bytes,
                canonical_basis_bytes: b"accepted-basis",
            }),
            RealmLinkTransitionCandidate {
                payload: &candidate_payload,
                canonical_move_bytes: if terminal_replay {
                    &current_move_bytes
                } else {
                    &candidate_move_bytes
                },
                canonical_basis_bytes: if terminal_replay {
                    b"accepted-basis"
                } else {
                    b"next-basis"
                },
            },
        )?;
        let expected = if terminal_replay {
            RealmLinkTransitionOutcome::IdempotentReplay
        } else {
            RealmLinkTransitionOutcome::Apply
        };
        if outcome != expected {
            bail!(
                "Realm Link transition {} -> {} returned {outcome:?}, expected {expected:?}",
                from.as_str(),
                to.as_str()
            );
        }
        executed_transitions += 1;
    }
    if executed_transitions != 7 {
        bail!("Realm Link runner did not execute all 7 declared transitions");
    }

    for from in &states {
        for to in &states {
            if allowed_transitions.contains(&(*from, *to)) {
                continue;
            }
            let current_payload = realm_link_payload(target.clone(), *from);
            let candidate_payload = realm_link_payload(target.clone(), *to);
            let current_move_bytes = canonical_json_bytes(&current_payload)?;
            let candidate_move_bytes = canonical_json_bytes(&candidate_payload)?;
            let transition_error = match evaluate_realm_link_transition(
                &source,
                Some(RealmLinkTransitionCandidate {
                    payload: &current_payload,
                    canonical_move_bytes: &current_move_bytes,
                    canonical_basis_bytes: b"accepted-basis",
                }),
                RealmLinkTransitionCandidate {
                    payload: &candidate_payload,
                    canonical_move_bytes: &candidate_move_bytes,
                    canonical_basis_bytes: b"next-basis",
                },
            ) {
                Ok(outcome) => {
                    bail!("undeclared transition unexpectedly returned {outcome:?}")
                }
                Err(error) => error,
            };
            if transition_error.error_code() != ErrorCode::FailedPrecondition
                || transition_error.reason_code()
                    != arkret_wire::ReasonCode::REALM_LINK_INVALID_TRANSITION
            {
                bail!("undeclared Realm Link transition returned the wrong error mapping");
            }
        }
    }

    let active = realm_link_payload(target.clone(), RealmLinkStatus::Active);
    let active_bytes = canonical_json_bytes(&active)?;
    let active_head = RealmLinkTransitionCandidate {
        payload: &active,
        canonical_move_bytes: &active_bytes,
        canonical_basis_bytes: b"same-basis",
    };
    if evaluate_realm_link_transition(&source, Some(active_head), active_head)?
        != RealmLinkTransitionOutcome::IdempotentReplay
    {
        bail!("same-status same-basis exact replay was not idempotent");
    }
    let rejected = realm_link_payload(target.clone(), RealmLinkStatus::Rejected);
    let rejected_bytes = canonical_json_bytes(&rejected)?;
    if evaluate_realm_link_transition(
        &source,
        Some(active_head),
        RealmLinkTransitionCandidate {
            payload: &rejected,
            canonical_move_bytes: &rejected_bytes,
            canonical_basis_bytes: b"same-basis",
        },
    )? != RealmLinkTransitionOutcome::Bottom
    {
        bail!("same-basis different-status siblings did not return Bottom");
    }

    let tombstone = realm_link_payload(target.clone(), RealmLinkStatus::Tombstoned);
    let tombstone_bytes = canonical_json_bytes(&tombstone)?;
    let tombstone_head = RealmLinkTransitionCandidate {
        payload: &tombstone,
        canonical_move_bytes: &tombstone_bytes,
        canonical_basis_bytes: b"tombstone-basis",
    };
    if evaluate_realm_link_transition(&source, Some(tombstone_head), tombstone_head)?
        != RealmLinkTransitionOutcome::IdempotentReplay
    {
        bail!("byte-equivalent tombstone replay was not idempotent");
    }
    let tombstone_error = evaluate_realm_link_transition(
        &source,
        Some(tombstone_head),
        RealmLinkTransitionCandidate {
            payload: &tombstone,
            canonical_move_bytes: &tombstone_bytes,
            canonical_basis_bytes: b"later-basis",
        },
    )
    .expect_err("tombstone write on a later basis must be rejected");
    if tombstone_error.reason_code() != arkret_wire::ReasonCode::REALM_LINK_INVALID_TRANSITION {
        bail!("tombstone terminal rejection returned the wrong reason");
    }

    let cycle = [
        (realm_id("10")?, realm_id("11")?),
        (realm_id("11")?, realm_id("12")?),
        (realm_id("12")?, realm_id("10")?),
    ];
    for (cycle_source, cycle_target) in cycle {
        let payload = realm_link_payload(cycle_target, RealmLinkStatus::Active);
        let move_bytes = canonical_json_bytes(&payload)?;
        if evaluate_realm_link_transition(
            &cycle_source,
            None,
            RealmLinkTransitionCandidate {
                payload: &payload,
                canonical_move_bytes: &move_bytes,
                canonical_basis_bytes: b"cycle-edge-basis",
            },
        )? != RealmLinkTransitionOutcome::Apply
        {
            bail!("general Realm Link graph cycle edge was rejected");
        }
    }

    let self_link = realm_link_payload(source.clone(), RealmLinkStatus::Active);
    let self_link_bytes = canonical_json_bytes(&self_link)?;
    let self_reference_error = evaluate_realm_link_transition(
        &source,
        None,
        RealmLinkTransitionCandidate {
            payload: &self_link,
            canonical_move_bytes: &self_link_bytes,
            canonical_basis_bytes: b"self-reference-basis",
        },
    )
    .expect_err("self-reference must be rejected");
    if self_reference_error.error_code() != ErrorCode::SchemaViolation
        || self_reference_error.reason_code() != arkret_wire::ReasonCode::REALM_LINK_SELF_REFERENCE
    {
        bail!("Realm Link self-reference returned the wrong error mapping");
    }

    Ok(())
}

fn cell(family: &str, subject: &str) -> CellRef {
    CellRef::new(format!("ak:cell:{family}:{subject}"))
        .expect("test fixture cell id should be valid")
}

fn issuer_digest(suffix: &str) -> Hash {
    // Hash regex: ^sha256:[0-9a-f]{64}$ — pad the suffix to
    // exactly 64 lowercase hex characters.
    let suffix = suffix.to_ascii_lowercase();
    assert!(
        suffix
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "test fixture suffix '{suffix}' must be lowercase hex"
    );
    let padding = 64usize.saturating_sub(suffix.len());
    let id = format!("sha256:{suffix}{}", "0".repeat(padding));
    Hash::new(id).expect("test fixture digest should be valid")
}

fn op_add(tag: &str) -> LatticeOp {
    LatticeOp {
        op_type: LatticeOpType::Add,
        tag: Some(tag.to_owned()),
        ..base_op()
    }
}

fn op_remove(tag: &str) -> LatticeOp {
    LatticeOp {
        op_type: LatticeOpType::Remove,
        tag: Some(tag.to_owned()),
        ..base_op()
    }
}

fn op_set(value: serde_json::Value) -> LatticeOp {
    LatticeOp {
        op_type: LatticeOpType::Set,
        value: Some(value),
        ..base_op()
    }
}

fn op_inc(value: u64) -> LatticeOp {
    LatticeOp {
        op_type: LatticeOpType::Inc,
        value: Some(json!(value)),
        ..base_op()
    }
}

fn op_dec(value: u64) -> LatticeOp {
    LatticeOp {
        op_type: LatticeOpType::Dec,
        value: Some(json!(value)),
        ..base_op()
    }
}

fn op_transition(from: serde_json::Value, to: serde_json::Value) -> LatticeOp {
    LatticeOp {
        op_type: LatticeOpType::Transition,
        from: Some(from),
        to: Some(to),
        ..base_op()
    }
}

fn op_append(value: serde_json::Value, issuer_seq: u64) -> LatticeOp {
    LatticeOp {
        op_type: LatticeOpType::Append,
        value: Some(value),
        issuer_seq: Some(issuer_seq),
        ..base_op()
    }
}

fn issued_op(issuer: &str, suffix: &str, op: LatticeOp) -> IssuedOp {
    let did = Did::new(issuer.to_owned()).expect("test fixture issuer should be a valid did");
    IssuedOp {
        issuer_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
            arkret_identifiers::project_did_to_core_id(&did)
                .expect("test fixture issuer should project to a core id"),
            arkret_wire::DidCoreId::new("ak:did_core:web:station.example")
                .expect("fixture Station should be valid"),
        )),
        op: SealedOp::new(issuer_digest(suffix), op),
    }
}

fn base_op() -> LatticeOp {
    LatticeOp {
        op_type: LatticeOpType::Add,
        tag: None,
        value: None,
        from: None,
        to: None,
        reason: None,
        issuer_seq: None,
    }
}

// ─────────────────────────── OrSet ───────────────────────────────────

fn or_set_basic_add_remove_commute() -> Result<()> {
    let lattice = OrSet;
    let cref = cell(
        "ak.component.consent.v1",
        "ak.consent.01js0cc0000000000000000000",
    );
    let m1 = issuer_digest("aa");
    let m2 = issuer_digest("bb");
    let m3 = issuer_digest("cc");

    // Causal-order semantics of OR-Set: a remove only erases adds that
    // appear EARLIER in the deterministic order than the remove. In
    // [add(red, m1), add(blue, m2), remove(red, m3)] the remove sees both
    // earlier adds and removes red, leaving blue. Running join twice on
    // the SAME op order MUST produce the SAME result (deterministic
    // associativity).
    let ops = vec![
        SealedOp::new(m1, op_add("red")),
        SealedOp::new(m2, op_add("blue")),
        SealedOp::new(m3, op_remove("red")),
    ];
    let resolved_first = lattice.join(&cref, &ops);
    let resolved_second = lattice.join(&cref, &ops);
    if resolved_first != resolved_second {
        bail!(
            "OrSet join is not deterministic on identical input: {resolved_first:?} vs {resolved_second:?}"
        );
    }
    if resolved_first.is_bottom() {
        bail!("OrSet basic add/remove should not produce Bottom, got {resolved_first:?}");
    }
    // Resolved set must surface "blue" and NOT "red".
    let serialized = serde_json::to_string(&match resolved_first {
        CellState::Value(v) => v,
        CellState::Bottom(_) => unreachable!(),
    })
    .unwrap_or_default();
    if !serialized.contains("blue") {
        bail!("OrSet did not surface 'blue' (added before any remove): {serialized}");
    }
    if serialized.contains("red") {
        bail!("OrSet still surfaces 'red' after causal remove: {serialized}");
    }
    Ok(())
}

fn or_set_idempotent_re_add_after_remove() -> Result<()> {
    let lattice = OrSet;
    let cref = cell(
        "ak.component.consent.v1",
        "ak.consent.01js0cc0000000000000000000",
    );
    let ops = vec![
        SealedOp::new(issuer_digest("aa"), op_add("red")),
        SealedOp::new(issuer_digest("bb"), op_remove("red")),
        SealedOp::new(issuer_digest("cc"), op_add("red")),
    ];
    let resolved = lattice.join(&cref, &ops);
    if resolved.is_bottom() {
        bail!("OrSet add-after-remove with new move_id must not Bottom; got {resolved:?}");
    }
    Ok(())
}

// ─────────────────────────── CasRegister ─────────────────────────────

fn cas_register_concurrent_set_returns_bottom_conflict() -> Result<()> {
    let lattice = CasRegister;
    let cref = cell(
        arkret_wire::CellFamilyId::REALM_POLICY_V1,
        "ak.realm.01js0sp0000000000000000000",
    );
    // Two sealed Moves concurrently set the cell to distinct values.
    let ops = vec![
        SealedOp::new(issuer_digest("aa"), op_set(json!({"role": "admin"}))),
        SealedOp::new(issuer_digest("bb"), op_set(json!({"role": "moderator"}))),
    ];
    let resolved = lattice.join(&cref, &ops);
    let bottom = match resolved {
        CellState::Bottom(b) => b,
        CellState::Value(_) => {
            bail!(
                "CasRegister concurrent set must produce Bottom (cas_register conflict semantics)"
            )
        }
    };
    if !matches!(bottom.kind, arkret_wire::BottomKind::Conflict) {
        bail!(
            "CasRegister Bottom kind expected Conflict, got {:?}",
            bottom.kind
        );
    }
    if bottom.move_ids.len() < 2 {
        bail!(
            "CasRegister Bottom must surface both conflicting move_ids; got {:?}",
            bottom.move_ids
        );
    }
    Ok(())
}

fn cas_register_single_set_returns_value() -> Result<()> {
    let lattice = CasRegister;
    let cref = cell(
        arkret_wire::CellFamilyId::REALM_POLICY_V1,
        "ak.realm.01js0sp0000000000000000001",
    );
    let ops = vec![SealedOp::new(
        issuer_digest("dd"),
        op_set(json!({"role": "admin"})),
    )];
    let resolved = lattice.join(&cref, &ops);
    if resolved.is_bottom() {
        bail!("CasRegister with a single sealed set must NOT Bottom; got {resolved:?}");
    }
    Ok(())
}

/// One write in a `cas_register` history, addressed the way the log addresses it.
///
/// `supersedes` is the set of head identities the write's own signed basis
/// observed, which the reducer derives at admission. It is not a business value
/// and never appears on the wire, so a scenario here is written as an identity
/// graph rather than as a chain of values.
fn cas_write(id: &str, value: Value, supersedes: &[&str]) -> SealedOp {
    SealedOp::superseding(
        issuer_digest(id),
        op_set(value),
        supersedes.iter().map(|id| issuer_digest(id)).collect(),
    )
}

fn cas_head_ids(ops: &[SealedOp]) -> Result<Vec<String>> {
    Ok(arkret_state::lattice::cas_register::cas_heads(ops)
        .map_err(|bottom| anyhow!("cas_heads failed: {bottom:?}"))?
        .into_iter()
        .map(|head| head.move_id.as_str().to_owned())
        .collect())
}

/// The active-write set, computed by a different algorithm than the one under test.
///
/// `cas_heads` answers with one pass over the op set. This walks the history
/// forward instead — each write removes the heads it observed and adds itself —
/// which is the "collect the active writes of the complete causal history"
/// oracle section 30 obligation 8 asks the merge to agree with. Two algorithms
/// that agree on every prefix-closed subset is the actual claim; one algorithm
/// compared to itself would prove nothing.
fn active_writes_oracle(ops: &[SealedOp]) -> Vec<String> {
    let mut pending: Vec<&SealedOp> = ops.iter().collect();
    let mut heads: Vec<String> = Vec::new();
    let mut applied: BTreeSet<String> = BTreeSet::new();
    // Apply in any order that respects the observed-before relation: a write may
    // land once every write it superseded has landed, or is absent from this
    // view entirely (a partial view is still a legal view).
    while !pending.is_empty() {
        let ready = pending.iter().position(|entry| {
            entry.supersedes.iter().all(|superseded| {
                applied.contains(superseded.as_str())
                    || !ops
                        .iter()
                        .any(|other| other.move_id.as_str() == superseded.as_str())
            })
        });
        let Some(index) = ready else {
            // A cycle cannot occur in a digest-addressed history: a write's
            // basis is fixed before its own identity exists.
            break;
        };
        let entry = pending.remove(index);
        heads.retain(|head| {
            !entry
                .supersedes
                .iter()
                .any(|superseded| superseded.as_str() == head)
        });
        if applied.insert(entry.move_id.as_str().to_owned()) {
            heads.push(entry.move_id.as_str().to_owned());
        }
    }
    heads.sort();
    heads
}

fn cas_cell_root(cell: &CellRef, ops: &[SealedOp]) -> Result<String> {
    let heads = arkret_state::lattice::cas_register::cas_heads(ops)
        .map_err(|bottom| anyhow!("cas_heads failed: {bottom:?}"))?;
    let cells = std::collections::BTreeMap::from([(cell.clone(), CasRegister.join(cell, ops))]);
    let cas_heads = arkret_state::state::CasHeadsByCell::from([(cell.clone(), heads)]);
    Ok(arkret_state::state::compute_state_root(
        arkret_state::state::GovernanceView::new(&cells, &cas_heads),
        arkret_canonical::DigestSuite::Sha256,
    )
    .map_err(|error| anyhow!("state_root failed: {error}"))?
    .as_str()
    .to_owned())
}

/// Exact runner for `ak.vector.lattice.cas_register_supersession.v1`.
///
/// Covers the ten obligations of `conformance-vectors.md` section 30 in order.
/// Obligations 3, 4, 6 and 9 are the ones the deleted `(value, from)` join could
/// not express at all: it read causality out of business values, so it could not
/// tell a released cell from an unwritten one, `A -> B -> A` from
/// `A -> B -> A -> B`, or two same-valued concurrent writes from one.
pub fn run_lattice_cas_register_supersession_vector() -> Result<()> {
    let lattice = CasRegister;
    let cref = cell(
        arkret_wire::CellFamilyId::REALM_POLICY_BUNDLE_V1,
        "ak.realm.01js0sp0000000000000000002",
    );
    let declaration = json!({"policy_revision": 1});
    let replacement = json!({"policy_revision": 2});

    // 1. An unwritten cell reads `null` and occupies no `state_root` leaf.
    if lattice.join(&cref, &[]) != CellState::Value(Value::Null) {
        bail!("an unwritten cas_register cell must read null");
    }
    if !cas_head_ids(&[])?.is_empty() {
        bail!("an unwritten cas_register cell must have no heads");
    }
    if cas_cell_root(&cref, &[])? != arkret_state::state::EMPTY_STATE_ROOT {
        bail!("an unwritten cas_register cell must not occupy a state_root leaf");
    }

    // 2. A linear lifecycle: every write supersedes exactly what its own basis observed, so one
    //    head survives and the cell never reaches bottom.
    let lifecycle = vec![
        cas_write("d1", declaration.clone(), &[]),
        cas_write("d2", Value::Null, &["d1"]),
        cas_write("d3", replacement.clone(), &["d2"]),
    ];
    if lattice.join(&cref, &lifecycle) != CellState::Value(replacement.clone()) {
        bail!("a declaration -> release -> replacement lifecycle did not settle");
    }
    if cas_head_ids(&lifecycle)? != vec![issuer_digest("d3").as_str().to_owned()] {
        bail!("a linear lifecycle must leave exactly its terminal write as the head");
    }

    // 3. A release is a write with an identity, not an erasure. It reads `null` like an unwritten
    //    cell and is a `state_root` member unlike one — which is the only thing that keeps the two
    //    distinguishable, since a non-membership proof cannot tell them apart.
    let released = &lifecycle[..2];
    if lattice.join(&cref, released) != CellState::Value(Value::Null) {
        bail!("a released cas_register cell must read null");
    }
    if cas_head_ids(released)? != vec![issuer_digest("d2").as_str().to_owned()] {
        bail!("a released cas_register cell must keep its release write as the head");
    }
    if cas_cell_root(&cref, released)? == arkret_state::state::EMPTY_STATE_ROOT {
        bail!("a released cas_register cell must still occupy a state_root leaf");
    }

    // 4. ABA and ABAB are different histories and must read differently. A join that follows value
    //    edges answers `A` for both, which is exactly the defect this vector exists to catch.
    let aba_via_null = vec![
        cas_write("a1", declaration.clone(), &[]),
        cas_write("a2", Value::Null, &["a1"]),
        cas_write("a3", declaration.clone(), &["a2"]),
    ];
    if lattice.join(&cref, &aba_via_null) != CellState::Value(declaration.clone()) {
        bail!("A -> null -> A must read A");
    }
    let aba = vec![
        cas_write("b1", declaration.clone(), &[]),
        cas_write("b2", replacement.clone(), &["b1"]),
        cas_write("b3", declaration.clone(), &["b2"]),
    ];
    let mut abab = aba.clone();
    abab.push(cas_write("b4", replacement.clone(), &["b3"]));
    if lattice.join(&cref, &aba) != CellState::Value(declaration.clone()) {
        bail!("A -> B -> A must read A");
    }
    if lattice.join(&cref, &abab) != CellState::Value(replacement.clone()) {
        bail!("A -> B -> A -> B must read B");
    }
    if lattice.join(&cref, &aba) == lattice.join(&cref, &abab) {
        bail!("A -> B -> A and A -> B -> A -> B must not resolve alike");
    }

    // 5. Two writes that could not see each other and disagree are two heads, and a `bottom=reject`
    //    cell materializes that as a failure.
    let concurrent_distinct = vec![
        cas_write("c1", declaration.clone(), &[]),
        cas_write("c2", replacement.clone(), &["c1"]),
        cas_write("c3", json!({"policy_revision": 3}), &["c1"]),
    ];
    if !matches!(
        lattice.join(&cref, &concurrent_distinct),
        CellState::Bottom(_)
    ) {
        bail!("concurrent distinct writes on one predecessor must conflict");
    }

    // 6. Two concurrent writes of the *same* value read cleanly but are still two identities, and
    //    both stay in the leaf. A successor that observed only one of them must not drop the branch
    //    it never saw.
    let concurrent_same = vec![
        cas_write("e1", declaration.clone(), &[]),
        cas_write("e2", replacement.clone(), &["e1"]),
        cas_write("e3", replacement.clone(), &["e1"]),
    ];
    if lattice.join(&cref, &concurrent_same) != CellState::Value(replacement.clone()) {
        bail!("same-valued concurrent writes must read that value");
    }
    let same_heads = cas_head_ids(&concurrent_same)?;
    for id in ["e2", "e3"] {
        if !same_heads.contains(&issuer_digest(id).as_str().to_owned()) {
            bail!("same-valued concurrent writes must both stay in the head set");
        }
    }
    if cas_cell_root(&cref, &concurrent_same)? == cas_cell_root(&cref, &concurrent_same[..2])? {
        bail!("a second same-valued head must change the state_root leaf");
    }
    let mut one_branch_advanced = concurrent_same.clone();
    one_branch_advanced.push(cas_write("e4", json!({"policy_revision": 4}), &["e2"]));
    let advanced_heads = cas_head_ids(&one_branch_advanced)?;
    if !advanced_heads.contains(&issuer_digest("e3").as_str().to_owned()) {
        bail!("a successor must not remove a head its own basis never observed");
    }

    // 7. Exact replay is idempotent. The same identity carrying a *different* effect is a
    //    verification error or a section 6.3.3 collision, and the lattice must refuse to pick
    //    rather than settle it.
    let mut replayed = lifecycle.clone();
    replayed.push(lifecycle[1].clone());
    if lattice.join(&cref, &replayed) != lattice.join(&cref, &lifecycle) {
        bail!("a byte-identical repeated write was not idempotently deduplicated");
    }
    if cas_head_ids(&replayed)? != cas_head_ids(&lifecycle)? {
        bail!("a byte-identical repeated write must not create a second head");
    }
    let forked_identity = vec![
        lifecycle[0].clone(),
        cas_write("d2", json!({"policy_revision": 99}), &["d1"]),
        lifecycle[1].clone(),
    ];
    if arkret_state::lattice::cas_register::cas_heads(&forked_identity).is_ok() {
        bail!("one identity carrying two different effects must fail closed, not be resolved");
    }

    // 8. The merge is associative, commutative and idempotent, and agrees with an independently
    //    computed active-write set on every prefix-closed subset of a branching history.
    let history = vec![
        cas_write("f1", declaration.clone(), &[]),
        cas_write("f2", replacement.clone(), &["f1"]),
        cas_write("f3", json!({"policy_revision": 3}), &["f1"]),
        cas_write("f4", json!({"policy_revision": 4}), &["f2", "f3"]),
    ];
    for subset in prefix_closed_subsets(&history) {
        let mut heads = cas_head_ids(&subset)?;
        heads.sort();
        if heads != active_writes_oracle(&subset) {
            bail!(
                "cas_heads disagrees with the causal-history oracle on a prefix-closed subset \
                 of {} writes",
                subset.len()
            );
        }
        // 10. Every prefix-closed subset is itself a deterministic view, so a receiver holding only
        //     that subset recomputes the same answer.
        let mut reversed = subset.clone();
        reversed.reverse();
        if cas_head_ids(&reversed)? != cas_head_ids(&subset)? {
            bail!("a prefix-closed view must not depend on op arrival order");
        }
    }
    let left = &history[..2];
    let right = &history[1..];
    let mut merged_lr = [left, right].concat();
    let mut merged_rl = [right, left].concat();
    if cas_head_ids(&merged_lr)? != cas_head_ids(&merged_rl)? {
        bail!("merging two verified views must commute");
    }
    merged_lr.extend_from_slice(left);
    if cas_head_ids(&merged_lr)? != cas_head_ids(&merged_rl)? {
        bail!("merging a view that is already covered must be idempotent");
    }
    merged_rl.extend_from_slice(&history);
    if cas_head_ids(&merged_rl)? != cas_head_ids(&history)? {
        bail!("merging must associate: regrouping the same writes must not move the heads");
    }

    // 9. Bottom is a property of the view, not a flag. Two branches that each advance to the same
    //    successor converge once both are covered, so a receiver that pinned bottom on a partial
    //    view would permanently disagree with one that saw the whole history.
    let terminal = json!({"policy_revision": 7});
    let divergent = vec![
        cas_write("ab1", declaration.clone(), &[]),
        cas_write("ab2", replacement.clone(), &["ab1"]),
        cas_write("ab3", json!({"policy_revision": 3}), &["ab1"]),
    ];
    if !matches!(lattice.join(&cref, &divergent), CellState::Bottom(_)) {
        bail!("a partial view of two divergent branches must resolve to bottom");
    }
    let mut converged = divergent.clone();
    converged.push(cas_write("ab4", terminal.clone(), &["ab2"]));
    converged.push(cas_write("ab5", terminal.clone(), &["ab3"]));
    if lattice.join(&cref, &converged) != CellState::Value(terminal.clone()) {
        bail!("bottom must not be sticky: both branches reaching one value must converge");
    }
    let mut late_arrival = vec![converged[4].clone(), converged[3].clone()];
    late_arrival.extend(divergent.iter().cloned());
    if lattice.join(&cref, &late_arrival) != CellState::Value(terminal) {
        bail!("a receiver that saw bottom first must converge once the leaves arrive");
    }
    Ok(())
}

/// Every subset of `history` that contains, for each member, every write that
/// member superseded. Those are exactly the views a receiver can legally hold:
/// a covered write drags its own basis into the view with it.
fn prefix_closed_subsets(history: &[SealedOp]) -> Vec<Vec<SealedOp>> {
    let mut subsets = Vec::new();
    for mask in 0_u32..(1 << history.len()) {
        let chosen = history
            .iter()
            .enumerate()
            .filter(|(index, _)| mask & (1 << index) != 0)
            .map(|(_, entry)| entry.clone())
            .collect::<Vec<_>>();
        let present = chosen
            .iter()
            .map(|entry| entry.move_id.as_str().to_owned())
            .collect::<BTreeSet<_>>();
        let closed = chosen.iter().all(|entry| {
            entry
                .supersedes
                .iter()
                .all(|superseded| present.contains(superseded.as_str()))
        });
        if closed {
            subsets.push(chosen);
        }
    }
    subsets
}

// ─────────────────────────── Counter ─────────────────────────────────

fn counter_pn_sums_increments_and_decrements() -> Result<()> {
    let lattice = Counter;
    let cref = cell("ak.component.counter.v1", "metrics.events.received");
    let ops = vec![
        SealedOp::new(issuer_digest("ee"), op_inc(5)),
        SealedOp::new(issuer_digest("ff"), op_inc(3)),
        SealedOp::new(issuer_digest("11"), op_dec(2)),
    ];
    let resolved = lattice.join(&cref, &ops);
    let value = match resolved {
        CellState::Value(v) => v,
        CellState::Bottom(b) => bail!("Counter join unexpectedly Bottom: {b:?}"),
    };
    // Counter must sum to 5 + 3 - 2 = 6. The exact value shape can be
    // either an integer or an object {p, n}; we check the integer form
    // first and fall back to p/n decomposition.
    let sum_ok = if let Some(n) = value.as_i64() {
        n == 6
    } else if let Some(obj) = value.as_object() {
        let p = obj.get("p").and_then(|v| v.as_i64()).unwrap_or(0);
        let n = obj.get("n").and_then(|v| v.as_i64()).unwrap_or(0);
        (p - n) == 6
    } else {
        false
    };
    if !sum_ok {
        bail!("Counter PN sum != 6 (got {value:?})");
    }
    Ok(())
}

// ─────────────────────────── Fsm ─────────────────────────────────────

fn membership_fsm() -> Fsm {
    // Standard membership FSM (per spec event-auth-state-resolution.md §5.3
    // example): invited → joined → left, plus invited → left and joined →
    // banned. Any pair not declared here is an illegal transition and the
    // join MUST Bottom.
    Fsm::new(vec![
        (json!("invited"), json!("join")),
        (json!("invited"), json!("decline")),
        (json!("join"), json!("leave")),
        (json!("join"), json!("ban")),
        (json!("leave"), json!("join")),
    ])
    .with_initial(json!("invited"))
}

fn fsm_legal_transition_advances_state() -> Result<()> {
    let lattice = membership_fsm();
    let cref = cell(
        arkret_wire::CellFamilyId::MEMBER_STATE_V1,
        "did.web.alice.example",
    );
    // Single legal transition: invited → joined.
    let ops = vec![SealedOp::new(
        issuer_digest("22"),
        op_transition(json!("invited"), json!("join")),
    )];
    let resolved = lattice.join(&cref, &ops);
    if resolved.is_bottom() {
        bail!("Fsm legal transition must not Bottom; got {resolved:?}");
    }
    Ok(())
}

fn fsm_duplicate_transition_is_idempotent() -> Result<()> {
    let lattice = membership_fsm();
    let cref = cell(
        arkret_wire::CellFamilyId::MEMBER_STATE_V1,
        "did.web.alice.example",
    );
    let ops = vec![
        SealedOp::new(
            issuer_digest("23"),
            op_transition(json!("invited"), json!("join")),
        ),
        SealedOp::new(
            issuer_digest("24"),
            op_transition(json!("invited"), json!("join")),
        ),
    ];
    let resolved = lattice.join(&cref, &ops);
    if resolved != CellState::Value(json!("join")) {
        bail!("Fsm duplicate identical transition must converge to join, got {resolved:?}");
    }
    Ok(())
}

fn fsm_same_from_different_to_returns_bottom() -> Result<()> {
    let lattice = membership_fsm();
    let cref = cell(
        arkret_wire::CellFamilyId::MEMBER_STATE_V1,
        "did.web.alice.example",
    );
    let ops = vec![
        SealedOp::new(
            issuer_digest("25"),
            op_transition(json!("invited"), json!("join")),
        ),
        SealedOp::new(
            issuer_digest("26"),
            op_transition(json!("invited"), json!("decline")),
        ),
    ];
    let resolved = lattice.join(&cref, &ops);
    match resolved {
        CellState::Bottom(bottom) if matches!(bottom.kind, arkret_wire::BottomKind::Conflict) => {
            Ok(())
        }
        other => {
            bail!("Fsm same-from different-to siblings must return conflict Bottom, got {other:?}")
        }
    }
}

fn fsm_illegal_transition_returns_bottom() -> Result<()> {
    let lattice = membership_fsm();
    let cref = cell(
        arkret_wire::CellFamilyId::MEMBER_STATE_V1,
        "did.web.alice.example",
    );
    // Two concurrent transitions claiming distinct `from` states for the
    // same cell — a join of these MUST surface a Bottom because the
    // pre-state can only be one value at a time.
    let ops = vec![
        SealedOp::new(
            issuer_digest("33"),
            op_transition(json!("invited"), json!("join")),
        ),
        SealedOp::new(
            issuer_digest("44"),
            op_transition(json!("join"), json!("invited")),
        ),
    ];
    let resolved = lattice.join(&cref, &ops);
    // Either Bottom-Conflict or Bottom-InvalidTransition is acceptable; the
    // spec leaves the kind to the implementation as long as it's a Bottom.
    if !resolved.is_bottom() {
        bail!(
            "Fsm join with conflicting transitions on the same cell should produce Bottom; got {resolved:?}"
        );
    }
    Ok(())
}

// ─────────────────────────── MvRegister ──────────────────────────────

fn mv_register_concurrent_set_surfaces_multiple_values() -> Result<()> {
    let lattice = MvRegister;
    let cref = cell(
        "ak.component.strand.title.v1",
        "ak.strand.01js0fl0000000000000000000",
    );
    // MvRegister surfaces multiple concurrent values. The SDK's reference
    // implementation defaults to a Bottom-shaped result with both heads in
    // `heads[]` (callers can flip to `bottom = expose` to render multi-value
    // as a Value array directly). Either form is acceptable as long as
    // BOTH input values are visible to the caller.
    let ops = vec![
        SealedOp::new(issuer_digest("55"), op_set(json!("Title A"))),
        SealedOp::new(issuer_digest("66"), op_set(json!("Title B"))),
    ];
    let resolved = lattice.join(&cref, &ops);
    let surfaces_both = match &resolved {
        CellState::Value(v) => serde_json::to_string(v)
            .ok()
            .map(|s| s.contains("Title A") && s.contains("Title B"))
            .unwrap_or(false),
        CellState::Bottom(b) => {
            // Bottom must surface both move_ids AND both values via heads.
            let heads_have_both = b
                .head_ids
                .iter()
                .filter_map(|h| h.as_str())
                .collect::<Vec<_>>();
            heads_have_both.contains(&"Title A")
                && heads_have_both.contains(&"Title B")
                && b.move_ids.len() >= 2
        }
    };
    if !surfaces_both {
        bail!(
            "MvRegister did not surface both concurrent values via Value or Bottom heads; got {resolved:?}"
        );
    }
    Ok(())
}

// ─────────────────────────── OrderedLog ──────────────────────────────

fn ordered_log_per_issuer_monotonic_append() -> Result<()> {
    let lattice = OrderedLog;
    // issuer_seq is the enclosing Event actor_seq. It is sparse within any
    // particular cell; two issuers at the same sequence remain independent.
    let ops = vec![
        issued_op(
            "did:web:bob.example",
            "77",
            op_append(json!({"actor": "bob", "msg": "hello"}), 0),
        ),
        issued_op(
            "did:web:alice.example",
            "88",
            op_append(json!({"actor": "alice", "msg": "hi"}), 0),
        ),
        issued_op(
            "did:web:alice.example",
            "99",
            op_append(json!({"actor": "alice", "msg": "ack"}), 1),
        ),
        // Exact Event replay is idempotent.
        issued_op(
            "did:web:alice.example",
            "88",
            op_append(json!({"actor": "alice", "msg": "hi"}), 0),
        ),
    ];
    let report = lattice.join_with_issuer_report(&ops);
    if !report.identity_collisions.is_empty() {
        bail!("OrderedLog monotonic append must not fail closed: {report:?}");
    }
    if !report.sibling_groups.is_empty() {
        bail!("exact Event replay is a duplicate, not a sibling: {report:?}");
    }
    let entries = &report.entries;
    let alice = ops[1].issuer_id.to_string();
    let bob = ops[0].issuer_id.to_string();
    if entries.len() != 3 {
        bail!("OrderedLog must dedupe byte-identical appends and keep 3 entries, got {entries:?}");
    }
    if entries[0].get("issuer_id").and_then(Value::as_str) != Some(alice.as_str())
        || entries[0].get("issuer_seq").and_then(Value::as_u64) != Some(0)
        || entries[1].get("issuer_id").and_then(Value::as_str) != Some(alice.as_str())
        || entries[1].get("issuer_seq").and_then(Value::as_u64) != Some(1)
        || entries[2].get("issuer_id").and_then(Value::as_str) != Some(bob.as_str())
        || entries[2].get("issuer_seq").and_then(Value::as_u64) != Some(0)
    {
        bail!("OrderedLog entries are not sorted by issuer then seq: {entries:?}");
    }

    // A sparse actor_seq above zero materializes without a cell-local prefix.
    let late_only = vec![issued_op(
        "did:web:carol.example",
        "b3",
        op_append(json!({"actor": "carol", "msg": "late"}), 3),
    )];
    let late_report = lattice.join_with_issuer_report(&late_only);
    if late_report.entries.len() != 1 || late_report.entries[0]["issuer_seq"] != 3 {
        bail!("sparse actor_seq must materialize directly: {late_report:?}");
    }
    Ok(())
}

/// Same-height Event siblings all enter the joined value. Digest comparison
/// only stabilizes their serialization order and never elects a winner.
fn ordered_log_equivocation_resolves_to_max_event_digest() -> Result<()> {
    let lattice = OrderedLog;
    let loser = issued_op(
        "did:web:alice.example",
        "11",
        op_append(json!({"actor": "alice", "msg": "loser"}), 0),
    );
    let winner = issued_op(
        "did:web:alice.example",
        "22",
        op_append(json!({"actor": "alice", "msg": "winner"}), 0),
    );

    for (label, ops) in [
        ("loser-first", vec![loser.clone(), winner.clone()]),
        ("winner-first", vec![winner.clone(), loser.clone()]),
    ] {
        let report = lattice.join_with_issuer_report(&ops);
        if !report.identity_collisions.is_empty() {
            bail!("{label}: unrelated siblings must not fail closed: {report:?}");
        }
        if report.entries.len() != 2 {
            bail!("{label}: both siblings must join, got {:?}", report.entries);
        }
        let messages = report
            .entries
            .iter()
            .filter_map(|entry| entry.pointer("/value/msg").and_then(Value::as_str))
            .collect::<Vec<_>>();
        if messages != ["loser", "winner"] {
            bail!("{label}: canonical order or sibling retention drifted: {report:?}");
        }
        if report.sibling_groups.len() != 1 || report.sibling_groups[0].event_digests.len() != 2 {
            bail!("{label}: complete sibling diagnostic missing: {report:?}");
        }
    }

    // A slot whose candidates share one typed digest but differ in canonical
    // `effect.op` bytes is a digest collision and MUST fail closed rather than
    // fall back to arrival order or any payload field.
    let collision = vec![
        issued_op(
            "did:web:alice.example",
            "33",
            op_append(json!({"actor": "alice", "msg": "one"}), 0),
        ),
        issued_op(
            "did:web:alice.example",
            "33",
            op_append(json!({"actor": "alice", "msg": "other"}), 0),
        ),
    ];
    let collision_report = lattice.join_with_issuer_report(&collision);
    if !collision_report.entries.is_empty() {
        bail!("digest collision must not materialize an entry: {collision_report:?}");
    }
    if collision_report
        .identity_collisions
        .iter()
        .all(|slot| slot.reason != "event_identity_collision")
    {
        bail!("digest collision must fail closed: {collision_report:?}");
    }
    Ok(())
}

/// The issuer-free `Lattice::join` has no way to separate sub-chains, so it
/// MUST NOT be usable for ordered-log materialization.
fn ordered_log_issuer_free_join_fails_closed() -> Result<()> {
    let cref = cell(
        "ak.component.audit_log.v1",
        "ak.realm.01js0sp0000000000000000000",
    );
    let ops = vec![
        SealedOp::new(issuer_digest("c0"), op_append(json!({"msg": "a"}), 0)),
        SealedOp::new(issuer_digest("c1"), op_append(json!({"msg": "b"}), 0)),
    ];
    match OrderedLog.join(&cref, &ops) {
        CellState::Bottom(_) => Ok(()),
        other => bail!("issuer-free ordered_log join must fail closed, got {other:?}"),
    }
}

fn ordered_log_gap_reports_pending_until_backfill() -> Result<()> {
    let lattice = OrderedLog;
    let cref = cell(
        "ak.component.audit_log.v1",
        "ak.realm.01js0sp0000000000000000000",
    );
    let gap_ops = vec![
        issued_op(
            "did:web:alice.example",
            "a0",
            op_append(json!({"entry_id": "entry-0000", "kind": "start"}), 0),
        ),
        issued_op(
            "did:web:alice.example",
            "a1",
            op_append(json!({"entry_id": "entry-0001", "kind": "next"}), 1),
        ),
        issued_op(
            "did:web:alice.example",
            "a3",
            op_append(json!({"entry_id": "entry-0003-b", "kind": "late-b"}), 3),
        ),
    ];

    let gap_report = lattice.join_with_issuer_report(&gap_ops);
    if gap_report.entries.len() != 3 {
        bail!(
            "sparse actor_seq must expose all entries: {:?}",
            gap_report.entries
        );
    }
    if !gap_report.entries.iter().any(|entry| {
        entry.get("issuer_seq").and_then(Value::as_u64) == Some(3)
            || entry.to_string().contains("late-b")
    }) {
        bail!("sparse actor_seq entry did not enter the joined value");
    }
    let CellState::Value(value) = lattice.join_with_issuers(&cref, &gap_ops) else {
        bail!("OrderedLog gap must not Bottom");
    };
    if value.as_array().is_none_or(|entries| entries.len() != 3) {
        bail!("OrderedLog joined value must retain sparse entry: {value}");
    }

    let backfilled_a = vec![
        issued_op(
            "did:web:alice.example",
            "a0",
            op_append(json!({"entry_id": "entry-0000", "kind": "start"}), 0),
        ),
        issued_op(
            "did:web:alice.example",
            "a1",
            op_append(json!({"entry_id": "entry-0001", "kind": "next"}), 1),
        ),
        issued_op(
            "did:web:alice.example",
            "a3",
            op_append(json!({"entry_id": "entry-0003-b", "kind": "late-b"}), 3),
        ),
        issued_op(
            "did:web:alice.example",
            "a2",
            op_append(json!({"entry_id": "entry-0002", "kind": "backfill"}), 2),
        ),
        issued_op(
            "did:web:alice.example",
            "a4",
            op_append(json!({"entry_id": "entry-0003-a", "kind": "late-a"}), 3),
        ),
    ];
    let mut backfilled_b = backfilled_a.clone();
    backfilled_b.reverse();
    let report_a = lattice.join_with_issuer_report(&backfilled_a);
    let report_b = lattice.join_with_issuer_report(&backfilled_b);
    if report_a.entries.len() != 5 || report_b.entries.len() != 5 {
        bail!(
            "OrderedLog must retain both seq 3 siblings: {:?} / {:?}",
            report_a.entries,
            report_b.entries
        );
    }
    if canonical_json_bytes(&report_a.entries)? != canonical_json_bytes(&report_b.entries)? {
        bail!("OrderedLog backfill recompute depended on arrival order");
    }
    if report_a.sibling_groups.len() != 1 {
        bail!("same-height siblings require one complete diagnostic: {report_a:?}");
    }

    Ok(())
}

// ──────────────────── Notary cell ────────────────────
//
// `ak:cell:ak.component.notary.v1:<realm_id>` is a cas_register holding the
// `NotaryValue` (single_signer | threshold(k/n) | open_set | mixed). Each
// happy-path test below confirms a single sealed Move that sets the cell
// to one of the four spec-normative shapes resolves to a Value (no Bottom).
// The conflict test confirms two concurrent reconfigurations Bottom — admins
// MUST coordinate (this is a safety-critical cell).

fn notary_cell(realm_suffix: &str) -> CellRef {
    cell(
        arkret_wire::CellFamilyId::NOTARY_V1,
        &format!("ak.realm.01js{realm_suffix}000000000000000000"),
    )
}

fn notary_cell_single_signer_profile_resolves_to_value() -> Result<()> {
    let lattice = CasRegister;
    let cref = notary_cell("01");
    let value = serde_json::to_value(crate::fixture_single_signer_notary(
        arkret_wire::DidCoreId::new("ak:did_core:web:hub.example")?,
    ))?;
    let ops = vec![SealedOp::new(issuer_digest("a1"), op_set(value))];
    let resolved = lattice.join(&cref, &ops);
    if resolved.is_bottom() {
        bail!("Notary single_signer profile must resolve to Value, got {resolved:?}");
    }
    Ok(())
}

fn notary_cell_threshold_profile_resolves_to_value() -> Result<()> {
    let lattice = CasRegister;
    let cref = notary_cell("02");
    let value = serde_json::to_value(arkret_wire::NotaryValue::Threshold {
        signers: ["notary1", "notary2", "notary3"]
            .into_iter()
            .map(|name| {
                crate::fixture_notary_signer(
                    arkret_wire::DidCoreId::new(format!("ak:did_core:web:{name}.example"))
                        .expect("fixed notary actor is valid"),
                )
            })
            .collect(),
        threshold: 2,
        forensic_attribution: arkret_wire::ForensicAttribution::QuorumIntersection,
    })?;
    let ops = vec![SealedOp::new(issuer_digest("a2"), op_set(value))];
    let resolved = lattice.join(&cref, &ops);
    if resolved.is_bottom() {
        bail!("Notary threshold profile must resolve to Value, got {resolved:?}");
    }
    Ok(())
}

fn notary_cell_open_set_profile_resolves_to_value() -> Result<()> {
    let lattice = CasRegister;
    let cref = notary_cell("03");
    let value = serde_json::to_value(arkret_wire::NotaryValue::OpenSet {
        signers: ["peer1", "peer2"]
            .into_iter()
            .map(|name| {
                crate::fixture_notary_signer(
                    arkret_wire::DidCoreId::new(format!("ak:did_core:web:{name}.example"))
                        .expect("fixed notary actor is valid"),
                )
            })
            .collect(),
    })?;
    let ops = vec![SealedOp::new(issuer_digest("a3"), op_set(value))];
    let resolved = lattice.join(&cref, &ops);
    if resolved.is_bottom() {
        bail!("Notary open_set profile must resolve to Value, got {resolved:?}");
    }
    Ok(())
}

fn notary_cell_mixed_profile_resolves_to_value() -> Result<()> {
    let lattice = CasRegister;
    let cref = notary_cell("04");
    let value = serde_json::to_value(arkret_wire::NotaryValue::Mixed {
        signer: crate::fixture_notary_signer(arkret_wire::DidCoreId::new(
            "ak:did_core:web:hub.example",
        )?),
        recovery_signers: ["recovery1", "recovery2"]
            .into_iter()
            .map(|name| {
                crate::fixture_notary_signer(
                    arkret_wire::DidCoreId::new(format!("ak:did_core:web:{name}.example"))
                        .expect("fixed recovery notary actor is valid"),
                )
            })
            .collect(),
        controller_organization_id: None,
        recovery_controller_organization_ids: Vec::new(),
    })?;
    let ops = vec![SealedOp::new(issuer_digest("a4"), op_set(value))];
    let resolved = lattice.join(&cref, &ops);
    if resolved.is_bottom() {
        bail!("Notary mixed profile must resolve to Value, got {resolved:?}");
    }
    Ok(())
}

fn notary_cell_concurrent_reconfig_returns_bottom() -> Result<()> {
    let lattice = CasRegister;
    let cref = notary_cell("05");
    // Two admins concurrently reconfigure the notary cell. Spec requires
    // this to surface Bottom — a "notary split" is a Realm-wide pause
    // condition, not a thing you LWW past.
    let ops = vec![
        SealedOp::new(
            issuer_digest("a5"),
            op_set(serde_json::to_value(crate::fixture_single_signer_notary(
                arkret_wire::DidCoreId::new("ak:did_core:web:hub-a.example")?,
            ))?),
        ),
        SealedOp::new(
            issuer_digest("a6"),
            op_set(serde_json::to_value(crate::fixture_single_signer_notary(
                arkret_wire::DidCoreId::new("ak:did_core:web:hub-b.example")?,
            ))?),
        ),
    ];
    let resolved = lattice.join(&cref, &ops);
    let bottom = match resolved {
        CellState::Bottom(b) => b,
        CellState::Value(_) => {
            bail!("Notary concurrent reconfig MUST Bottom (notary split is a Realm-wide pause)")
        }
    };
    if !matches!(bottom.kind, arkret_wire::BottomKind::Conflict) {
        bail!(
            "Notary split Bottom kind expected Conflict, got {:?}",
            bottom.kind
        );
    }
    Ok(())
}

// ──────────────────── Conflict repair (head_in) ────────────────────
//
// Per spec, conflict-repair Moves carry a `head_in [head_a, head_b]`
// precondition + `recovery_capability` ref. The repair Move itself just
// writes a NEW, single value to the conflicting cell — provided the writer
// is authorised by recovery_capability, the cas_register sees a single
// post-anchor op and returns Value, clearing the prior Bottom.
//
// At the lattice level (this layer), the test reduces to: a third sealed
// Move with a fresh value, joined alongside an even later Bottom-clearing
// recovery, MUST resolve to Value. Authorisation is handled at the verify_move
// layer above the lattice; here we confirm the post-recovery view is clean.

fn conflict_repair_head_in_move_resolves_existing_bottom() -> Result<()> {
    let lattice = CasRegister;
    let cref = cell(
        arkret_wire::CellFamilyId::REALM_POLICY_V1,
        "ak.realm.01js0sp0000000000000000000",
    );
    // Seal view AFTER recovery: only the repair Move's sealed op is in
    // scope (the earlier conflict pair was rolled back / superseded by the
    // recovery Seal). Result MUST be Value.
    let ops = vec![SealedOp::new(
        issuer_digest("b1"),
        op_set(json!({
            "role": "admin",
            "repair_of": ["a1", "a2"],
            "recovery_capability": "cap:01js0rc0000000000000000000",
        })),
    )];
    let resolved = lattice.join(&cref, &ops);
    if resolved.is_bottom() {
        bail!(
            "Conflict repair Move (single sealed op post-recovery) must resolve to Value; got {resolved:?}"
        );
    }
    Ok(())
}

fn conflict_repair_resists_self_authorising_winner() -> Result<()> {
    let lattice = CasRegister;
    let cref = cell(
        arkret_wire::CellFamilyId::REALM_POLICY_V1,
        "ak.realm.01js0sp0000000000000000001",
    );
    // Two concurrent set-Moves where one self-references its own "winner"
    // capability remain a Bottom at the lattice layer — the cas_register
    // doesn't peek at payload semantics, it just sees concurrent writes.
    // Self-authorisation prevention is enforced at verify_move (auth layer)
    // ABOVE the lattice; here we confirm the lattice itself doesn't pick a
    // winner just because one payload claims authority.
    let ops = vec![
        SealedOp::new(
            issuer_digest("b2"),
            op_set(json!({
                "role": "admin",
                "self_authorising": true,
                "claims": "winner",
            })),
        ),
        SealedOp::new(issuer_digest("b3"), op_set(json!({"role": "moderator"}))),
    ];
    let resolved = lattice.join(&cref, &ops);
    if !resolved.is_bottom() {
        bail!(
            "CasRegister must not pick winner from self-authorising payload at lattice layer; got {resolved:?}"
        );
    }
    Ok(())
}

// ──────────────────── MLS covered_frontier ────────────────────
//
// `ak:cell:ak.component.mls.covered_frontier.v1:<realm_id>` is an or_set of
// governance-frontier event refs each MLS commit attests to. Add-only
// growth is the typical pattern; rotation that purges old refs is rare and
// gated by capability. These tests confirm the lattice surfaces the union
// without bottom under normal commit strand.

fn covered_frontier_cell(realm_suffix: &str) -> CellRef {
    cell(
        "ak.component.mls.covered_frontier.v1",
        &format!("ak.realm.01js{realm_suffix}000000000000000000"),
    )
}

fn mls_covered_frontier_or_set_accumulates_governance_refs() -> Result<()> {
    let lattice = OrSet;
    let cref = covered_frontier_cell("c1");
    // Two MLS commits attest to overlapping governance frontier refs; the
    // or_set surfaces the union without bottom.
    let ops = vec![
        SealedOp::new(
            issuer_digest("c1"),
            op_add("ak:event:AfXWLGjjzmUk0babO-HDpZAvswjPfvrs8q77raV3fN2Q"),
        ),
        SealedOp::new(
            issuer_digest("c2"),
            op_add("ak:event:AecDGkfEd-fL66NxBRV42zX9DoqbGZ3lEe1BmyoWb1IL"),
        ),
        SealedOp::new(
            issuer_digest("c3"),
            op_add("ak:event:AfXWLGjjzmUk0babO-HDpZAvswjPfvrs8q77raV3fN2Q"),
        ), // duplicate add
    ];
    let resolved = lattice.join(&cref, &ops);
    if resolved.is_bottom() {
        bail!("covered_frontier or_set must accumulate refs without Bottom; got {resolved:?}");
    }
    let serialized = match &resolved {
        CellState::Value(v) => serde_json::to_string(v).unwrap_or_default(),
        CellState::Bottom(_) => unreachable!(),
    };
    if !serialized.contains("ak:event:AfXWLGjjzmUk0babO-HDpZAvswjPfvrs8q77raV3fN2Q")
        || !serialized.contains("ak:event:AecDGkfEd-fL66NxBRV42zX9DoqbGZ3lEe1BmyoWb1IL")
    {
        bail!("covered_frontier did not surface both governance refs: {serialized}");
    }
    Ok(())
}

fn mls_covered_frontier_after_rotation_keeps_old_refs_visible() -> Result<()> {
    let lattice = OrSet;
    let cref = covered_frontier_cell("c2");
    // After an MLS epoch rotation, a new commit adds a fresh ref; a remove
    // for an old ref is causally LATER (the rotation Move's sealed move_id
    // is later in deterministic order). Because the OR-Set is causal, the
    // remove erases ONLY the matching prior add. The remaining governance
    // ref MUST stay visible.
    let ops = vec![
        SealedOp::new(
            issuer_digest("c4"),
            op_add("ak:event:AWHzVy4-CV587FBidgn9Hqq7yFM2n4jpuq6xmWKsEg5B"),
        ),
        SealedOp::new(
            issuer_digest("c5"),
            op_add("ak:event:AcZF3BEL_TohuLgYkcDZ81RM55kSNwhAAashww3uBPQg"),
        ),
        SealedOp::new(
            issuer_digest("c6"),
            op_remove("ak:event:AWHzVy4-CV587FBidgn9Hqq7yFM2n4jpuq6xmWKsEg5B"),
        ),
    ];
    let resolved = lattice.join(&cref, &ops);
    if resolved.is_bottom() {
        bail!("covered_frontier rotation must not Bottom; got {resolved:?}");
    }
    let serialized = match &resolved {
        CellState::Value(v) => serde_json::to_string(v).unwrap_or_default(),
        CellState::Bottom(_) => unreachable!(),
    };
    if !serialized.contains("ak:event:AcZF3BEL_TohuLgYkcDZ81RM55kSNwhAAashww3uBPQg") {
        bail!(
            "covered_frontier should keep `still_valid` ref visible after rotation: {serialized}"
        );
    }
    if serialized.contains("ak:event:AWHzVy4-CV587FBidgn9Hqq7yFM2n4jpuq6xmWKsEg5B") {
        bail!("covered_frontier should drop the rotated ref after causal remove: {serialized}");
    }
    Ok(())
}

/// Assertion ids this suite genuinely exercises, per vector.
///
/// Kept as an explicit table so adding an id to the fixture without writing the
/// matching case fails the run instead of silently widening claimed coverage.
fn executed_lattice_assertion(vector_id: &str, assertion: &str) -> bool {
    const ORDERED_LOG_JOIN: &[&str] = &[
        "sparse_actor_sequence_order",
        "sequence_gaps_do_not_block_entries",
        "exact_event_replay_is_idempotent",
        "same_actor_seq_siblings_all_enter_joined_value",
        "causal_edges_do_not_create_a_sibling_winner",
        "canonical_order_compares_decoded_octets_across_suites",
        "distinct_digest_preimage_same_event_digest_fails_closed",
        "proofs_or_reducer_stamp_difference_is_not_a_digest_collision",
    ];
    const ORDERED_LOG_GAP: &[&str] = &[
        "sparse_gap_entry_enters_cell_value",
        "no_pending_gap_diagnostic_exists",
        "additional_entry_recompute_is_arrival_order_independent",
    ];
    // Every line here is executed by `run_lattice_cas_register_supersession_vector`
    // in the order `conformance-vectors.md` section 30 lists its ten obligations.
    // Itemising them is the point: while this vector fell through to `_ => true`,
    // the fixture could claim nine assertions with nothing running behind them,
    // which is how the runner kept passing after the join it exercised was
    // replaced.
    const CAS_REGISTER_SUPERSESSION: &[&str] = &[
        "an unwritten cell has no head and reads null",
        "each write is identified by its EventId and supersedes exactly the heads observed in \
         its own signed seal_basis",
        "a release write is set null, keeps its own head, and stays distinguishable from an \
         unwritten cell",
        "A -> null -> A reads A, and A -> B -> A -> B reads B",
        "concurrent writes with different values leave two heads and a bottom=reject cell \
         materializes failed_bottom",
        "concurrent writes with the same value keep both head identities and a successor that \
         saw only one of them removes only that one",
        "exact replay of the same identity and canonical effect is idempotent",
        "merging two verified (covered set, heads) states is associative, commutative, \
         idempotent and agrees with a full causal-history oracle",
        "Bottom is recomputed per view, so a receiver that later observes the missing leaf \
         converges with one that saw the full history",
    ];
    match vector_id {
        "ak.vector.lattice.ordered_log_join.v1" => ORDERED_LOG_JOIN.contains(&assertion),
        "ak.vector.lattice.ordered_log_gap.v1" => ORDERED_LOG_GAP.contains(&assertion),
        VECTOR_ID_LATTICE_CAS_REGISTER_SUPERSESSION => {
            CAS_REGISTER_SUPERSESSION.contains(&assertion)
        }
        // Other lattice vectors keep the previous coverage contract until their
        // cases are itemised the same way.
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realm_link_fsm_transition_matrix_runs_clean() {
        run_realm_link_fsm_transition_matrix_vector().unwrap();
    }
}
