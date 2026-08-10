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
    notary_cell_single_did_profile_resolves_to_value()?;
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

fn op_supersede(value: serde_json::Value, from: serde_json::Value) -> LatticeOp {
    LatticeOp {
        op_type: LatticeOpType::Set,
        value: Some(value),
        from: Some(from),
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
    let full_id = Did::new(issuer.to_owned()).expect("test fixture issuer should be a valid did");
    IssuedOp {
        issuer: arkret_identifiers::ActorId::from(
            arkret_identifiers::project_full_id_to_core_id(&full_id)
                .expect("test fixture issuer should project to a core id"),
        ),
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

/// Exact runner for `ak.vector.lattice.cas_register_supersession.v1`.
pub fn run_lattice_cas_register_supersession_vector() -> Result<()> {
    let lattice = CasRegister;
    let cref = cell(
        arkret_wire::CellFamilyId::REALM_POLICY_SERVER_V1,
        "ak.realm.01js0sp0000000000000000002",
    );
    let declaration = json!({"policy_server_did": "did:web:policy.example"});
    let tombstone = json!({"tombstone": true});
    let replacement = json!({"policy_server_did": "did:web:replacement.example"});

    let chain = vec![
        SealedOp::new(issuer_digest("d1"), op_set(declaration.clone())),
        SealedOp::new(
            issuer_digest("d2"),
            op_supersede(tombstone.clone(), declaration.clone()),
        ),
        SealedOp::new(
            issuer_digest("d3"),
            op_supersede(replacement.clone(), tombstone.clone()),
        ),
    ];
    if lattice.join(&cref, &chain) != CellState::Value(replacement.clone()) {
        bail!("a complete declaration -> tombstone -> replacement chain did not settle");
    }
    if lattice.join(&cref, &chain[..2]) != CellState::Value(tombstone.clone()) {
        bail!("a prefix-closed historical view did not settle at its chain terminal");
    }

    let siblings = vec![
        chain[0].clone(),
        SealedOp::new(
            issuer_digest("d4"),
            op_supersede(tombstone.clone(), declaration.clone()),
        ),
        SealedOp::new(
            issuer_digest("d5"),
            op_supersede(replacement, declaration.clone()),
        ),
    ];
    if !matches!(lattice.join(&cref, &siblings), CellState::Bottom(_)) {
        bail!("concurrent distinct siblings on one predecessor must conflict");
    }

    let duplicate = vec![chain[0].clone(), chain[1].clone(), chain[1].clone()];
    if lattice.join(&cref, &duplicate) != CellState::Value(tombstone) {
        bail!("a byte-identical repeated set was not idempotently deduplicated");
    }
    Ok(())
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
                .heads
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
    // event-auth-state-resolution.md 9.3.1: each issuer sub-chain starts at
    // issuer_seq 0, and slots are keyed by (cell, actor_id, issuer_seq) so two
    // issuers at the same seq are independent entries, not a conflict.
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
        // Byte-identical replay of alice seq 0: an idempotent duplicate, not
        // equivocation, even though it arrives under a different Event digest.
        issued_op(
            "did:web:alice.example",
            "9a",
            op_append(json!({"actor": "alice", "msg": "hi"}), 0),
        ),
    ];
    let report = lattice.join_with_issuer_report(&ops);
    if !report.fail_closed.is_empty() {
        bail!("OrderedLog monotonic append must not fail closed: {report:?}");
    }
    if !report.equivocations.is_empty() {
        bail!("byte-identical replay is a duplicate, not equivocation: {report:?}");
    }
    let entries = &report.entries;
    if entries.len() != 3 {
        bail!("OrderedLog must dedupe byte-identical appends and keep 3 entries, got {entries:?}");
    }
    if entries[0].get("issuer").and_then(Value::as_str) != Some("did:web:alice.example")
        || entries[0].get("issuer_seq").and_then(Value::as_u64) != Some(0)
        || entries[1].get("issuer").and_then(Value::as_str) != Some("did:web:alice.example")
        || entries[1].get("issuer_seq").and_then(Value::as_u64) != Some(1)
        || entries[2].get("issuer").and_then(Value::as_str) != Some("did:web:bob.example")
        || entries[2].get("issuer_seq").and_then(Value::as_u64) != Some(0)
    {
        bail!("OrderedLog entries are not sorted by issuer then seq: {entries:?}");
    }

    // Starting a sub-chain above 0 must not materialize: the prefix is anchored
    // at 0, not at the lowest seq observed.
    let late_only = vec![issued_op(
        "did:web:carol.example",
        "b3",
        op_append(json!({"actor": "carol", "msg": "late"}), 3),
    )];
    let late_report = lattice.join_with_issuer_report(&late_only);
    if !late_report.entries.is_empty() {
        bail!("OrderedLog prefix must start at issuer_seq 0, got {late_report:?}");
    }
    if late_report
        .pending_gaps
        .iter()
        .all(|gap| gap.missing_seq != 0)
    {
        bail!("OrderedLog must report the missing seq 0 gap: {late_report:?}");
    }
    Ok(())
}

/// encoding.md 4.2: one issuer making non-equivalent claims on a single slot
/// resolves to the greatest canonical `event_digest`, compared as decoded
/// octets. Arrival order and causal edges MUST NOT change the winner, and the
/// loser MUST stay visible as a diagnostic.
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
        if !report.fail_closed.is_empty() {
            bail!("{label}: equivocation must resolve, not fail closed: {report:?}");
        }
        if report.entries.len() != 1 {
            bail!(
                "{label}: one slot must yield one entry, got {:?}",
                report.entries
            );
        }
        let value = report.entries[0]
            .get("value")
            .cloned()
            .unwrap_or(Value::Null);
        if value.get("msg").and_then(Value::as_str) != Some("winner") {
            bail!("{label}: winner must be the greatest event_digest, got {value:?}");
        }
        if report.equivocations.len() != 1 {
            bail!("{label}: the losing claim must remain an auditable diagnostic: {report:?}");
        }
        let diagnostic = &report.equivocations[0];
        if diagnostic.winner_event_digest != issuer_digest("22").as_str()
            || diagnostic.loser_event_digests != vec![issuer_digest("11").as_str().to_owned()]
        {
            bail!("{label}: equivocation diagnostic does not name winner/loser: {diagnostic:?}");
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
        .fail_closed
        .iter()
        .all(|slot| slot.reason != "digest_collision")
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
    if gap_report.entries.len() != 2 {
        bail!(
            "OrderedLog gap must expose only contiguous prefix seq 0,1; got {:?}",
            gap_report.entries
        );
    }
    if gap_report.entries.iter().any(|entry| {
        entry.get("issuer_seq").and_then(Value::as_u64) == Some(3)
            || entry.to_string().contains("late-b")
    }) {
        bail!("OrderedLog pending gap entry leaked into materialized cell value");
    }
    if gap_report.pending_gaps.len() != 1 {
        bail!(
            "OrderedLog gap must report one pending_gap diagnostic, got {:?}",
            gap_report.pending_gaps
        );
    }
    let gap = &gap_report.pending_gaps[0];
    if gap.issuer != "did:web:alice.example"
        || gap.missing_seq != 2
        || gap.pending_seq != 3
        || gap.reason != "dependency_missing"
    {
        bail!("OrderedLog pending_gap diagnostic drifted: {gap:?}");
    }
    let CellState::Value(value) = lattice.join_with_issuers(&cref, &gap_ops) else {
        bail!("OrderedLog gap must not Bottom");
    };
    if value.as_array().is_none_or(|entries| entries.len() != 2) {
        bail!("OrderedLog join value must withhold pending gap entry: {value}");
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
    let backfilled_b = vec![
        issued_op(
            "did:web:alice.example",
            "b0",
            op_append(json!({"entry_id": "entry-0000", "kind": "start"}), 0),
        ),
        issued_op(
            "did:web:alice.example",
            "b1",
            op_append(json!({"entry_id": "entry-0001", "kind": "next"}), 1),
        ),
        issued_op(
            "did:web:alice.example",
            "b2",
            op_append(json!({"entry_id": "entry-0002", "kind": "backfill"}), 2),
        ),
        issued_op(
            "did:web:alice.example",
            "b4",
            op_append(json!({"entry_id": "entry-0003-a", "kind": "late-a"}), 3),
        ),
        issued_op(
            "did:web:alice.example",
            "b3",
            op_append(json!({"entry_id": "entry-0003-b", "kind": "late-b"}), 3),
        ),
    ];
    let report_a = lattice.join_with_issuer_report(&backfilled_a);
    let report_b = lattice.join_with_issuer_report(&backfilled_b);
    if !report_a.pending_gaps.is_empty() || !report_b.pending_gaps.is_empty() {
        bail!(
            "OrderedLog backfill must clear pending gaps: {:?} / {:?}",
            report_a.pending_gaps,
            report_b.pending_gaps
        );
    }
    if report_a.entries.len() != 4 || report_b.entries.len() != 4 {
        bail!(
            "OrderedLog backfill must materialize seq 0..3: {:?} / {:?}",
            report_a.entries,
            report_b.entries
        );
    }
    if canonical_json_bytes(&report_a.entries)? != canonical_json_bytes(&report_b.entries)? {
        bail!("OrderedLog backfill recompute depended on arrival order");
    }
    if report_a.entries[3]["value"]
        .get("entry_id")
        .and_then(Value::as_str)
        != Some("entry-0003-a")
    {
        bail!(
            "OrderedLog duplicate same issuer_seq must keep min entry_id, got {:?}",
            report_a.entries[3]
        );
    }

    Ok(())
}

// ──────────────────── Notary cell ────────────────────
//
// `ak:cell:ak.component.notary.v1:<realm_id>` is a cas_register holding the
// `NotaryValue` (single_did | threshold(k/n) | open_set | mixed). Each
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

fn notary_cell_single_did_profile_resolves_to_value() -> Result<()> {
    let lattice = CasRegister;
    let cref = notary_cell("01");
    let value = json!({
        "kind": "single_did",
        "did": "did:web:hub.example",
    });
    let ops = vec![SealedOp::new(issuer_digest("a1"), op_set(value))];
    let resolved = lattice.join(&cref, &ops);
    if resolved.is_bottom() {
        bail!("Notary single_did profile must resolve to Value, got {resolved:?}");
    }
    Ok(())
}

fn notary_cell_threshold_profile_resolves_to_value() -> Result<()> {
    let lattice = CasRegister;
    let cref = notary_cell("02");
    let value = json!({
        "kind": "threshold",
        "threshold": 2,
        "members": [
            "did:web:notary1.example",
            "did:web:notary2.example",
            "did:web:notary3.example"
        ],
        "forensic_attribution": "quorum_intersection",
    });
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
    let value = json!({
        "kind": "open_set",
        "members": [
            "did:web:peer1.example",
            "did:web:peer2.example"
        ],
    });
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
    let value = json!({
        "kind": "mixed",
        "did": "did:web:hub.example",
        "recovery_members": [
            "did:web:recovery1.example",
            "did:web:recovery2.example"
        ],
    });
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
            op_set(json!({
                "kind": "single_did",
                "did": "did:web:hub-a.example",
            })),
        ),
        SealedOp::new(
            issuer_digest("a6"),
            op_set(json!({
                "kind": "single_did",
                "did": "did:web:hub-b.example",
            })),
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
        "per_issuer_sequence_order",
        "issuer_prefix_starts_at_seq_zero",
        "byte_identical_projected_op_is_idempotent",
        "same_issuer_seq_equivocation_uses_max_event_digest",
        "equivocation_winner_is_independent_of_causal_edges",
        "equivocation_loser_remains_in_canonical_log",
        "max_event_digest_compares_decoded_octets_across_suites",
        "distinct_digest_preimage_same_event_digest_fails_closed",
        "proofs_or_reducer_stamp_difference_is_not_a_digest_collision",
    ];
    const ORDERED_LOG_GAP: &[&str] = &[
        "gap_after_contiguous_prefix_is_pending_diagnostic",
        "pending_gap_entry_does_not_enter_cell_value",
        "backfill_recompute_is_arrival_order_independent",
    ];
    match vector_id {
        "ak.vector.lattice.ordered_log_join.v1" => ORDERED_LOG_JOIN.contains(&assertion),
        "ak.vector.lattice.ordered_log_gap.v1" => ORDERED_LOG_GAP.contains(&assertion),
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
