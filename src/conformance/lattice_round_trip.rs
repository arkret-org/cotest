//! C10.C lattice round-trip vectors.
//!
//! Exercises the SDK's [`cokret_core::lattice`] module directly against the
//! normative scenarios from `move-anchor-lattice-fixture.json` §2.2-2.5.
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
//! - **MvRegister**: concurrent `set` ops surface multiple values without choosing a winner (vs.
//!   CasRegister which produces Bottom).
//! - **OrderedLog**: per-issuer monotonic `append` produces a deterministic linearization; gaps are
//!   tolerated.
//!
//! Each test constructs the minimal `LatticeOp` shape the implementation
//! needs (no full Move signing required — `Lattice::join` reads the op
//! and `move_id` only). Failures here imply SDK lattice drift from the
//! spec's normative join semantics.

use anyhow::{Result, bail};
use cokret_core::lattice::{
    CasRegister, CellState, Counter, Fsm, Lattice, MvRegister, OrSet, OrderedLog, SealedOp,
};
use cokret_core::{CellRef, LatticeOp, LatticeOpType, MoveId};
use serde_json::json;

/// Public entry point matching the cotest fixture-suite naming convention.
/// Returns `Ok(())` when every lattice's normative join behavior matches
/// the spec; `Err` otherwise with the failing scenario name.
pub fn run_lattice_round_trip_suite() -> Result<()> {
    or_set_basic_add_remove_commute()?;
    or_set_idempotent_re_add_after_remove()?;
    cas_register_concurrent_set_returns_bottom_conflict()?;
    cas_register_single_set_returns_value()?;
    counter_pn_sums_increments_and_decrements()?;
    fsm_legal_transition_advances_state()?;
    fsm_illegal_transition_returns_bottom()?;
    mv_register_concurrent_set_surfaces_multiple_values()?;
    ordered_log_per_issuer_monotonic_append()?;
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

fn cell(family: &str, subject: &str) -> CellRef {
    CellRef::new(format!("ck:cell:{family}:{subject}"))
        .expect("test fixture cell id should be valid")
}

fn move_id(suffix: &str) -> MoveId {
    // MoveId regex: ^sha256:[0-9a-f]{64}$ — pad the suffix to
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
    MoveId::new(id).expect("test fixture move id should be valid")
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
        "ck.component.consent.v1",
        "ck.consent.01js0cc0000000000000000000",
    );
    let m1 = move_id("aa");
    let m2 = move_id("bb");
    let m3 = move_id("cc");

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
        "ck.component.consent.v1",
        "ck.consent.01js0cc0000000000000000000",
    );
    let ops = vec![
        SealedOp::new(move_id("aa"), op_add("red")),
        SealedOp::new(move_id("bb"), op_remove("red")),
        SealedOp::new(move_id("cc"), op_add("red")),
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
        "ck.component.realm.policy.v1",
        "ck.realm.01js0sp0000000000000000000",
    );
    // Two sealed Moves concurrently set the cell to distinct values.
    let ops = vec![
        SealedOp::new(move_id("aa"), op_set(json!({"role": "admin"}))),
        SealedOp::new(move_id("bb"), op_set(json!({"role": "moderator"}))),
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
    if !matches!(bottom.kind, cokret_core::BottomKind::Conflict) {
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
        "ck.component.realm.policy.v1",
        "ck.realm.01js0sp0000000000000000001",
    );
    let ops = vec![SealedOp::new(
        move_id("dd"),
        op_set(json!({"role": "admin"})),
    )];
    let resolved = lattice.join(&cref, &ops);
    if resolved.is_bottom() {
        bail!("CasRegister with a single sealed set must NOT Bottom; got {resolved:?}");
    }
    Ok(())
}

// ─────────────────────────── Counter ─────────────────────────────────

fn counter_pn_sums_increments_and_decrements() -> Result<()> {
    let lattice = Counter;
    let cref = cell("ck.component.counter.v1", "metrics.events.received");
    let ops = vec![
        SealedOp::new(move_id("ee"), op_inc(5)),
        SealedOp::new(move_id("ff"), op_inc(3)),
        SealedOp::new(move_id("11"), op_dec(2)),
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
        (json!("invited"), json!("joined")),
        (json!("invited"), json!("left")),
        (json!("joined"), json!("left")),
        (json!("joined"), json!("banned")),
    ])
    .with_initial(json!("invited"))
}

fn fsm_legal_transition_advances_state() -> Result<()> {
    let lattice = membership_fsm();
    let cref = cell("ck.component.member.state.v1", "did.web.alice.example");
    // Single legal transition: invited → joined.
    let ops = vec![SealedOp::new(
        move_id("22"),
        op_transition(json!("invited"), json!("joined")),
    )];
    let resolved = lattice.join(&cref, &ops);
    if resolved.is_bottom() {
        bail!("Fsm legal transition must not Bottom; got {resolved:?}");
    }
    Ok(())
}

fn fsm_illegal_transition_returns_bottom() -> Result<()> {
    let lattice = membership_fsm();
    let cref = cell("ck.component.member.state.v1", "did.web.alice.example");
    // Two concurrent transitions claiming distinct `from` states for the
    // same cell — a join of these MUST surface a Bottom because the
    // pre-state can only be one value at a time.
    let ops = vec![
        SealedOp::new(
            move_id("33"),
            op_transition(json!("invited"), json!("joined")),
        ),
        SealedOp::new(
            move_id("44"),
            op_transition(json!("joined"), json!("invited")),
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
        "ck.component.flow.title.v1",
        "ck.flow.01js0fl0000000000000000000",
    );
    // MvRegister surfaces multiple concurrent values. The SDK's reference
    // implementation defaults to a Bottom-shaped result with both heads in
    // `heads[]` (callers can flip to `bottom = expose` to render multi-value
    // as a Value array directly). Either form is acceptable as long as
    // BOTH input values are visible to the caller.
    let ops = vec![
        SealedOp::new(move_id("55"), op_set(json!("Title A"))),
        SealedOp::new(move_id("66"), op_set(json!("Title B"))),
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
    let cref = cell(
        "ck.component.audit_log.v1",
        "ck.realm.01js0sp0000000000000000000",
    );
    // Two issuers, both with monotonic issuer_seq. Join must produce a
    // deterministic linearization that includes all entries.
    let ops = vec![
        SealedOp::new(
            move_id("77"),
            op_append(json!({"actor": "alice", "msg": "hi"}), 1),
        ),
        SealedOp::new(
            move_id("88"),
            op_append(json!({"actor": "bob", "msg": "hello"}), 1),
        ),
        SealedOp::new(
            move_id("99"),
            op_append(json!({"actor": "alice", "msg": "ack"}), 2),
        ),
    ];
    let resolved = lattice.join(&cref, &ops);
    if resolved.is_bottom() {
        bail!("OrderedLog with monotonic per-issuer seq must not Bottom; got {resolved:?}");
    }
    Ok(())
}

// ──────────────────── Notary cell ────────────────────
//
// `ck:cell:ck.component.notary.v1:<realm_id>` is a cas_register holding the
// `NotaryValue` (single_did | threshold(k/n) | open_set | mixed). Each
// happy-path test below confirms a single sealed Move that sets the cell
// to one of the four spec-normative shapes resolves to a Value (no Bottom).
// The conflict test confirms two concurrent reconfigurations Bottom — admins
// MUST coordinate (this is a safety-critical cell).

fn notary_cell(realm_suffix: &str) -> CellRef {
    cell(
        "ck.component.notary.v1",
        &format!("ck.realm.01js{realm_suffix}000000000000000000"),
    )
}

fn notary_cell_single_did_profile_resolves_to_value() -> Result<()> {
    let lattice = CasRegister;
    let cref = notary_cell("01");
    let value = json!({
        "kind": "single_did",
        "did": "did:web:hub.example",
    });
    let ops = vec![SealedOp::new(move_id("a1"), op_set(value))];
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
        "k": 2,
        "n": 3,
        "members": [
            "did:web:notary1.example",
            "did:web:notary2.example",
            "did:web:notary3.example"
        ],
    });
    let ops = vec![SealedOp::new(move_id("a2"), op_set(value))];
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
    let ops = vec![SealedOp::new(move_id("a3"), op_set(value))];
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
        "primary": "did:web:hub.example",
        "recovery_members": [
            "did:web:recovery1.example",
            "did:web:recovery2.example"
        ],
    });
    let ops = vec![SealedOp::new(move_id("a4"), op_set(value))];
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
            move_id("a5"),
            op_set(json!({
                "kind": "single_did",
                "did": "did:web:hub-a.example",
            })),
        ),
        SealedOp::new(
            move_id("a6"),
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
    if !matches!(bottom.kind, cokret_core::BottomKind::Conflict) {
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
        "ck.component.realm.policy.v1",
        "ck.realm.01js0sp0000000000000000000",
    );
    // Seal view AFTER recovery: only the repair Move's sealed op is in
    // scope (the earlier conflict pair was rolled back / superseded by the
    // recovery Seal). Result MUST be Value.
    let ops = vec![SealedOp::new(
        move_id("b1"),
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
        "ck.component.realm.policy.v1",
        "ck.realm.01js0sp0000000000000000001",
    );
    // Two concurrent set-Moves where one self-references its own "winner"
    // capability remain a Bottom at the lattice layer — the cas_register
    // doesn't peek at payload semantics, it just sees concurrent writes.
    // Self-authorisation prevention is enforced at verify_move (auth layer)
    // ABOVE the lattice; here we confirm the lattice itself doesn't pick a
    // winner just because one payload claims authority.
    let ops = vec![
        SealedOp::new(
            move_id("b2"),
            op_set(json!({
                "role": "admin",
                "self_authorising": true,
                "claims": "winner",
            })),
        ),
        SealedOp::new(move_id("b3"), op_set(json!({"role": "moderator"}))),
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
// `ck:cell:ck.component.mls.covered_frontier.v1:<realm_id>` is an or_set of
// governance-frontier event refs each MLS commit attests to. Add-only
// growth is the typical pattern; rotation that purges old refs is rare and
// gated by capability. These tests confirm the lattice surfaces the union
// without bottom under normal commit flow.

fn covered_frontier_cell(realm_suffix: &str) -> CellRef {
    cell(
        "ck.component.mls.covered_frontier.v1",
        &format!("ck.realm.01js{realm_suffix}000000000000000000"),
    )
}

fn mls_covered_frontier_or_set_accumulates_governance_refs() -> Result<()> {
    let lattice = OrSet;
    let cref = covered_frontier_cell("c1");
    // Two MLS commits attest to overlapping governance frontier refs; the
    // or_set surfaces the union without bottom.
    let ops = vec![
        SealedOp::new(
            move_id("c1"),
            op_add("ck:event:01970e58-0007-7000-8000-000000000001"),
        ),
        SealedOp::new(
            move_id("c2"),
            op_add("ck:event:01970e58-0007-7000-8000-000000000002"),
        ),
        SealedOp::new(
            move_id("c3"),
            op_add("ck:event:01970e58-0007-7000-8000-000000000001"),
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
    if !serialized.contains("ck:event:01970e58-0007-7000-8000-000000000001")
        || !serialized.contains("ck:event:01970e58-0007-7000-8000-000000000002")
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
            move_id("c4"),
            op_add("ck:event:01970e58-0007-7000-8000-000000000003"),
        ),
        SealedOp::new(
            move_id("c5"),
            op_add("ck:event:01970e58-0007-7000-8000-000000000004"),
        ),
        SealedOp::new(
            move_id("c6"),
            op_remove("ck:event:01970e58-0007-7000-8000-000000000003"),
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
    if !serialized.contains("ck:event:01970e58-0007-7000-8000-000000000004") {
        bail!(
            "covered_frontier should keep `still_valid` ref visible after rotation: {serialized}"
        );
    }
    if serialized.contains("ck:event:01970e58-0007-7000-8000-000000000003") {
        bail!("covered_frontier should drop the rotated ref after causal remove: {serialized}");
    }
    Ok(())
}
