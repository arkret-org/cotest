//! Live Calendar RSVP convergence.

/// Blocked in soland, not in Calendar semantics.
///
/// soland has no admission path by which a client can write a data-plane cell.
/// An Event carrying `effects[]` is classified by which anchor it holds, and
/// all three outcomes are closed
/// (`validation/envelope/control_move.rs`, `.../capability_refs.rs`):
///
/// 1. Neither anchor → "Control Move with effects requires seal_basis.leaves".
/// 2. `seal_basis` → it *is* a Control Move, and `validate_cba_effect_planes` then rejects it with
///    `failed_plane: Control Move effects[] must not write data-plane cell`.
/// 3. `seal_ref` + `auth_context` → a DataEvent, so every named grant must appear in the *sealed
///    cell* state at that `seal_ref` (`data_event_grants_from_state_at_ref` reads
///    `ak:cell:ak.component.capability.grant.v1:*`).
///
/// Door 3 is the one that should work, and it cannot: the Event log and the
/// Move/Seal DAG are disjoint in soland today. `put_pending_move` has exactly
/// two callers, both admin routes (`admin/seal/notary.rs`, `admin/seal/bottom.rs`),
/// so an `ak.capability.grant` Event never becomes a Move and never reaches a
/// Seal. This scenario drives the admin compaction route and the resulting
/// compaction Seal reports `covered_event_digests: []` — there was nothing
/// pending to fold. The founding grant is therefore unprojectable at any
/// `seal_ref`, and the RSVP is refused with
/// `capability_denied: … is not projected at seal_ref`.
///
/// None of this is Calendar-specific: it blocks every data-plane Event that
/// carries effects. RSVP is simply the first such Event to exist, which is why
/// the gap surfaced here. Closing it means deciding how Control Events reach
/// the Move/Seal DAG — an architectural call on soland's control plane, not a
/// Calendar fix.
///
/// The scenario body is complete and already drives a signing pass; remove this
/// attribute once a client-issued grant can reach a Seal.
#[ignore = "soland has no path from a client-issued capability grant to a Seal, so no DataEvent can write a cell"]
#[tokio::test(flavor = "multi_thread")]
async fn calendar_rsvp_converges_across_concurrent_responses() {
    cotest::scenarios::calendar_rsvp_convergence::calendar_rsvp_converges_across_concurrent_responses()
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn calendar_rsvp_without_cell_effect_is_rejected() {
    cotest::scenarios::calendar_rsvp_convergence::calendar_rsvp_without_cell_effect_is_rejected()
        .await
        .unwrap();
}
