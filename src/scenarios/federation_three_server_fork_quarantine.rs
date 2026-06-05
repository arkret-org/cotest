//! CT-1 - Three-server federation fork quarantine.
//!
//! Spec references:
//! - `cokret-spec/spec/v1/zh/sync/federation.md` section 4.1: federation Event exchange uses `POST
//!   /_cokret/peer/events`.
//! - `cokret-spec/spec/v1/zh/sync/federation.md` section 4.2: federation backfill uses `GET
//!   /_cokret/peer/events?realms=...`.
//! - `cokret-spec/spec/v1/zh/sync/federation.md` section 4.5: federation peers exchange signed
//!   Realm frontier evidence via `GET /_cokret/peer/events/frontier?realm_id=...`; if two peers
//!   expose incompatible evidence for the same `(realm_id, actor_id, actor_seq)` or the same
//!   `event_id`, receivers MUST quarantine and report `duplicate_conflict` or
//!   `witness_disagreement` as appropriate.
//!
//! Scenario sketch:
//!
//! 1. Spawn alpha, beta and gamma soland instances, each with a distinct service DID.
//! 2. Configure pairwise federation peer policy out of band so each service DID can call the other
//!    services' `/_cokret/peer/*` surface.
//! 3. Alice creates Realm `R` on alpha. Alpha seeds beta and gamma by pushing the bootstrap Event
//!    Envelopes through `POST /_cokret/peer/events`.
//! 4. Alpha, beta and gamma accept conflicting local Event observations for the same Realm causal
//!    slot.
//! 5. Each node pushes its candidate Event to the other two through `POST /_cokret/peer/events`. A
//!    duplicate event id with different canonical bytes MUST be rejected or quarantined as
//!    `duplicate_conflict`.
//! 6. Each node probes the others with `GET /_cokret/peer/events/frontier?realm_id={realm_id}` and
//!    compares `(heads, frontier_root, actor_seq_upper_bounds, witness_receipts)`.
//! 7. Divergent frontier evidence MUST not advance the local accepted Realm frontier. The peer's
//!    delta remains quarantined until raw replay, quorum witness evidence, or operator-approved
//!    fork resolution reconciles it.
//!
//! Status: ignored scaffold. It becomes executable once soland exposes the
//! full three-node outbound federation driver and an observable quarantine
//! result for probe-detected forks.

use anyhow::Result;

use crate::harness::TestServerGroup;

/// CT-1 - three-server fork quarantine probe.
///
/// The real assertions are blocked on soland's three-node outbound federation
/// driver and probe-detected fork quarantine reporting. The scaffold still
/// validates that the three external soland instances can be spawned when the
/// ignored test is explicitly requested.
pub async fn three_server_fork_quarantine_run() -> Result<()> {
    let Some(group) = TestServerGroup::try_multi_external("ct1-fork-quarantine-3node", 3).await?
    else {
        return Ok(());
    };
    assert_eq!(
        group.len(),
        3,
        "three-node group must have exactly 3 servers"
    );

    let _alpha = group.server(0);
    let _beta = group.server(1);
    let _gamma = group.server(2);

    unimplemented!(
        "CT-1 three-server fork quarantine is blocked on soland outbound \
         peer Events push, frontier probe scheduling, and observable \
         duplicate_conflict / witness_disagreement quarantine reporting over \
         /_cokret/peer/events and /_cokret/peer/events/frontier."
    )
}
