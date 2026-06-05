//! CT-1 — Three-server federation fork quarantine (entrypoint).
//!
//! Spawns 3 soland instances and races three concurrent conflicting
//! Moves against the same cell across all three; verifies that after
//! forced federation push the three nodes agree on a single canonical
//! frontier and the two minority branches are quarantined per
//! `sync/federation.md` §4.5 (`duplicate_conflict`).
//!
//! See `cotest::scenarios::federation_three_server_fork_quarantine` for
//! the full walk-through and prerequisite blockers.
//!
//! Run with:
//!
//!   cargo test --test federation_three_server_fork_quarantine -- --ignored

use anyhow::Result;
use serial_test::serial;

/// Gating: needs soland E2E-FED-1 (outbound HTTP federation push) +
/// E2E-FED-2 (RFC 9421 verify) + §4.5 peer frontier comparison surface
/// (`GET /_cokret/peer/events/frontier` + `duplicate_conflict` reason_code).
/// Issue: CT-1 (three-server fork quarantine)
#[tokio::test]
#[ignore = "needs soland E2E-FED-1 (outbound HTTP federation push) + E2E-FED-2 (RFC 9421 verify) + §4.5 peer frontier comparison surface (`GET /_cokret/peer/events/frontier` + `duplicate_conflict` reason_code) — see CT-1"]
#[serial]
async fn three_server_fork_quarantine_converges_on_canonical_frontier() -> Result<()> {
    cotest::scenarios::federation_three_server_fork_quarantine::three_server_fork_quarantine_run()
        .await
}
