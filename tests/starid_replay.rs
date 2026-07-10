//! ST-1 — starid replay-rejection test (entrypoint).
//!
//! Verifies starid rejects a re-submitted DID create with `cas_conflict`. See
//! `cotest::scenarios::starid_replay` for the actual probe logic.
//!
//! Marked `#[ignore]` because the test spawns a real `starid` binary; CI
//! runners without one built (or without `STARID_BIN=...`) cleanly skip.
//! Locally:
//!
//!   cargo test --test starid_replay -- --ignored

use anyhow::Result;
use serial_test::serial;

/// Gating: needs a `starid` binary on PATH (or `STARID_BIN=...`); spawns
/// a real process to exercise replay-rejection.
/// Issue: ST-1 (starid replay rejection)
/// Tier: live
#[tokio::test]
#[ignore = "needs starid binary on PATH or `STARID_BIN=...`"]
#[serial]
async fn starid_rejects_replayed_inception() -> Result<()> {
    cotest::scenarios::starid_replay::starid_rejects_replayed_inception_run().await
}
