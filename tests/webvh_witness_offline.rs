//! CT-5 — `did:webvh` witness offline >24h + emergency recovery (entrypoint).
//!
//! Marked `#[ignore]` because the test depends on:
//!   * a Rust-side mock-witness spawner (the JS mock at `cotest/e2e/mocks/mock-witness.mjs`
//!     supports the `/health` flip hook, but there's no Rust helper to spawn it yet);
//!   * a starid health-state diagnostic endpoint;
//!   * a max-evidence-age short-window override for the test;
//!   * `rotation_kind="emergency"` tagging on the registrar.
//!
//! See `cotest::scenarios::webvh_witness_offline` for the full sketch
//! and prerequisite list.
//!
//! Run with:
//!
//!   cargo test --test webvh_witness_offline -- --ignored

use anyhow::Result;
use serial_test::serial;

/// Gating: needs mock-witness Rust spawner + starid health-state
/// diagnostic + `max-evidence-age` override + `rotation_kind=emergency`
/// tagging.
/// Issue: CT-5 (webvh witness offline)
#[tokio::test]
#[ignore = "needs mock-witness Rust spawner + starid health-state diagnostic + max-evidence-age override + rotation_kind=emergency tagging (see CT-5)"]
#[serial]
async fn webvh_witness_offline_then_emergency_recovery() -> Result<()> {
    cotest::scenarios::webvh_witness_offline::webvh_witness_offline_recovery_run().await
}
