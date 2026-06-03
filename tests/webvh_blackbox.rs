//! Round-27 / C32.8 — black-box webvh conformance suite (test entrypoint).
//!
//! The harness logic lives in `cotest::scenarios::webvh_blackbox`; this file
//! is a thin entrypoint so the integration test list mirrors the scenario
//! module list.
//!
//! Marked `#[ignore]` because the test spawns a real `starid` binary and CI
//! runners may not have one built. Locate the binary via `STARID_BIN=...` or
//! by building the sibling `cokret/starid` checkout, then run with:
//!
//!   cargo test --test webvh_blackbox -- --ignored
//!
//! The current ignore-blocker is *purely* binary availability — when the
//! binary is locatable, the spawn helper resolves the path, exports a free
//! port via `STARID_BIND`, waits on `/health`, runs the 5 vectors, and tears
//! the child down on `Drop`.

use anyhow::Result;
use serial_test::serial;

/// Gating: needs a `starid` binary on PATH (or `STARID_BIN=...`); spawns
/// a real process to run the 5 webvh conformance vectors.
/// Issue: Round-27 / C32.8 (webvh blackbox)
#[tokio::test]
#[ignore = "needs starid binary on PATH or `STARID_BIN=...`"]
#[serial]
async fn webvh_blackbox_conformance_vectors_run() -> Result<()> {
    cotest::scenarios::webvh_blackbox::webvh_blackbox_conformance_vectors_run().await
}
