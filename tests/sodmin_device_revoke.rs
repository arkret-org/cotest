//! SOD-1 — Sodmin device revoke cascade workflow (entrypoint).
//!
//! Marked `#[ignore]` because the test depends on:
//!   * A Rust-side spawner for sodmin (Dioxus admin UI);
//!   * A joint soland+coauth+sodmin bootstrap helper (no equivalent in
//!     `_helpers/coauth_bootstrap.rs` today);
//!   * Playwright integration from inside `cargo test` (playwright scaffolding currently only
//!     exists in `cotest/e2e/` TypeScript);
//!   * Soland session-invalidation-on-device-revoke cascade in soland's auth middleware.
//!
//! See `cotest::scenarios::sodmin_device_revoke` for the full
//! prerequisite list.
//!
//! Run with:
//!
//!   cargo test --test sodmin_device_revoke -- --ignored

use anyhow::Result;
use serial_test::serial;

/// Gating: needs sodmin Dioxus UI spawner + joint
/// soland+coauth+sodmin bootstrap + Rust-side playwright integration +
/// soland device-revoke cascade.
/// Issue: SOD-1 (sodmin device revoke cascade)
#[tokio::test]
#[ignore = "needs sodmin Dioxus UI spawner + soland+coauth+sodmin joint bootstrap + Rust-side playwright + soland device-revoke cascade (see SOD-1)"]
#[serial]
async fn sodmin_device_revoke_cascades_to_coauth_and_soland_session() -> Result<()> {
    cotest::scenarios::sodmin_device_revoke::sodmin_device_revoke_cascade_run().await
}
