//! TB-2 — teabay resolve-realm three-lookup fixture (entrypoint).
//!
//! Verifies the resolve-realm surface accepts `realm_id` / `alias` /
//! `invite_token` parameter shapes. See
//! `cotest::scenarios::teabay_resolve_realm` for the actual probe logic and
//! the codex-confirmed observation that all three currently converge to a
//! single resource_id lookup.
//!
//! Marked `#[ignore]` because the test spawns `teabay` against a Postgres
//! DSN (`DATABASE_URL`, `TEABAY_BIN`); CI runners without one cleanly skip.
//! Locally:
//!
//!   cargo test --test teabay_resolve_realm -- --ignored

use anyhow::Result;
use serial_test::serial;

/// Gating: spawns teabay against a real Postgres — needs `TEABAY_BIN`
/// and `DATABASE_URL`.
/// Issue: TB-2 (resolve-realm three-lookup fixture)
#[tokio::test]
#[ignore = "needs teabay binary + DATABASE_URL"]
#[serial]
async fn teabay_resolve_realm_three_lookups() -> Result<()> {
    cotest::scenarios::teabay_resolve_realm::teabay_resolve_realm_three_lookups_run().await
}
