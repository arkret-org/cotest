//! Teabay current-v1 exact Realm lookup and blinded-not-found entrypoint.
//!
//! Marked `#[ignore]` because the test spawns `flagon` against a Postgres
//! DSN (`DATABASE_URL`, `TEABAY_BIN`); CI runners without one cleanly skip.
//! Locally:
//!
//!   cargo test --test teabay_resolve_realm -- --ignored

use anyhow::Result;
use serial_test::serial;

/// Gating: spawns flagon against a real Postgres — needs `TEABAY_BIN`
/// and `DATABASE_URL`.
/// Issue: TB-2 (resolve-realm three-lookup fixture)
/// Tier: live
#[tokio::test]
#[ignore = "needs flagon binary + DATABASE_URL"]
#[serial]
async fn teabay_resolve_realm_unknown_is_blinded() -> Result<()> {
    cotest::scenarios::teabay_resolve_realm::teabay_resolve_realm_unknown_is_blinded_run().await
}
