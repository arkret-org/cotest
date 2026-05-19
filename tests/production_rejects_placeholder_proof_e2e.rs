//! T1.3 — End-to-end production-mode placeholder-proof rejection gate.
//!
//! Spawns soland with `SOLAND_DEVELOPMENT_MODE=false` and posts an
//! Event Envelope carrying the yougen pre-T1.3 placeholder proof
//! (`jws == "a..b"`). The request MUST be rejected with HTTP 401 or
//! 403 — either with `dev_proof_in_production` (T1.3 proof check
//! fired) or with `unauthenticated` (auth wall fired first because
//! dev-login is disabled in production mode).
//!
//! Marked `#[ignore]` because it spawns a live soland binary; opt in
//! locally with:
//!
//!   cargo test --test production_rejects_placeholder_proof_e2e -- --ignored
//!
//! The scenario silently returns `Ok(())` when no soland binary is
//! locatable (no `SOLAND_BIN` and no sibling-checkout debug build),
//! matching the convention of the rest of the cotest scenario suite.

use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[ignore = "T1.3 — spawns soland binary; run with --ignored when SOLAND_BIN or a sibling-checkout build is available."]
#[serial]
async fn production_rejects_placeholder_proof_e2e() -> Result<()> {
    cotest::scenarios::production_rejects_placeholder_proof_e2e
        ::production_rejects_placeholder_proof_e2e_run()
        .await
}
