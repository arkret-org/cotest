//! T3.5 — Handle → Join end-to-end conformance entrypoint.
//!
//! Pins the clean-break chain: a handle claim resolves an exact `AccountId`,
//! membership carries it as an `ActorId`, and the Station coordinate remains
//! both identity and routing truth.
//!
//! The scenario in `cotest::scenarios::handle_to_join_e2e` always exercises
//! the SDK happy path + all seven negatives, and best-effort drives a live
//! `POST /_arkret/find/directory/resolve-handle` against teabay when COAUTH_BIN,
//! SOLAND_BIN, TEABAY_BIN and their required env vars (DATABASE_URL,
//! COAUTH_DATABASE_URI, docker) are all present.
//!
//! Marked `#[ignore]` because the live leg spawns real sibling binaries and
//! a Postgres docker container. The opt-in invocation is:
//!
//!   cargo test --test handle_to_join_e2e -- --ignored
//!
//! When the sibling stack is missing, the scenario still exercises the SDK
//! contract surface and returns `Ok(())` — matching the convention used by
//! every other `#[ignore]` test in cotest.

use anyhow::Result;
use serial_test::serial;

/// Gating: live leg spawns coauth/soland/teabay binaries; runs only when
/// COAUTH_BIN / SOLAND_BIN / TEABAY_BIN (or sibling-checkout builds) are
/// available. Without binaries the scenario still exercises the SDK
/// contract surface.
/// Issue: T3.5 (Handle → Join end-to-end)
/// Tier: live
#[tokio::test]
#[ignore = "T3.5 — exercises the Handle → Join chain; live leg spawns coauth/soland/teabay binaries. Run with --ignored when COAUTH_BIN / SOLAND_BIN / TEABAY_BIN (or sibling-checkout builds) are available."]
#[serial]
async fn handle_to_join_e2e() -> Result<()> {
    cotest::scenarios::handle_to_join_e2e::handle_to_join_e2e_run().await
}
