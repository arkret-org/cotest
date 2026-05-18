//! TB-2 — teabay resolve-space three-lookup fixture (entrypoint).
//!
//! Verifies the resolve-space surface accepts `space_id` / `alias` /
//! `invite_token` parameter shapes. See
//! `cotest::scenarios::teabay_resolve_space` for the actual probe logic and
//! the codex-confirmed observation that all three currently converge to a
//! single resource_id lookup.
//!
//! Marked `#[ignore]` because the test spawns `teabay` against a Postgres
//! DSN (`DATABASE_URL`, `TEABAY_BIN`); CI runners without one cleanly skip.
//! Locally:
//!
//!   cargo test --test teabay_resolve_space -- --ignored

use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[ignore = "needs teabay binary + DATABASE_URL"]
#[serial]
async fn teabay_resolve_space_three_lookups() -> Result<()> {
    cotest::scenarios::teabay_resolve_space::teabay_resolve_space_three_lookups_run().await
}
