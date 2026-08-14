//! T8.1 — Full multi-service end-to-end conformance entrypoint.
//!
//! Drives the entire cross-project strand from subject DID mint through
//! coauth handle_claim, teabay directory resolve_handle, soland
//! member_add, inkson mock message send, floria blind-wakeup gateway,
//! chime mock receive, rebind handover, and revocation.
//!
//! The scenario in `cotest::scenarios::full_stack_e2e`:
//!  - Always exercises the SDK contract surface (happy path + every negative case).
//!  - Best-effort drives the live four-binary stack (coauth + soland + teabay + floria) when
//!    **all** of COAUTH_BIN, SOLAND_BIN, TEABAY_BIN, and FLORIA_BIN — plus their declared
//!    `required_env_vars` — are present.
//!
//! Marked `#[ignore]` because the live leg spawns real sibling binaries
//! and an ephemeral Postgres docker container. The opt-in invocation is:
//!
//!   cargo test --test full_stack_e2e -- --ignored
//!
//! When any binary is missing the live leg silently skips and the SDK
//! contract surface still runs — matching the convention used by
//! `handle_to_join_e2e` and `production_rejects_placeholder_proof_e2e`.

use anyhow::Result;
use serial_test::serial;

/// Gating: live multi-service stack — spawns coauth/soland/teabay/
/// floria binaries. Requires all `*_BIN` env vars (or sibling-checkout
/// builds) on PATH. When any binary is missing the live leg silently
/// skips and the SDK contract surface still runs.
/// Issue: T8.1 (full-stack E2E)
/// Tier: live
#[tokio::test(flavor = "multi_thread")]
#[ignore = "T8.1 — full multi-service E2E; live leg spawns coauth/soland/teabay/floria. Run with --ignored when all *_BIN env vars (or sibling-checkout builds) are available."]
#[serial]
async fn full_stack_e2e() -> Result<()> {
    cotest::scenarios::full_stack_e2e::full_stack_e2e_run().await
}
