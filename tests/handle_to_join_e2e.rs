//! T3.5 — Handle → Join end-to-end conformance entrypoint.
//!
//! Stitches the four pieces shipped in T3.1–T3.4:
//!
//!   - T3.1 ships `MemberDeliveryBindingCandidate` + typed SDK validator.
//!   - T3.2 wires `handle_claim` issuance in coauth (canonical
//!     `contrix://...` URI + `member_delivery_binding`).
//!   - T3.3 lands the soland `delivery_binding_policy` reducer
//!     (`recipient_service_not_allowed` / `binding_source_not_allowed`).
//!   - T3.4 adds the teabay `cx.directory.resolve_handle(intent="member_add")`
//!     allow-list filter.
//!
//! The scenario in `cotest::scenarios::handle_to_join_e2e` always exercises
//! the SDK happy path + all seven negatives, and best-effort drives a live
//! `POST /api/v1/directory/resolve-handle` against teabay when COAUTH_BIN,
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
#[tokio::test]
#[ignore = "T3.5 — exercises the Handle → Join chain; live leg spawns coauth/soland/teabay binaries. Run with --ignored when COAUTH_BIN / SOLAND_BIN / TEABAY_BIN (or sibling-checkout builds) are available."]
#[serial]
async fn handle_to_join_e2e() -> Result<()> {
    cotest::scenarios::handle_to_join_e2e::handle_to_join_e2e_run().await
}
