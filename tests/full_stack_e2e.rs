//! T8.1 — Cross-project strand contract entrypoint.
//!
//! Drives the typed cross-project strand: handle claim resolves an exact
//! account, membership carries it, a message payload round-trips, and the
//! blind-wakeup sanitizer rejects every stable protocol identifier.
//!
//! The scenario in `cotest::scenarios::full_stack_e2e` composes
//! `handle_to_join_e2e` with the push blind-payload sanitizers. Like that
//! scenario it spawns nothing and reaches no network, so it runs in the default
//! deterministic suite.
//!
//! It was previously `#[ignore]`d and documented as best-effort driving "the
//! live four-binary stack (coauth + soland + teabay + floria)" when every
//! `*_BIN` env var was present. No such leg exists — the scenario has no HTTP
//! client and no process spawn — so the gate excluded a pure contract test from
//! every profile while claiming live coverage it never had. The real
//! multi-service bring-up lives in `_bootstrap_smoke::joint_service_smoke` and
//! `soland_teabay_directory_sync`, both selected by the `services-live` profile.

use anyhow::Result;

/// Gating: none. Pure SDK/type contract surface across the cross-project
/// strand; no binaries, no database, no network.
/// Issue: T8.1 (cross-project strand contract)
/// Tier: contract
#[tokio::test(flavor = "multi_thread")]
async fn full_stack_e2e() -> Result<()> {
    cotest::scenarios::full_stack_e2e::full_stack_e2e_run().await
}
