//! T3.5 — Handle → Join conformance entrypoint.
//!
//! Pins the clean-break chain: a handle claim resolves an exact `AccountId`,
//! membership carries it as an `ActorId`, and the Station coordinate remains
//! both identity and routing truth.
//!
//! The scenario in `cotest::scenarios::handle_to_join_e2e` exercises the SDK
//! happy path plus every negative against the typed models. It spawns nothing
//! and reaches no network, so it runs in the default deterministic suite.
//!
//! It was previously `#[ignore]`d and documented as best-effort driving a live
//! `POST /_arkret/find/directory/resolve-handle` against teabay. No such leg
//! exists in the scenario — it has no HTTP client and no process spawn — so the
//! gate excluded a pure contract test from every profile while claiming live
//! coverage it never had. Live directory resolution is covered by
//! `soland_teabay_directory_sync`, which really does bring the stack up.

use anyhow::Result;

/// Gating: none. Pure SDK/type contract surface over the handle-to-membership
/// chain; no binaries, no database, no network.
/// Issue: T3.5 (Handle → Join)
/// Tier: contract
#[tokio::test]
async fn handle_to_join_e2e() -> Result<()> {
    cotest::scenarios::handle_to_join_e2e::handle_to_join_e2e_run().await
}
