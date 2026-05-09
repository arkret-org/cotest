//! E1 Round 24 — federation two-node start entrypoint.
//!
//! Spawns two real soland binaries and runs the federation harness scaffold.
//! Real two-node Move-replay scenarios are TODO(e1-federation); see
//! `cotest::scenarios::federation_two_node_e1`.
//!
//! Marked `#[ignore]` for now so that environments without the soland
//! binary built locally do not regress in CI; remove the `#[ignore]` when
//! the round-25 actual two-node Move-replay payload lands.

use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[ignore = "TODO(e1-federation): scaffold-only landing in round 24; full two-node payload comes in round 25"]
#[serial]
async fn two_node_federation_harness_starts() -> Result<()> {
    cotest::scenarios::federation_two_node_e1::two_node_federation_harness_starts().await
}
