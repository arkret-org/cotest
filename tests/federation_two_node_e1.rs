//! E2 Round 26 — federation two-node real Move-replay entrypoint.
//!
//! Spawns two real soland binaries and exercises the federation Move
//! forwarding surface (push-anchors / pull-anchors) between them.
//!
//! Marked `#[ignore = "needs soland binary on PATH"]` so CI runners without a
//! built soland binary opt-in. Run locally with:
//!   `cargo test --test federation_two_node_e1 -- --ignored`.

use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[ignore = "needs soland binary on PATH"]
#[serial]
async fn two_node_federation_harness_starts() -> Result<()> {
    cotest::scenarios::federation_two_node_e1::two_node_federation_harness_starts().await
}
