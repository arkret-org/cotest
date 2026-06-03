//! E2 Round 26 / C33.4 / C35.2 — federation two-node real Move-replay entrypoint.
//!
//! Spawns two real soland binaries and exercises the federation Move
//! forwarding surface (push-anchors / pull-anchors) between them.
//!
//! C33.4 routed the multi-server spawn through the reusable `external_binary`
//! helper (`TestServerGroup::try_multi_external`) so the test runs against
//! the pre-built `soland.exe` without paying the `cargo run` startup cost
//! per server. Locate the binary via `SOLAND_BIN=...` or by building the
//! sibling `cokret/soland` checkout.
//!
//! C35.2 promoted the test out of `#[ignore]`: the in-scenario binary lookup
//! silently returns `Ok(())` when neither `SOLAND_BIN` is set nor the
//! sibling-checkout binary exists, so CI runners without a built soland skip
//! cleanly rather than failing. The `device_id` fixture was also rewritten
//! to use a runtime-minted `ck:device:<uuidv7>` per `cokret_identifiers`
//! `is_strict_typed_id` validation.

use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn two_node_federation_harness_starts() -> Result<()> {
    cotest::scenarios::federation_two_node_e1::two_node_federation_harness_starts().await
}
