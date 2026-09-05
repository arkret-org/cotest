//! Live consent isolation between a Realm-local ephemeral pairwise actor and
//! an ordinary root Account (scenario `identity/consent-grant` E1.4).
//!
//! This ignored test requires a pre-built Soland binary (`SOLAND_BIN` or the
//! sibling checkout target). It never falls back to `cargo run` when the
//! binary is absent.

use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns a pre-built Soland process and admits a real minimal-metadata pairwise actor"]
#[serial]
async fn consent_pairwise_isolation_live() -> Result<()> {
    cotest::scenarios::consent_pairwise_isolation_live::run_consent_pairwise_isolation_live().await
}
