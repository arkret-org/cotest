//! Live minimal-metadata pairwise KeyPackage authority coverage.
//!
//! This ignored test requires a pre-built Soland binary (`SOLAND_BIN` or the
//! sibling checkout target). It never falls back to `cargo run` when the
//! binary is absent.

use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "spawns a pre-built Soland process and exercises real RFC 9420 pairwise KeyPackages"]
#[serial]
async fn minimal_metadata_pairwise_keypackage_live() -> Result<()> {
    cotest::scenarios::minimal_metadata_pairwise_keypackage_live::run_minimal_metadata_pairwise_keypackage_live().await
}
