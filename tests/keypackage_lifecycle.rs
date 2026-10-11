//! Live MLS KeyPackage lifecycle legs of `ak.suite.crypto.keypackage_lifecycle.v1`.
//! They need a prebuilt Coland and PostgreSQL and soft-skip without them unless
//! `COTEST_REQUIRE_LIVE_SERVICES=1`.

use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn same_station_keypackage_claim_genesis_add_and_welcome_lifecycle() -> Result<()> {
    cotest::scenarios::mls_lifecycle_live::run_same_station_mls_keypackage_lifecycle_live().await
}
