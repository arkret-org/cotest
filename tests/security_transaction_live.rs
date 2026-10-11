use anyhow::Result;
use serial_test::serial;

/// Gating: Requires a Station advertising the security-transaction operation bundle.
/// Tier: live
#[tokio::test]
#[serial]
#[ignore = "security-transaction operations are not in an advertised station bundle"]
async fn live_coland_security_transaction_create_replays_first_outcome() -> Result<()> {
    cotest::scenarios::security_transaction_live::security_transaction_create_is_durable_on_live_coland()
        .await
}
