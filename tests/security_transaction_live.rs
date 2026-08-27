use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
#[ignore = "security-transaction operations are not in an advertised principal-server bundle"]
async fn live_soland_security_transaction_create_replays_first_outcome() -> Result<()> {
    cotest::scenarios::security_transaction_live::security_transaction_create_is_durable_on_live_soland()
        .await
}
