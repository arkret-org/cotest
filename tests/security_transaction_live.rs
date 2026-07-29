use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn live_soland_security_transaction_create_replays_first_outcome() -> Result<()> {
    cotest::scenarios::security_transaction_live::security_transaction_create_is_durable_on_live_soland()
        .await
}

#[tokio::test]
#[serial]
async fn live_soland_recovery_transaction_requires_a_durable_session() -> Result<()> {
    cotest::scenarios::security_transaction_live::recovery_transaction_rejects_unknown_session_on_live_soland()
        .await
}
