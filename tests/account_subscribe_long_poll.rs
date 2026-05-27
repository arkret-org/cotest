use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn account_subscribe_skips_quiet_realms_and_long_polls() -> Result<()> {
    cotest::scenarios::account_subscribe_long_poll::account_subscribe_skips_quiet_realms_and_long_polls()
        .await
}
