use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn account_summary_follows_bootstrap_default_strand_and_restart() -> Result<()> {
    cotest::scenarios::protocol_payloads::account_summary_follows_bootstrap_default_strand_and_restart()
        .await
}
