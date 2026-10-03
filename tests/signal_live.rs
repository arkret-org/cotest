use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn accepted_signal_self_peer_recipient_and_read_only_denials() -> Result<()> {
    cotest::scenarios::signal_live::run().await
}
