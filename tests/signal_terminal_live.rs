use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn queued_and_delayed_signal_after_last_member_ban() -> Result<()> {
    cotest::scenarios::signal_live::run_ban().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn queued_and_delayed_signal_after_tombstone_on_websocket() -> Result<()> {
    cotest::scenarios::signal_live::run_terminal().await
}
