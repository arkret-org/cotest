use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn actual_inkson_http_and_websocket_idle_tail_and_reload() -> Result<()> {
    cotest_inkson_client_tests::scenarios::websocket_live::run_follower_idle_and_reload().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn actual_websocket_lifetime_drains_and_closes_with_registered_code() -> Result<()> {
    cotest_inkson_client_tests::scenarios::websocket_live::run_bounded_drain().await
}
