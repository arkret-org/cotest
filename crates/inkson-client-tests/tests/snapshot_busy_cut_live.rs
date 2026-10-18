use anyhow::Result;

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn actual_member_snapshot_and_native_follower_progress_during_busy_writes() -> Result<()> {
    cotest_inkson_client_tests::scenarios::websocket_live::multistream::run_busy_cut().await
}
