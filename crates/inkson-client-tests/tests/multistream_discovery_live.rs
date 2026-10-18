use anyhow::Result;

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn actual_inkson_discovers_beyond_sixty_four_streams_while_idle_busy_and_after_new_scope()
-> Result<()> {
    cotest_inkson_client_tests::scenarios::websocket_live::multistream::run().await
}
