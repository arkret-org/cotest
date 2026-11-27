use anyhow::Result;

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn actual_inkson_follows_one_realm_stream_across_sixty_five_chats_and_new_placements()
-> Result<()> {
    cotest_inkson_client_tests::scenarios::websocket_live::multistream::run().await
}
