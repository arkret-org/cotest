use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn same_device_sessions_remain_distinct_across_durable_cursor_revocation() -> Result<()> {
    cotest::scenarios::cursor_revocation_live::same_device_distinct_session_cursor_revocation_live()
        .await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_revoked_waiting_http_continuation_never_publishes_or_advances() -> Result<()> {
    cotest::scenarios::cursor_revocation_live::waiting_http_cursor_revocation_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_revoked_waiting_websocket_preserves_the_canonical_cursor_error() -> Result<()> {
    cotest::scenarios::cursor_revocation_live::waiting_websocket_cursor_revocation_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn queued_account_frames_recheck_revocation_at_physical_websocket_output() -> Result<()> {
    cotest::scenarios::cursor_revocation_live::queued_websocket_cursor_revocation_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn cursor_revocation_is_visible_between_two_processes_sharing_one_durable_issuer()
-> Result<()> {
    cotest::scenarios::cursor_revocation_live::shared_database_two_process_cursor_revocation_live()
        .await
}
