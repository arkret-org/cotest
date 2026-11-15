use anyhow::Result;

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn actual_member_snapshot_and_native_follower_progress_during_busy_writes() -> Result<()> {
    cotest_inkson_client_tests::scenarios::websocket_live::multistream::run_busy_cut().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn actual_frozen_account_pages_finish_while_writes_continue() -> Result<()> {
    cotest_inkson_client_tests::conformance::client_sync::run_frozen_current_baseline(
        "actual_frozen_account_pages_finish_while_writes_continue",
        false,
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn actual_frozen_account_pages_resume_after_owned_client_kill() -> Result<()> {
    cotest_inkson_client_tests::conformance::client_sync::run_frozen_current_baseline(
        "actual_frozen_account_pages_resume_after_owned_client_kill",
        true,
    )
    .await
}
