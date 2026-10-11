use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn joined_member_receives_new_epoch_signal_after_other_member_leaves() -> Result<()> {
    cotest::scenarios::signal_live::run_remaining_member_leave().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn joined_member_receives_new_epoch_signal_after_other_member_is_banned() -> Result<()> {
    cotest::scenarios::signal_live::run_remaining_member_ban().await
}
