use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn account_subscribe_skips_quiet_realms_and_long_polls() -> Result<()> {
    cotest::scenarios::account_subscribe_long_poll::account_subscribe_skips_quiet_realms_and_long_polls()
        .await
}

#[tokio::test]
#[serial]
async fn invited_members_exchange_post_join_messages_over_account_subscribe() -> Result<()> {
    cotest::scenarios::account_subscribe_long_poll::invited_members_exchange_post_join_messages_over_account_subscribe()
        .await
}

#[tokio::test]
#[serial]
async fn cancelled_pending_invite_disappears_from_invite_views() -> Result<()> {
    cotest::scenarios::account_subscribe_long_poll::cancelled_pending_invite_disappears_from_invite_views()
        .await
}
