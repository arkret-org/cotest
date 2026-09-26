use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn account_contact_space_message_sync_workflow() -> Result<()> {
    cotest::scenarios::collaboration_workflow::account_contact_space_message_sync_workflow().await
}

#[tokio::test]
#[serial]
async fn standard_session_grant_revoke_invalidates_current_session() -> Result<()> {
    cotest::scenarios::collaboration_workflow::standard_session_grant_revoke_invalidates_current_session().await
}
