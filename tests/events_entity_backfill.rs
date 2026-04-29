use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn backfill_pages_recover_messages_missing_from_limited_client_page() -> Result<()> {
    cotest::scenarios::events_entity_backfill::backfill_pages_recover_messages_missing_from_limited_client_page().await
}

#[tokio::test]
#[serial]
async fn repo_entity_state_operations_are_submitted_and_backfilled() -> Result<()> {
    cotest::scenarios::events_entity_backfill::repo_entity_state_operations_are_submitted_and_backfilled().await
}
