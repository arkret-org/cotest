use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn backfill_pages_recover_messages_missing_from_limited_client_page() -> Result<()> {
    cotest::scenarios::events_backfill::backfill_pages_recover_messages_missing_from_limited_client_page().await
}
