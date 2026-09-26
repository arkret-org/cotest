use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn backfill_pages_recover_messages() -> Result<()> {
    cotest::scenarios::events_backfill::backfill_pages_recover_messages().await
}

#[tokio::test]
#[serial]
async fn backfill_is_stable_during_new_writes() -> Result<()> {
    cotest::scenarios::events_backfill::backfill_is_stable_during_new_writes().await
}

#[tokio::test]
#[serial]
async fn page_size_change_replays_the_same_position() -> Result<()> {
    cotest::scenarios::events_backfill::page_size_change_replays_the_same_position().await
}
