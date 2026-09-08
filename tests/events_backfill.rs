use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn backfill_pages_recover_messages_missing_from_limited_client_page() -> Result<()> {
    cotest::scenarios::events_backfill::backfill_pages_recover_messages_missing_from_limited_client_page().await
}

#[tokio::test]
#[serial]
async fn backfill_remains_gap_free_while_new_events_arrive() -> Result<()> {
    cotest::scenarios::events_backfill::backfill_remains_gap_free_while_new_events_arrive().await
}

#[tokio::test]
#[serial]
async fn event_cursor_allows_page_size_change_without_replaying_the_boundary() -> Result<()> {
    cotest::scenarios::events_backfill::event_cursor_allows_page_size_change_without_replaying_the_boundary().await
}

#[tokio::test]
#[serial]
async fn event_cursor_rejects_different_order() -> Result<()> {
    cotest::scenarios::events_backfill::event_cursor_binds_scope_and_order(true).await
}

#[tokio::test]
#[serial]
async fn event_cursor_rejects_different_realm_selector() -> Result<()> {
    cotest::scenarios::events_backfill::event_cursor_binds_scope_and_order(false).await
}

#[tokio::test]
#[serial]
async fn event_cursor_normalizes_selector_order() -> Result<()> {
    cotest::scenarios::events_backfill::event_cursor_normalizes_selector_order().await
}

#[tokio::test]
#[serial]
async fn event_cursor_cannot_be_reused_by_another_authorized_member() -> Result<()> {
    cotest::scenarios::events_backfill::event_cursor_cannot_be_reused_by_another_authorized_member()
        .await
}

#[tokio::test]
#[serial]
async fn event_scan_rejects_barrier_and_stream_cursor_role_confusion() -> Result<()> {
    cotest::scenarios::events_backfill::event_scan_rejects_barrier_and_stream_cursor_role_confusion(
    )
    .await
}
