use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn kanban_creates_keep_one_identity_across_receipt_backfill_and_retry() -> Result<()> {
    cotest_inkson_client_tests::scenarios::kanban_identity_boundary::kanban_creates_keep_one_identity_across_receipt_backfill_and_retry(
    )
    .await
}
