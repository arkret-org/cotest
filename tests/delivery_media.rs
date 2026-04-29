use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn key_upload_query_and_claim_edges_are_enforced() -> Result<()> {
    cotest::scenarios::delivery_media::key_upload_query_and_claim_edges_are_enforced().await
}

#[tokio::test]
#[serial]
async fn to_device_messages_are_idempotent_opaque_and_drained_once() -> Result<()> {
    cotest::scenarios::delivery_media::to_device_messages_are_idempotent_opaque_and_drained_once()
        .await
}

#[tokio::test]
#[serial]
async fn blob_integrity_head_range_and_missing_edges_work() -> Result<()> {
    cotest::scenarios::delivery_media::blob_integrity_head_range_and_missing_edges_work().await
}

#[tokio::test]
#[serial]
async fn push_and_moderation_edges_are_enforced() -> Result<()> {
    cotest::scenarios::delivery_media::push_and_moderation_edges_are_enforced().await
}
