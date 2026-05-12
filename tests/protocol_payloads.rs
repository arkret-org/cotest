use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn events_keys_device_blob_push_and_moderation_surfaces_work() -> Result<()> {
    cotest::scenarios::protocol_payloads::events_keys_device_blob_push_and_moderation_surfaces_work(
    )
    .await
}
