use anyhow::Result;

#[tokio::test]
async fn key_backup_replace_with_authorized_device_works() -> Result<()> {
    cotest::scenarios::protocol_payloads::key_backup_replace_with_authorized_device_works().await
}
