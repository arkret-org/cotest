use anyhow::Result;

#[tokio::test]
async fn key_backup_replace_with_authorized_device_works() -> Result<()> {
    cotest::scenarios::protocol_payloads::key_backup_replace_with_authorized_device_works().await
}

#[tokio::test]
async fn key_backup_list_absent_at_confirmed_pcr_genesis() -> Result<()> {
    cotest::scenarios::protocol_payloads::key_backup_list_absent_at_confirmed_pcr_genesis().await
}

#[tokio::test]
async fn key_backup_active_pointer_is_committed_and_listed_at_its_pcr_cut() -> Result<()> {
    cotest::scenarios::protocol_payloads::key_backup_active_pointer_is_committed_and_listed_at_its_pcr_cut().await
}
