use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn key_backup_put_get_negative_paths_fail_closed() -> Result<()> {
    cotest::scenarios::key_backup_negative::key_backup_put_get_negative_run().await
}
