use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn key_backup_recovery_account_state_requires_policy_and_did_recovery() -> Result<()> {
    cotest::scenarios::key_backup_recovery_account_state::key_backup_recovery_account_state_run()
        .await
}
