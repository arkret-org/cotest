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
async fn key_backup_list_serves_stored_backup_as_closed_metadata() -> Result<()> {
    cotest::scenarios::protocol_payloads::key_backup_list_serves_stored_backup_as_closed_metadata()
        .await
}

#[tokio::test]
async fn key_backup_active_pointer_is_committed_and_listed_at_its_pcr_cut() -> Result<()> {
    cotest::scenarios::protocol_payloads::key_backup_active_pointer_is_committed_and_listed_at_its_pcr_cut().await
}

#[tokio::test]
async fn security_rotation_runs_worker_steps_to_local_commit() -> Result<()> {
    cotest::scenarios::security_rotation_live::security_rotation_runs_worker_steps_to_local_commit()
        .await
}

#[tokio::test]
async fn security_rotation_rejected_revoke_restores_the_target_device() -> Result<()> {
    cotest::scenarios::security_rotation_live::security_rotation_rejected_revoke_restores_the_target_device().await
}

#[tokio::test]
async fn security_rotation_erase_resumes_after_a_partial_failure() -> Result<()> {
    cotest::scenarios::security_rotation_live::security_rotation_erase_resumes_after_a_partial_failure().await
}

#[tokio::test]
async fn key_backup_device_quorum_delete_removes_an_envelope() -> Result<()> {
    cotest::scenarios::security_rotation_live::key_backup_device_quorum_delete_removes_an_envelope()
        .await
}

#[tokio::test]
async fn key_backup_recovery_unlock_delete_is_session_exact_and_zero_write() -> Result<()> {
    cotest::scenarios::security_rotation_live::key_backup_recovery_unlock_delete_is_session_exact_and_zero_write().await
}

#[tokio::test]
async fn security_rotation_erase_resumes_after_an_unrelated_pcr_commit() -> Result<()> {
    cotest::scenarios::security_rotation_live::security_rotation_erase_resumes_after_an_unrelated_pcr_commit().await
}

#[tokio::test]
async fn security_rotation_erase_resume_stops_after_a_pointer_change() -> Result<()> {
    cotest::scenarios::security_rotation_live::security_rotation_erase_resume_stops_after_a_pointer_change().await
}
