use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn repo_submit_read_expand_idempotency_and_cas_edges() -> Result<()> {
    cotest::scenarios::repo_sync_index::repo_submit_read_expand_idempotency_and_cas_edges().await
}

#[tokio::test]
#[serial]
async fn repo_rejects_unsigned_unknown_family_and_repo_mismatch() -> Result<()> {
    cotest::scenarios::repo_sync_index::repo_rejects_unsigned_unknown_family_and_repo_mismatch()
        .await
}

#[tokio::test]
#[serial]
async fn sync_directory_and_index_parameter_edges_are_enforced() -> Result<()> {
    cotest::scenarios::repo_sync_index::sync_directory_and_index_parameter_edges_are_enforced()
        .await
}
