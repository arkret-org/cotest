use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn federation_endpoints_reject_invalid_input_shapes() -> Result<()> {
    cotest::scenarios::federation_contract::federation_endpoints_reject_invalid_input_shapes().await
}

#[tokio::test]
#[serial]
async fn federation_replay_snapshot_and_redaction_contracts_work() -> Result<()> {
    cotest::scenarios::federation_contract::federation_replay_snapshot_and_redaction_contracts_work(
    )
    .await
}

#[tokio::test]
#[serial]
async fn federation_remote_operations_project_to_sync_and_index() -> Result<()> {
    cotest::scenarios::federation_contract::federation_remote_operations_project_to_sync_and_index()
        .await
}
