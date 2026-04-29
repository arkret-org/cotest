use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn cross_server_collaboration_flow_works() -> Result<()> {
    cotest::scenarios::federation_collaboration::cross_server_collaboration_flow_works().await
}
