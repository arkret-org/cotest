use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn direct_conversation_repair_two_service_durable_closure() -> Result<()> {
    cotest::scenarios::direct_conversation_repair_live::run_direct_conversation_repair_live().await
}
