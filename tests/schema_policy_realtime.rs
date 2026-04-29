use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn schema_registry_lifecycle_and_visibility_work() -> Result<()> {
    cotest::scenarios::schema_policy_realtime::schema_registry_lifecycle_and_visibility_work().await
}

#[tokio::test]
#[serial]
async fn policy_documents_shape_decisions_and_ownership_work() -> Result<()> {
    cotest::scenarios::schema_policy_realtime::policy_documents_shape_decisions_and_ownership_work()
        .await
}

#[tokio::test]
#[serial]
async fn typing_and_push_rules_flow_work() -> Result<()> {
    cotest::scenarios::schema_policy_realtime::typing_and_push_rules_flow_work().await
}

#[tokio::test]
#[serial]
async fn webrtc_session_signal_flow_and_guards_work() -> Result<()> {
    cotest::scenarios::schema_policy_realtime::webrtc_session_signal_flow_and_guards_work().await
}
