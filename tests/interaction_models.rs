use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn message_revision_reaction_marker_and_subscribe_work() -> Result<()> {
    cotest::scenarios::interaction_models::message_revision_reaction_marker_and_subscribe_work()
        .await
}

#[tokio::test]
#[serial]
async fn entity_relation_and_view_endpoints_work() -> Result<()> {
    cotest::scenarios::interaction_models::entity_relation_and_view_endpoints_work().await
}
