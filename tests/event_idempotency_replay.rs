use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn duplicate_event_submit_is_idempotent_and_projects_once() -> Result<()> {
    cotest::scenarios::event_idempotency_replay::duplicate_event_submit_is_idempotent_and_projects_once().await
}
