use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn duplicate_event_submit_is_idempotent_and_projects_once() -> Result<()> {
    cotest::scenarios::event_idempotency_replay::duplicate_event_submit_is_idempotent_and_projects_once().await
}

#[tokio::test]
#[serial]
async fn duplicate_edit_and_redaction_replay_project_once() -> Result<()> {
    cotest::scenarios::event_idempotency_replay::duplicate_edit_and_redaction_replay_project_once()
        .await
}
