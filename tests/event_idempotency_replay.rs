use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn duplicate_event_submit_is_idempotent_and_projects_once() -> Result<()> {
    cotest::scenarios::event_idempotency_replay::duplicate_event_submit_is_idempotent_and_projects_once().await
}

#[tokio::test]
#[serial]
async fn concurrent_event_retransmission_accepts_once_and_allows_the_next_write() -> Result<()> {
    cotest::scenarios::event_idempotency_replay::concurrent_event_retransmission_accepts_once_and_allows_the_next_write().await
}

#[tokio::test]
#[serial]
async fn idempotency_keys_are_isolated_between_authenticated_actors() -> Result<()> {
    cotest::scenarios::event_idempotency_replay::idempotency_keys_are_isolated_between_authenticated_actors().await
}
