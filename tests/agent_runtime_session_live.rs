//! Live Agent provision → PCR genesis → runtime pairing → Agent session.

#[tokio::test(flavor = "multi_thread")]
async fn agent_is_provisioned_founded_paired_and_reads_its_queue_with_its_session()
-> anyhow::Result<()> {
    cotest::scenarios::agent_runtime_live::run_agent_runtime_session_live().await
}

#[tokio::test(flavor = "multi_thread")]
async fn agent_runtime_authors_actor_private_requests_and_drafts_for_its_controller()
-> anyhow::Result<()> {
    cotest::scenarios::agent_runtime_live::run_agent_actor_private_events_live().await
}
