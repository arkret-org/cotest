#[tokio::test(flavor = "multi_thread")]
async fn actual_controller_transitions_keep_the_terminal_barrier() -> anyhow::Result<()> {
    cotest::scenarios::agent_runtime_live::run_agent_controller_lifecycle_boundary().await
}
