#[tokio::test(flavor = "multi_thread")]
async fn actual_controller_transitions_keep_the_terminal_barrier() -> anyhow::Result<()> {
    let result =
        cotest::scenarios::agent_runtime_live::run_agent_controller_lifecycle_production().await?;
    assert_eq!(result.cases.len(), 1);
    assert_eq!(result.cases[0].case_id, "agent_controller_lifecycle");
    assert_eq!(result.cases[0].assertions, 8);
    Ok(())
}
