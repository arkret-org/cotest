#[tokio::test]
async fn real_issuer_requires_accepted_controller_grants_without_runtime_challenges()
-> anyhow::Result<()> {
    let execution =
        cotest::scenarios::agent_runtime_live::run_agent_human_approval_production().await?;
    assert_eq!(execution.cases.len(), 1);
    assert_eq!(execution.cases[0].assertions, 5);
    Ok(())
}
