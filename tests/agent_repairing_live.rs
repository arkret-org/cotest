#[tokio::test(flavor = "multi_thread")]
async fn exact_supersedes_and_replacement_handles_cross_real_station_admission()
-> anyhow::Result<()> {
    let result = cotest::scenarios::agent_runtime_live::run_agent_repairing_production().await?;
    assert_eq!(result.cases[0].case_id, "agent_repairing_supersede");
    assert_eq!(result.cases[0].assertions, 8);
    Ok(())
}
