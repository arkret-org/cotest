//! Every provision obligation requires fresh native and browser consumption.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn complete_provision_crosses_native_admission_and_actual_browser_recovery()
-> anyhow::Result<()> {
    let result = cotest::scenarios::agent_runtime_live::run_agent_provision_production().await?;
    assert_eq!(result.cases.len(), 1);
    assert_eq!(result.cases[0].case_id, "agent_provision");
    assert_eq!(result.cases[0].assertions, 20);
    Ok(())
}
