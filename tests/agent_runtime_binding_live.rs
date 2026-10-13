#[tokio::test(flavor = "multi_thread")]
async fn pending_runtime_binding_uses_actual_native_keys_and_station_admission()
-> anyhow::Result<()> {
    let execution =
        cotest::scenarios::agent_runtime_live::run_agent_runtime_binding_admission().await?;
    assert_eq!(execution.cases.len(), 1);
    assert_eq!(execution.cases[0].case_id, "agent_runtime_key_binding");
    assert_eq!(execution.cases[0].assertions, 13);
    Ok(())
}
