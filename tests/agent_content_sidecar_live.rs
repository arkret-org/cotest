#[tokio::test(flavor = "multi_thread")]
async fn actual_sidecar_bootstrap_does_not_release_pending_endpoint_payload() -> anyhow::Result<()>
{
    let result =
        cotest::scenarios::agent_runtime_live::run_agent_content_sidecar_production().await?;
    println!("[agent-sidecar-cases] {result:#?}");
    assert_eq!(
        result
            .cases
            .iter()
            .map(|row| row.case_id.as_str())
            .collect::<Vec<_>>(),
        cotest::scenarios::agent_runtime_live::REVIEWED_SIDECAR_CONTENT_CASES
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn actual_coauth_effective_sidecar_read_uses_consumed_endpoint() -> anyhow::Result<()> {
    cotest::scenarios::agent_runtime_live::run_agent_content_sidecar_read_production().await
}

#[tokio::test(flavor = "multi_thread")]
async fn cross_station_project_history_withdrawal_and_rejoin() -> anyhow::Result<()> {
    cotest::scenarios::agent_runtime_live::run_cross_station_project_history().await
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_project_home_sidecar_creation_and_recovery() -> anyhow::Result<()> {
    cotest::scenarios::agent_runtime_live::run_home_sidecar_offline().await
}
