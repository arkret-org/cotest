#[tokio::test(flavor = "multi_thread")]
async fn private_scope_disclosure_and_public_history_cross_real_station() -> anyhow::Result<()> {
    let result =
        cotest::scenarios::agent_runtime_live::run_agent_requested_scope_privacy_production()
            .await?;
    assert_eq!(result.cases[0].case_id, "agent_requested_scope_privacy");
    assert_eq!(result.cases[0].assertions, 4);
    Ok(())
}
