#[tokio::test(flavor = "multi_thread")]
async fn current_policy_and_resource_correlation_cross_real_issuer_and_station()
-> anyhow::Result<()> {
    let result =
        cotest::scenarios::agent_runtime_live::run_agent_content_policy_production().await?;
    println!("[agent-policy-cases] {result:#?}");
    assert_eq!(
        result
            .cases
            .iter()
            .map(|case| case.case_id.as_str())
            .collect::<Vec<_>>(),
        cotest::scenarios::agent_runtime_live::REVIEWED_POLICY_CONTENT_CASES
    );
    Ok(())
}
