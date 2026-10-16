#[tokio::test(flavor = "multi_thread")]
async fn real_grant_paths_preserve_resource_correlation_and_current_source() -> anyhow::Result<()> {
    let result =
        cotest::scenarios::agent_runtime_live::run_agent_content_grant_production().await?;
    println!("[agent-grant-cases] {result:#?}");
    assert_eq!(result.cases.len(), 8);
    assert_eq!(
        result
            .cases
            .iter()
            .map(|case| case.case_id.as_str())
            .collect::<Vec<_>>(),
        cotest::scenarios::agent_runtime_live::REVIEWED_GRANT_CONTENT_CASES,
    );
    Ok(())
}
