#[tokio::test(flavor = "multi_thread")]
async fn real_grant_paths_preserve_resource_correlation_and_current_source() -> anyhow::Result<()> {
    let result =
        cotest::scenarios::agent_runtime_live::run_agent_content_grant_production().await?;
    println!("[agent-grant-cases] {result:#?}");
    assert_eq!(result.cases.len(), 6);
    Ok(())
}
