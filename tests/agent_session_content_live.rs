#[tokio::test(flavor = "multi_thread")]
async fn membership_content_session_uses_fresh_issue_and_current_refresh() -> anyhow::Result<()> {
    let execution =
        cotest::scenarios::agent_runtime_live::run_agent_session_content_production().await?;
    println!("[agent-nested-content] {execution:#?}");
    assert_eq!(execution.cases.len(), 18);
    assert!(execution.cases.iter().all(|case| case.assertions > 0));
    Ok(())
}
