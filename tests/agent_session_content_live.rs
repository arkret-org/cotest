#[tokio::test(flavor = "multi_thread")]
async fn membership_content_session_uses_fresh_issue_and_current_refresh() -> anyhow::Result<()> {
    let execution =
        cotest::scenarios::agent_runtime_live::run_agent_session_content_production().await?;
    println!("[agent-nested-content] {execution:#?}");
    assert!(execution.cases.iter().all(|case| case.assertions > 0));
    assert_eq!(
        execution
            .cases
            .iter()
            .map(|case| case.case_id.as_str())
            .collect::<Vec<_>>(),
        cotest::scenarios::agent_runtime_live::REVIEWED_CONTENT_CASES,
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn direct_participant_content_session_is_fresh_bounded_and_current() -> anyhow::Result<()> {
    cotest::scenarios::agent_runtime_live::run_agent_direct_content_session_boundary().await
}
