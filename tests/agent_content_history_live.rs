#[tokio::test(flavor = "multi_thread")]
async fn current_join_history_floor_does_not_exempt_the_original_agent_author() -> anyhow::Result<()>
{
    let result =
        cotest::scenarios::agent_runtime_live::run_agent_content_history_production().await?;
    println!("[agent-history-cases] {result:#?}");
    assert_eq!(
        result
            .cases
            .iter()
            .map(|row| row.case_id.as_str())
            .collect::<Vec<_>>(),
        cotest::scenarios::agent_runtime_live::REVIEWED_HISTORY_CONTENT_CASES
    );
    Ok(())
}
