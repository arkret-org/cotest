#[tokio::test(flavor = "multi_thread")]
async fn actual_content_ceilings_and_holder_replacement() -> anyhow::Result<()> {
    let result =
        cotest::scenarios::agent_runtime_live::run_agent_content_ceiling_production().await?;
    println!("[agent-ceiling-cases] {result:#?}");
    assert_eq!(
        result
            .cases
            .iter()
            .map(|row| row.case_id.as_str())
            .collect::<Vec<_>>(),
        cotest::scenarios::agent_runtime_live::REVIEWED_CEILING_CONTENT_CASES
    );
    Ok(())
}
