#[tokio::test(flavor = "multi_thread")]
async fn actual_handoff_does_not_supply_unregistered_cross_authority_content() -> anyhow::Result<()>
{
    let result =
        cotest::scenarios::agent_runtime_live::run_agent_content_cross_authority_production()
            .await?;
    println!("[agent-cross-authority-cases] {result:#?}");
    assert_eq!(
        result
            .cases
            .iter()
            .map(|case| case.case_id.as_str())
            .collect::<Vec<_>>(),
        cotest::scenarios::agent_runtime_live::REVIEWED_CROSS_AUTHORITY_CONTENT_CASES
    );
    assert!(result.cases.iter().all(|case| case.assertions > 0));
    Ok(())
}
