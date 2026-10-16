#[tokio::test(flavor = "multi_thread")]
async fn actual_agent_reads_verified_contact_interval_without_origin() -> anyhow::Result<()> {
    let result =
        cotest::scenarios::agent_runtime_live::run_agent_content_direct_interval_production()
            .await?;
    println!("[agent-direct-interval-cases] {result:#?}");
    assert_eq!(
        result
            .cases
            .iter()
            .map(|case| case.case_id.as_str())
            .collect::<Vec<_>>(),
        cotest::scenarios::agent_runtime_live::REVIEWED_DIRECT_INTERVAL_CONTENT_CASES
    );
    assert!(result.cases.iter().all(|case| case.assertions > 0));
    Ok(())
}
