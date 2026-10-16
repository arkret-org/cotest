#[tokio::test(flavor = "multi_thread")]
async fn actual_agent_payload_waits_for_its_target_private_epoch() -> anyhow::Result<()> {
    let result = cotest::scenarios::agent_runtime_live::run_agent_content_mls_production().await?;
    println!("[agent-payload-mls-cases] {result:#?}");
    assert_eq!(
        result
            .cases
            .iter()
            .map(|case| case.case_id.as_str())
            .collect::<Vec<_>>(),
        cotest::scenarios::agent_runtime_live::REVIEWED_MLS_CONTENT_CASES
    );
    assert!(result.cases.iter().all(|case| case.assertions > 0));
    Ok(())
}
