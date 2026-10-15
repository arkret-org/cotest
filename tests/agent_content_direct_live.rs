#[tokio::test(flavor = "multi_thread")]
async fn direct_content_authority_crosses_real_issuer_mls_and_consumption() -> anyhow::Result<()> {
    let result =
        cotest::scenarios::agent_runtime_live::run_agent_content_direct_production().await?;
    println!("[agent-direct-content-cases] {result:#?}");
    assert_eq!(
        result
            .cases
            .iter()
            .map(|row| row.case_id.as_str())
            .collect::<Vec<_>>(),
        cotest::scenarios::agent_runtime_live::REVIEWED_DIRECT_CONTENT_CASES
    );
    Ok(())
}
