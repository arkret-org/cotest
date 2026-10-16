#[tokio::test(flavor = "multi_thread")]
async fn actual_sidecar_bootstrap_does_not_release_pending_endpoint_payload() -> anyhow::Result<()>
{
    let result =
        cotest::scenarios::agent_runtime_live::run_agent_content_sidecar_production().await?;
    println!("[agent-sidecar-cases] {result:#?}");
    assert_eq!(
        result
            .cases
            .iter()
            .map(|row| row.case_id.as_str())
            .collect::<Vec<_>>(),
        cotest::scenarios::agent_runtime_live::REVIEWED_SIDECAR_CONTENT_CASES
    );
    Ok(())
}
