#[tokio::test(flavor = "multi_thread")]
async fn canonical_pairing_failure_reasons_cross_the_real_gate_without_business_writes()
-> anyhow::Result<()> {
    let result =
        cotest::scenarios::agent_runtime_live::run_agent_pairing_expiry_production().await?;
    assert_eq!(result.cases[0].case_id, "agent_pairing_expiry");
    Ok(())
}
