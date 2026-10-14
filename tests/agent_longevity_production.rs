#[tokio::test(flavor = "multi_thread")]
async fn canonical_longevity_requires_the_entire_live_key_accountability_grant_and_issuer_conjunction()
-> anyhow::Result<()> {
    let result = cotest::scenarios::agent_runtime_live::run_agent_longevity_production().await?;
    anyhow::ensure!(
        result.cases.len() == 1
            && result.cases[0].case_id == "agent_longevity_no_expiry"
            && result.cases[0].assertions == 8
    );
    Ok(())
}
