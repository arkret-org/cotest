#[tokio::test(flavor = "multi_thread")]
async fn controller_signed_agent_profile_uses_its_own_pcr() -> anyhow::Result<()> {
    let execution =
        cotest::scenarios::agent_runtime_live::run_agent_pcr_profile_admission().await?;
    assert_eq!(execution.cases.len(), 1);
    assert_eq!(execution.cases[0].case_id, "agent_pcr_separation");
    assert_eq!(execution.cases[0].assertions, 9);
    Ok(())
}
