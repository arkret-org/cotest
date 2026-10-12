#[tokio::test(flavor = "multi_thread")]
async fn agent_session_proofs_replay_and_lifecycle_use_real_coauth_and_station()
-> anyhow::Result<()> {
    let result =
        cotest::scenarios::agent_runtime_live::run_agent_session_grant_replay_production().await?;
    assert_eq!(result.cases[0].case_id, "agent_session_grant_replay");
    assert_eq!(result.cases[0].assertions, 4);
    Ok(())
}
