#[tokio::test(flavor = "multi_thread")]
async fn real_issuer_accepts_long_lived_and_same_key_sessions_then_enforces_lifecycle()
-> anyhow::Result<()> {
    cotest::scenarios::agent_runtime_live::run_agent_longevity_session_boundary().await
}
