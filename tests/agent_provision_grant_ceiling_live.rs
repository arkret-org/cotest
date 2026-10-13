#[tokio::test(flavor = "multi_thread")]
async fn structured_agent_grants_use_the_immutable_provision_ceiling() -> anyhow::Result<()> {
    cotest::scenarios::agent_runtime_live::run_agent_provision_grant_ceiling_boundary().await
}
