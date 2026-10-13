#[tokio::test(flavor = "multi_thread")]
async fn recovery_precedes_agent_inception_and_provision_reservation() -> anyhow::Result<()> {
    cotest::scenarios::agent_runtime_live::run_agent_provision_prerequisites_boundary().await
}
