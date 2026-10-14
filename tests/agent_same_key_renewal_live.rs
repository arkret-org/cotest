#[tokio::test(flavor = "multi_thread")]
async fn same_key_controller_renewal_replaces_the_exact_dot_and_refuses_stale_basis()
-> anyhow::Result<()> {
    cotest::scenarios::agent_runtime_live::run_agent_same_key_renewal_boundary().await
}
