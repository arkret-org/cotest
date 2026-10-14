#[tokio::test(flavor = "multi_thread")]
async fn attributed_agent_requires_a_real_narrow_scope_and_selected_confirmation()
-> anyhow::Result<()> {
    cotest::scenarios::agent_runtime_live::run_agent_act_on_behalf_boundary().await
}
