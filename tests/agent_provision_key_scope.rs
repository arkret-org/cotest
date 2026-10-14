//! Key narrowing and immutable ceiling refusals use real admission.

#[tokio::test(flavor = "multi_thread")]
async fn narrower_key_preserves_action_resource_and_mandatory_constraint_ceiling()
-> anyhow::Result<()> {
    cotest::scenarios::agent_runtime_live::run_agent_provision_key_scope_boundary().await
}
