use anyhow::Result;

#[test]
fn agent_pairing_request_loss_response_loss_activation_and_invalidation() -> Result<()> {
    cotest::conformance::run_agent_pairing_durable_coordination_matrix()
}
