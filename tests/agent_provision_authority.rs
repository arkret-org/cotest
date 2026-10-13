//! Real service signatures, proof refusal and pre-runtime completion cuts.

#[tokio::test(flavor = "multi_thread")]
async fn original_controller_proof_and_completion_cut_hold_in_both_modes() -> anyhow::Result<()> {
    cotest::scenarios::agent_runtime_live::run_agent_provision_authority_boundary().await
}
