use anyhow::Result;
use cotest::conformance::run_agent_draft_pending_intent_account_subscribe_conformance;

#[test]
fn public_pending_intent_account_channel_covers_the_joint_protocol_matrix() -> Result<()> {
    let coverage = run_agent_draft_pending_intent_account_subscribe_conformance()?;
    assert_eq!(coverage.protocol_cases.len(), 7);
    assert!(coverage.assertions >= 29);
    Ok(())
}
