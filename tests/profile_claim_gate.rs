use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn live_describe_profile_claim_gate_from_env() -> Result<()> {
    cotest::scenarios::profile_claim_gate::live_describe_profile_claim_gate_from_env().await
}

#[test]
fn negative_profile_claims_fail_closed() -> Result<()> {
    cotest::scenarios::profile_claim_gate::profile_claim_gate_negative_claims_fail_closed()
}
