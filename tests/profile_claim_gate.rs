use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn live_describe_profile_claim_gate_from_env() -> Result<()> {
    cotest::scenarios::profile_claim_gate::live_describe_profile_claim_gate_from_env().await
}
