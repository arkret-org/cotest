use anyhow::Result;

#[test]
fn downstream_impact_contracts_follow_current_sdk_and_reducer() -> Result<()> {
    cotest::conformance::run_downstream_impact_contract_suite()
}
