use anyhow::Result;
use cotest::conformance::run_authority_event_submit_carrier_conformance;

#[test]
fn endpoint_specific_authority_event_submit_carriers_match_spec_and_sdk() -> Result<()> {
    let coverage = run_authority_event_submit_carrier_conformance()?;
    assert_eq!(coverage.static_cases.len(), 10);
    assert!(coverage.assertions >= 41);
    assert_eq!(
        coverage.canonical_named_suite,
        "ak.suite.peer.event_submit.semantic_union.v1"
    );
    assert_eq!(coverage.service_e2e_status, "unwired");
    Ok(())
}
