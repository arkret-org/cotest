use anyhow::Result;

#[test]
fn spec_business_flows_cover_operation_registry_surfaces() -> Result<()> {
    cotest::conformance::run_spec_business_flow_coverage_suite()
}
