#[test]
fn canonical_federation_cases_use_real_ingress_and_current_origin_binding() -> anyhow::Result<()> {
    let execution = cotest::conformance::run_federation_idempotency_production_suite()?;
    let fixture =
        cotest::conformance::load_fixture_value("federation-idempotency-key-revoke-fixture.json")?;
    let cases = fixture["cases"].as_array().unwrap();
    let missing = execution.missing_against_cases(cases)?;
    assert!(missing.is_empty());
    assert_eq!(execution.cases.len(), 5);
    assert_eq!(
        execution
            .cases
            .iter()
            .map(|case| case.assertions)
            .sum::<usize>(),
        15
    );
    execution.assert_complete_against(&fixture)?;
    println!("{execution:#?}\nmissing: {missing:?}");
    Ok(())
}
