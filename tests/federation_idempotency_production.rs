#[test]
fn canonical_federation_cases_use_real_ingress_and_keep_the_missing_binding_explicit()
-> anyhow::Result<()> {
    let execution = cotest::conformance::run_federation_idempotency_production_suite()?;
    let fixture =
        cotest::conformance::load_fixture_value("federation-idempotency-key-revoke-fixture.json")?;
    let cases = fixture["cases"].as_array().unwrap();
    let missing = execution.missing_against_cases(cases)?;
    assert_eq!(missing, ["removed_origin_binding_denies_the_replay"]);
    assert_eq!(execution.cases.len(), 4);
    assert_eq!(
        execution
            .cases
            .iter()
            .map(|case| case.assertions)
            .sum::<usize>(),
        12
    );
    assert!(execution.assert_complete_against(&fixture).is_err());
    println!("{execution:#?}\nmissing: {missing:?}");
    Ok(())
}
