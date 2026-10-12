//! Canonical Agent evidence must come from the real admission consumer.

#[test]
fn agent_genesis_cases_cross_real_http_admission_and_preserve_rejected_state() -> anyhow::Result<()>
{
    let execution = cotest::conformance::run_agent_vectors_production_suite()?;
    println!("{execution:#?}");
    let fixture = cotest::conformance::load_fixture_value("agent-vectors-fixture.json")?;
    let mut cases = fixture["schema_validation_cases"]
        .as_array()
        .unwrap()
        .clone();
    cases.extend_from_slice(fixture["cases"].as_array().unwrap());
    let missing = execution.missing_against_cases(&cases)?;
    assert_eq!(execution.cases.len(), 17);
    assert_eq!(missing.len(), 13);
    assert!(
        execution
            .cases
            .iter()
            .any(|case| case.case_id == "agent_presence_requires_expiry_and_refresh")
    );
    assert!(execution.cases.iter().all(|case| case.assertions > 0));
    assert!(execution.assert_complete_against(&fixture).is_err());
    Ok(())
}
