//! Canonical Agent evidence must come from the real admission consumer.

#[test]
fn agent_genesis_cases_cross_real_http_admission_and_preserve_rejected_state() -> anyhow::Result<()>
{
    let execution = cotest::conformance::run_agent_vectors_production_suite()?;
    println!("{execution:#?}");
    let fixture = cotest::conformance::load_fixture_value("agent-vectors-fixture.json")?;
    let cases = fixture["cases"].as_array().unwrap();
    let missing = execution.missing_against_cases(cases)?;
    assert_eq!(execution.cases.len(), 2);
    assert_eq!(missing.len(), cases.len() - 2);
    assert!(execution.cases.iter().all(|case| case.assertions > 0));
    assert!(execution.assert_complete_against(&fixture).is_err());
    Ok(())
}
