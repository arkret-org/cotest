use anyhow::Result;

#[test]
fn canonical_terminal_suite_executes_all_eight_production_cases() -> Result<()> {
    let execution = cotest::conformance::run_terminal_replication_authority_suite()?;
    assert_eq!(execution.cases.len(), 8);
    assert!(execution.cases.iter().all(|case| case.assertions > 0));
    println!("{execution:#?}");
    Ok(())
}
