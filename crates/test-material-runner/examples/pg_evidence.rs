//! Isolated formal dispatcher: the Coauth route tests must actually execute.
fn main() -> anyhow::Result<()> {
    let coverage =
        cotest_test_material_runner::run_test_material_rejection_suite_with_pg_coverage()?;
    println!(
        "Coauth HTTP/PG independent DID, key-id and trust-domain routes executed; {} local cases",
        coverage.execution.cases.len()
    );
    anyhow::ensure!(
        coverage.service_e2e_gaps.is_empty(),
        "full suite remains unproved: {:?}",
        coverage.service_e2e_gaps
    );
    Ok(())
}
