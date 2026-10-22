use anyhow::Result;

#[tokio::test(flavor = "multi_thread")]
/// Gating: requires real TLS Stations and PostgreSQL.
/// Tier: live
#[ignore = "requires real TLS Stations and PostgreSQL"]
async fn last_member_terminal_journey_on_default_stack() -> Result<()> {
    cotest::conformance::run_terminal_replication_authority_case("last_member_leave_then_terminal")
        .await?;
    Ok(())
}

#[test]
fn canonical_terminal_suite_executes_all_eight_production_cases() -> Result<()> {
    let execution = cotest::conformance::run_terminal_replication_authority_suite()?;
    assert_eq!(execution.cases.len(), 8);
    assert!(execution.cases.iter().all(|case| case.assertions > 0));
    println!("{execution:#?}");
    Ok(())
}
