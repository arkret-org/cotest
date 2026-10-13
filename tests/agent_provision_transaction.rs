//! Real HTTP and PostgreSQL observations; no canonical coverage promotion.

#[test]
fn agent_provision_prepare_rollback_and_replay_cross_production_admission() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime
        .block_on(cotest::scenarios::agent_runtime_live::run_agent_genesis_production_cases())?;
    println!("{result:#?}");
    assert_eq!(result.cases.len(), 4);
    assert!(result.cases.iter().all(|case| case.assertions > 0));
    Ok(())
}
