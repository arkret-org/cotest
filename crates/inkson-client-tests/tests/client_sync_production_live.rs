use anyhow::Result;

#[test]
#[serial_test::serial]
fn sidecar_checkpoint_cases_use_the_actual_account_driver() -> Result<()> {
    assert!(
        std::path::Path::new(env!("CARGO_BIN_EXE_cotest-inkson-checkpoint-readback")).is_file()
    );
    let execution =
        cotest_inkson_client_tests::conformance::client_sync::run_sync_client_production_suite()?;
    assert_eq!(
        execution.cases.len(),
        cotest_inkson_client_tests::conformance::client_sync::PRODUCTION_CASE_COUNT
    );
    assert!(execution.cases.iter().all(|case| case.assertions > 0));
    let fixture = cotest::conformance::load_fixture_value("client-sync-fixture.json")?;
    let missing = cotest::conformance::missing_sync_production_cases(&execution, &fixture)?;
    assert!(
        missing.is_empty(),
        "every canonical Sync case requires actual production execution"
    );
    assert!(
        missing
            .iter()
            .all(|name| !execution.cases.iter().any(|case| &case.case_id == name))
    );
    Ok(())
}

#[test]
#[serial_test::serial]
fn private_agent_sidecar_reply_recovers_in_the_original_account_attempt() -> Result<()> {
    let execution=cotest_inkson_client_tests::conformance::client_sync::run_sync_private_reply_production_case()?;
    assert_eq!(execution.cases.len(), 1);
    assert_eq!(
        execution.cases[0].case_id,
        "sidecar_missing_tail_recovers_automatically_without_another_request"
    );
    assert!(execution.cases[0].assertions > 0);
    Ok(())
}
