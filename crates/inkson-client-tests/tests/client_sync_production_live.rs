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
        !missing.is_empty(),
        "a production subset cannot close the whole Sync suite"
    );
    assert!(
        missing
            .iter()
            .all(|name| !execution.cases.iter().any(|case| &case.case_id == name))
    );
    Ok(())
}
