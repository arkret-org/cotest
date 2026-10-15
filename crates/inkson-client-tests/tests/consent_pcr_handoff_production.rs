#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn actual_pcr_scoped_import_signed_handoff_and_recovery() {
    tokio::task::LocalSet::new()
        .run_until(cotest::harness::heap_future(
            cotest::scenarios::consent_pcr_handoff::run_planned_handoff_live,
        ))
        .await
        .unwrap();
}
