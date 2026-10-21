#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn ordinary_local_authoring_recovers_real_accepted_unknown_after_cold_reopen()
-> anyhow::Result<()> {
    tokio::task::LocalSet::new().run_until(cotest::harness::heap_future(
        cotest_inkson_client_tests::conformance::message_send::run_native_message_unknown_cold_recovery,
    )).await
}
