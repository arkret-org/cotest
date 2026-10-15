#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn actual_station_native_and_media_consent_cuts() {
    let local = tokio::task::LocalSet::new();
    local
        .run_until(cotest::harness::heap_future(
            cotest_inkson_client_tests::conformance::consent_cache::run_three_cuts_live,
        ))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn named_consent_cache_all_fourteen_cases() {
    tokio::task::LocalSet::new()
        .run_until(cotest::harness::heap_future(
            cotest_inkson_client_tests::conformance::consent_cache::run_consent_cache_suite_live,
        ))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn actual_presence_and_media_current_cuts() {
    tokio::task::LocalSet::new().run_until(cotest::harness::heap_future(
        cotest_inkson_client_tests::conformance::consent_cache::run_presence_and_media_cuts_live,
    )).await.unwrap();
}
