#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn human_pcr_rejects_transfer_and_preserves_native_consent() {
    tokio::task::LocalSet::new()
        .run_until(cotest::harness::heap_future(
            cotest::scenarios::human_pcr_station_binding::run_station_binding_live,
        ))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial_test::serial]
async fn real_coauth_revocation_keeps_human_sessions_at_the_account_station() {
    tokio::task::LocalSet::new()
        .run_until(cotest::harness::heap_future(
            cotest::scenarios::human_pcr_station_binding::run_coauth_device_boundary_live,
        ))
        .await
        .unwrap();
}
