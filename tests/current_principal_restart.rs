//! Live Human PCR current-principal restart and index-eviction coverage.

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn current_principal_survives_index_eviction_and_restart() {
    cotest::scenarios::current_principal_restart::current_principal_survives_index_eviction_and_restart()
        .await
        .unwrap();
}
