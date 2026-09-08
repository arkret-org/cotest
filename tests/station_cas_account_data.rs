#[test]
fn station_cas_account_data_vector_runs_clean() {
    cotest::conformance::run_station_cas_account_data_vector()
        .expect("Station-CAS account-data vector must pass");
}
