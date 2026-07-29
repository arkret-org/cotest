use cotest::conformance::{
    run_account_data_cas_convergence_vector_suite, run_read_cursor_multi_device_merge_vector_suite,
};

#[test]
fn read_cursor_multi_device_merge_fixture_executes_sdk_algorithm() {
    run_read_cursor_multi_device_merge_vector_suite()
        .expect("read cursor multi-device merge vector must pass");
}

#[test]
fn account_data_cas_convergence_fixture_executes_reference_register() {
    run_account_data_cas_convergence_vector_suite()
        .expect("account data CAS convergence vector must pass");
}
