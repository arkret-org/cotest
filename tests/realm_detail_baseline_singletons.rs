#[test]
fn realm_detail_baseline_singletons_vector_runs_clean() {
    cotest::conformance::run_realm_detail_baseline_singletons_vector()
        .expect("realm detail baseline singletons vector must pass");
}
