#[test]
fn timeline_window_completion_vector_runs_clean() {
    cotest::conformance::run_timeline_window_completion_vector()
        .expect("timeline window completion vector must pass");
}
