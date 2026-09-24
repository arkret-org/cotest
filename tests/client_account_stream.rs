//! `ak.vector.sync.client_account_stream.v1` entrypoint.
//!
//! Replaces the three retired per-vector entrypoints (`station_cas_account_data`,
//! `timeline_window_completion`, `realm_detail_baseline_singletons`) whose
//! vectors and `sync-fixture.json` were withdrawn from the spec registry with
//! the authority-commit protocol. The Station-CAS account-data capability keeps
//! its runner in `conformance::account_data_cas_convergence`
//! (`account-data-cas-convergence-fixture.json`); baseline-versus-incremental
//! ordering is now a section of the client-sync fixture executed here.
#[test]
fn client_account_stream_vector_runs_clean() {
    cotest::conformance::run_sync_fixture_suite().expect("client account stream vector must pass");
}
