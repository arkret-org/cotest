//! P4-C — key-backup 3-class 409 differentiation + first-backup gate +
//! post-reset stale + recovery schemas.

use cotest::scenarios::key_backup::{
    first_backup_gate::first_backup_gate_run, post_reset_stale::post_reset_stale_run,
    recovery_schemas::recovery_schemas_run, series_chain_broken::series_chain_broken_run,
    series_predecessor_not_found::series_predecessor_not_found_run,
    series_seq_not_monotonic::series_seq_not_monotonic_run,
};

#[tokio::test]
async fn kb_series_chain_broken() {
    series_chain_broken_run().await.unwrap();
}

#[tokio::test]
async fn kb_series_seq_not_monotonic() {
    series_seq_not_monotonic_run().await.unwrap();
}

#[tokio::test]
async fn kb_series_predecessor_not_found() {
    series_predecessor_not_found_run().await.unwrap();
}

#[tokio::test]
async fn kb_first_backup_gate() {
    first_backup_gate_run().await.unwrap();
}

#[tokio::test]
async fn kb_post_reset_stale() {
    post_reset_stale_run().await.unwrap();
}

#[tokio::test]
async fn kb_recovery_schemas() {
    recovery_schemas_run().await.unwrap();
}
