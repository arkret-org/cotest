use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn real_watch_current_preserves_clear_revision_and_enforces_whole_value_cas() -> Result<()> {
    cotest::scenarios::strand_watch_live::run_strand_watch_current_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn real_registered_watch_pair_and_audited_read_preserve_durable_fences() -> Result<()> {
    cotest::scenarios::strand_watch_live::run_registered_watch_audit_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn real_two_stations_forward_registered_watch_pair_and_audited_read() -> Result<()> {
    cotest::scenarios::strand_watch_live::run_registered_watch_audit_peer_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn real_registered_watch_scan_boundary_and_lost_ack_survive_cold_restart() -> Result<()> {
    cotest::scenarios::strand_watch_live::run_registered_watch_audit_scan_recovery_live().await
}
