//! Real signed Sidecar atomic ensure, private native scans and snapshots.
use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn sidecar_ensure_replay_and_private_native_disclosure_are_real() -> Result<()> {
    cotest::scenarios::sidecar_authority_live::run().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn pending_agent_sidecar_http_reads_disclose_handshakes_without_private_content() -> Result<()>
{
    cotest::scenarios::sidecar_authority_live::run_pending_agent_disclosure().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn distinct_stations_controller_agent_join_uses_home_source_and_governor_membership()
-> Result<()> {
    cotest::harness::heap_future(
        cotest::scenarios::agent_runtime_live::run_cross_station_agent_join,
    )
    .await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn home_rejects_an_expired_runtime_before_cross_station_admission() -> Result<()> {
    cotest::harness::heap_future(
        cotest::scenarios::agent_runtime_live::run_cross_station_expired_session,
    )
    .await
}
