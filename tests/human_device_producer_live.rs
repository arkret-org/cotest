//! Decision 0107 live legs. Both need a prebuilt Soland and PostgreSQL; they
//! soft-skip without them unless `COTEST_REQUIRE_LIVE_SERVICES=1`.

use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn same_station_human_device_control_and_data_events_share_one_producer_rule() -> Result<()> {
    cotest::scenarios::human_device_producer_live::run_same_station_human_control_event_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn cross_station_authority_forward_admits_human_device_events_and_refuses_a_revoked_device()
-> Result<()> {
    cotest::scenarios::human_device_producer_live::run_cross_station_authority_forward_live().await
}
