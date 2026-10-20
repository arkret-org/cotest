use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn fanout_route_miss_survives_restart_recovers_and_cancels_on_authority_loss() -> Result<()> {
    cotest::scenarios::fanout_route_miss_live::run_fanout_route_miss_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn service_method_endpoint_successor_survives_retired_api_and_restart() -> Result<()> {
    cotest::scenarios::fanout_route_miss_live::service_route_live::endpoint_successor().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn service_method_faults_preserve_floor_ttl_and_pending_fanout() -> Result<()> {
    cotest::scenarios::fanout_route_miss_live::service_route_live::method_faults().await
}
