use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn fanout_route_miss_survives_restart_recovers_and_cancels_on_authority_loss() -> Result<()> {
    cotest::scenarios::fanout_route_miss_live::run_fanout_route_miss_live().await
}
