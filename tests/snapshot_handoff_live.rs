use anyhow::Result;

#[tokio::test]
#[serial_test::serial]
async fn three_station_stream_history_survives_unrelated_scope_loss_and_cold_restart() -> Result<()>
{
    cotest::scenarios::fanout_route_miss_live::origin_binding_live::snapshot_matrix::run().await
}
