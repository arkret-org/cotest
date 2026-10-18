use anyhow::Result;

#[tokio::test]
#[serial_test::serial]
async fn three_station_snapshot_handoff_keeps_exact_history_and_rechecks_unrelated_scope()
-> Result<()> {
    cotest::scenarios::fanout_route_miss_live::origin_binding_live::snapshot_matrix::run().await
}
