use anyhow::Result;
use cotest::scenarios::fanout_route_miss_live::terminal_restart_live;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn pending_route_terminal_survives_actual_station_restart() -> Result<()> {
    terminal_restart_live::pending_terminal_survives_restart(true).await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn pending_delivery_terminal_survives_actual_station_restart() -> Result<()> {
    terminal_restart_live::pending_terminal_survives_restart(false).await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn last_member_leave_stays_closed_after_actual_station_restart() -> Result<()> {
    terminal_restart_live::departure_survives_restart(false).await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn last_member_ban_stays_closed_after_actual_station_restart() -> Result<()> {
    terminal_restart_live::departure_survives_restart(true).await
}
