use anyhow::Result;
use cotest::scenarios::fanout_route_miss_live::erasure_receipt_live;

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn independent_receipt_survives_leave_holder_process_restart() -> Result<()> {
    erasure_receipt_live::run(false).await
}

#[tokio::test(flavor = "multi_thread")]
#[serial_test::serial]
async fn independent_receipt_survives_ban_holder_process_restart() -> Result<()> {
    erasure_receipt_live::run(true).await
}
