use anyhow::Result;
use cotest::scenarios::fanout_route_miss_live::terminal_gap_live;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn terminal_missing_predecessor_repairs_full_and_withheld_chain() -> Result<()> {
    terminal_gap_live::recover(None).await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn last_member_leave_with_gap_repairs_only_through_termination() -> Result<()> {
    terminal_gap_live::recover(Some(false)).await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn last_member_ban_with_gap_repairs_only_through_termination() -> Result<()> {
    terminal_gap_live::recover(Some(true)).await
}
