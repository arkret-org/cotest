use anyhow::Result;

#[tokio::test(flavor = "multi_thread")]
async fn terminal_closes_all_live_child_consumers_after_signed_admission_and_restart() -> Result<()>
{
    cotest::scenarios::fanout_route_miss_live::terminal_consumers_live::run().await
}
