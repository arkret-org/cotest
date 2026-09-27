use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn real_watch_current_preserves_clear_revision_and_enforces_whole_value_cas() -> Result<()> {
    cotest::scenarios::strand_watch_live::run_strand_watch_current_live().await
}
