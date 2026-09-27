use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn real_strand_stage_cas_archive_and_restore_preserve_independent_axes() -> Result<()> {
    cotest::scenarios::strand_lifecycle_live::run_strand_lifecycle_live().await
}
