use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn teabay_signed_ingest_negative_paths_fail_closed() -> Result<()> {
    cotest::scenarios::teabay_signed_ingest_negative::teabay_signed_ingest_negative_run().await
}
