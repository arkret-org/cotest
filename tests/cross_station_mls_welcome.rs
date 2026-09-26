//! Cross-Station MLS Welcomes: the governance Station writes a remote
//! recipient's Welcome into the Commit's committed-replication intent, and the
//! member Station queues it after re-verifying the claim against its ledger.

use anyhow::Result;
use cotest::transcripts::init_transcript_writer;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn cross_station_mls_welcome() -> Result<()> {
    let _guard = init_transcript_writer("cross_station_mls_welcome", None)?;
    cotest::scenarios::cross_station_mls_welcome::cross_station_mls_welcome_run().await
}
