//! A Station Y member activates MLS in a Station X Realm through a forwarded
//! `ak.mls.genesis` that carries its two public Blobs.

use anyhow::Result;
use cotest::transcripts::init_transcript_writer;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn cross_station_mls_genesis() -> Result<()> {
    let _guard = init_transcript_writer("cross_station_mls_genesis", None)?;
    cotest::scenarios::cross_station_mls_genesis::cross_station_mls_genesis_run().await
}
