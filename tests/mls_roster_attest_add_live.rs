//! Real two-Station MLS Add attestation ingress with signed peer transport,
//! historical recipient signatures, exact accepted provenance and replay.

use anyhow::Result;
use cotest::transcripts::init_transcript_writer;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peer_mls_attest_add_signed_history_and_accepted_cut() -> Result<()> {
    let _guard =
        init_transcript_writer("peer_mls_attest_add_signed_history_and_accepted_cut", None)?;
    cotest::scenarios::cross_station_mls_welcome::cross_station_mls_attest_add_run().await
}
