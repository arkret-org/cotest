//! S4 — a Station Y Account joins a Station X Realm by accepting its directed
//! Invite through its own Station, and then writes into it.

use anyhow::Result;
use cotest::transcripts::init_transcript_writer;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn cross_station_invite_join() -> Result<()> {
    let _guard = init_transcript_writer("cross_station_invite_join", None)?;
    cotest::scenarios::cross_station_invite_join::cross_station_invite_join_run().await
}
