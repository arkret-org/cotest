//! S2 — live directed invite create and private dispatch to a same-Station
//! invitee.

use anyhow::Result;
use cotest::transcripts::init_transcript_writer;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn invite_create_is_committed_and_dispatched_once() -> Result<()> {
    let _guard = init_transcript_writer("invite_create_and_dispatch", None)?;
    cotest::scenarios::invite_create_and_dispatch::invite_create_and_dispatch_run().await
}
