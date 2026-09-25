//! S5 — live Message edit and retraction on the Event/RealmCommit carrier.

use anyhow::Result;
use cotest::transcripts::init_transcript_writer;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn message_is_edited_and_retracted_by_its_author() -> Result<()> {
    let _guard = init_transcript_writer("message_edit_and_retract", None)?;
    cotest::scenarios::message_edit_and_retract::message_edit_and_retract_run().await
}
