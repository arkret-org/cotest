use anyhow::Result;
use cotest::transcripts::init_transcript_writer;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn governing_member_adds_remote_recipient_and_messages_survive_exact_replay() -> Result<()> {
    let _guard = init_transcript_writer("message_mls_cross_station_live", None)?;
    cotest::scenarios::message_mls_cross_station_live::run().await
}
