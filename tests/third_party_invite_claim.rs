use anyhow::Result;
use cotest::transcripts::init_transcript_writer;
use serial_test::serial;
#[tokio::test(flavor="multi_thread")]
#[serial]
async fn third_party_invite_claim_and_join_across_stations()->Result<()> {
    let _guard=init_transcript_writer("third_party_invite_claim",None)?;
    cotest::scenarios::third_party_invite_claim_live::third_party_invite_claim_run().await
}
