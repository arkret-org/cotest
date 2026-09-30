use anyhow::Result;
use cotest::transcripts::init_transcript_writer;
use serial_test::serial;
#[tokio::test(flavor="multi_thread")]
#[serial]
async fn historical_wip_approval_and_private_audit()->Result<()> {
    let _guard=init_transcript_writer("approval_admission",None)?;
    cotest::scenarios::approval_admission_live::approval_admission_run().await
}
