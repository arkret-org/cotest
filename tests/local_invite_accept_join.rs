//! S3 — a same-Station account joins by accepting its directed Invite, posts
//! once granted, and leaves.

use anyhow::Result;
use cotest::transcripts::init_transcript_writer;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn local_invite_accept_join() -> Result<()> {
    let _guard = init_transcript_writer("local_invite_accept_join", None)?;
    cotest::scenarios::local_invite_accept_join::local_invite_accept_join_run().await
}
