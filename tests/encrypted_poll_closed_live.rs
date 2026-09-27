//! The v1 encrypted-poll boundary against a real Station and PostgreSQL.

use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn encrypted_message_with_poll_response_heads_is_rejected_without_a_commit_or_vote()
-> Result<()> {
    cotest::scenarios::encrypted_poll_closed_live::run().await
}
