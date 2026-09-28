//! Circle Poll accepted-source-scope boundary against a real Station and PostgreSQL.

use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn plaintext_poll_vote_is_circle_scoped_and_cross_circle_vote_writes_nothing() -> Result<()> {
    cotest::scenarios::circle_poll_scope_live::run().await
}
