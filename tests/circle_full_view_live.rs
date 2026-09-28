//! Circle full-view disclosure against a real Station and PostgreSQL.

use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn realm_membership_alone_never_grants_full_circle_view() -> Result<()> {
    cotest::scenarios::circle_full_view_live::run().await
}
