//! Circle parent-generation invalidation through two real Stations.

use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn circle_parent_leave_ban_rejoin_never_rewrites_or_revives_old_joins() -> Result<()> {
    cotest::scenarios::circle_parent_membership_live::run().await
}
