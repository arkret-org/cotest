use anyhow::Result;
use serial_test::serial;
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn parent_membership_reads_current_same_governor_under_durable_lock_with_zero_refusal_effects()
-> Result<()> {
    cotest::scenarios::realm_parent_membership_live::run().await
}
