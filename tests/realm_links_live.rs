use anyhow::Result;
use serial_test::serial;
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn realm_links_never_cascade_policy_capability_or_notification_and_retired_carriers_write_nothing()
-> Result<()> {
    cotest::scenarios::realm_links_live::run().await
}
