use anyhow::Result;
use serial_test::serial;
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn organization_consent_and_account_actor_authorization_survive_real_storage_and_reopen()
-> Result<()> {
    cotest::scenarios::realm_organization_account_live::run().await
}
