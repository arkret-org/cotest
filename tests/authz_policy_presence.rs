use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn authz_grant_lifecycle_and_audit_work() -> Result<()> {
    cotest::scenarios::authz_policy_presence::authz_grant_lifecycle_and_audit_work().await
}

#[tokio::test]
#[serial]
async fn push_and_ice_contracts_work() -> Result<()> {
    cotest::scenarios::authz_policy_presence::push_and_ice_contracts_work().await
}
