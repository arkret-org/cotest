use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn principal_bridge_contracts_are_discoverable() -> Result<()> {
    cotest::scenarios::bridge_contracts::principal_bridge_contracts_are_discoverable().await
}

#[tokio::test]
#[serial]
async fn starid_optional_resolver_profile_is_discoverable() -> Result<()> {
    cotest::scenarios::bridge_contracts::starid_optional_resolver_profile_is_discoverable().await
}

#[tokio::test]
#[serial]
async fn session_grant_exchange_uses_configured_coauth_introspection() -> Result<()> {
    cotest::scenarios::bridge_contracts::session_grant_exchange_uses_configured_coauth_introspection()
        .await
}
