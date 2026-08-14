use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn principal_bridge_contracts_are_discoverable() -> Result<()> {
    cotest::scenarios::bridge_contracts::principal_bridge_contracts_are_discoverable().await
}

#[tokio::test]
#[serial]
async fn session_grant_presentation_uses_configured_coauth_introspection() -> Result<()> {
    cotest::scenarios::bridge_contracts::session_grant_presentation_uses_configured_coauth_introspection()
        .await
}

#[tokio::test]
#[serial]
async fn external_webvh_provider_is_discoverable() -> Result<()> {
    cotest::scenarios::bridge_contracts::external_webvh_provider_is_discoverable().await
}
