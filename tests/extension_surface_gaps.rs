use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn applet_lifecycle_surfaces_are_not_advertised_until_routes_exist() -> Result<()> {
    cotest::scenarios::extension_surface_gaps::applet_lifecycle_surfaces_are_not_advertised_until_routes_exist().await
}

#[tokio::test]
#[serial]
async fn agent_lifecycle_surfaces_are_advertised_when_routes_exist() -> Result<()> {
    cotest::scenarios::extension_surface_gaps::agent_lifecycle_surfaces_are_advertised_when_routes_exist().await
}
