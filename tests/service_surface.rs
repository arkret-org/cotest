use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn server_exposes_core_service_surface() -> Result<()> {
    cotest::scenarios::service_surface::server_exposes_core_service_surface().await
}

#[tokio::test]
#[serial]
async fn advertised_operations_are_mounted_and_selectable() -> Result<()> {
    cotest::scenarios::service_surface::advertised_operations_are_mounted_and_selectable().await
}
