use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn flagon_directory_service_profile_is_discoverable() -> Result<()> {
    cotest::scenarios::directory_service::flagon_directory_service_profile_is_discoverable().await
}
