use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn teabay_directory_service_profile_is_discoverable() -> Result<()> {
    cotest::scenarios::directory_service::teabay_directory_service_profile_is_discoverable().await
}
