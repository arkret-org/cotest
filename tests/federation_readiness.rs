use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn two_sut_instances_are_isolated_and_federation_ready() -> Result<()> {
    cotest::scenarios::federation_readiness::two_sut_instances_are_isolated_and_federation_ready()
        .await
}
