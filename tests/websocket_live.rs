use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn production_websocket_discovery_and_upgrade() -> Result<()> {
    cotest::scenarios::websocket_live::run_production_discovery().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn real_tls_authentication_three_rails_resume_and_reauth() -> Result<()> {
    cotest::scenarios::websocket_live::run_transport_and_three_rails().await
}
