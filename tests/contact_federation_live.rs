use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn normal_contact_round_crosses_two_stations() -> Result<()> {
    cotest::scenarios::contact_federation_live::normal_round_crosses_two_stations().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn concurrent_requests_complete_glare_round() -> Result<()> {
    cotest::scenarios::contact_federation_live::concurrent_requests_complete_glare_round().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn old_and_new_contact_signatures_survive_cold_peer_restart() -> Result<()> {
    cotest::scenarios::contact_federation_live::old_and_new_contact_signatures_survive_cold_peer_restart().await
}
