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

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn same_station_checkpoint_acceptance_and_response_are_atomic_and_replayable() -> Result<()> {
    cotest::scenarios::contact_federation_live::checkpoint_replay_and_long_history(false).await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn two_station_checkpoint_recovers_frozen_request_and_compacts_history_beyond_64_rounds()
-> Result<()> {
    cotest::scenarios::contact_federation_live::checkpoint_replay_and_long_history(true).await
}
