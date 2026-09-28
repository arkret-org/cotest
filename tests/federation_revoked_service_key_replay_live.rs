use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn revoked_service_key_replay_fails_current_peer_auth_without_new_commit() -> Result<()> {
    cotest::scenarios::fanout_route_miss_live::run_federation_revoked_service_key_replay_live()
        .await
}
