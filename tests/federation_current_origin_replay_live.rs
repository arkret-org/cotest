use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn held_commit_replay_requires_current_origin_after_peer_auth() -> Result<()> {
    cotest::scenarios::fanout_route_miss_live::run_federation_current_origin_replay_live().await
}
