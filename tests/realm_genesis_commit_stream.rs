use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn realm_genesis_commit_stream_preserves_founding_replay_and_continuation() -> Result<()> {
    cotest::scenarios::realm_genesis_commit_stream::realm_genesis_commit_stream_preserves_founding_replay_and_continuation().await
}

#[tokio::test]
/// Gating: requires the real Coauth/Coland deployment; mandatory in the joint API migration gate.
/// Tier: live
#[ignore = "requires the real Coauth/Coland deployment; mandatory in the joint API migration gate"]
async fn canonical_realm_genesis_api_migration() -> Result<()> {
    cotest::scenarios::realm_genesis_commit_stream::canonical_realm_genesis_api_migration().await
}
