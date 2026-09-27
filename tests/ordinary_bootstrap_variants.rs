use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn ordinary_bootstrap_retry_preserves_the_exact_commits_and_conflict_writes_nothing()
-> Result<()> {
    cotest::scenarios::protocol_payloads::ordinary_bootstrap_retry_preserves_the_exact_commits_and_conflict_writes_nothing().await
}

#[tokio::test]
#[serial]
async fn ordinary_bootstrap_admits_a_restricted_join_policy_and_refuses_unprovable_gates()
-> Result<()> {
    cotest::scenarios::protocol_payloads::ordinary_bootstrap_admits_a_restricted_join_policy_and_refuses_unprovable_gates().await
}
