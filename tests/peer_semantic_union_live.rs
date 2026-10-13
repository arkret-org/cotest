use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn peer_carrier_union_consumes_original_commits_and_rejects_retired_siblings_with_zero_business_writes()
-> Result<()> {
    cotest::scenarios::peer_semantic_union_live::run().await
}
