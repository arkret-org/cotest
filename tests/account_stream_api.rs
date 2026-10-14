use anyhow::Result;

#[tokio::test]
#[ignore = "requires the canonical joint Coauth deployment"]
async fn canonical_account_stream_api_migration() -> Result<()> {
    cotest::scenarios::account_stream_api::canonical_account_stream_api_migration().await
}
