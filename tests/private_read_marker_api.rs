use anyhow::Result;

#[tokio::test]
#[ignore = "requires the canonical joint Coauth deployment"]
async fn canonical_private_read_marker_api_migration() -> Result<()> {
    cotest::scenarios::private_read_marker_api::canonical_private_read_marker_api_migration().await
}
