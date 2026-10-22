use anyhow::Result;

#[tokio::test]
/// Gating: requires prebuilt Coland and isolated PostgreSQL databases.
/// Tier: live
#[ignore = "requires prebuilt Coland and isolated PostgreSQL databases"]
async fn transport_negotiation_api_migration() -> Result<()> {
    cotest::scenarios::transport_negotiation_api::transport_negotiation_api_migration().await
}
