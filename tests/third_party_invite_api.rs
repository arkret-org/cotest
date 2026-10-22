use anyhow::Result;

#[tokio::test]
/// Gating: requires prebuilt Coland and isolated PostgreSQL.
/// Tier: live
#[ignore = "requires prebuilt Coland and isolated PostgreSQL"]
async fn third_party_invite_api_migration() -> Result<()> {
    cotest::scenarios::third_party_invite_claim_live::third_party_invite_api_migration().await
}
