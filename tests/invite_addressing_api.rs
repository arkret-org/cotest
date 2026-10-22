#[tokio::test]
/// Gating: requires isolated real Stations and PostgreSQL; mandatory native API migration runner.
/// Tier: live
#[ignore = "requires isolated real Stations and PostgreSQL; mandatory native API migration runner"]
async fn invite_addressing_api_migration() -> anyhow::Result<()> {
    cotest::scenarios::invite_addressing_api::invite_addressing_api_migration().await
}
