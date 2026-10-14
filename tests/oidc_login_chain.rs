#[tokio::test]
#[ignore = "requires the real Coauth/Coland deployment; mandatory in the joint API migration gate"]
async fn canonical_oidc_login_chain_api_migration() -> anyhow::Result<()> {
    cotest::scenarios::oidc_login_chain::canonical_oidc_login_chain_api_migration().await
}
