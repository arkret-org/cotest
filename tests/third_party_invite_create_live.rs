use anyhow::Result;

#[tokio::test]
async fn third_party_invite_create_requires_current_allowlist() -> Result<()> {
    cotest::scenarios::third_party_invite_create_live::third_party_invite_create_requires_current_allowlist().await
}
