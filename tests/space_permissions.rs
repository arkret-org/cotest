use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn space_creation_and_owner_only_mutations_are_enforced() -> Result<()> {
    cotest::scenarios::space_permissions::space_creation_and_owner_only_mutations_are_enforced()
        .await
}

#[tokio::test]
#[serial]
async fn private_visibility_non_member_send_and_deleted_space_edges() -> Result<()> {
    cotest::scenarios::space_permissions::private_visibility_non_member_send_and_deleted_space_edges().await
}
