use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn identity_surface_and_receipts_work() -> Result<()> {
    cotest::scenarios::identity_directory_index::identity_surface_and_receipts_work().await
}

#[tokio::test]
#[serial]
async fn discovery_and_index_demo_projection_shapes_work() -> Result<()> {
    cotest::scenarios::identity_directory_index::discovery_and_index_demo_projection_shapes_work()
        .await
}

#[tokio::test]
#[serial]
async fn contacts_invites_listing_export_and_audit_work() -> Result<()> {
    cotest::scenarios::identity_directory_index::contacts_invites_listing_export_and_audit_work()
        .await
}

#[tokio::test]
#[serial]
async fn directory_discoverability_and_actor_privacy_work() -> Result<()> {
    cotest::scenarios::identity_directory_index::directory_discoverability_and_actor_privacy_work()
        .await
}
