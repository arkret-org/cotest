use anyhow::Result;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn identity_surface_and_receipts_work() -> Result<()> {
    cotest::scenarios::identity_directory::identity_surface_and_receipts_work().await
}

#[tokio::test]
#[serial]
async fn contacts_invites_listing_export_and_audit_work() -> Result<()> {
    cotest::scenarios::identity_directory::contacts_invites_listing_export_and_audit_work().await
}
