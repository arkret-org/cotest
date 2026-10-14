use anyhow::Result;
use cotest::scenarios::api_mls_migrations::MlsApiCase;

#[tokio::test]
#[ignore = "requires prebuilt Coland and isolated PostgreSQL"]
async fn private_marker_circle_scope_api_migration() -> Result<()> {
    cotest::scenarios::mls_lifecycle_live::run_with_api_migration(MlsApiCase::CircleMarkers).await
}

#[tokio::test]
#[ignore = "requires prebuilt Coland and isolated PostgreSQL"]
async fn audited_e2ee_api_migration() -> Result<()> {
    cotest::scenarios::mls_lifecycle_live::run_with_api_migration(MlsApiCase::AuditedReport).await
}

#[tokio::test]
#[ignore = "requires prebuilt Coland and isolated PostgreSQL"]
async fn discussion_upgrade_api_migration() -> Result<()> {
    cotest::scenarios::mls_lifecycle_live::run_with_api_migration(MlsApiCase::Discussion).await
}

#[tokio::test]
#[ignore = "requires prebuilt Coland and isolated PostgreSQL"]
async fn read_receipt_signals_api_migration() -> Result<()> {
    cotest::scenarios::mls_lifecycle_live::run_with_api_migration(MlsApiCase::ReceiptSignals).await
}

#[tokio::test]
#[ignore = "requires prebuilt Coland and isolated PostgreSQL"]
async fn private_marker_encrypted_notification_api_migration() -> Result<()> {
    cotest::scenarios::mls_lifecycle_live::run_with_api_migration(MlsApiCase::MarkerPrivacy).await
}
