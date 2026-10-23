#[tokio::test]
async fn relocation_survives_three_hosts_offline_recovery_and_restart() -> anyhow::Result<()> {
    cotest::scenarios::identity_directory::relocation::relocation_survives_three_hosts_offline_recovery_and_restart().await
}

#[tokio::test]
async fn account_business_survives_did_host_outage_and_signed_resolution_updates()
-> anyhow::Result<()> {
    cotest::scenarios::identity_directory::relocation_business::account_business_survives_did_host_outage_and_signed_resolution_updates().await
}

#[tokio::test]
async fn service_migration_preserves_business_and_refreshes_peer_route() -> anyhow::Result<()> {
    cotest::scenarios::identity_directory::relocation_service::service_migration_preserves_business_and_refreshes_peer_route().await
}
