//! Independent 2045-M10 compositions; these do not mint operation coverage.

/// Gating: 2133 requires owned native services and isolated PostgreSQL.
///
/// Tier: live
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires an owned Coland process and isolated PostgreSQL"]
async fn accepted_mls_epochs_and_adjacent_windows_keep_reaction_current_domains_separate()
-> anyhow::Result<()> {
    cotest::scenarios::reaction_mls_http_live::verify_domains().await
}

/// Gating: 2133 requires owned native services and isolated PostgreSQL.
///
/// Tier: live
#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires an owned Coland process and a native near-8MiB active-current fill"]
async fn large_active_reaction_shape_obeys_whole_snapshot_http_budget() -> anyhow::Result<()> {
    cotest::scenarios::reaction_mls_http_live::verify_capacity().await
}
