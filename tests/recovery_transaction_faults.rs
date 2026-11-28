use anyhow::Result;

/// Gating: 2133 requires owned native services and isolated PostgreSQL.
///
/// Tier: live
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires owned native Coauth/Station executables and independent PostgreSQL"]
async fn recovery_native_two_transactions_same_session_generation_race() -> Result<()> {
    cotest::conformance::recovery_transaction_faults::run_native_recovery_fault_case(
        "same_session_race",
    )
    .await
}

/// Gating: 2133 requires owned native services and isolated PostgreSQL.
///
/// Tier: live
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "kills and restarts an owned native Station over independent PostgreSQL"]
async fn recovery_native_kill_before_acceptance_has_zero_effects_then_exact_retry() -> Result<()> {
    cotest::conformance::recovery_transaction_faults::run_native_recovery_fault_case(
        "pre_accept_kill",
    )
    .await
}

/// Gating: 2133 requires owned native services and isolated PostgreSQL.
///
/// Tier: live
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "withholds real TCP response, kills and restarts the owned native Station"]
async fn recovery_native_kill_after_commit_before_observation_restores_exact_c_and_two_commits()
-> Result<()> {
    cotest::conformance::recovery_transaction_faults::run_native_recovery_fault_case(
        "post_accept_response_loss_restart",
    )
    .await
}

/// Gating: 2133 requires owned native services and isolated PostgreSQL.
///
/// Tier: live
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires actual Coland completion followed by real Coauth PostgreSQL rollback"]
async fn recovery_native_issuer_rollback_preserves_pcr_and_retries_aa_only() -> Result<()> {
    cotest::conformance::recovery_transaction_faults::run_native_recovery_fault_case(
        "issuer_rollback_after_native_completion",
    )
    .await
}

/// Gating: 2133 requires owned native services and isolated PostgreSQL.
///
/// Tier: live
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires native accepted-Device issue after losing the old holder private key"]
async fn recovery_native_lost_holder_uses_ordinary_issue_without_rewriting_outcome() -> Result<()> {
    cotest::conformance::recovery_transaction_faults::run_native_recovery_fault_case(
        "lost_holder_ordinary_issue",
    )
    .await
}

/// Gating: independently issued native replacement, Station and issuer PostgreSQL.
///
/// Tier: live
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires owned Coland and Coauth executables with independent PostgreSQL"]
async fn recovery_native_prepared_inventory_original_and_root() -> Result<()> {
    cotest::conformance::recovery_transaction_faults::run_native_recovery_fault_case(
        "prepared_inventory",
    )
    .await
}
