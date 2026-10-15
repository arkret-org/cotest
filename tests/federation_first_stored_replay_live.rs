use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn unchanged_peer_basis_replays_the_original_stored_outcome() -> Result<()> {
    cotest::scenarios::fanout_route_miss_live::idempotency_live::run_federation_first_stored_outcome_replay_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn changed_basis_reauthorizes_under_current_transport() -> Result<()> {
    cotest::scenarios::fanout_route_miss_live::idempotency_live::run_federation_changed_basis_replay_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn revoked_key_rejects_before_accessing_a_locked_real_cache() -> Result<()> {
    cotest::scenarios::fanout_route_miss_live::idempotency_live::run_federation_revoked_key_before_cache_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn ordered_items_keep_original_outcomes_after_their_final_policy_cut() -> Result<()> {
    cotest::scenarios::fanout_route_miss_live::idempotency_live::run_federation_ordered_items_replay_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn canonical_full_body_replays_without_an_optional_http_key() -> Result<()> {
    cotest::scenarios::fanout_route_miss_live::idempotency_live::run_federation_no_header_first_stored_replay_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn concurrent_identical_requests_share_one_durable_first_stored_receipt() -> Result<()> {
    cotest::scenarios::fanout_route_miss_live::idempotency_live::run_federation_concurrent_first_stored_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn failed_receipt_insert_rolls_back_the_entire_accepted_replica() -> Result<()> {
    cotest::scenarios::fanout_route_miss_live::idempotency_live::run_federation_receipt_rollback_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn removed_origin_binding_refuses_exact_replay_under_the_unchanged_active_key() -> Result<()>
{
    cotest::scenarios::fanout_route_miss_live::origin_binding_live::run_removed_origin_binding_replay_live().await
}
