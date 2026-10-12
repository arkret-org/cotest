use anyhow::Result;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn same_device_sessions_remain_distinct_across_durable_cursor_revocation() -> Result<()> {
    cotest::scenarios::cursor_revocation_live::same_device_distinct_session_cursor_revocation_live()
        .await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_revoked_waiting_http_continuation_never_publishes_or_advances() -> Result<()> {
    cotest::scenarios::cursor_revocation_live::waiting_http_cursor_revocation_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn a_revoked_waiting_websocket_preserves_the_canonical_cursor_error() -> Result<()> {
    cotest::scenarios::cursor_revocation_live::waiting_websocket_cursor_revocation_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn queued_account_frames_recheck_revocation_at_physical_websocket_output() -> Result<()> {
    cotest::scenarios::cursor_revocation_live::queued_websocket_cursor_revocation_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn cursor_revocation_is_visible_between_two_processes_sharing_one_durable_issuer()
-> Result<()> {
    cotest::scenarios::cursor_revocation_live::shared_database_two_process_cursor_revocation_live()
        .await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn concurrent_issuance_cannot_install_a_cut_after_its_input_was_revoked() -> Result<()> {
    cotest::scenarios::cursor_revocation_live::issuance_racing_completed_revocation_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn completed_revocation_remains_visible_under_a_repeatable_read_database_default()
-> Result<()> {
    cotest::scenarios::cursor_revocation_live::issuance_racing_repeatable_read_default_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn old_realm_pages_keep_their_original_snapshot_and_independent_revocation_identity()
-> Result<()> {
    cotest::scenarios::cursor_revocation_live::immutable_realm_pages_remain_isolated_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn legal_wire_expiry_precedes_unknown_binding_and_revocation_without_state_changes()
-> Result<()> {
    cotest::scenarios::cursor_revocation_live::legal_expired_wire_precedes_binding_and_revocation_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn realm_list_issuance_cannot_install_a_page_after_its_input_was_revoked() -> Result<()> {
    cotest::scenarios::cursor_revocation_live::realm_list_issuance_racing_revocation_live().await
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn immutable_cursor_issuance_lookup_and_gc_costs_are_measured_on_real_postgres() -> Result<()>
{
    cotest::scenarios::cursor_revocation_live::immutable_cursor_cost_live().await
}
