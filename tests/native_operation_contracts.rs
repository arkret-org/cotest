//! Positive operation contracts require real owned services and accepted originals.

#[tokio::test(flavor = "multi_thread")]
async fn call_invitation_retains_real_recipient_and_fresh_holder_verdict() -> anyhow::Result<()> {
    cotest::scenarios::native_operation_contracts::call_invitation().await
}
#[test]
fn mls_interop_entry_future_keeps_large_child_state_on_the_heap() {
    fn check<F: std::future::Future>(_: impl FnOnce() -> F) {
        assert!(
            std::mem::size_of::<F>() < 64 * 1024,
            "native entry future must not inline its large fixture state"
        );
    }
    check(cotest::scenarios::native_operation_contracts::mls_interop);
}

#[test]
fn all_native_operation_schema_references_resolve_once() -> anyhow::Result<()> {
    cotest::scenarios::native_operation_contracts::validate_registered_schema_bindings()
}

#[tokio::test(flavor = "multi_thread")]
async fn account_identity_creation_preserves_native_issuer_and_pcr_originals() -> anyhow::Result<()>
{
    cotest::scenarios::native_operation_contracts::account_identity_creation().await
}

#[tokio::test(flavor = "multi_thread")]
async fn account_device_sessions_preserve_issuer_originals_and_real_consumer() -> anyhow::Result<()>
{
    cotest::scenarios::native_operation_contracts::account_device_sessions().await
}

#[tokio::test(flavor = "multi_thread")]
async fn account_device_pairing_retains_real_target_and_admitted_original() -> anyhow::Result<()> {
    cotest::scenarios::native_operation_contracts::account_device_pairing().await
}

#[tokio::test(flavor = "multi_thread")]
async fn account_policy_recovery_retains_accepted_unit_and_issuer_originals() -> anyhow::Result<()>
{
    cotest::scenarios::native_operation_contracts::account_policy_recovery().await
}

#[tokio::test(flavor = "multi_thread")]
async fn account_security_rotation_retains_worker_and_local_commit_originals() -> anyhow::Result<()>
{
    cotest::scenarios::native_operation_contracts::account_security_rotation().await
}

#[tokio::test(flavor = "multi_thread")]
async fn account_private_storage_retains_encryption_and_durable_effects() -> anyhow::Result<()> {
    cotest::scenarios::native_operation_contracts::account_private_storage().await
}

#[tokio::test(flavor = "multi_thread")]
async fn mls_interop_retains_native_claims_mls_and_mimi_originals() -> anyhow::Result<()> {
    cotest::scenarios::native_operation_contracts::mls_interop().await
}

#[tokio::test(flavor = "multi_thread")]
async fn account_consent_retains_holder_current_and_admitted_quarantine() -> anyhow::Result<()> {
    cotest::scenarios::native_operation_contracts::account_consent().await
}

#[tokio::test(flavor = "multi_thread")]
async fn identity_reservations_retain_fresh_authentication_and_published_originals()
-> anyhow::Result<()> {
    cotest::scenarios::native_operation_contracts::identity_reservations().await
}

#[tokio::test(flavor = "multi_thread")]
async fn service_registrations_retain_actual_native_bootstrap_and_receipt() -> anyhow::Result<()> {
    cotest::scenarios::native_operation_contracts::service_registrations().await
}

#[tokio::test(flavor = "multi_thread")]
async fn organization_registrations_retain_external_control_and_native_lifecycle()
-> anyhow::Result<()> {
    cotest::scenarios::native_operation_contracts::organization_registrations().await
}

#[tokio::test(flavor = "multi_thread")]
async fn blob_presign_retains_classified_native_object_and_live_policy() -> anyhow::Result<()> {
    cotest::scenarios::native_operation_contracts::blob_presign().await
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_keypackage_claims_retain_two_native_authorities_and_original_cas()
-> anyhow::Result<()> {
    cotest::scenarios::native_operation_contracts::peer_keypackage_claims().await
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_contacts_retain_two_native_authorities_and_nonempty_originals() -> anyhow::Result<()>
{
    cotest::scenarios::native_operation_contracts::peer_contacts().await
}

#[tokio::test(flavor = "multi_thread")]
async fn applet_installations_retain_original_sources_and_exact_fenced_replays()
-> anyhow::Result<()> {
    cotest::scenarios::native_operation_contracts::applet_installations().await
}

#[tokio::test(flavor = "multi_thread")]
async fn push_gateway_retains_native_registration_receipt_and_provider_dispatch()
-> anyhow::Result<()> {
    cotest::scenarios::native_operation_contracts::push_gateway().await
}

#[tokio::test(flavor = "multi_thread")]
async fn applet_managed_configuration_retains_review_originals_and_native_route()
-> anyhow::Result<()> {
    cotest::scenarios::native_operation_contracts::applet_managed_configuration().await
}

#[tokio::test(flavor = "multi_thread")]
async fn account_erasure_retains_native_terminal_intent_and_physical_receipt() -> anyhow::Result<()>
{
    cotest::scenarios::native_operation_contracts::account_erasure_status().await
}


#[tokio::test(flavor = "multi_thread")]
async fn mimi_proxy_download_retains_public_object_current_policy_and_provider_originals()
-> anyhow::Result<()> {
    cotest::scenarios::native_operation_contracts::mimi_proxy_download().await
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_consent_retains_real_hosting_current_proxy_and_worker_effects() -> anyhow::Result<()>
{
    cotest::scenarios::native_operation_contracts::peer_consent().await
}
