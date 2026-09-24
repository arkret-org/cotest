use anyhow::Result;
use cotest::conformance::{
    run_did_binding_digest_kat_suite, run_key_backup_delete_authority_vector,
    run_keypackage_self_claim_authorization_idempotency_vector,
    run_signal_device_authorization_domain_vector,
};

#[test]
fn spec_open_batch_exact_vector_runners_close_their_ids() -> Result<()> {
    run_key_backup_delete_authority_vector()?;
    run_signal_device_authorization_domain_vector()?;
    run_keypackage_self_claim_authorization_idempotency_vector()?;
    run_did_binding_digest_kat_suite()?;
    Ok(())
}
