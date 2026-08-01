use anyhow::Result;
use cotest::conformance::{
    run_did_binding_digest_kat_suite, run_key_backup_delete_authority_vector,
    run_keypackage_self_claim_authorization_idempotency_vector,
    run_lattice_cas_register_supersession_vector, run_mimi_provider_directory_signature_vector,
    run_signal_device_authorization_domain_vector,
};

#[test]
fn spec_open_batch_exact_vector_runners_close_all_eight_ids() -> Result<()> {
    run_lattice_cas_register_supersession_vector()?;
    run_key_backup_delete_authority_vector()?;
    run_mimi_provider_directory_signature_vector()?;
    run_signal_device_authorization_domain_vector()?;
    run_keypackage_self_claim_authorization_idempotency_vector()?;
    run_did_binding_digest_kat_suite()?;
    Ok(())
}
