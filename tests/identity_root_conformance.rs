//! Cold-root custody, bootstrap, recovery, and generation-fence conformance.

use cotest::conformance::{
    run_did_webvh_v1_adapter_fixture_suite, run_identity_model_generation_fence_suite,
    run_identity_recovery_kdf_fixture_suite, run_identity_root_anchor_checkpoint_suite,
    run_schema_validation_fixture_suite,
};

#[test]
fn identity_recovery_kdf_known_answers_are_byte_exact() {
    run_identity_recovery_kdf_fixture_suite().expect("identity recovery KDF conformance");
}

#[test]
fn identity_root_bootstrap_reanchor_and_handoff_checkpoints_hold() {
    run_identity_root_anchor_checkpoint_suite().expect("identity root anchor checkpoints");
}

#[test]
fn identity_models_and_device_generations_fail_closed() {
    run_identity_model_generation_fence_suite().expect("identity model generation conformance");
}

#[test]
fn canonical_webvh_and_principal_agent_schema_paths_remain_conformant() {
    run_did_webvh_v1_adapter_fixture_suite().expect("did:webvh history conformance");
    run_schema_validation_fixture_suite().expect("principal/Agent PCR schema conformance");
}
