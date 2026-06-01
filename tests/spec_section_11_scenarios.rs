//! P4-B — integration entrypoints for `conformance-vectors.md` §11
//! (personal agent + sidecar). 9 vectors; each pins the SDK-side
//! contract (constants, error codes, deterministic derivations). Deep
//! reducer assertions are marked `TODO(P4-impl)` and land against a
//! live soland under P5.

use cotest::scenarios::spec_section_11::act_on_behalf_attribution::act_on_behalf_attribution_run;
use cotest::scenarios::spec_section_11::controller_deactivate_cascade::controller_deactivate_cascade_run;
use cotest::scenarios::spec_section_11::eligibility_tristate_and_revocation::eligibility_tristate_and_revocation_run;
use cotest::scenarios::spec_section_11::existence_privacy::existence_privacy_run;
use cotest::scenarios::spec_section_11::multi_agent_publish_attribution::multi_agent_publish_attribution_run;
use cotest::scenarios::spec_section_11::pairing_expiry_auto_revoke::pairing_expiry_auto_revoke_run;
use cotest::scenarios::spec_section_11::provisioning_pairing_grant_order::provisioning_pairing_grant_order_run;
use cotest::scenarios::spec_section_11::session_grant_replay_guard::session_grant_replay_guard_run;
use cotest::scenarios::spec_section_11::sidecar_circle_idempotent_ensure::sidecar_circle_idempotent_ensure_run;

#[tokio::test]
async fn s11_provisioning_pairing_grant_order() {
    provisioning_pairing_grant_order_run().await.unwrap();
}

#[tokio::test]
async fn s11_pairing_expiry_auto_revoke() {
    pairing_expiry_auto_revoke_run().await.unwrap();
}

#[tokio::test]
async fn s11_session_grant_replay_guard() {
    session_grant_replay_guard_run().await.unwrap();
}

#[tokio::test]
async fn s11_controller_deactivate_cascade() {
    controller_deactivate_cascade_run().await.unwrap();
}

#[tokio::test]
async fn s11_act_on_behalf_attribution() {
    act_on_behalf_attribution_run().await.unwrap();
}

#[tokio::test]
async fn s11_sidecar_circle_idempotent_ensure() {
    sidecar_circle_idempotent_ensure_run().await.unwrap();
}

#[tokio::test]
async fn s11_existence_privacy() {
    existence_privacy_run().await.unwrap();
}

#[tokio::test]
async fn s11_eligibility_tristate_and_revocation() {
    eligibility_tristate_and_revocation_run().await.unwrap();
}

#[tokio::test]
async fn s11_multi_agent_publish_attribution() {
    multi_agent_publish_attribution_run().await.unwrap();
}
