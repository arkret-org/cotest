//! P4-B — integration entrypoints for `conformance-vectors.md` §11
//! (personal agent + sidecar). 9 vectors; each pins the SDK-side
//! contract (constants, error codes, deterministic derivations). Deep
//! reducer assertions are marked `TODO(P4-impl)` and land against a
//! live soland under P5.

use cotest::scenarios::spec_section_11::{
    act_on_behalf_attribution::act_on_behalf_attribution_run,
    controller_deactivate_cascade::controller_deactivate_cascade_run,
    eligibility_tristate_and_revocation::eligibility_tristate_and_revocation_run,
    existence_privacy::existence_privacy_run,
    multi_agent_publish_attribution::multi_agent_publish_attribution_run,
    pairing_expiry_auto_revoke::pairing_expiry_auto_revoke_run,
    provisioning_pairing_grant_order::provisioning_pairing_grant_order_run,
    session_grant_replay_guard::session_grant_replay_guard_run,
    sidecar_circle_idempotent_ensure::sidecar_circle_idempotent_ensure_run,
};

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
