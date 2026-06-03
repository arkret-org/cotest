//! Round 4 / A2 — per-vector scenario stubs for the security closure
//! fixture (`cokret-spec/spec/v1/artifacts/fixtures/security-closure-vectors.json`).
//!
//! Every vector listed in the spec snapshot is registered here. For each
//! one we:
//!
//! * pin the canonical `vector_id` string,
//! * expose a wire-shape sanity check that confirms the fixture loads, carries the expected
//!   `vector_id`, and that every step exposes the typed `runner{}` contract,
//! * expose a deterministic local runner-contract round-trip for each vector so the suite can run
//!   without live downstream services.
//!
//! The actual end-to-end SUT wiring lives in implementer projects
//! (soland / coauth / teabay / yougen). Cotest keeps these vector gates
//! live by validating the canonical runner contract locally.

use anyhow::{Context, Result, anyhow};

use crate::conformance::{
    ObservedRunner, REQUIRED_SECURITY_CLOSURE_VECTOR_IDS, SecurityClosureFixture,
};

/// All vector ids covered by the round-4 security closure suite. Kept in
/// the same order as the spec fixture so diffs read top-to-bottom.
pub const VECTOR_IDS: &[&str] = REQUIRED_SECURITY_CLOSURE_VECTOR_IDS;

/// Load the canonical fixture and verify the vector is present + every
/// step exposes the typed runner contract. Used as the default cotest-side
/// gate for an implementer that does not yet expose a SUT runner.
pub fn assert_vector_present(vector_id: &str) -> Result<()> {
    let fixture =
        SecurityClosureFixture::load().context("loading security-closure-vectors.json")?;
    let vector = fixture.vector(vector_id).context("vector lookup")?;
    if vector.steps.is_empty() {
        return Err(anyhow!(
            "security_closure_vectors[{vector_id}] has zero steps"
        ));
    }
    for step in &vector.steps {
        if step.runner.operation.is_empty() {
            return Err(anyhow!(
                "security_closure_vectors[{vector_id}].{}.runner.operation must be non-empty",
                step.name
            ));
        }
        if step.runner.expected_audit_reason.is_empty() {
            return Err(anyhow!(
                "security_closure_vectors[{vector_id}].{}.runner.expected_audit_reason must be non-empty",
                step.name
            ));
        }
    }
    Ok(())
}

/// Run the local fixture runner contract for one vector by feeding each
/// expected runner output back through the typed comparison helper.
pub fn assert_vector_runner_contract(vector_id: &str) -> Result<()> {
    let fixture =
        SecurityClosureFixture::load().context("loading security-closure-vectors.json")?;
    let vector = fixture.vector(vector_id).context("vector lookup")?;
    for step in &vector.steps {
        let observed = ObservedRunner {
            transcript: step.runner.transcript.clone(),
            state_transition: step.runner.expected_state_transition.clone(),
            external_response: step.runner.expected_external_response.clone(),
            audit_reason: step.runner.expected_audit_reason.clone(),
        };
        step.compare(&observed).with_context(|| {
            format!(
                "runner contract round-trip failed for {vector_id}.{}",
                step.name
            )
        })?;
    }
    Ok(())
}

// ── Individual vector pins ──────────────────────────────────────────────────
//
// Each `pub const VECTOR_<NAME>` is grep-able and matches the canonical
// `vector_id` slot in the fixture, so a downstream `assert_vector_present`
// call lands directly on the right step set.

pub const VECTOR_FEDERATION_IDEMPOTENCY_AFTER_KEY_REVOKE: &str =
    "cx.vector.federation.idempotency_after_key_revoke.v1";
pub const VECTOR_WEBRTC_MEDIA_PLAINTEXT_DOWNGRADE: &str =
    "cx.vector.webrtc.media_plaintext_downgrade.v1";
pub const VECTOR_IDENTITY_LINK_EAGER_INVALIDATION: &str =
    "cx.vector.identity_link.eager_invalidation.v1";
pub const VECTOR_IDENTITY_LINK_POLICY_TIGHTENING_INVALIDATION: &str =
    "cx.vector.identity_link.policy_tightening_invalidation.v1";
pub const VECTOR_LATE_KEY_RECOVERY_REMOVED_ACTOR: &str =
    "cx.vector.late_key_recovery.removed_actor.v1";
pub const VECTOR_INVITE_OOB_CODE_ENTROPY: &str = "cx.vector.invite.oob_code_entropy.v1";
pub const VECTOR_INVITE_FAILURE_INDISTINGUISHABLE: &str =
    "cx.vector.invite.failure_indistinguishable.v1";
pub const VECTOR_CONSENT_SCOPE_CASCADE: &str = "cx.vector.consent.scope_cascade.v1";
pub const VECTOR_CONSENT_CACHE_INVALIDATION: &str = "cx.vector.consent.cache_invalidation.v1";
pub const VECTOR_SYNC_SOFT_FAIL_RECONCILE: &str = "cx.vector.sync.soft_fail_reconcile.v1";
pub const VECTOR_LATTICE_LWW_OPEN_SET: &str = "cx.vector.lattice.lww_open_set.v1";
pub const VECTOR_E2EE_RELAXED_WINDOW_EXCEEDS_CEILING: &str =
    "cx.vector.e2ee_relaxed.window_exceeds_ceiling.v1";

#[cfg(test)]
mod tests {
    use super::*;

    /// Every required `vector_id` we pin in this module is also present
    /// in the canonical fixture and exposes the typed runner contract.
    #[test]
    fn every_vector_id_is_loadable() {
        for vector_id in VECTOR_IDS {
            assert_vector_present(vector_id)
                .unwrap_or_else(|err| panic!("vector {vector_id} missing or malformed: {err}"));
        }
    }

    #[test]
    fn every_vector_runner_contract_round_trips() {
        for vector_id in VECTOR_IDS {
            assert_vector_runner_contract(vector_id)
                .unwrap_or_else(|err| panic!("vector {vector_id} runner contract failed: {err}"));
        }
    }
}
