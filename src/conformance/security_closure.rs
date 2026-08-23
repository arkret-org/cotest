//! Round 4 / A2 — security-closure-fixture runner contract.
//!
//! Loads `arkret-spec/spec/v1/artifacts/fixtures/security-closure-fixture.json`
//! (13 vector ids, runner contract introduced by spec commit
//! `892c5d7 test: add security closure runner contract`) and verifies the
//! wire-level shape every conformant implementer is expected to expose:
//!
//! ```text
//! runner {
//!   given_state,
//!   operation,
//!   transcript,
//!   expected_state_transition,
//!   expected_external_response,
//!   expected_audit_reason,
//! }
//! ```
//!
//! For each vector we expose typed parsers so downstream end-to-end
//! scenarios can compare an observed
//! `(transcript, state_transition, external_response, audit_reason)` quad
//! against the fixture. Vectors whose implementer-side wire support is not
//! yet ready stay behind `#[ignore]` in `tests/security_closure_fixture.rs`
//! as active local runner-contract checks in `tests/security_closure_fixture.rs`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{fixture_path, validate_profile};

/// Canonical fixture filename. The Python lint (`check_security_closure_fixture`)
/// pins the same path on the spec side.
pub const SECURITY_CLOSURE_VECTORS_FIXTURE: &str = "security-closure-fixture.json";

/// Canonical conformance profile for the security closure fixture suite.
pub const SECURITY_CLOSURE_VECTORS_PROFILE: &str = "ak.vector_group.privacy_security.v1";

/// The vector ids the round-4 spec promotes from prose to fixture. The list is
/// pinned here so any drift on either side is loud.
pub const REQUIRED_SECURITY_CLOSURE_VECTOR_IDS: &[&str] = &[
    crate::scenarios::security_closure_fixture::VECTOR_FEDERATION_IDEMPOTENCY_AFTER_KEY_REVOKE,
    "ak.vector.webrtc.media_plaintext_downgrade.v1",
    "ak.vector.identity_link.eager_invalidation.v1",
    "ak.vector.identity_link.policy_tightening_invalidation.v1",
    "ak.vector.late_key_recovery.removed_actor.v1",
    "ak.vector.invite.oob_code_entropy.v1",
    "ak.vector.invite.failure_indistinguishable.v1",
    "ak.vector.invite.claim_reducer_state_machine.v1",
    "ak.vector.consent.scope_cascade.v1",
    "ak.vector.consent.cache_invalidation.v1",
    "ak.vector.sync.soft_fail_reconcile.v1",
    "ak.vector.lattice.lww_open_set.v1",
    "ak.vector.e2ee_relaxed.window_exceeds_ceiling.v1",
    // 2026-08-17 — account lifecycle left the Event/PCR finality domain for the
    // Account Authority issuer ledger (`identity/account-lifecycle.md` §3.1).
    // The genesis/CAS, replay, fork, gap-recovery, binding-rollback and
    // receipted-fanout closure is cross-object and single-writer, so it is a
    // conformance vector rather than a schema case.
    crate::conformance::account_status_issuer_ledger::VECTOR_ID_ACCOUNT_STATUS_ISSUER_LEDGER,
];

/// Top-level fixture shape.
#[derive(Clone, Debug, Deserialize)]
pub struct SecurityClosureFixture {
    pub suite: String,
    pub profile: String,
    pub version: String,
    #[serde(default)]
    pub description: String,
    pub security_closure_fixture: Vec<SecurityClosureVector>,
}

/// One vector with N steps.
#[derive(Clone, Debug, Deserialize)]
pub struct SecurityClosureVector {
    pub vector_id: String,
    pub steps: Vec<SecurityClosureStep>,
}

/// A single step within a vector. The `runner` block is the canonical
/// contract every conformant implementer must produce.
#[derive(Clone, Debug, Deserialize)]
pub struct SecurityClosureStep {
    pub name: String,
    pub input: Value,
    pub expected: SecurityClosureExpected,
    pub runner: SecurityClosureRunner,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SecurityClosureExpected {
    pub outcome: String,
    #[serde(default)]
    pub reason_code: Option<String>,
    #[serde(default)]
    pub invariants: Vec<String>,
    #[serde(default)]
    pub response: Option<Value>,
}

/// The typed runner contract introduced by spec `892c5d7`.
#[derive(Clone, Debug, Deserialize)]
pub struct SecurityClosureRunner {
    pub given_state: Value,
    pub operation: String,
    pub transcript: Value,
    pub expected_state_transition: Value,
    pub expected_external_response: Value,
    pub expected_audit_reason: String,
}

impl SecurityClosureFixture {
    /// Resolve the canonical fixture path via the standard cotest
    /// spec-artifacts root.
    pub fn fixture_path() -> PathBuf {
        fixture_path(SECURITY_CLOSURE_VECTORS_FIXTURE)
    }

    /// Load and parse the fixture, validating the profile pin.
    pub fn load() -> Result<Self> {
        let path = Self::fixture_path();
        Self::load_from(&path)
    }

    /// Load + parse from an explicit path (used by tests with synthetic
    /// fixtures and by the spec-roots override path).
    pub fn load_from(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read security-closure-fixture {}", path.display()))?;
        let value: Value = serde_json::from_str(&raw)
            .with_context(|| format!("parse security-closure-fixture {}", path.display()))?;
        validate_profile(&value, SECURITY_CLOSURE_VECTORS_PROFILE)?;
        let fixture: SecurityClosureFixture = serde_json::from_value(value)
            .with_context(|| format!("decode security-closure-fixture {}", path.display()))?;
        if fixture.suite != "security_closure_fixture" {
            bail!(
                "security-closure-fixture suite drifted: expected `security_closure_fixture`, got `{}`",
                fixture.suite,
            );
        }
        Ok(fixture)
    }

    /// Look up a vector by id. Returns an error if missing.
    pub fn vector(&self, vector_id: &str) -> Result<&SecurityClosureVector> {
        self.security_closure_fixture
            .iter()
            .find(|v| v.vector_id == vector_id)
            .ok_or_else(|| anyhow!("security-closure-fixture missing vector_id `{vector_id}`"))
    }
}

/// Observed runner output an implementer-under-test exposes after running
/// a vector step. Compared against the fixture's `runner.*` block by
/// [`SecurityClosureStep::compare`]. Producing this struct is intentionally
/// implementer-side glue (cotest only validates shape).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ObservedRunner {
    pub transcript: Value,
    pub state_transition: Value,
    pub external_response: Value,
    pub audit_reason: String,
}

impl SecurityClosureStep {
    /// Wire-shape comparison: returns Ok(()) iff observed equals expected
    /// across all four channels. Mismatch produces an anyhow error
    /// summarising the first differing channel.
    pub fn compare(&self, observed: &ObservedRunner) -> Result<()> {
        if observed.transcript != self.runner.transcript {
            bail!(
                "security_closure[{}].transcript mismatch:\n expected = {}\n   actual = {}",
                self.name,
                self.runner.transcript,
                observed.transcript,
            );
        }
        if observed.state_transition != self.runner.expected_state_transition {
            bail!(
                "security_closure[{}].state_transition mismatch:\n expected = {}\n   actual = {}",
                self.name,
                self.runner.expected_state_transition,
                observed.state_transition,
            );
        }
        if observed.external_response != self.runner.expected_external_response {
            bail!(
                "security_closure[{}].external_response mismatch:\n expected = {}\n   actual = {}",
                self.name,
                self.runner.expected_external_response,
                observed.external_response,
            );
        }
        if observed.audit_reason != self.runner.expected_audit_reason {
            bail!(
                "security_closure[{}].audit_reason mismatch: expected `{}`, got `{}`",
                self.name,
                self.runner.expected_audit_reason,
                observed.audit_reason,
            );
        }
        Ok(())
    }
}

/// Top-level sanity suite — wire shape closure over the fixture itself.
///
/// Pins:
/// * profile equals `ak.vector_group.privacy_security.v1`
/// * every required vector_id is present
/// * every step exposes the full 6-field `runner{}` contract
/// * `expected_state_transition.outcome` (when set) matches `expected.outcome` (mirrors the
///   spec-side lint `check_security_closure_fixture`)
pub fn run_security_closure_fixture_suite() -> Result<()> {
    let fixture = SecurityClosureFixture::load()?;
    validate_security_closure_fixture(&fixture)
}

/// Same as [`run_security_closure_fixture_suite`] but takes the parsed
/// fixture directly. Used by unit tests against synthetic data.
pub fn validate_security_closure_fixture(fixture: &SecurityClosureFixture) -> Result<()> {
    if fixture.profile != SECURITY_CLOSURE_VECTORS_PROFILE {
        bail!(
            "security-closure-fixture profile drift: expected `{}`, got `{}`",
            SECURITY_CLOSURE_VECTORS_PROFILE,
            fixture.profile,
        );
    }
    let mut seen = std::collections::BTreeSet::new();
    for vector in &fixture.security_closure_fixture {
        if !seen.insert(vector.vector_id.clone()) {
            bail!(
                "security-closure-fixture duplicates vector_id `{}`",
                vector.vector_id
            );
        }
        if vector.steps.is_empty() {
            bail!(
                "security-closure-fixture vector `{}` has zero steps",
                vector.vector_id
            );
        }
        for step in &vector.steps {
            if step.name.is_empty() {
                bail!(
                    "security-closure-fixture[{}] has empty step.name",
                    vector.vector_id
                );
            }
            if step.runner.operation.is_empty() {
                bail!(
                    "security-closure-fixture[{}].{}.runner.operation must be non-empty",
                    vector.vector_id,
                    step.name,
                );
            }
            if step.runner.expected_audit_reason.is_empty() {
                bail!(
                    "security-closure-fixture[{}].{}.runner.expected_audit_reason must be non-empty",
                    vector.vector_id,
                    step.name,
                );
            }
            // The spec-side `check_security_closure_fixture` lint enforces
            // outcome consistency between `expected.outcome` and
            // `runner.expected_state_transition.outcome`. We mirror that
            // here so a stale fixture drops out loudly.
            if let Some(state_outcome) = step
                .runner
                .expected_state_transition
                .get("outcome")
                .and_then(Value::as_str)
                && state_outcome != step.expected.outcome
            {
                bail!(
                    "security-closure-fixture[{}].{}.runner.expected_state_transition.outcome `{}` \
                         does not match expected.outcome `{}`",
                    vector.vector_id,
                    step.name,
                    state_outcome,
                    step.expected.outcome,
                );
            }
        }
    }
    for required in REQUIRED_SECURITY_CLOSURE_VECTOR_IDS {
        if !seen.contains(*required) {
            bail!("security-closure-fixture missing required vector_id `{required}`");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_fixture_round_trips() {
        let fixture = SecurityClosureFixture::load().expect("spec fixture parses");
        validate_security_closure_fixture(&fixture).expect("fixture must satisfy round-4 lint");
        for required in REQUIRED_SECURITY_CLOSURE_VECTOR_IDS {
            assert!(
                fixture
                    .security_closure_fixture
                    .iter()
                    .any(|v| v.vector_id == *required),
                "fixture missing required vector_id {required}"
            );
        }
    }

    #[test]
    fn compare_succeeds_on_round_trip() {
        let fixture = SecurityClosureFixture::load().expect("spec fixture parses");
        // Pick the first step of the first vector and feed its expected
        // back as the observed runner.
        let vector = fixture
            .security_closure_fixture
            .first()
            .expect("fixture non-empty");
        let step = vector.steps.first().expect("vector has at least one step");
        let observed = ObservedRunner {
            transcript: step.runner.transcript.clone(),
            state_transition: step.runner.expected_state_transition.clone(),
            external_response: step.runner.expected_external_response.clone(),
            audit_reason: step.runner.expected_audit_reason.clone(),
        };
        step.compare(&observed).expect("identity round-trip");
    }

    #[test]
    fn compare_detects_audit_reason_drift() {
        let fixture = SecurityClosureFixture::load().expect("spec fixture parses");
        let vector = fixture.security_closure_fixture.first().unwrap();
        let step = vector.steps.first().unwrap();
        let mut observed = ObservedRunner {
            transcript: step.runner.transcript.clone(),
            state_transition: step.runner.expected_state_transition.clone(),
            external_response: step.runner.expected_external_response.clone(),
            audit_reason: step.runner.expected_audit_reason.clone(),
        };
        observed.audit_reason = "drifted".to_string();
        assert!(step.compare(&observed).is_err());
    }
}
