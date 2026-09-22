//! Executable receiver-side AEAD nonce tuple replay conformance runner.
//!
//! The fixture describes the state transition around decryption: the first
//! ciphertext digest binds a `(key_ref, purpose, aead_profile, counter)`
//! tuple, an exact retry folds without decrypting again, and a different
//! ciphertext for the same tuple is rejected before decryption or effects.

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use arkret_wire::{ErrorCode, Hash, ReasonCode};
use serde::Deserialize;

pub const AEAD_NONCE_REPLAY_ENTRYPOINT: &str = "ak.suite.crypto.aead_nonce_replay.v1";
pub const FIXTURE: &str = "aead-nonce-replay-fixture.json";

const VECTOR_ID: &str = "ak.vector.crypto.aead_nonce_replay.v1";
const RECEIVER_STATE_KEY: [&str; 4] = ["key_ref", "purpose", "aead_profile", "counter"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRoot {
    profile: String,
    version: String,
    suite: String,
    runner: Runner,
    covers_vectors: Vec<String>,
    receiver_state_key: Vec<String>,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Runner {
    kind: String,
    entrypoint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCase {
    #[serde(rename = "case")]
    case_id: String,
    prior_binding: Option<String>,
    candidate_ciphertext_digest: String,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    decision: String,
    #[serde(default)]
    error_code: Option<String>,
    #[serde(default)]
    reason_code: Option<String>,
    bind_digest: bool,
    decrypt_attempts: usize,
    #[serde(default)]
    durable_effects: Option<usize>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ReceiverState {
    bound_digest: Option<Hash>,
    decrypt_attempts: usize,
    durable_effects: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReceiverDecision {
    Accept,
    Fold,
    Reject(&'static str),
}

impl ReceiverState {
    fn seeded(prior_binding: Option<&str>) -> Result<Self> {
        Ok(Self {
            bound_digest: prior_binding
                .map(|digest| Hash::new(digest.to_owned()))
                .transpose()?,
            ..Self::default()
        })
    }

    fn receive(&mut self, candidate: Hash) -> ReceiverDecision {
        match self.bound_digest.as_ref() {
            None => {
                self.bound_digest = Some(candidate);
                self.decrypt_attempts += 1;
                ReceiverDecision::Accept
            }
            Some(bound) if bound == &candidate => ReceiverDecision::Fold,
            Some(_) => ReceiverDecision::Reject(ReasonCode::AEAD_NONCE_COUNTER_REPLAY),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
    pub decrypt_attempts: usize,
    pub state_changed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AeadNonceReplayExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
    pub accepted_cases: usize,
    pub folded_cases: usize,
    pub rejected_cases: usize,
}

fn spec_artifacts_root() -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT") {
        return PathBuf::from(root);
    }
    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        let root = PathBuf::from(root);
        for candidate in [root.clone(), root.join("spec").join("v1").join("artifacts")] {
            if candidate.join("fixtures").is_dir() {
                return candidate;
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
}

fn load_fixture() -> Result<FixtureRoot> {
    let path = spec_artifacts_root().join("fixtures").join(FIXTURE);
    serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("parse fixture {}", path.display()))
}

fn validate_fixture_metadata(fixture: &FixtureRoot) -> Result<()> {
    ensure!(
        fixture.profile == "ak.profile.blob_node.v1",
        "fixture profile drifted"
    );
    ensure!(
        !fixture.version.trim().is_empty(),
        "fixture version is empty"
    );
    ensure!(
        fixture.suite == "aead_nonce_replay",
        "fixture suite drifted"
    );
    ensure!(fixture.runner.kind == "named_suite", "runner kind drifted");
    ensure!(
        fixture.runner.entrypoint == AEAD_NONCE_REPLAY_ENTRYPOINT,
        "runner entrypoint drifted"
    );
    ensure!(
        fixture
            .covers_vectors
            .iter()
            .map(String::as_str)
            .eq([VECTOR_ID]),
        "fixture vector closure drifted"
    );
    ensure!(
        fixture
            .receiver_state_key
            .iter()
            .map(String::as_str)
            .eq(RECEIVER_STATE_KEY),
        "receiver replay tuple drifted"
    );
    Ok(())
}

fn run_case(case: &FixtureCase) -> Result<(CaseExecutionResult, ReceiverDecision)> {
    let mut state = ReceiverState::seeded(case.prior_binding.as_deref())?;
    let before = state.clone();
    let candidate = Hash::new(case.candidate_ciphertext_digest.clone())?;
    let decision = state.receive(candidate.clone());
    let state_changed = state.bound_digest != before.bound_digest;

    let assertions = match decision {
        ReceiverDecision::Accept => {
            ensure!(
                case.expected.decision == "accept",
                "accept decision drifted"
            );
            ensure!(
                case.expected.bind_digest,
                "first ciphertext must bind its digest"
            );
            ensure!(
                state.bound_digest.as_ref() == Some(&candidate),
                "candidate digest was not bound"
            );
            ensure!(
                state.decrypt_attempts == case.expected.decrypt_attempts,
                "accept decrypt count drifted"
            );
            ensure!(
                state_changed,
                "first ciphertext did not change receiver state"
            );
            5
        }
        ReceiverDecision::Fold => {
            ensure!(case.expected.decision == "fold", "fold decision drifted");
            ensure!(!case.expected.bind_digest, "exact retry rebound its digest");
            ensure!(
                state.decrypt_attempts == case.expected.decrypt_attempts,
                "fold decrypt count drifted"
            );
            ensure!(!state_changed, "exact retry changed receiver state");
            4
        }
        ReceiverDecision::Reject(reason) => {
            ensure!(
                case.expected.decision == "reject",
                "reject decision drifted"
            );
            ensure!(
                !case.expected.bind_digest,
                "rejected ciphertext bound its digest"
            );
            ensure!(
                case.expected.error_code.as_deref() == Some(ErrorCode::FAILED_PRECONDITION),
                "rejection error code drifted"
            );
            ensure!(
                case.expected.reason_code.as_deref() == Some(reason),
                "rejection reason drifted"
            );
            ensure!(
                ReasonCode::from_wire(reason).descriptor().is_some(),
                "rejection reason is not registered"
            );
            ensure!(
                state.decrypt_attempts == case.expected.decrypt_attempts,
                "rejection attempted decryption"
            );
            ensure!(
                state.durable_effects == case.expected.durable_effects.unwrap_or_default(),
                "rejection durable effects drifted"
            );
            ensure!(
                state == before,
                "rejected ciphertext changed receiver state"
            );
            8
        }
    };

    Ok((
        CaseExecutionResult {
            case_id: case.case_id.clone(),
            assertions,
            decrypt_attempts: state.decrypt_attempts,
            state_changed,
        },
        decision,
    ))
}

pub fn run_aead_nonce_replay_suite() -> Result<AeadNonceReplayExecution> {
    let fixture = load_fixture()?;
    validate_fixture_metadata(&fixture)?;
    let mut cases = Vec::with_capacity(fixture.cases.len());
    let mut accepted_cases = 0;
    let mut folded_cases = 0;
    let mut rejected_cases = 0;
    for case in &fixture.cases {
        let (result, decision) = run_case(case)?;
        match decision {
            ReceiverDecision::Accept => accepted_cases += 1,
            ReceiverDecision::Fold => folded_cases += 1,
            ReceiverDecision::Reject(_) => rejected_cases += 1,
        }
        cases.push(result);
    }
    ensure!(cases.len() == 3, "expected all three nonce replay cases");
    ensure!(
        (accepted_cases, folded_cases, rejected_cases) == (1, 1, 1),
        "fixture must cover accept, fold, and reject exactly once"
    );
    Ok(AeadNonceReplayExecution {
        entrypoint: AEAD_NONCE_REPLAY_ENTRYPOINT,
        fixture: FIXTURE,
        cases,
        accepted_cases,
        folded_cases,
        rejected_cases,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_accept_fold_and_reject_without_unsafe_decrypts() {
        let execution = run_aead_nonce_replay_suite().unwrap();
        assert_eq!(execution.entrypoint, AEAD_NONCE_REPLAY_ENTRYPOINT);
        assert_eq!(execution.cases.len(), 3);
        assert_eq!(execution.accepted_cases, 1);
        assert_eq!(execution.folded_cases, 1);
        assert_eq!(execution.rejected_cases, 1);
        assert_eq!(execution.cases[0].decrypt_attempts, 1);
        assert_eq!(execution.cases[1].decrypt_attempts, 0);
        assert_eq!(execution.cases[2].decrypt_attempts, 0);
        assert!(execution.cases.iter().all(|case| case.assertions > 0));
    }

    #[test]
    fn divergent_replay_preserves_the_seeded_binding() {
        let fixture = load_fixture().unwrap();
        let rejected = &fixture.cases[2];
        let (result, decision) = run_case(rejected).unwrap();
        assert_eq!(
            decision,
            ReceiverDecision::Reject(ReasonCode::AEAD_NONCE_COUNTER_REPLAY)
        );
        assert!(!result.state_changed);
        assert_eq!(result.decrypt_attempts, 0);
    }
}
