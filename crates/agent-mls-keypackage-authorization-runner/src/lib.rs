//! Executable Agent MLS KeyPackage authorization fixture runner.
//!
//! The runner drives the production MLS endpoint carrier and
//! `verify_ordinary_agent_mls_binding`. A successful admission is the only
//! path that reaches the encryption sink; every rejection snapshots that sink
//! so an arbitrary error cannot satisfy the zero-effect contract.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, ensure};
use arkret_models_crypto::MlsWelcomeEnvelope;
use arkret_policy::{
    AgentMlsSignerClaim, AgentMlsSignerView, AuthorGroupStateView, AuthorLeaf,
    AuthorLeafCredential, verify_ordinary_agent_mls_binding,
};
use arkret_wire::{AccountId, ActorId, DidCoreId, EventId, MlsGroupId};
use ed25519_dalek::{Signature, Signer, SigningKey};
use serde::Deserialize;
use serde_json::{Value, json};

pub const AGENT_MLS_KEYPACKAGE_AUTHORIZATION_ENTRYPOINT: &str =
    "ak.suite.agent.mls_keypackage_authorization.v1";
pub const FIXTURE: &str = "agent-mls-keypackage-authorization-fixture.json";

const VECTOR_ID: &str = "ak.vector.agent.mls_keypackage_authorization.v1";
const GROUP_ID: &str = "QjKOSorlqs3IquY7OikTUTy_Z0mMiL0X2mK4jAOT4R4";
const GROUP_STATE_REF: &str = "ak:event:ATrYU3cGlcWkAcHXWgJ8sIYfraoV9pIwEHNNStEqHvFh";
const STATION_ID: &str = "ak:did_core:webvh:z6mkstation";
const LEAF_TRANSCRIPT: &[u8] = b"arkret/cotest/agent-mls-leaf/v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRoot {
    profile: String,
    version: String,
    suite: String,
    runner: FixtureRunner,
    covers_vectors: Vec<String>,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRunner {
    kind: String,
    entrypoint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCase {
    name: String,
    covers_decision_points: Vec<String>,
    expected: Expected,
    agent_id: String,
    claim_principal_id: String,
    current_agent_key_authorize_event_id: String,
    claim_agent_key_authorize_event_id: Option<String>,
    device_authorize_event_id: Option<String>,
    current_verification_method: String,
    leaf_signature_key: String,
    leaf_signature_valid: bool,
    authorization_status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    decision: String,
    #[serde(default)]
    encryption_may_proceed: Option<bool>,
    #[serde(default)]
    encryption_attempted: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
    pub accepted_effects: usize,
    pub rejected_zero_effects: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentMlsKeypackageAuthorizationExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
    pub accepted_effects: usize,
    pub rejected_zero_effects: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdmissionRejection {
    CarrierBindingInvalid,
    LeafSignatureInvalid,
    AgentMlsLeafBindingMismatch,
}

#[derive(Default)]
struct EncryptionSink {
    encrypted_cases: Vec<String>,
}

impl EncryptionSink {
    fn encrypt(&mut self, case_id: &str) {
        self.encrypted_cases.push(case_id.to_owned());
    }
}

fn artifacts_root() -> PathBuf {
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
    let path = artifacts_root().join("fixtures").join(FIXTURE);
    serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("parse fixture {}", path.display()))
}

fn signing_key(method: &str) -> SigningKey {
    let seed = if method.ends_with("#runtime-1") {
        [0x11; 32]
    } else if method.ends_with("#runtime-2") {
        [0x22; 32]
    } else {
        [0x33; 32]
    };
    SigningKey::from_bytes(&seed)
}

fn actor(principal_id: &str) -> Result<ActorId> {
    Ok(ActorId::account(AccountId::new(
        DidCoreId::new(principal_id.to_owned())?,
        DidCoreId::new(STATION_ID.to_owned())?,
    )))
}

fn carrier(case: &FixtureCase) -> Result<MlsWelcomeEnvelope, AdmissionRejection> {
    let mut value = json!({
        "group_id": GROUP_ID,
        "epoch": 4,
        "recipient_principal_id": case.claim_principal_id,
        "recipient_agent_id": case.claim_principal_id,
        "recipient_agent_verification_method": case.current_verification_method,
        "agent_key_authorize_event_id": case.claim_agent_key_authorize_event_id,
        "welcome": "AA",
        "welcome_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    });
    if let Some(device_id) = &case.device_authorize_event_id {
        value["recipient_device_id"] = Value::String(device_id.clone());
    }
    serde_json::from_value(value).map_err(|_| AdmissionRejection::CarrierBindingInvalid)
}

fn active_view(case: &FixtureCase) -> Result<AgentMlsSignerView> {
    let is_active = case.authorization_status == "active";
    let leaf_actor = actor(&case.agent_id)?;
    let leaf_key = signing_key(&case.leaf_signature_key).verifying_key();
    let active_leaves = is_active
        .then(|| AuthorLeaf {
            leaf_index: 7,
            credential: AuthorLeafCredential::Basic {
                identity: leaf_actor.canonical_bytes().expect("valid fixture actor"),
            },
            signature_key: leaf_key.to_bytes().to_vec(),
            leaf_node_canonical_bytes: vec![0xa1, 0x07],
        })
        .into_iter()
        .collect();
    let leaf_authorization_refs = if is_active {
        vec![(
            7,
            EventId::new(case.current_agent_key_authorize_event_id.clone())?,
        )]
    } else {
        Vec::new()
    };
    Ok(AgentMlsSignerView {
        group_state: AuthorGroupStateView {
            group_id: MlsGroupId::new(GROUP_ID.to_owned()).map_err(|error| anyhow!(error))?,
            epoch: 4,
            group_state_ref: GROUP_STATE_REF.to_owned(),
            active_leaves,
        },
        leaf_authorization_refs,
    })
}

fn admit_and_encrypt(
    case: &FixtureCase,
    sink: &mut EncryptionSink,
) -> Result<(), AdmissionRejection> {
    carrier(case)?;

    let leaf_signer = signing_key(&case.leaf_signature_key);
    let mut signature = leaf_signer.sign(LEAF_TRANSCRIPT).to_bytes();
    if !case.leaf_signature_valid {
        signature[0] ^= 1;
    }
    let signature = Signature::from_bytes(&signature);
    leaf_signer
        .verifying_key()
        .verify_strict(LEAF_TRANSCRIPT, &signature)
        .map_err(|_| AdmissionRejection::LeafSignatureInvalid)?;

    let authorized_key = signing_key(&case.current_verification_method).verifying_key();
    let view = active_view(case).map_err(|_| AdmissionRejection::AgentMlsLeafBindingMismatch)?;
    let signer_actor = actor(&case.claim_principal_id)
        .map_err(|_| AdmissionRejection::AgentMlsLeafBindingMismatch)?;
    let authorization_ref = case
        .claim_agent_key_authorize_event_id
        .as_ref()
        .ok_or(AdmissionRejection::CarrierBindingInvalid)
        .and_then(|event_id| {
            EventId::new(event_id.clone()).map_err(|_| AdmissionRejection::CarrierBindingInvalid)
        })?;
    verify_ordinary_agent_mls_binding(
        &view,
        &AgentMlsSignerClaim {
            group_id: GROUP_ID,
            epoch: 4,
            group_state_ref: GROUP_STATE_REF,
            signer_actor_id: &signer_actor,
            signing_key: authorized_key.as_bytes(),
            agent_key_authorize_event_id: &authorization_ref,
        },
    )
    .map_err(|_| AdmissionRejection::AgentMlsLeafBindingMismatch)?;

    sink.encrypt(&case.name);
    Ok(())
}

fn expected_rejection(case_id: &str) -> Option<AdmissionRejection> {
    match case_id {
        "current_agent_authorization_is_accepted" => None,
        "delegated_device_binding_is_rejected" | "cross_principal_binding_is_rejected" => {
            Some(AdmissionRejection::CarrierBindingInvalid)
        }
        "leaf_signature_key_mismatch_is_rejected"
        | "stale_authorize_event_is_rejected"
        | "revoked_authorization_is_rejected"
        | "expired_authorization_is_rejected" => {
            Some(AdmissionRejection::AgentMlsLeafBindingMismatch)
        }
        "invalid_leaf_signature_is_rejected" => Some(AdmissionRejection::LeafSignatureInvalid),
        _ => None,
    }
}

pub fn run_agent_mls_keypackage_authorization_suite()
-> Result<AgentMlsKeypackageAuthorizationExecution> {
    let fixture = load_fixture()?;
    ensure!(fixture.profile == "ak.profile.agent_runtime.v1");
    ensure!(!fixture.version.trim().is_empty());
    ensure!(fixture.suite == "agent_mls_keypackage_authorization");
    ensure!(fixture.runner.kind == "named_suite");
    ensure!(fixture.runner.entrypoint == AGENT_MLS_KEYPACKAGE_AUTHORIZATION_ENTRYPOINT);
    ensure!(fixture.covers_vectors == [VECTOR_ID]);
    ensure!(fixture.cases.len() == 8);

    let mut sink = EncryptionSink::default();
    let mut results = Vec::with_capacity(fixture.cases.len());
    for case in &fixture.cases {
        ensure!(
            case.covers_decision_points
                == ["AK-SDK-009/keypackage_did_authorization_precedes_encryption"]
        );
        let before = sink.encrypted_cases.clone();
        let outcome = admit_and_encrypt(case, &mut sink);
        let expected_accept = case.expected.decision == "accepted";
        ensure!(
            expected_accept == (case.name == "current_agent_authorization_is_accepted"),
            "unknown or misclassified fixture case {}",
            case.name
        );
        ensure!(
            expected_accept || case.expected.decision == "rejected",
            "unknown decision in {}",
            case.name
        );
        ensure!(
            outcome.is_ok() == expected_accept,
            "{} produced {outcome:?}, expected {}",
            case.name,
            case.expected.decision
        );
        ensure!(
            outcome.as_ref().err().copied() == expected_rejection(&case.name),
            "{} reached the wrong rejection branch: {outcome:?}",
            case.name
        );
        if expected_accept {
            ensure!(case.expected.encryption_may_proceed == Some(true));
            ensure!(sink.encrypted_cases.len() == before.len() + 1);
            ensure!(sink.encrypted_cases.last() == Some(&case.name));
        } else {
            ensure!(case.expected.encryption_attempted == Some(false));
            ensure!(sink.encrypted_cases == before, "{} changed sink", case.name);
        }
        results.push(CaseExecutionResult {
            case_id: case.name.clone(),
            assertions: case.covers_decision_points.len() + 3,
            accepted_effects: usize::from(expected_accept),
            rejected_zero_effects: usize::from(!expected_accept),
        });
    }
    ensure!(sink.encrypted_cases.len() == 1);
    Ok(AgentMlsKeypackageAuthorizationExecution {
        entrypoint: AGENT_MLS_KEYPACKAGE_AUTHORIZATION_ENTRYPOINT,
        fixture: FIXTURE,
        accepted_effects: sink.encrypted_cases.len(),
        rejected_zero_effects: results.iter().map(|case| case.rejected_zero_effects).sum(),
        cases: results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_all_fixture_cases_through_production_binding() {
        let result = run_agent_mls_keypackage_authorization_suite().unwrap();
        assert_eq!(result.cases.len(), 8);
        assert_eq!(result.accepted_effects, 1);
        assert_eq!(result.rejected_zero_effects, 7);
        assert!(result.cases.iter().all(|case| case.assertions >= 4));
    }

    #[test]
    fn each_negative_branch_leaves_the_encryption_sink_unchanged() {
        let fixture = load_fixture().unwrap();
        for case in fixture
            .cases
            .iter()
            .filter(|case| case.expected.decision == "rejected")
        {
            let mut sink = EncryptionSink {
                encrypted_cases: vec!["sentinel".to_owned()],
            };
            let before = sink.encrypted_cases.clone();
            assert!(admit_and_encrypt(case, &mut sink).is_err(), "{}", case.name);
            assert_eq!(sink.encrypted_cases, before, "{}", case.name);
        }
    }
}
