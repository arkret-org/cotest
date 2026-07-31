//! Executable conformance suite for ordinary-Realm Native Agent signer evidence.
//!
//! This runner consumes the normative spec fixture and exercises every named
//! positive/negative case against the public SDK APIs.  Merely finding the
//! fixture or deserializing its DTOs is not considered conformance.

use anyhow::{Context, Result, bail};
use arkret_models_collaboration::agent_signer_evidence::{
    AGENT_KEY_COMPONENT, AgentAuthorizationEvidence, AgentAuthorizationStateWitness,
    AgentAuthorizationStatus, AgentAuthorizationTransitionWitness,
    AgentEvidenceFreshnessAttestation, AgentEvidenceSourceProof, AgentSignerEvidence,
    AgentSigningKeyBinding,
};
use arkret_policy::{
    AgentMlsSignerClaim, AgentMlsSignerView, AuthorGroupStateView, AuthorLeaf,
    AuthorLeafCredential, verify_ordinary_agent_mls_binding,
};
use arkret_signatures::PublicKeyMaterial;
use arkret_signatures::agent_evidence::{
    AgentEvidenceRejectedReason, AgentEvidenceUnresolvedReason,
    AgentSignerEvidenceValidationContext, AgentSignerEvidenceVerdict, SignerPrincipalKind,
    SignerRegime, agent_authorization_cell_ref, agent_signing_key_binding_digest,
    agent_signing_key_binding_signing_bytes, dispatch_signer_regime,
    validate_agent_signer_evidence, verify_agent_signing_key_binding,
    verify_event_signer_controller,
};
use arkret_wire::{
    CellRef, Did, DidUrl, Event, EventId, Hash, Hlc, NonEmptyString, RealmId, SchemaId, Seal,
};
use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;

use super::{fixture_runner_entrypoint, load_fixture_value, validate_profile};

pub const AGENT_SIGNER_EVIDENCE_FIXTURE: &str = "agent-signer-evidence-fixture.json";
pub const AGENT_SIGNER_EVIDENCE_SUITE: &str = "ak.suite.agent.signer_evidence.v1";

pub const ALL_AGENT_SIGNER_EVIDENCE_CASES: &[&str] = &[
    "native_agent_active_at_admission_and_matching_leaf",
    "delegated_agent_keeps_actor_in_proof_transcript",
    "stale_freshness_is_unresolved",
    "superseded_old_key_new_event_is_rejected",
    "historical_event_before_rotation_remains_verified",
    "method_fragment_mismatch_is_rejected",
    "duplicate_agent_leaf_is_rejected",
    "applet_does_not_enter_agent_regime",
    "minimal_metadata_forbids_agent_query",
    "binding_controller_mismatch_is_rejected",
    "binding_public_key_digest_mismatch_is_rejected",
    "binding_controller_proof_invalid_is_rejected",
    "binding_agent_key_id_mismatch_is_rejected",
    "state_witness_agent_mismatch_is_rejected",
    "state_witness_authorization_ref_mismatch_is_rejected",
    "state_witness_frontier_mismatch_is_rejected",
    "freshness_signature_invalid_is_rejected",
    "freshness_frontier_conflict_is_rejected",
    "cache_frontier_rollback_is_unresolved",
    "revoked_historical_event_inside_interval_remains_verified",
    "revoked_old_key_new_event_is_rejected",
    "historical_transition_witness_missing_is_rejected",
    "historical_transition_witness_event_mismatch_is_rejected",
    "expired_event_at_boundary_is_rejected",
    "missing_agent_leaf_is_rejected",
    "agent_leaf_signature_key_mismatch_is_rejected",
    "agent_leaf_authorization_ref_mismatch_is_rejected",
    "wrong_mls_epoch_is_rejected",
    "non_winning_group_state_is_rejected",
    "high_assurance_missing_transparency_is_unresolved",
    "unknown_principal_does_not_enter_agent_regime",
    "ordinary_device_does_not_enter_agent_regime",
];

#[derive(Clone)]
struct ValidationInputs {
    signer_id: Did,
    agent_key_id: NonEmptyString,
    authorization_realm_id: RealmId,
    controller_id: Did,
    verification_method: DidUrl,
    authorization_event_id: EventId,
    public_key_digest: Hash,
    binding_digest: Hash,
    event_accepted_frontier: NonEmptyString,
    event_accepted_at: DateTime<Utc>,
    now: DateTime<Utc>,
    controller_key: PublicKeyMaterial,
    seal_lineage_signatures_verified: bool,
    freshness_signature_verified: bool,
    require_transparency: bool,
    transparency_verified: bool,
}

impl ValidationInputs {
    fn from_fixture(
        binding: &AgentSigningKeyBinding,
        evidence: &AgentSignerEvidence,
        controller_key: PublicKeyMaterial,
    ) -> Self {
        Self {
            signer_id: binding.agent_id.clone(),
            agent_key_id: binding.agent_key_id.clone(),
            authorization_realm_id: RealmId::new("ak:realm:01964137-0000-7000-8000-000000000007")
                .unwrap(),
            controller_id: binding.controller_id.clone(),
            verification_method: binding.verification_method.clone(),
            authorization_event_id: binding.agent_key_authorize_event_id.clone(),
            public_key_digest: binding.public_key_digest.clone(),
            binding_digest: agent_signing_key_binding_digest(binding)
                .expect("normative binding digest must be valid"),
            event_accepted_frontier: evidence.state_witness.accepted_frontier.clone(),
            event_accepted_at: Utc.with_ymd_and_hms(2026, 7, 25, 0, 1, 0).unwrap(),
            now: Utc.with_ymd_and_hms(2026, 7, 25, 0, 2, 0).unwrap(),
            controller_key,
            seal_lineage_signatures_verified: true,
            freshness_signature_verified: true,
            require_transparency: false,
            transparency_verified: false,
        }
    }

    fn validate(&self, evidence: Option<&AgentSignerEvidence>) -> AgentSignerEvidenceVerdict {
        validate_agent_signer_evidence(
            evidence,
            &AgentSignerEvidenceValidationContext {
                signer_id: &self.signer_id,
                agent_key_id: &self.agent_key_id,
                authorization_realm_id: &self.authorization_realm_id,
                controller_id: &self.controller_id,
                verification_method: &self.verification_method,
                agent_key_authorize_event_id: &self.authorization_event_id,
                authorize_public_key_digest: &self.public_key_digest,
                authorize_signing_key_binding_digest: &self.binding_digest,
                event_accepted_frontier: &self.event_accepted_frontier,
                event_accepted_at: self.event_accepted_at,
                now: self.now,
                controller_public_key: &self.controller_key,
                seal_lineage_signatures_verified: self.seal_lineage_signatures_verified,
                freshness_signature_verified: self.freshness_signature_verified,
                require_transparency: self.require_transparency,
                transparency_verified: self.transparency_verified,
            },
        )
    }
}

pub fn run_agent_signer_evidence_vector_suite() -> Result<()> {
    let fixture = load_fixture_value(AGENT_SIGNER_EVIDENCE_FIXTURE)?;
    validate_profile(&fixture, "ak.profile.agent_signer_evidence.v1")?;
    if fixture_runner_entrypoint(&fixture)? != AGENT_SIGNER_EVIDENCE_SUITE {
        bail!("Agent signer-evidence fixture runner entrypoint drifted");
    }

    let binding_vector = fixture
        .get("binding_vector")
        .and_then(Value::as_object)
        .context("Agent signer-evidence fixture missing binding_vector")?;
    let binding: AgentSigningKeyBinding = serde_json::from_value(
        binding_vector
            .get("binding")
            .cloned()
            .context("binding_vector.binding missing")?,
    )?;
    let controller_key = PublicKeyMaterial::Ed25519Raw {
        bytes: arkret_canonical::base64url_decode(
            binding_vector
                .get("controller_public_key")
                .and_then(Value::as_str)
                .context("binding_vector.controller_public_key missing")?,
        )?,
    };
    verify_byte_exact_binding(binding_vector, &binding, &controller_key)?;

    let case_values = fixture
        .get("cases")
        .and_then(Value::as_array)
        .context("Agent signer-evidence fixture cases missing")?;
    let case_names = case_values
        .iter()
        .map(|case| {
            case.get("name")
                .and_then(Value::as_str)
                .context("Agent signer-evidence case missing name")
        })
        .collect::<Result<Vec<_>>>()?;
    if case_names != ALL_AGENT_SIGNER_EVIDENCE_CASES {
        bail!(
            "Agent signer-evidence case registry drifted: expected {:?}, got {:?}",
            ALL_AGENT_SIGNER_EVIDENCE_CASES,
            case_names
        );
    }

    let base_evidence = fixture_evidence(binding.clone());
    let inputs = ValidationInputs::from_fixture(&binding, &base_evidence, controller_key);
    for case in case_values {
        run_case(
            case.get("name").and_then(Value::as_str).unwrap(),
            case,
            &binding,
            &base_evidence,
            &inputs,
        )?;
    }
    Ok(())
}

fn verify_byte_exact_binding(
    vector: &serde_json::Map<String, Value>,
    binding: &AgentSigningKeyBinding,
    controller_key: &PublicKeyMaterial,
) -> Result<()> {
    let signing_bytes = agent_signing_key_binding_signing_bytes(binding)
        .map_err(|reason| anyhow::anyhow!(reason.as_str()))?;
    let expected_signing_bytes = arkret_canonical::base64url_decode(
        vector
            .get("signing_input_base64url")
            .and_then(Value::as_str)
            .context("binding_vector.signing_input_base64url missing")?,
    )?;
    if signing_bytes != expected_signing_bytes {
        bail!("Agent signing-key binding signing bytes drifted");
    }
    let context = b"ak.agent-signing-key-binding-v1\n";
    let expected_canonical = vector
        .get("canonical_without_jws")
        .and_then(Value::as_str)
        .context("binding_vector.canonical_without_jws missing")?
        .as_bytes();
    if signing_bytes.strip_prefix(context) != Some(expected_canonical) {
        bail!("Agent signing-key binding canonical JSON drifted");
    }
    let digest = agent_signing_key_binding_digest(binding)
        .map_err(|reason| anyhow::anyhow!(reason.as_str()))?;
    if Some(digest.as_str()) != vector.get("binding_digest").and_then(Value::as_str) {
        bail!("Agent signing-key binding digest drifted");
    }
    verify_agent_signing_key_binding(
        binding,
        &binding.agent_id,
        &binding.agent_key_id,
        &binding.controller_id,
        &binding.verification_method,
        &binding.agent_key_authorize_event_id,
        &binding.public_key_digest,
        &digest,
        controller_key,
    )
    .map_err(|reason| anyhow::anyhow!(reason.as_str()))?;
    Ok(())
}

fn fixture_evidence(binding: AgentSigningKeyBinding) -> AgentSignerEvidence {
    let cell_ref = agent_authorization_cell_ref(&binding.agent_id, &binding.agent_key_id).unwrap();
    let binding_digest = agent_signing_key_binding_digest(&binding).unwrap();
    let cell_value = serde_json::json!({
        "tag": binding.agent_key_authorize_event_id,
        "value": {
            "agent_id": binding.agent_id,
            "key_id": binding.agent_key_id,
            "verification_method": binding.verification_method,
            "public_key_digest": binding.public_key_digest,
            "signing_key_binding_digest": binding_digest
        }
    });
    let leaf_digest = arkret_state::state_value_leaf_digest(
        &CellRef::new(cell_ref.as_str().to_owned()).unwrap(),
        &cell_value,
    )
    .unwrap();
    let authorization_seal =
        fixture_seal(leaf_digest.clone(), "01970e589d21-0004-a13f9c2e", vec![]);
    let authorization_frontier =
        NonEmptyString::new(authorization_seal.id.as_str().to_owned()).unwrap();
    AgentSignerEvidence {
        schema: NonEmptyString::new(SchemaId::AGENT_SIGNER_EVIDENCE_V1.to_owned()).unwrap(),
        authorization: AgentAuthorizationEvidence {
            status: AgentAuthorizationStatus::Active,
            authorized_event_id: binding.agent_key_authorize_event_id.clone(),
            accepted_frontier: authorization_frontier.clone(),
            accepted_at: Utc.with_ymd_and_hms(2026, 7, 25, 0, 0, 0).unwrap(),
            valid_from_frontier: authorization_frontier.clone(),
            not_before: Utc.with_ymd_and_hms(2026, 7, 25, 0, 0, 0).unwrap(),
            valid_until_frontier: None,
            expires_at: None,
            transition_event_id: None,
        },
        state_witness: AgentAuthorizationStateWitness {
            component: NonEmptyString::new(AGENT_KEY_COMPONENT.to_owned()).unwrap(),
            agent_id: binding.agent_id.clone(),
            authorization_event_id: binding.agent_key_authorize_event_id.clone(),
            accepted_frontier: authorization_frontier,
            seal_id: authorization_seal.id.clone(),
            state_root: authorization_seal.state_root.clone(),
            seal: authorization_seal.clone(),
            cell_ref,
            cell_value,
            leaf_digest,
            leaf_index: 0,
            leaf_count: 1,
            inclusion_proof: vec![],
        },
        transition_witness: None,
        seal_lineage: vec![authorization_seal.clone()],
        freshness_attestation: AgentEvidenceFreshnessAttestation {
            source_service_id: Did::new("did:webvh:z6mkservice:service.example").unwrap(),
            observed_frontier: NonEmptyString::new(authorization_seal.id.as_str().to_owned())
                .unwrap(),
            issued_at: Utc.with_ymd_and_hms(2026, 7, 25, 0, 1, 0).unwrap(),
            expires_at: Utc.with_ymd_and_hms(2026, 7, 25, 0, 3, 0).unwrap(),
            source_proof: AgentEvidenceSourceProof {
                kind: NonEmptyString::new("detached_jws".to_owned()).unwrap(),
                verification_method: DidUrl::new(
                    "did:webvh:z6mkservice:service.example#notary-key",
                )
                .unwrap(),
                jws: NonEmptyString::new("fixture-signature".to_owned()).unwrap(),
            },
        },
        signing_key_binding: binding,
        transparency: None,
    }
}

fn fixture_hash(byte: char) -> Hash {
    Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
}

fn fixture_seal(state_root: Hash, hlc: &str, predecessor_refs: Vec<arkret_wire::SealId>) -> Seal {
    let notary_id = Did::new("did:webvh:z6mkservice:service.example").unwrap();
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        [24; 32],
        notary_id.clone(),
        crate::fixture_did_url(format!("{notary_id}#notary-key")),
    );
    Seal::sign_single(
        RealmId::new("ak:realm:01964137-0000-7000-8000-000000000007").unwrap(),
        predecessor_refs,
        vec![],
        state_root,
        Hlc::new(hlc).unwrap(),
        &signer,
    )
    .unwrap()
}

fn transition_evidence(
    base: &AgentSignerEvidence,
    status: AgentAuthorizationStatus,
) -> AgentSignerEvidence {
    let mut evidence = base.clone();
    evidence.authorization.status = status;
    evidence.authorization.transition_event_id =
        Some(EventId::new("ak:event:01964137-0000-7000-8000-000000000011").unwrap());
    let transition_event_id = evidence.authorization.transition_event_id.clone().unwrap();
    let transition_key_id = evidence.signing_key_binding.agent_key_id.clone();
    let cell_ref =
        agent_authorization_cell_ref(&evidence.signing_key_binding.agent_id, &transition_key_id)
            .unwrap();
    let cell_value = serde_json::json!({
        "tag": transition_event_id,
        "value": {
            "key_id": transition_key_id
        }
    });
    let leaf_digest = arkret_state::state_value_leaf_digest(
        &CellRef::new(cell_ref.as_str().to_owned()).unwrap(),
        &cell_value,
    )
    .unwrap();
    let transition_seal = fixture_seal(
        leaf_digest.clone(),
        "01970e589d21-0005-a13f9c2e",
        vec![base.state_witness.seal.id.clone()],
    );
    let transition_frontier = NonEmptyString::new(transition_seal.id.as_str().to_owned()).unwrap();
    evidence.authorization.valid_until_frontier = Some(transition_frontier.clone());
    evidence.transition_witness = Some(AgentAuthorizationTransitionWitness {
        component: NonEmptyString::new(AGENT_KEY_COMPONENT.to_owned()).unwrap(),
        agent_id: evidence.signing_key_binding.agent_id.clone(),
        authorization_event_id: evidence
            .signing_key_binding
            .agent_key_authorize_event_id
            .clone(),
        transition_event_id: transition_event_id.clone(),
        transition_key_id: transition_key_id.clone(),
        accepted_frontier: transition_frontier,
        seal_id: transition_seal.id.clone(),
        state_root: transition_seal.state_root.clone(),
        seal: transition_seal.clone(),
        cell_ref,
        cell_value,
        leaf_digest,
        leaf_index: 0,
        leaf_count: 1,
        inclusion_proof: vec![],
    });
    evidence.seal_lineage.push(transition_seal.clone());
    evidence.freshness_attestation.observed_frontier =
        NonEmptyString::new(transition_seal.id.as_str().to_owned()).unwrap();
    evidence
}

fn assert_verdict(
    name: &str,
    actual: AgentSignerEvidenceVerdict,
    expected: AgentSignerEvidenceVerdict,
) -> Result<()> {
    if actual != expected {
        bail!("{name}: expected {expected:?}, got {actual:?}");
    }
    Ok(())
}

fn assert_verified(name: &str, actual: AgentSignerEvidenceVerdict) -> Result<()> {
    if !matches!(actual, AgentSignerEvidenceVerdict::Verified(_)) {
        bail!("{name}: expected Verified, got {actual:?}");
    }
    Ok(())
}

fn run_case(
    name: &str,
    case: &Value,
    binding: &AgentSigningKeyBinding,
    base: &AgentSignerEvidence,
    inputs: &ValidationInputs,
) -> Result<()> {
    match name {
        "native_agent_active_at_admission_and_matching_leaf" => {
            assert_verified(name, inputs.validate(Some(base)))?;
            let (view, key) = mls_fixture(binding, 1);
            verify_mls_fixture(&view, binding, &key)?;
        }
        "delegated_agent_keeps_actor_in_proof_transcript" => {
            let actor = Did::new(
                case.get("actor_id")
                    .and_then(Value::as_str)
                    .context("delegated case actor_id missing")?,
            )?;
            let signer = Did::new(
                case.get("executed_by")
                    .and_then(Value::as_str)
                    .context("delegated case executed_by missing")?,
            )?;
            let mut event = Event::new(
                arkret_wire::EventKind::MESSAGE_CREATE,
                arkret_wire::ScopeRef::Realm {
                    realm_id: RealmId::new("ak:realm:01964137-0000-7000-8000-000000000009")?,
                },
                actor.clone(),
                1,
                arkret_wire::Hlc::new("01970e589d21-0004-a13f9c2e")?,
                serde_json::json!({}),
            )?;
            event.executed_by = Some(signer.clone());
            let result = verify_event_signer_controller(&event, &binding.verification_method)
                .map_err(|reason| anyhow::anyhow!(reason.as_str()))?;
            if result.binding_actor_id != actor || result.signer_id != signer {
                bail!("{name}: actor/signer transcript binding drifted");
            }
        }
        "stale_freshness_is_unresolved" => {
            let mut context = inputs.clone();
            context.now = base.freshness_attestation.expires_at;
            assert_verdict(
                name,
                context.validate(Some(base)),
                AgentSignerEvidenceVerdict::Unresolved(AgentEvidenceUnresolvedReason::Stale),
            )?;
        }
        "superseded_old_key_new_event_is_rejected" => {
            let evidence = transition_evidence(base, AgentAuthorizationStatus::Superseded);
            let mut context = inputs.clone();
            context.event_accepted_frontier = evidence
                .transition_witness
                .as_ref()
                .unwrap()
                .accepted_frontier
                .clone();
            assert_verdict(
                name,
                context.validate(Some(&evidence)),
                AgentSignerEvidenceVerdict::Rejected(
                    AgentEvidenceRejectedReason::AuthorizationInactive,
                ),
            )?;
        }
        "historical_event_before_rotation_remains_verified" => {
            let evidence = transition_evidence(base, AgentAuthorizationStatus::Superseded);
            assert_verified(name, inputs.validate(Some(&evidence)))?;
        }
        "method_fragment_mismatch_is_rejected" => {
            let mut context = inputs.clone();
            context.verification_method =
                DidUrl::new("did:webvh:z6mkagent:agent.example#runtime-2")
                    .map_err(anyhow::Error::msg)?;
            assert_signing_key_rejected(name, context.validate(Some(base)))?;
        }
        "duplicate_agent_leaf_is_rejected" => {
            let (view, key) = mls_fixture(binding, 2);
            if verify_mls_fixture(&view, binding, &key).is_ok() {
                bail!("{name}: duplicate Agent leaf was accepted");
            }
        }
        "applet_does_not_enter_agent_regime" => {
            if dispatch_signer_regime(false, SignerPrincipalKind::Applet)
                == Ok(SignerRegime::OrdinaryNativeAgent)
            {
                bail!("{name}: Applet entered Native Agent regime");
            }
        }
        "minimal_metadata_forbids_agent_query" => {
            if dispatch_signer_regime(true, SignerPrincipalKind::NativeAgent)
                != Ok(SignerRegime::MinimalMetadata)
                || case.get("agent_evidence_queries").and_then(Value::as_u64) != Some(0)
                || case.get("device_directory_queries").and_then(Value::as_u64) != Some(0)
            {
                bail!("{name}: minimal-metadata dispatch/query invariant drifted");
            }
        }
        "binding_controller_mismatch_is_rejected" => {
            let mut evidence = base.clone();
            evidence.signing_key_binding.controller_id =
                Did::new("did:webvh:z6mkother:controller.example")?;
            assert_signing_key_rejected(name, inputs.validate(Some(&evidence)))?;
        }
        "binding_public_key_digest_mismatch_is_rejected" => {
            let mut evidence = base.clone();
            evidence.signing_key_binding.public_key_digest = fixture_hash('a');
            assert_signing_key_rejected(name, inputs.validate(Some(&evidence)))?;
        }
        "binding_controller_proof_invalid_is_rejected" => {
            let mut evidence = base.clone();
            evidence.signing_key_binding.controller_proof.jws =
                NonEmptyString::new("invalid.detached.jws".to_owned())
                    .map_err(anyhow::Error::msg)?;
            assert_signing_key_rejected(name, inputs.validate(Some(&evidence)))?;
        }
        "binding_agent_key_id_mismatch_is_rejected" => {
            let mut context = inputs.clone();
            context.agent_key_id =
                NonEmptyString::new("did:webvh:z6mkagent:agent.example#runtime-2".to_owned())
                    .map_err(anyhow::Error::msg)?;
            assert_signing_key_rejected(name, context.validate(Some(base)))?;
        }
        "state_witness_agent_mismatch_is_rejected" => {
            let mut evidence = base.clone();
            evidence.state_witness.agent_id = Did::new("did:webvh:z6mkother:agent.example")?;
            assert_signing_key_rejected(name, inputs.validate(Some(&evidence)))?;
        }
        "state_witness_authorization_ref_mismatch_is_rejected" => {
            let mut evidence = base.clone();
            evidence.state_witness.authorization_event_id =
                EventId::new("ak:event:01964137-0000-7000-8000-000000000099")?;
            assert_signing_key_rejected(name, inputs.validate(Some(&evidence)))?;
        }
        "state_witness_frontier_mismatch_is_rejected" => {
            let mut evidence = base.clone();
            evidence.state_witness.accepted_frontier =
                NonEmptyString::new("agent-key-frontier:9".to_owned())
                    .map_err(anyhow::Error::msg)?;
            assert_signing_key_rejected(name, inputs.validate(Some(&evidence)))?;
        }
        "freshness_signature_invalid_is_rejected" => {
            let mut context = inputs.clone();
            context.freshness_signature_verified = false;
            assert_signing_key_rejected(name, context.validate(Some(base)))?;
        }
        "freshness_frontier_conflict_is_rejected" => {
            let mut evidence = base.clone();
            evidence.seal_lineage.push(fixture_seal(
                fixture_hash('8'),
                "01970e589d21-0006-a13f9c2e",
                vec![],
            ));
            assert_verdict(
                name,
                inputs.validate(Some(&evidence)),
                AgentSignerEvidenceVerdict::Rejected(
                    AgentEvidenceRejectedReason::AuthorizationConflicted,
                ),
            )?;
        }
        "cache_frontier_rollback_is_unresolved" => {
            let mut stale = base.clone();
            stale.freshness_attestation.expires_at = inputs.now;
            assert_verdict(
                name,
                inputs.validate(Some(&stale)),
                AgentSignerEvidenceVerdict::Unresolved(AgentEvidenceUnresolvedReason::Stale),
            )?;
        }
        "revoked_historical_event_inside_interval_remains_verified" => {
            let evidence = transition_evidence(base, AgentAuthorizationStatus::Revoked);
            assert_verified(name, inputs.validate(Some(&evidence)))?;
        }
        "revoked_old_key_new_event_is_rejected" => {
            let evidence = transition_evidence(base, AgentAuthorizationStatus::Revoked);
            let mut context = inputs.clone();
            context.event_accepted_frontier = evidence
                .transition_witness
                .as_ref()
                .unwrap()
                .accepted_frontier
                .clone();
            assert_verdict(
                name,
                context.validate(Some(&evidence)),
                AgentSignerEvidenceVerdict::Rejected(
                    AgentEvidenceRejectedReason::AuthorizationInactive,
                ),
            )?;
        }
        "historical_transition_witness_missing_is_rejected" => {
            let mut evidence = transition_evidence(base, AgentAuthorizationStatus::Superseded);
            evidence.transition_witness = None;
            assert_verdict(
                name,
                inputs.validate(Some(&evidence)),
                AgentSignerEvidenceVerdict::Rejected(
                    AgentEvidenceRejectedReason::AuthorizationInactive,
                ),
            )?;
        }
        "historical_transition_witness_event_mismatch_is_rejected" => {
            let mut evidence = transition_evidence(base, AgentAuthorizationStatus::Revoked);
            evidence
                .transition_witness
                .as_mut()
                .unwrap()
                .transition_event_id =
                EventId::new("ak:event:01964137-0000-7000-8000-000000000099")?;
            assert_signing_key_rejected(name, inputs.validate(Some(&evidence)))?;
        }
        "expired_event_at_boundary_is_rejected" => {
            let mut evidence = base.clone();
            evidence.authorization.status = AgentAuthorizationStatus::Expired;
            evidence.authorization.expires_at =
                Some(Utc.with_ymd_and_hms(2026, 7, 25, 0, 1, 0).unwrap());
            assert_verdict(
                name,
                inputs.validate(Some(&evidence)),
                AgentSignerEvidenceVerdict::Rejected(
                    AgentEvidenceRejectedReason::AuthorizationInactive,
                ),
            )?;
        }
        "missing_agent_leaf_is_rejected" => {
            let (view, key) = mls_fixture(binding, 0);
            if verify_mls_fixture(&view, binding, &key).is_ok() {
                bail!("{name}: missing Agent leaf was accepted");
            }
        }
        "agent_leaf_signature_key_mismatch_is_rejected" => {
            let (mut view, key) = mls_fixture(binding, 1);
            view.group_state.active_leaves[0].signature_key = vec![9; 32];
            if verify_mls_fixture(&view, binding, &key).is_ok() {
                bail!("{name}: mismatched Agent leaf key was accepted");
            }
        }
        "agent_leaf_authorization_ref_mismatch_is_rejected" => {
            let (mut view, key) = mls_fixture(binding, 1);
            view.leaf_authorization_refs[0].1 =
                EventId::new("ak:event:01964137-0000-7000-8000-000000000099")?;
            if verify_mls_fixture(&view, binding, &key).is_ok() {
                bail!("{name}: mismatched Agent leaf authorization lineage was accepted");
            }
        }
        "wrong_mls_epoch_is_rejected" => {
            let (mut view, key) = mls_fixture(binding, 1);
            view.group_state.epoch += 1;
            if verify_mls_fixture(&view, binding, &key).is_ok() {
                bail!("{name}: wrong MLS epoch was accepted");
            }
        }
        "non_winning_group_state_is_rejected" => {
            let (mut view, key) = mls_fixture(binding, 1);
            view.group_state.group_state_ref =
                "ak:event:01964137-0000-7000-8000-000000000005".to_owned();
            if verify_mls_fixture(&view, binding, &key).is_ok() {
                bail!("{name}: non-winning MLS group state was accepted");
            }
        }
        "high_assurance_missing_transparency_is_unresolved" => {
            let mut context = inputs.clone();
            context.require_transparency = true;
            assert_verdict(
                name,
                context.validate(Some(base)),
                AgentSignerEvidenceVerdict::Unresolved(AgentEvidenceUnresolvedReason::Missing),
            )?;
        }
        "unknown_principal_does_not_enter_agent_regime" => {
            if dispatch_signer_regime(false, SignerPrincipalKind::Unknown).is_ok() {
                bail!("{name}: unknown principal entered a signer regime");
            }
        }
        "ordinary_device_does_not_enter_agent_regime" => {
            if dispatch_signer_regime(false, SignerPrincipalKind::Device)
                != Ok(SignerRegime::OrdinaryDevice)
                || case.get("agent_evidence_queries").and_then(Value::as_u64) != Some(0)
            {
                bail!("{name}: ordinary device entered Agent regime");
            }
        }
        other => bail!("unimplemented Agent signer-evidence vector case {other}"),
    }
    Ok(())
}

fn assert_signing_key_rejected(name: &str, actual: AgentSignerEvidenceVerdict) -> Result<()> {
    assert_verdict(
        name,
        actual,
        AgentSignerEvidenceVerdict::Rejected(AgentEvidenceRejectedReason::SigningKeyMismatch),
    )
}

fn mls_fixture(
    binding: &AgentSigningKeyBinding,
    matching_leaf_count: usize,
) -> (AgentMlsSignerView, Vec<u8>) {
    let key = arkret_canonical::base64url_decode(binding.public_key.key.as_str()).unwrap();
    let active_leaves = (0..matching_leaf_count)
        .map(|index| AuthorLeaf {
            leaf_index: index as u32 + 1,
            credential: AuthorLeafCredential::Basic {
                identity: binding.agent_id.as_str().as_bytes().to_vec(),
            },
            signature_key: key.clone(),
        })
        .collect::<Vec<_>>();
    let leaf_authorization_refs = active_leaves
        .iter()
        .map(|leaf| {
            (
                leaf.leaf_index,
                binding.agent_key_authorize_event_id.clone(),
            )
        })
        .collect();
    (
        AgentMlsSignerView {
            group_state: AuthorGroupStateView {
                group_id: "group".to_owned(),
                epoch: 4,
                group_state_ref: "ak:event:01964137-0000-7000-8000-000000000004".to_owned(),
                active_leaves,
            },
            leaf_authorization_refs,
        },
        key,
    )
}

fn verify_mls_fixture(
    view: &AgentMlsSignerView,
    binding: &AgentSigningKeyBinding,
    key: &[u8],
) -> Result<u32> {
    verify_ordinary_agent_mls_binding(
        view,
        &AgentMlsSignerClaim {
            group_id: "group",
            epoch: 4,
            group_state_ref: "ak:event:01964137-0000-7000-8000-000000000004",
            signer_id: &binding.agent_id,
            signing_key: key,
            agent_key_authorize_event_id: &binding.agent_key_authorize_event_id,
        },
    )
    .map_err(Into::into)
}
