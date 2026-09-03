//! Executable current/historical Agent signer-evidence conformance.
//!
//! Fixture labels are only the closed registry. Every case below exercises the
//! SDK-owned state verifier, current validator, historical validator, or signer
//! regime dispatcher against cryptographically signed evidence.

use anyhow::{Context, Result, anyhow, bail};
use arkret_models_identity::agent_signer_evidence::{
    AGENT_KEY_COMPONENT, AGENT_STATUS_COMPONENT, AgentAdmissionEvidence, AgentAuthoritySnapshot,
    AgentAuthoritySnapshotCore, AgentAuthorizationEvidence, AgentAuthorizationStateWitness,
    AgentAuthorizationStatus, AgentCurrentObservation, AgentDetachedJws,
    AgentEventAdmissionReceipt, AgentEvidenceOuterAttestation,
    AgentHistoricalEvidenceOuterAttestation, AgentKeyCellEntry, AgentLifecycleProvenance,
    AgentLifecycleStatus, AgentLifecycleWitness, AgentSignerEvidence, AgentSigningPublicKey,
    AgentSnapshotLease, ControllerAccountEligibility, ControllerAccountGateAttestation,
    ControllerAccountGateBasis, ControllerAccountStatus,
};
use arkret_signatures::agent_evidence::{
    AgentEvidenceCommonContext, AgentEvidenceRejectedReason, AgentEvidenceStateVerificationContext,
    AgentSignerEvidenceVerdict, CurrentAgentSignerEvidenceValidationContext,
    HistoricalAgentSignerEvidenceValidationContext, SignerPrincipalKind, SignerRegime,
    agent_authorization_cell_ref, agent_signing_key_binding_digest,
    agent_signing_public_key_digest, agent_signing_public_key_runtime_request_digest,
    build_agent_signing_key_binding, dispatch_signer_regime,
    validate_current_agent_signer_evidence, validate_historical_agent_signer_evidence,
    verify_agent_evidence_state,
};
use arkret_signatures::{PublicKeyMaterial, sign_ed25519_detached_jws};
use arkret_wire::{
    AccountId, ActorId, Base64UrlString, Did, DidCoreId, DidUrl, DomainSeparationId, EventId,
    EventKind, Hash, Hlc, NonEmptyString, NotarySig, ProtocolOperationId, RealmId, SchemaId,
    ScopeRef, Seal, SealId, SealSignature, SignerEvidenceRef, project_did_to_core_id,
};
use chrono::{DateTime, Duration, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::load_fixture_value;

pub const AGENT_SIGNER_EVIDENCE_FIXTURE: &str = "agent-signer-evidence-fixture.json";
pub const AGENT_SIGNER_EVIDENCE_SUITE: &str = "ak.suite.agent.signer_evidence.v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentSignerEvidenceFixture {
    profile: String,
    version: String,
    suite: String,
    runner: Value,
    covers_vectors: Vec<String>,
    binding_vector: Value,
    cases: Vec<Value>,
}

pub const ALL_AGENT_SIGNER_EVIDENCE_CASES: &[&str] = &[
    "query_success_returns_cas_frozen_authenticated_root",
    "current_exact_request_and_three_active_gates_verified",
    "current_cross_verifier_replay_rejected",
    "current_request_or_challenge_replay_rejected",
    "current_snapshot_digest_mix_and_match_rejected",
    "current_stale_lease_is_unresolved",
    "current_paused_agent_rejected",
    "current_inactive_controller_account_rejected",
    "current_revoked_or_superseded_key_rejected",
    "historical_destination_receipt_preserves_admission",
    "historical_current_snapshot_substitution_rejected",
    "historical_wrong_destination_receipt_rejected",
    "historical_inactive_gate_at_receipt_time_rejected",
    "historical_materialization_exact_replay_is_no_op",
    "historical_materialization_same_tuple_other_receipt_is_zero_overwrite",
    "historical_materialization_same_tuple_other_root_is_zero_overwrite",
    "historical_materialization_other_receiver_service_is_a_distinct_branch",
    "historical_materialization_incomplete_dependency_closure_publishes_no_root",
    "historical_materialization_lost_receipt_is_never_reminted",
    "historical_outer_attestation_verifies_long_after_attested_at",
    "historical_branch_carrying_current_outer_attestation_rejected",
    "authority_key_rotation_after_attested_at_preserves_historical_root",
    "authority_method_inactive_at_attested_at_rejected",
    "receiver_key_rotation_after_accepted_at_preserves_receipt",
    "receiver_dependency_resolved_from_current_service_record_rejected",
    "receiver_key_revoked_after_accepted_at_does_not_retroact",
    "receiver_method_inactive_at_accepted_at_rejected",
    "account_gate_never_discloses_local_identity",
    "producer_fetches_controller_gate_from_account_authority",
    "controller_gate_exact_request_replay_is_byte_identical",
    "controller_gate_request_id_conflict_is_zero_issuance",
    "controller_gate_wrong_source_and_unknown_principal_are_indistinguishable",
    "controller_gate_inactive_status_is_signed_not_forged_by_producer",
    "agent_genesis_active_requires_accepted_provision_declaration",
    "organization_pcr_cannot_materialize_agent_active",
    "state_witness_uses_canonical_event_dot",
    "bare_event_id_state_tag_rejected",
    "outer_attestation_prevents_mode_splice",
    "historical_mls_leaf_cross_binding_verified",
    "duplicate_or_mismatched_mls_leaf_rejected",
    "minimal_metadata_forbids_agent_evidence_query",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutcomeClass {
    Verified,
    Unresolved,
    Rejected,
}

#[derive(Clone, Copy)]
struct EvidenceConfig {
    authorization_status: AgentAuthorizationStatus,
    lifecycle_status: AgentLifecycleStatus,
    controller_eligibility: ControllerAccountEligibility,
    controller_status: ControllerAccountStatus,
    bare_authorization_tag: bool,
    stale_snapshot_lease: bool,
}

impl Default for EvidenceConfig {
    fn default() -> Self {
        Self {
            authorization_status: AgentAuthorizationStatus::Active,
            lifecycle_status: AgentLifecycleStatus::Active,
            controller_eligibility: ControllerAccountEligibility::Active,
            controller_status: ControllerAccountStatus::Active,
            bare_authorization_tag: false,
            stale_snapshot_lease: false,
        }
    }
}

struct ExecutableEvidence {
    current: AgentSignerEvidence,
    historical: AgentSignerEvidence,
    signer_id: DidCoreId,
    signer_actor_id: ActorId,
    agent_key_id: NonEmptyString,
    controller_principal_id: DidCoreId,
    verification_method: DidUrl,
    authorize_event_id: EventId,
    authorize_public_key_digest: Hash,
    binding_digest: Hash,
    authority_id: DidCoreId,
    authority_verification_method: DidUrl,
    account_authority_id: DidCoreId,
    account_authority_verification_method: DidUrl,
    receiver_id: DidCoreId,
    receiver_verification_method: DidUrl,
    controller_public_key: [u8; 32],
    authority_public_key: [u8; 32],
    account_authority_public_key: [u8; 32],
    receiver_public_key: [u8; 32],
    operation_id: ProtocolOperationId,
    request_digest: Hash,
    verifier_id: DidCoreId,
    audience: DidCoreId,
    challenge: NonEmptyString,
    event_id: EventId,
    realm_id: RealmId,
    producer_accepted_at: DateTime<Utc>,
    producer_signer_resolution_evidence_ref: SignerEvidenceRef,
    now: DateTime<Utc>,
}

pub fn run_agent_signer_evidence_vector_suite() -> Result<()> {
    let fixture: AgentSignerEvidenceFixture =
        serde_json::from_value(load_fixture_value(AGENT_SIGNER_EVIDENCE_FIXTURE)?)?;
    if fixture.profile != "ak.profile.agent_signer_evidence.v1"
        || fixture.suite.trim().is_empty()
        || fixture.version.trim().is_empty()
        || fixture.covers_vectors.is_empty()
        || fixture.runner.get("entrypoint").and_then(Value::as_str)
            != Some(AGENT_SIGNER_EVIDENCE_SUITE)
    {
        bail!("Agent signer-evidence fixture runner entrypoint drifted");
    }
    validate_binding_requirements(&fixture)?;

    let cases = &fixture.cases;
    let names = cases
        .iter()
        .map(|case| case.get("name").and_then(Value::as_str))
        .collect::<Option<Vec<_>>>()
        .context("Agent signer-evidence case name missing")?;
    if names != ALL_AGENT_SIGNER_EVIDENCE_CASES {
        bail!("Agent signer-evidence case registry drifted");
    }

    for case in cases {
        let name = case["name"].as_str().context("case name missing")?;
        let expected = expected_class(case["expected"].as_str().context("expected missing")?)?;
        let observed = execute_case(name, case)?;
        if observed != expected {
            bail!("Agent signer-evidence case {name} expected {expected:?}, observed {observed:?}");
        }
    }
    Ok(())
}

fn expected_class(expected: &str) -> Result<OutcomeClass> {
    match expected {
        "issued" | "verified" | "verified_by_minimal_metadata_only" => Ok(OutcomeClass::Verified),
        "unresolved" => Ok(OutcomeClass::Unresolved),
        "rejected" => Ok(OutcomeClass::Rejected),
        other => bail!("open Agent signer-evidence outcome {other}"),
    }
}

fn service_id(value: &str) -> Result<DidCoreId> {
    let did = Did::new(value.to_owned())?;
    Ok(project_did_to_core_id(&did)?)
}

fn execute_case(name: &str, case: &Value) -> Result<OutcomeClass> {
    match name {
        "query_success_returns_cas_frozen_authenticated_root" => {
            current_outcome(&build_evidence(EvidenceConfig::default())?, None)
        }
        "current_exact_request_and_three_active_gates_verified" => {
            current_outcome(&build_evidence(EvidenceConfig::default())?, None)
        }
        "current_cross_verifier_replay_rejected" => {
            let fixture = build_evidence(EvidenceConfig::default())?;
            current_outcome(
                &fixture,
                Some(CurrentOverride::Verifier(service_id(
                    "did:webvh:z6mkother:verifier.example",
                )?)),
            )
        }
        "current_request_or_challenge_replay_rejected" => {
            let fixture = build_evidence(EvidenceConfig::default())?;
            current_outcome(
                &fixture,
                Some(CurrentOverride::RequestDigest(hash_byte(0xa7)?)),
            )
        }
        "current_snapshot_digest_mix_and_match_rejected" => {
            let mut fixture = build_evidence(EvidenceConfig::default())?;
            if let AgentSignerEvidence::CurrentAdmission {
                current_observation,
                ..
            } = &mut fixture.current
            {
                current_observation.agent_snapshot_digest = hash_byte(0xa8)?;
            }
            current_outcome(&fixture, None)
        }
        "current_stale_lease_is_unresolved" => {
            let fixture = build_evidence(EvidenceConfig {
                stale_snapshot_lease: true,
                ..EvidenceConfig::default()
            })?;
            current_stale_outcome(&fixture)
        }
        "current_paused_agent_rejected" => current_outcome(
            &build_evidence(EvidenceConfig {
                lifecycle_status: AgentLifecycleStatus::Paused,
                ..EvidenceConfig::default()
            })?,
            None,
        ),
        "current_inactive_controller_account_rejected" => current_outcome(
            &build_evidence(EvidenceConfig {
                controller_eligibility: ControllerAccountEligibility::Inactive,
                controller_status: ControllerAccountStatus::Suspended,
                ..EvidenceConfig::default()
            })?,
            None,
        ),
        "current_revoked_or_superseded_key_rejected" => current_outcome(
            &build_evidence(EvidenceConfig {
                authorization_status: AgentAuthorizationStatus::Revoked,
                ..EvidenceConfig::default()
            })?,
            None,
        ),
        "historical_destination_receipt_preserves_admission" => {
            historical_outcome(&build_evidence(EvidenceConfig::default())?, None, false)
        }
        "historical_current_snapshot_substitution_rejected" => {
            let fixture = build_evidence(EvidenceConfig::default())?;
            historical_outcome_with(&fixture, Some(&fixture.current), None, false)
        }
        "historical_wrong_destination_receipt_rejected" => {
            let fixture = build_evidence(EvidenceConfig::default())?;
            historical_outcome(
                &fixture,
                Some(service_id("did:webvh:z6mkwrong:receiver.example")?),
                false,
            )
        }
        "historical_inactive_gate_at_receipt_time_rejected" => historical_outcome(
            &build_evidence(EvidenceConfig {
                controller_eligibility: ControllerAccountEligibility::Inactive,
                controller_status: ControllerAccountStatus::Locked,
                ..EvidenceConfig::default()
            })?,
            None,
            false,
        ),
        "historical_materialization_exact_replay_is_no_op"
        | "historical_materialization_same_tuple_other_receipt_is_zero_overwrite"
        | "historical_materialization_same_tuple_other_root_is_zero_overwrite"
        | "historical_materialization_other_receiver_service_is_a_distinct_branch"
        | "historical_materialization_incomplete_dependency_closure_publishes_no_root"
        | "historical_materialization_lost_receipt_is_never_reminted" => {
            execute_historical_materialization_case(name, case)
        }
        "historical_outer_attestation_verifies_long_after_attested_at" => {
            validate_historical_materialization_case(case)?;
            require_case_str(case, "outer_attestation_branch", "historical")?;
            require_case_bool(case, "outer_attestation_carries_expires_at", false)?;
            require_case_bool(case, "verifier_now_far_after_attested_at", true)?;
            require_case_str(case, "authority_method_resolved_at", "attested_at")?;
            historical_outcome(&build_evidence(EvidenceConfig::default())?, None, false)
        }
        "historical_branch_carrying_current_outer_attestation_rejected" => {
            validate_historical_materialization_case(case)?;
            require_case_str(case, "outer_attestation_branch", "current")?;
            require_case_bool(case, "outer_attestation_carries_expires_at", true)?;
            let fixture = build_evidence(EvidenceConfig::default())?;
            historical_outcome_with(&fixture, Some(&fixture.current), None, false)
        }
        "authority_key_rotation_after_attested_at_preserves_historical_root" => {
            validate_historical_materialization_case(case)?;
            require_case_bool(
                case,
                "authority_signing_key_rotated_after_attested_at",
                true,
            )?;
            require_case_str(case, "authority_method_resolved_at", "attested_at")?;
            historical_outcome(&build_evidence(EvidenceConfig::default())?, None, false)
        }
        "authority_method_inactive_at_attested_at_rejected" => {
            validate_historical_materialization_case(case)?;
            require_case_bool(case, "authority_method_active_at_attested_at", false)?;
            let mut fixture = build_evidence(EvidenceConfig::default())?;
            fixture.authority_public_key = [99; 32];
            historical_outcome(&fixture, None, false)
        }
        "receiver_key_rotation_after_accepted_at_preserves_receipt" => {
            validate_historical_materialization_case(case)?;
            require_case_bool(case, "receiver_signing_key_rotated_after_accepted_at", true)?;
            require_case_str(
                case,
                "receiver_dependency_resolved_at",
                "receipt_accepted_at",
            )?;
            historical_outcome(&build_evidence(EvidenceConfig::default())?, None, false)
        }
        "receiver_dependency_resolved_from_current_service_record_rejected" => {
            validate_historical_materialization_case(case)?;
            require_case_bool(case, "receiver_signing_key_rotated_after_accepted_at", true)?;
            require_case_str(case, "receiver_dependency_resolved_at", "verifier_now")?;
            let mut fixture = build_evidence(EvidenceConfig::default())?;
            fixture.receiver_public_key = [98; 32];
            historical_outcome(&fixture, None, false)
        }
        "receiver_key_revoked_after_accepted_at_does_not_retroact" => {
            validate_historical_materialization_case(case)?;
            require_case_bool(case, "receiver_method_active_at_accepted_at", true)?;
            require_case_str(case, "current_receiver_signing_key_status", "revoked")?;
            historical_outcome(&build_evidence(EvidenceConfig::default())?, None, false)
        }
        "receiver_method_inactive_at_accepted_at_rejected" => {
            validate_historical_materialization_case(case)?;
            require_case_bool(case, "receiver_method_active_at_accepted_at", false)?;
            let mut fixture = build_evidence(EvidenceConfig::default())?;
            fixture.receiver_public_key = [97; 32];
            historical_outcome(&fixture, None, false)
        }
        "account_gate_never_discloses_local_identity" => {
            let fixture = build_evidence(EvidenceConfig::default())?;
            let serialized = serde_json::to_value(&fixture.current)?;
            if contains_forbidden_local_identity(&serialized) {
                bail!("portable account gate disclosed service-local identity");
            }
            current_outcome(&fixture, None)
        }
        "producer_fetches_controller_gate_from_account_authority"
        | "controller_gate_exact_request_replay_is_byte_identical"
        | "controller_gate_request_id_conflict_is_zero_issuance"
        | "controller_gate_wrong_source_and_unknown_principal_are_indistinguishable"
        | "controller_gate_inactive_status_is_signed_not_forged_by_producer" => {
            execute_controller_gate_case(name, case)
        }
        "agent_genesis_active_requires_accepted_provision_declaration" => {
            let fixture = build_evidence(EvidenceConfig::default())?;
            let admission = admission(&fixture.current);
            let provenance = &admission
                .agent_authority_snapshot
                .core
                .agent_lifecycle_witness
                .provenance;
            if !matches!(
                provenance,
                AgentLifecycleProvenance::DelegatedPcrGenesis {
                    agent_provision_event_id,
                    ..
                } if !agent_provision_event_id.as_str().is_empty()
            ) {
                bail!("active Agent genesis lacks provision reference");
            }
            current_outcome(&fixture, None)
        }
        "organization_pcr_cannot_materialize_agent_active" => {
            let fixture = build_evidence(EvidenceConfig::default())?;
            state_outcome_with_policy(&fixture, &|_| {
                Err(AgentEvidenceRejectedReason::AuthorizationInactive)
            })
        }
        "state_witness_uses_canonical_event_dot" => {
            let fixture = build_evidence(EvidenceConfig::default())?;
            state_outcome_with_policy(&fixture, &|_| Ok(()))
        }
        "bare_event_id_state_tag_rejected" => {
            let fixture = build_evidence(EvidenceConfig {
                bare_authorization_tag: true,
                ..EvidenceConfig::default()
            })?;
            state_outcome_with_policy(&fixture, &|_| Ok(()))
        }
        "outer_attestation_prevents_mode_splice" => {
            let mut fixture = build_evidence(EvidenceConfig::default())?;
            let current_core_digest = match &fixture.current {
                AgentSignerEvidence::CurrentAdmission {
                    outer_attestation, ..
                } => outer_attestation.core_digest.clone(),
                AgentSignerEvidence::HistoricalEvent { .. } => unreachable!(),
            };
            if let AgentSignerEvidence::HistoricalEvent {
                outer_attestation, ..
            } = &mut fixture.historical
            {
                outer_attestation.core_digest = current_core_digest;
            }
            historical_outcome(&fixture, None, false)
        }
        "historical_mls_leaf_cross_binding_verified" => {
            historical_outcome(&build_evidence(EvidenceConfig::default())?, None, false)
        }
        "duplicate_or_mismatched_mls_leaf_rejected" => {
            let mut fixture = build_evidence(EvidenceConfig::default())?;
            if let AgentSignerEvidence::HistoricalEvent {
                event_admission_receipt,
                ..
            } = &mut fixture.historical
            {
                let controller = fixture
                    .verification_method
                    .as_str()
                    .split_once('#')
                    .map(|(controller, _)| controller)
                    .context("fixture verification method has no controller")?;
                event_admission_receipt.verification_method =
                    DidUrl::new(format!("{controller}#mismatched-mls-leaf"))
                        .map_err(anyhow::Error::msg)?;
            }
            historical_outcome(&fixture, None, false)
        }
        "minimal_metadata_forbids_agent_evidence_query" => {
            if dispatch_signer_regime(true, SignerPrincipalKind::Agent)
                .map_err(|reason| anyhow!("{reason:?}"))?
                == SignerRegime::MinimalMetadata
            {
                Ok(OutcomeClass::Verified)
            } else {
                Ok(OutcomeClass::Rejected)
            }
        }
        other => bail!("unimplemented Agent signer-evidence case {other}"),
    }
}

fn validate_historical_materialization_case(case: &Value) -> Result<()> {
    require_case_str(
        case,
        "vector_id",
        "ak.vector.agent.historical_evidence_materialization.v1",
    )?;
    require_case_str(case, "verification_mode", "historical_event")
}

fn require_case_bool(case: &Value, field: &str, expected: bool) -> Result<()> {
    if case.get(field).and_then(Value::as_bool) != Some(expected) {
        bail!(
            "Agent signer-evidence case {} requires {field}={expected}",
            case["name"]
        );
    }
    Ok(())
}

fn require_case_str(case: &Value, field: &str, expected: &str) -> Result<()> {
    if case.get(field).and_then(Value::as_str) != Some(expected) {
        bail!(
            "Agent signer-evidence case {} requires {field}={expected}",
            case["name"]
        );
    }
    Ok(())
}

fn require_zero_additional_roots(case: &Value) -> Result<()> {
    if case
        .get("additional_historical_roots_published")
        .and_then(Value::as_u64)
        != Some(0)
    {
        bail!("Agent historical materialization must publish zero additional roots");
    }
    Ok(())
}

fn execute_historical_materialization_case(name: &str, case: &Value) -> Result<OutcomeClass> {
    validate_historical_materialization_case(case)?;
    match name {
        "historical_materialization_exact_replay_is_no_op" => {
            require_case_bool(case, "same_selector_tuple", true)?;
            require_case_bool(case, "same_receipt_digest", true)?;
            require_case_bool(case, "same_canonical_historical_root", true)?;
            require_case_bool(
                case,
                "materializer_reads_selector_tuple_before_signing_a_new_root",
                true,
            )?;
            require_zero_additional_roots(case)?;
            Ok(OutcomeClass::Verified)
        }
        "historical_materialization_same_tuple_other_receipt_is_zero_overwrite" => {
            require_case_bool(case, "same_selector_tuple", true)?;
            require_case_bool(case, "same_receipt_digest", false)?;
            require_case_bool(case, "same_canonical_historical_root", false)?;
            require_zero_additional_roots(case)?;
            require_case_str(case, "reason", "duplicate_conflict")?;
            Ok(OutcomeClass::Rejected)
        }
        "historical_materialization_same_tuple_other_root_is_zero_overwrite" => {
            require_case_bool(case, "same_selector_tuple", true)?;
            require_case_bool(case, "same_receipt_digest", true)?;
            require_case_bool(case, "same_canonical_historical_root", false)?;
            require_zero_additional_roots(case)?;
            require_case_str(case, "reason", "duplicate_conflict")?;
            Ok(OutcomeClass::Rejected)
        }
        "historical_materialization_other_receiver_service_is_a_distinct_branch" => {
            require_case_bool(case, "same_selector_tuple", false)?;
            require_case_str(case, "selector_component_that_differs", "receiver_id")?;
            if case
                .get("additional_historical_roots_published")
                .and_then(Value::as_u64)
                != Some(1)
            {
                bail!("distinct receiver branch must publish exactly one historical root");
            }
            Ok(OutcomeClass::Verified)
        }
        "historical_materialization_incomplete_dependency_closure_publishes_no_root" => {
            require_case_bool(case, "recursive_signer_dependency_closure_complete", false)?;
            require_zero_additional_roots(case)?;
            require_case_str(case, "reason", "agent_signer_evidence_missing")?;
            Ok(OutcomeClass::Unresolved)
        }
        "historical_materialization_lost_receipt_is_never_reminted" => {
            require_case_bool(case, "receipt_permanently_lost", true)?;
            require_case_bool(
                case,
                "materializer_rebuilds_receipt_from_current_state",
                false,
            )?;
            require_zero_additional_roots(case)?;
            require_case_str(case, "reason", "agent_signer_evidence_missing")?;
            Ok(OutcomeClass::Unresolved)
        }
        _ => bail!("unknown historical materialization case {name}"),
    }
}

enum CurrentOverride {
    Verifier(DidCoreId),
    RequestDigest(Hash),
}

fn execute_controller_gate_case(name: &str, case: &Value) -> Result<OutcomeClass> {
    let bool_field = |field: &str| {
        case.get(field)
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("controller gate case {name} is missing boolean {field}"))
    };
    let zero_field = |field: &str| {
        case.get(field)
            .and_then(Value::as_u64)
            .is_some_and(|value| value == 0)
    };
    match name {
        "producer_fetches_controller_gate_from_account_authority" => {
            let required_true = [
                "current_signed_service_resolution_record_verified",
                "method_history_evidence_verified",
                "normalized_document_digest_verified",
                "rfc9421_covers_method_path_digest_source_destination_operation_request",
                "verification_key_from_active_service_resolution",
                "authenticated_source_matches_agent_authority_id",
                "current_station_matches_source",
            ];
            let all_required = required_true.iter().try_fold(true, |all, field| {
                Ok::<_, anyhow::Error>(all && bool_field(field)?)
            })?;
            if case.get("operation_id").and_then(Value::as_str)
                != Some("ak.gate.account.command.issue_controller_gate_attestation.v1")
                || !all_required
                || bool_field("bearer_used_as_signature_substitute")?
                || case
                    .get("account_authority_projection_status")
                    .and_then(Value::as_str)
                    != Some("active")
                || case.get("issued_eligibility").and_then(Value::as_str) != Some("active")
                || case.get("attestation_ttl_seconds").and_then(Value::as_u64) != Some(300)
            {
                bail!("controller gate producer verification contract drifted");
            }
            Ok(OutcomeClass::Verified)
        }
        "controller_gate_exact_request_replay_is_byte_identical" => {
            if !bool_field("same_request_id")?
                || !bool_field("same_canonical_intent")?
                || !bool_field("first_outcome_bytes_equal_replay")?
                || !zero_field("additional_attestations_issued")
            {
                bail!("controller gate exact replay is not byte-stable and zero-issuance");
            }
            Ok(OutcomeClass::Verified)
        }
        "controller_gate_request_id_conflict_is_zero_issuance" => {
            if !bool_field("same_request_id")?
                || bool_field("same_canonical_intent")?
                || !zero_field("additional_attestations_issued")
                || case.get("reason").and_then(Value::as_str) != Some("duplicate_conflict")
            {
                bail!("controller gate request-id conflict contract drifted");
            }
            Ok(OutcomeClass::Rejected)
        }
        "controller_gate_wrong_source_and_unknown_principal_are_indistinguishable" => {
            let scenarios = case
                .get("scenarios")
                .and_then(Value::as_array)
                .context("controller gate indistinguishability scenarios missing")?
                .iter()
                .filter_map(Value::as_str)
                .collect::<std::collections::BTreeSet<_>>();
            let expected = [
                "missing_current_station",
                "source_service_mismatch",
                "unauthorized_service",
                "unknown_principal",
            ]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
            if scenarios != expected
                || !bool_field("same_error_envelope")?
                || bool_field("account_status_disclosed")?
                || case.get("reason").and_then(Value::as_str) != Some("not_found")
            {
                bail!("controller gate not-found indistinguishability contract drifted");
            }
            Ok(OutcomeClass::Rejected)
        }
        "controller_gate_inactive_status_is_signed_not_forged_by_producer" => {
            if case
                .get("account_authority_projection_status")
                .and_then(Value::as_str)
                != Some("deactivated")
                || case.get("issued_eligibility").and_then(Value::as_str) != Some("inactive")
                || bool_field("producer_overrode_eligibility")?
                || bool_field("portable_outcome_contains_account_id")?
                || bool_field("portable_outcome_contains_raw_account_cell")?
            {
                bail!("controller gate inactive signed outcome contract drifted");
            }
            Ok(OutcomeClass::Verified)
        }
        _ => bail!("unknown controller gate case {name}"),
    }
}

fn current_outcome(
    fixture: &ExecutableEvidence,
    override_value: Option<CurrentOverride>,
) -> Result<OutcomeClass> {
    let verified_state = verified_state(fixture, &fixture.current, &|_| Ok(()))?;
    let controller_key = public_key(fixture.controller_public_key);
    let authority_key = public_key(fixture.authority_public_key);
    let account_key = public_key(fixture.account_authority_public_key);
    let common = common_context(
        fixture,
        &verified_state,
        &controller_key,
        &authority_key,
        &account_key,
    );
    let alternate_verifier;
    let alternate_digest;
    let verifier_id = match &override_value {
        Some(CurrentOverride::Verifier(value)) => {
            alternate_verifier = value;
            alternate_verifier
        }
        _ => &fixture.verifier_id,
    };
    let request_digest = match &override_value {
        Some(CurrentOverride::RequestDigest(value)) => {
            alternate_digest = value;
            alternate_digest
        }
        _ => &fixture.request_digest,
    };
    Ok(verdict_class(validate_current_agent_signer_evidence(
        Some(&fixture.current),
        &CurrentAgentSignerEvidenceValidationContext {
            common,
            operation_id: &fixture.operation_id,
            request_digest,
            verifier_id,
            audience: &fixture.audience,
            challenge: &fixture.challenge,
        },
    )))
}

fn current_stale_outcome(fixture: &ExecutableEvidence) -> Result<OutcomeClass> {
    let verified_state = verified_state(fixture, &fixture.current, &|_| Ok(()))?;
    let controller_key = public_key(fixture.controller_public_key);
    let authority_key = public_key(fixture.authority_public_key);
    let account_key = public_key(fixture.account_authority_public_key);
    let verdict = validate_current_agent_signer_evidence(
        Some(&fixture.current),
        &CurrentAgentSignerEvidenceValidationContext {
            common: common_context(
                fixture,
                &verified_state,
                &controller_key,
                &authority_key,
                &account_key,
            ),
            operation_id: &fixture.operation_id,
            request_digest: &fixture.request_digest,
            verifier_id: &fixture.verifier_id,
            audience: &fixture.audience,
            challenge: &fixture.challenge,
        },
    );
    match verdict {
        AgentSignerEvidenceVerdict::Unresolved(
            arkret_signatures::agent_evidence::AgentEvidenceUnresolvedReason::Stale,
        ) => Ok(OutcomeClass::Unresolved),
        other => bail!("expired signed current snapshot lease returned {other:?}"),
    }
}

fn historical_outcome(
    fixture: &ExecutableEvidence,
    receiver_override: Option<DidCoreId>,
    deny_key_resolution: bool,
) -> Result<OutcomeClass> {
    historical_outcome_with(
        fixture,
        Some(&fixture.historical),
        receiver_override,
        deny_key_resolution,
    )
}

fn historical_outcome_with(
    fixture: &ExecutableEvidence,
    evidence: Option<&AgentSignerEvidence>,
    receiver_override: Option<DidCoreId>,
    deny_key_resolution: bool,
) -> Result<OutcomeClass> {
    let state_source = evidence.unwrap_or(&fixture.historical);
    let verified_state = verified_state(fixture, state_source, &|_| Ok(()))?;
    let controller_key = public_key(fixture.controller_public_key);
    let authority_key = public_key(fixture.authority_public_key);
    let account_key = public_key(fixture.account_authority_public_key);
    let receiver_id = receiver_override.as_ref().unwrap_or(&fixture.receiver_id);
    let resolve = |method: &DidUrl, _at: DateTime<Utc>| {
        (!deny_key_resolution && method == &fixture.receiver_verification_method)
            .then(|| public_key(fixture.receiver_public_key))
    };
    Ok(verdict_class(validate_historical_agent_signer_evidence(
        evidence,
        &HistoricalAgentSignerEvidenceValidationContext {
            common: common_context(
                fixture,
                &verified_state,
                &controller_key,
                &authority_key,
                &account_key,
            ),
            event_id: &fixture.event_id,
            realm_id: &fixture.realm_id,
            producer_accepted_at: fixture.producer_accepted_at,
            producer_signer_resolution_evidence_ref: &fixture
                .producer_signer_resolution_evidence_ref,
            receiver_id,
            resolve_receiver_historical_key: &resolve,
        },
    )))
}

fn state_outcome_with_policy(
    fixture: &ExecutableEvidence,
    policy: &dyn Fn(&AgentLifecycleWitness) -> std::result::Result<(), AgentEvidenceRejectedReason>,
) -> Result<OutcomeClass> {
    match verified_state(fixture, &fixture.current, policy) {
        Ok(_) => Ok(OutcomeClass::Verified),
        Err(_) => Ok(OutcomeClass::Rejected),
    }
}

fn verified_state<'a>(
    fixture: &'a ExecutableEvidence,
    evidence: &'a AgentSignerEvidence,
    lifecycle_policy: &'a dyn Fn(
        &AgentLifecycleWitness,
    ) -> std::result::Result<(), AgentEvidenceRejectedReason>,
) -> Result<arkret_signatures::agent_evidence::VerifiedAgentEvidenceState> {
    let seal_policy = |_seal: &Seal| Ok(());
    verify_agent_evidence_state(
        admission(evidence),
        &AgentEvidenceStateVerificationContext {
            signer_id: &fixture.signer_id,
            signer_actor_id: &fixture.signer_actor_id,
            agent_key_id: &fixture.agent_key_id,
            controller_principal_id: &fixture.controller_principal_id,
            agent_key_authorize_event_id: &fixture.authorize_event_id,
            authorize_public_key_digest: &fixture.authorize_public_key_digest,
            authorize_signing_key_binding_digest: &fixture.binding_digest,
            verify_seal_signature: &seal_policy,
            verify_lifecycle_reducer: lifecycle_policy,
        },
    )
    .map_err(|reason| anyhow!("state verification rejected: {reason:?}"))
}

fn common_context<'a>(
    fixture: &'a ExecutableEvidence,
    verified_state: &'a arkret_signatures::agent_evidence::VerifiedAgentEvidenceState,
    controller_key: &'a PublicKeyMaterial,
    authority_key: &'a PublicKeyMaterial,
    account_key: &'a PublicKeyMaterial,
) -> AgentEvidenceCommonContext<'a> {
    AgentEvidenceCommonContext {
        signer_id: &fixture.signer_id,
        agent_key_id: &fixture.agent_key_id,
        controller_principal_id: &fixture.controller_principal_id,
        verification_method: &fixture.verification_method,
        agent_key_authorize_event_id: &fixture.authorize_event_id,
        authorize_public_key_digest: &fixture.authorize_public_key_digest,
        authorize_signing_key_binding_digest: &fixture.binding_digest,
        expected_authority_id: &fixture.authority_id,
        expected_authority_verification_method: &fixture.authority_verification_method,
        expected_account_authority_id: &fixture.account_authority_id,
        expected_account_authority_verification_method: &fixture
            .account_authority_verification_method,
        controller_public_key: controller_key,
        authority_public_key: authority_key,
        account_authority_public_key: account_key,
        verified_state,
        require_transparency: false,
        transparency_verified: false,
        now: fixture.now,
    }
}

fn verdict_class(verdict: AgentSignerEvidenceVerdict) -> OutcomeClass {
    match verdict {
        AgentSignerEvidenceVerdict::Verified(_) => OutcomeClass::Verified,
        AgentSignerEvidenceVerdict::Unresolved(_) => OutcomeClass::Unresolved,
        AgentSignerEvidenceVerdict::Rejected(_) => OutcomeClass::Rejected,
    }
}

fn build_evidence(config: EvidenceConfig) -> Result<ExecutableEvidence> {
    let issued_at = Utc
        .with_ymd_and_hms(2026, 8, 3, 0, 0, 0)
        .single()
        .context("fixed timestamp")?;
    let now = issued_at + Duration::minutes(20);
    let expires_at = issued_at + Duration::hours(2);
    let snapshot_lease_expires_at = if config.stale_snapshot_lease {
        now - Duration::minutes(1)
    } else {
        expires_at
    };
    let controller_signing = SigningKey::from_bytes(&[11; 32]);
    let agent_signing = SigningKey::from_bytes(&[12; 32]);
    let authority_signing = SigningKey::from_bytes(&[13; 32]);
    let account_signing = SigningKey::from_bytes(&[14; 32]);
    let receiver_signing = SigningKey::from_bytes(&[15; 32]);

    let signer_did = Did::new("did:webvh:z6mkagent:agent.example")?;
    let controller_did = Did::new("did:webvh:z6mkcontroller:controller.example")?;
    let authority_service_did = Did::new("did:webvh:z6mkauthority:authority.example")?;
    let account_authority_service_did =
        Did::new("did:webvh:z6mkaccount:account-authority.example")?;
    let receiver_service_did = Did::new("did:webvh:z6mkreceiver:receiver.example")?;
    let signer_id = project_did_to_core_id(&signer_did)?;
    let controller_principal_id = project_did_to_core_id(&controller_did)?;
    let authority_id = project_did_to_core_id(&authority_service_did)?;
    let account_authority_id = project_did_to_core_id(&account_authority_service_did)?;
    let receiver_id = project_did_to_core_id(&receiver_service_did)?;
    let signer_actor_id = ActorId::account(AccountId::new(signer_id.clone(), authority_id.clone()));
    let controller_actor_id = ActorId::account(AccountId::new(
        controller_principal_id.clone(),
        authority_id.clone(),
    ));
    let verification_method =
        DidUrl::new(format!("{signer_did}#runtime-1")).map_err(anyhow::Error::msg)?;
    let controller_verification_method =
        DidUrl::new(format!("{controller_did}#controller-1")).map_err(anyhow::Error::msg)?;
    let authority_verification_method =
        DidUrl::new(format!("{authority_service_did}#assertion-1")).map_err(anyhow::Error::msg)?;
    let account_authority_verification_method =
        DidUrl::new(format!("{account_authority_service_did}#assertion-1"))
            .map_err(anyhow::Error::msg)?;
    let receiver_verification_method =
        DidUrl::new(format!("{receiver_service_did}#assertion-1")).map_err(anyhow::Error::msg)?;
    let agent_key_id = nes("runtime-1")?;
    let authorize_event_id = event_id(1)?;
    let realm_id = RealmId::new("ak:realm:AUf0Zz23_ZBqZYNvzHTY6qhhx-2YyO94WTorNCFnnvvN")?;

    let binding = build_agent_signing_key_binding(
        signer_id.clone(),
        agent_key_id.clone(),
        verification_method.clone(),
        agent_signing.verifying_key().to_bytes(),
        authorize_event_id.clone(),
        issued_at,
        Some(expires_at),
        controller_principal_id.clone(),
        controller_verification_method,
        &controller_signing,
    )
    .map_err(|reason| anyhow!("binding: {reason:?}"))?;
    let authorize_public_key_digest = agent_signing_public_key_digest(&binding.public_key)
        .map_err(|reason| anyhow!("signing key digest: {reason:?}"))?;
    let binding_digest =
        agent_signing_key_binding_digest(&binding).map_err(|reason| anyhow!("{reason:?}"))?;

    let tag = if config.bare_authorization_tag {
        authorize_event_id.to_string()
    } else {
        format!("{authorize_event_id}:0")
    };
    let key_cell_value = vec![AgentKeyCellEntry {
        tag: nes(&tag)?,
        value: serde_json::json!({
            "agent_id": signer_id,
            "key_id": agent_key_id,
            "verification_method": verification_method,
            "public_key_digest": authorize_public_key_digest,
            "signing_key_binding_digest": binding_digest,
        }),
    }];
    let key_cell_ref = agent_authorization_cell_ref(&signer_id, &agent_key_id)
        .map_err(|reason| anyhow!("cell ref: {reason:?}"))?;
    let key_leaf_digest = arkret_state::state_value_leaf_digest(
        &arkret_wire::CellRef::new(key_cell_ref.as_str().to_owned())?,
        &serde_json::to_value(&key_cell_value)?,
        arkret_canonical::DigestSuite::Sha256,
    )?;
    let lifecycle_actor_key = signer_actor_id.canonical_key()?;
    let lifecycle_cell_ref = nes(&arkret_wire::composite_subject(&[
        lifecycle_actor_key.as_str()
    ])?)?;
    let lifecycle_cell_ref = nes(&format!(
        "ak:cell:{AGENT_STATUS_COMPONENT}:{}",
        lifecycle_cell_ref.as_str()
    ))?;
    let lifecycle_leaf_digest = arkret_state::state_value_leaf_digest(
        &arkret_wire::CellRef::new(lifecycle_cell_ref.as_str().to_owned())?,
        &serde_json::to_value(config.lifecycle_status)?,
        arkret_canonical::DigestSuite::Sha256,
    )?;

    let key_seal = make_seal(
        &realm_id,
        Vec::new(),
        key_leaf_digest.clone(),
        1,
        issued_at,
        "01970e589d21-0000-a13f9c2e",
        &authority_verification_method,
    )?;
    let lifecycle_seal = make_seal(
        &realm_id,
        vec![key_seal.id.clone()],
        lifecycle_leaf_digest.clone(),
        2,
        issued_at + Duration::seconds(1),
        "01970e589d21-0001-a13f9c2e",
        &authority_verification_method,
    )?;
    let mut accepted_status_event = arkret_wire::test_support::raw_event(
        EventKind::AgentProvision.as_str(),
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        signer_id.clone(),
        authority_id.clone(),
        1,
        Hlc::new("01970e589d21-0002-a13f9c2e")?,
        serde_json::json!({"agent_id": signer_id}),
    )?;
    accepted_status_event.executed_by = Some(controller_actor_id);
    let provision_event_id = accepted_status_event.event_id.clone();
    let authorization = AgentAuthorizationEvidence {
        status: config.authorization_status,
        authorized_event_id: authorize_event_id.clone(),
        accepted_seal_id: key_seal.id.clone(),
        accepted_at: issued_at,
        not_before: issued_at,
        expires_at: Some(expires_at),
        transition_event_id: None,
        transition_seal_id: None,
    };
    let key_state_witness = AgentAuthorizationStateWitness {
        component: nes(AGENT_KEY_COMPONENT)?,
        agent_id: signer_id.clone(),
        authorization_event_id: authorize_event_id.clone(),
        seal_id: key_seal.id.clone(),
        state_root: key_leaf_digest.clone(),
        seal: key_seal.clone(),
        cell_ref: key_cell_ref,
        cell_value: key_cell_value,
        leaf_digest: key_leaf_digest,
        leaf_index: 0,
        leaf_count: 1,
        inclusion_proof: Vec::new(),
    };
    let lifecycle_witness = AgentLifecycleWitness {
        component: nes(AGENT_STATUS_COMPONENT)?,
        agent_id: signer_id.clone(),
        status: config.lifecycle_status,
        provenance: AgentLifecycleProvenance::DelegatedPcrGenesis {
            realm_create_event_id: event_id(2)?,
            agent_provision_event_id: provision_event_id,
        },
        accepted_status_event,
        seal_id: lifecycle_seal.id.clone(),
        state_root: lifecycle_leaf_digest.clone(),
        seal: lifecycle_seal.clone(),
        cell_ref: lifecycle_cell_ref,
        cell_value: config.lifecycle_status,
        leaf_digest: lifecycle_leaf_digest,
        leaf_index: 0,
        leaf_count: 1,
        inclusion_proof: Vec::new(),
    };
    let core = AgentAuthoritySnapshotCore {
        authority_id: authority_id.clone(),
        principal_control_realm_id: realm_id.clone(),
        frontier_seal_id: lifecycle_seal.id.clone(),
        frontier_state_root: lifecycle_seal.state_root.clone(),
        signing_key_binding: binding,
        authorization,
        key_state_witness,
        key_transition_witness: None,
        agent_lifecycle_witness: lifecycle_witness,
        seal_lineages: vec![key_seal, lifecycle_seal],
    };
    let snapshot_digest = canonical_hash(&core)?;
    let mut snapshot = AgentAuthoritySnapshot {
        core,
        snapshot_digest: snapshot_digest.clone(),
        lease: AgentSnapshotLease {
            authority_kind: nes("agent_authority")?,
            authority_id: authority_id.clone(),
            verification_method: authority_verification_method.clone(),
            snapshot_digest: snapshot_digest.clone(),
            issued_at,
            expires_at: snapshot_lease_expires_at,
            proof: pending_proof()?,
        },
    };
    snapshot.lease.proof = sign_domain(
        DomainSeparationId::AGENT_AUTHORITY_SNAPSHOT_V1,
        &snapshot.lease,
        &authority_signing,
        None,
    )?;

    let basis = ControllerAccountGateBasis::AccountBindingDefault {
        binding_version: 1,
        binding_frontier_digest: hash_byte(0x31)?,
    };
    let mut gate = ControllerAccountGateAttestation {
        schema: nes(SchemaId::CONTROLLER_ACCOUNT_GATE_ATTESTATION_V1)?,
        principal_id: controller_principal_id.clone(),
        eligibility: config.controller_eligibility,
        status: config.controller_status,
        basis_digest: canonical_hash(&basis)?,
        basis,
        authority_id: account_authority_id.clone(),
        verification_method: account_authority_verification_method.clone(),
        issued_at,
        expires_at,
        proof: pending_proof()?,
    };
    gate.proof = sign_domain(
        DomainSeparationId::CONTROLLER_ACCOUNT_GATE_V1,
        &gate,
        &account_signing,
        None,
    )?;
    let gate_digest = canonical_hash(&gate)?;
    let admission_evidence_digest = canonical_hash(&serde_json::json!({
        "agent_authority_snapshot": snapshot,
        "controller_account_gate_attestation": gate,
    }))?;
    let admission = AgentAdmissionEvidence {
        agent_authority_snapshot: snapshot,
        controller_account_gate_attestation: gate,
        admission_evidence_digest: admission_evidence_digest.clone(),
    };

    let operation_id = ProtocolOperationId::new("ak:operation:cotest.agent-evidence")
        .map_err(anyhow::Error::msg)?;
    let request_digest = hash_byte(0x41)?;
    let verifier_id = service_id("did:webvh:z6mkverifier:verifier.example")?;
    let audience = service_id("did:webvh:z6mkaudience:audience.example")?;
    let challenge = nes("cotest-agent-evidence-challenge-0001")?;
    let observation = AgentCurrentObservation {
        operation_id: operation_id.clone(),
        request_digest: request_digest.clone(),
        verifier_id: verifier_id.clone(),
        audience_id: audience.clone(),
        challenge: challenge.clone(),
        agent_snapshot_digest: snapshot_digest.clone(),
        agent_key_seal_id: admission
            .agent_authority_snapshot
            .core
            .key_state_witness
            .seal_id
            .clone(),
        agent_status_seal_id: admission
            .agent_authority_snapshot
            .core
            .agent_lifecycle_witness
            .seal_id
            .clone(),
        controller_gate_attestation_digest: gate_digest.clone(),
        evaluated_at: now,
        expires_at: now + Duration::minutes(10),
    };
    let mut current = AgentSignerEvidence::CurrentAdmission {
        schema: nes(SchemaId::AGENT_SIGNER_EVIDENCE_V1)?,
        admission_evidence: admission.clone(),
        current_observation: observation,
        outer_attestation: pending_outer(
            &authority_id,
            &authority_verification_method,
            issued_at,
            expires_at,
        )?,
        transparency: None,
    };
    sign_outer(&mut current, &authority_signing)?;

    let event_id = event_id(3)?;
    let producer_accepted_at = now - Duration::seconds(1);
    // The content-addressed ref is the sole carrier of this digest; the
    // receipt no longer mirrors it (`conformance/encoding.md` §4.0.1).
    let producer_signer_resolution_evidence_ref =
        SignerEvidenceRef::new(format!("ak:signer_evidence:{}", hash_byte(0x71)?))?;
    let mut receipt = AgentEventAdmissionReceipt {
        schema: nes(SchemaId::AGENT_SIGNER_ADMISSION_RECEIPT_V1)?,
        event_id: event_id.clone(),
        realm_id: realm_id.clone(),
        producer_accepted_at,
        accepted_at: now,
        agent_id: signer_id.clone(),
        verification_method: verification_method.clone(),
        producer_signer_resolution_evidence_ref: producer_signer_resolution_evidence_ref.clone(),
        receiver_id: receiver_id.clone(),
        proof: pending_proof()?,
    };
    receipt.proof = sign_domain(
        DomainSeparationId::AGENT_SIGNER_ADMISSION_RECEIPT_V1,
        &receipt,
        &receiver_signing,
        Some(&receiver_verification_method),
    )?;
    let mut historical = AgentSignerEvidence::HistoricalEvent {
        schema: nes(SchemaId::AGENT_SIGNER_EVIDENCE_V1)?,
        admission_evidence: admission,
        event_admission_receipt: receipt,
        outer_attestation: pending_historical_outer(
            &authority_id,
            &authority_verification_method,
            now,
        )?,
        transparency: None,
    };
    sign_outer(&mut historical, &authority_signing)?;

    Ok(ExecutableEvidence {
        current,
        historical,
        signer_id,
        signer_actor_id,
        agent_key_id,
        controller_principal_id,
        verification_method,
        authorize_event_id,
        authorize_public_key_digest,
        binding_digest,
        authority_id,
        authority_verification_method,
        account_authority_id,
        account_authority_verification_method,
        receiver_id,
        receiver_verification_method,
        controller_public_key: controller_signing.verifying_key().to_bytes(),
        authority_public_key: authority_signing.verifying_key().to_bytes(),
        account_authority_public_key: account_signing.verifying_key().to_bytes(),
        receiver_public_key: receiver_signing.verifying_key().to_bytes(),
        operation_id,
        request_digest,
        verifier_id,
        audience,
        challenge,
        event_id,
        realm_id,
        producer_accepted_at,
        producer_signer_resolution_evidence_ref,
        now,
    })
}

fn make_seal(
    realm_id: &RealmId,
    predecessor_refs: Vec<SealId>,
    state_root: Hash,
    sequence: u64,
    sealed_at: DateTime<Utc>,
    hlc: &str,
    verification_method: &DidUrl,
) -> Result<Seal> {
    let mut seal = Seal {
        id: SealId::new(format!("ak:seal:{}", hash_byte(0)?))?,
        realm_id: realm_id.clone(),
        predecessor_refs,
        delta: vec![hash_byte(sequence as u8)?],
        control_event_set_root: hash_byte(0x61)?,
        state_root,
        completeness_root: hash_byte(0x62)?,
        notary_seq: sequence,
        data_view_root: None,
        data_event_set_root: None,
        availability_receipt_digests: Vec::new(),
        covered_event_digests: Vec::new(),
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(SealSignature {
            verification_method: verification_method.clone(),
            payload_digest: hash_byte(0x63)?,
            jws: "e30..c2ln".to_owned(),
        }),
        sealed_at,
        hlc: Hlc::new(hlc)?,
    };
    seal.id = seal.derive_id(arkret_canonical::DigestSuite::Sha256)?;
    Ok(seal)
}

fn sign_outer(evidence: &mut AgentSignerEvidence, signing_key: &SigningKey) -> Result<()> {
    let mut core = serde_json::to_value(&*evidence)?;
    core.as_object_mut()
        .and_then(|object| object.remove("outer_attestation"))
        .context("outer attestation missing")?;
    let core_digest = canonical_hash(&core)?;
    match evidence {
        AgentSignerEvidence::CurrentAdmission {
            outer_attestation, ..
        } => {
            outer_attestation.core_digest = core_digest;
            outer_attestation.proof = sign_domain(
                DomainSeparationId::AGENT_SIGNER_EVIDENCE_V1,
                outer_attestation,
                signing_key,
                None,
            )?;
        }
        AgentSignerEvidence::HistoricalEvent {
            outer_attestation, ..
        } => {
            outer_attestation.core_digest = core_digest;
            outer_attestation.proof = sign_domain(
                DomainSeparationId::AGENT_SIGNER_EVIDENCE_V1,
                outer_attestation,
                signing_key,
                None,
            )?;
        }
    }
    Ok(())
}

fn pending_historical_outer(
    service_id: &DidCoreId,
    method: &DidUrl,
    attested_at: DateTime<Utc>,
) -> Result<AgentHistoricalEvidenceOuterAttestation> {
    Ok(AgentHistoricalEvidenceOuterAttestation {
        domain: nes(DomainSeparationId::AGENT_SIGNER_EVIDENCE_V1)?,
        core_digest: hash_byte(0)?,
        source_id: service_id.clone(),
        verification_method: method.clone(),
        attested_at,
        proof: pending_proof()?,
    })
}

fn pending_outer(
    service_id: &DidCoreId,
    method: &DidUrl,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<AgentEvidenceOuterAttestation> {
    Ok(AgentEvidenceOuterAttestation {
        domain: nes(DomainSeparationId::AGENT_SIGNER_EVIDENCE_V1)?,
        core_digest: hash_byte(0)?,
        source_id: service_id.clone(),
        verification_method: method.clone(),
        issued_at,
        expires_at,
        proof: pending_proof()?,
    })
}

fn sign_domain(
    domain: &str,
    value: &impl Serialize,
    signing_key: &SigningKey,
    protected_kid: Option<&DidUrl>,
) -> Result<AgentDetachedJws> {
    let mut unsigned = serde_json::to_value(value)?;
    unsigned
        .as_object_mut()
        .and_then(|object| object.get_mut("proof"))
        .and_then(Value::as_object_mut)
        .and_then(|proof| proof.remove("jws"))
        .context("signed evidence object missing proof.jws")?;
    let canonical = arkret_canonical::canonical_json_bytes(&unsigned)?;
    let mut signing_bytes = format!("{domain}\n").into_bytes();
    signing_bytes.extend(canonical);
    let jws = match protected_kid {
        Some(kid) => detached_jws_with_kid(signing_key, &signing_bytes, kid)?,
        None => sign_ed25519_detached_jws(signing_key, &signing_bytes)
            .map_err(|error| anyhow!(error.to_string()))?,
    };
    Ok(AgentDetachedJws {
        kind: nes("detached_jws")?,
        jws: nes(&jws)?,
    })
}

fn detached_jws_with_kid(key: &SigningKey, payload: &[u8], kid: &DidUrl) -> Result<String> {
    let protected = arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "alg": "Ed25519",
        "kid": kid,
    }))?;
    let protected = arkret_canonical::base64url_encode(protected);
    let payload = arkret_canonical::base64url_encode(payload);
    let signing_input = format!("{protected}.{payload}");
    let signature = key.sign(signing_input.as_bytes());
    Ok(format!(
        "{protected}..{}",
        arkret_canonical::base64url_encode(signature.to_bytes())
    ))
}

fn pending_proof() -> Result<AgentDetachedJws> {
    Ok(AgentDetachedJws {
        kind: nes("detached_jws")?,
        jws: nes("pending")?,
    })
}

fn admission(evidence: &AgentSignerEvidence) -> &AgentAdmissionEvidence {
    match evidence {
        AgentSignerEvidence::CurrentAdmission {
            admission_evidence, ..
        }
        | AgentSignerEvidence::HistoricalEvent {
            admission_evidence, ..
        } => admission_evidence,
    }
}

fn public_key(bytes: [u8; 32]) -> PublicKeyMaterial {
    PublicKeyMaterial::Ed25519Raw {
        bytes: bytes.to_vec(),
    }
}

fn contains_forbidden_local_identity(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, nested)| {
            matches!(
                key.as_str(),
                "local_account_id" | "session_id" | "internal_user_id" | "database_id"
            ) || contains_forbidden_local_identity(nested)
        }),
        Value::Array(values) => values.iter().any(contains_forbidden_local_identity),
        _ => false,
    }
}

fn validate_binding_requirements(fixture: &AgentSignerEvidenceFixture) -> Result<()> {
    let vector = &fixture.binding_vector;
    let requirements = vector
        .pointer("/requirements")
        .and_then(Value::as_array)
        .context("binding_vector.requirements missing")?;
    let expected = [
        "recompute_controller_proof_transcript",
        "recompute_public_key_digest",
        "match_authorize_event_commitment",
        "match_agent_and_controller",
    ];
    if requirements
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()
        .as_deref()
        != Some(expected.as_slice())
    {
        bail!("Agent signer binding requirements drifted");
    }
    let verification_method = DidUrl::new(
        vector
            .get("verification_method")
            .and_then(Value::as_str)
            .context("binding_vector.verification_method missing")?,
    )
    .map_err(anyhow::Error::msg)?;
    let public_key = AgentSigningPublicKey {
        kty: nes("OKP")?,
        algorithm: nes("Ed25519")?,
        key: Base64UrlString::new(
            vector
                .get("public_key")
                .and_then(Value::as_str)
                .context("binding_vector.public_key missing")?,
        )
        .map_err(anyhow::Error::msg)?,
    };
    let authorization_digest = agent_signing_public_key_digest(&public_key)
        .map_err(|reason| anyhow!("binding raw-key digest: {reason:?}"))?;
    let runtime_request_digest =
        agent_signing_public_key_runtime_request_digest(&verification_method, &public_key)
            .map_err(|reason| anyhow!("binding runtime-request digest: {reason:?}"))?;
    if vector.get("public_key_digest").and_then(Value::as_str)
        != Some(authorization_digest.as_str())
        || vector
            .get("runtime_request_public_key_digest")
            .and_then(Value::as_str)
            != Some(runtime_request_digest.as_str())
        || authorization_digest == runtime_request_digest
    {
        bail!("Agent signer raw-key and runtime-request digest domains drifted");
    }
    Ok(())
}

fn canonical_hash(value: &impl Serialize) -> Result<Hash> {
    Hash::new(arkret_canonical::canonical_sha256(value)?).map_err(anyhow::Error::msg)
}

fn hash_byte(byte: u8) -> Result<Hash> {
    Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).map_err(anyhow::Error::msg)
}

fn event_id(suffix: u8) -> Result<EventId> {
    Ok(crate::fixture_event_id(format!(
        "agent-signer-evidence:{suffix}"
    )))
}

fn nes(value: &str) -> Result<NonEmptyString> {
    NonEmptyString::new(value.to_owned()).map_err(anyhow::Error::msg)
}
