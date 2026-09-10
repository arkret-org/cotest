//! Executable current/historical Agent signer-evidence conformance.
//!
//! The closed fixture registry includes transport/materializer contract checks.
//! Executable signer cases exercise the SDK-owned state verifier, current and
//! historical validators, and regime dispatcher against signed evidence.

use anyhow::{Context, Result, anyhow, bail};
use arkret_models_identity::agent_signer_evidence::{
    AGENT_KEY_COMPONENT, AGENT_STATUS_COMPONENT, AgentAdmissionEvidence, AgentAuthorityState,
    AgentAuthorityStateEvidence, AgentAuthorityStateLease, AgentAuthorizationEvidence,
    AgentAuthorizationStateWitness, AgentAuthorizationStatus, AgentDetachedJws,
    AgentEventAdmission, AgentEventAdmissionReceipt, AgentKeyCellEntry, AgentLifecycleProvenance,
    AgentLifecycleStatus, AgentLifecycleWitness, AgentSignerEvidence, AgentSigningPublicKey,
    ControllerAccountEligibility, ControllerAccountGateAttestation, ControllerAccountGateBasis,
    ControllerAccountStatus,
};
use arkret_signatures::agent_evidence::{
    AgentEvidenceCommonContext, AgentEvidenceRejectedReason, AgentEvidenceStateVerificationContext,
    AgentSignerEvidenceVerdict, CurrentAgentSignerEvidenceValidationContext,
    HistoricalAgentSignerEvidenceValidationContext, SignerPrincipalKind, SignerRegime,
    agent_authorization_cell_ref, agent_signing_public_key_digest,
    agent_signing_public_key_runtime_request_digest, dispatch_signer_regime,
    validate_current_agent_signer_evidence, validate_historical_agent_signer_evidence,
    verify_agent_evidence_state,
};
use arkret_signatures::{PublicKeyMaterial, sign_ed25519_detached_jws};
use arkret_wire::{
    AccountId, ActorId, Base64UrlString, Did, DidCoreId, DidUrl, EventId, EventKind, Hash, Hlc,
    NonEmptyString, NotarySig, RealmId, SchemaId, ScopeRef, Seal, SealId, SealSignature,
    SignerEvidenceRef, project_did_to_core_id,
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
    "current_stale_lease_is_unresolved",
    "current_paused_agent_rejected",
    "current_inactive_controller_account_rejected",
    "current_revoked_or_superseded_key_rejected",
    "historical_destination_receipt_preserves_admission",
    "historical_current_authority_state_substitution_rejected",
    "historical_wrong_destination_receipt_rejected",
    "historical_inactive_gate_at_receipt_time_rejected",
    "historical_materialization_exact_replay_is_no_op",
    "historical_materialization_same_tuple_other_receipt_is_zero_overwrite",
    "historical_materialization_same_tuple_other_root_is_zero_overwrite",
    "historical_materialization_other_receiver_service_is_a_distinct_branch",
    "historical_materialization_incomplete_dependency_closure_publishes_no_root",
    "historical_materialization_lost_receipt_is_never_reminted",
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
    "agent_genesis_active_witness_binds_admitted_genesis",
    "organization_pcr_cannot_materialize_agent_active",
    "state_witness_uses_canonical_event_dot",
    "bare_event_id_state_tag_rejected",
    "historical_mls_leaf_cross_binding_verified",
    "duplicate_or_mismatched_mls_leaf_rejected",
    "minimal_metadata_forbids_agent_evidence_query",
    "current_valid_relation_reuses_signed_state_across_signals",
    "current_shared_state_does_not_share_device_verification",
    "current_reconnect_and_trusted_restore_do_not_renew_state",
    "current_delta_hydrates_same_canonical_root",
    "current_delta_missing_state_or_dependency_unresolved",
    "current_state_substitution_rejected",
    "current_cross_account_station_or_scope_rejected",
    "current_state_age_cannot_exceed_300_seconds",
    "current_repackaging_does_not_extend_original_deadline",
    "current_gate_expiry_shortens_effective_deadline",
    "current_known_revocation_invalidates_before_deadline",
    "historical_same_station_uses_original_admission",
    "historical_same_station_second_receipt_rejected",
    "historical_other_receiver_requires_own_receipt",
    "historical_original_lease_survives_later_authority_rotation",
    "agent_pcr_resume_retains_original_genesis_notary",
    "controller_device_binding_uses_authorization_event_admitted_key",
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
    stale_authority_state_lease: bool,
    resumed: bool,
}

impl Default for EvidenceConfig {
    fn default() -> Self {
        Self {
            authorization_status: AgentAuthorizationStatus::Active,
            lifecycle_status: AgentLifecycleStatus::Active,
            controller_eligibility: ControllerAccountEligibility::Active,
            controller_status: ControllerAccountStatus::Active,
            bare_authorization_tag: false,
            stale_authority_state_lease: false,
            resumed: false,
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

    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().context("case name missing")?;
        let expected = expected_class(case["expected"].as_str().context("expected missing")?)?;
        match execute_case(name, case) {
            Ok(observed) if observed == expected => {}
            Ok(observed) => failures.push(format!(
                "{name}: expected {expected:?}, observed {observed:?}"
            )),
            Err(error) => failures.push(format!("{name}: {error:#}")),
        }
    }
    if !failures.is_empty() {
        bail!(
            "Agent signer-evidence cases failed:\n{}",
            failures.join("\n")
        );
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
            current_outcome(&build_evidence(EvidenceConfig::default())?)
        }
        "current_stale_lease_is_unresolved" => {
            let fixture = build_evidence(EvidenceConfig {
                stale_authority_state_lease: true,
                ..EvidenceConfig::default()
            })?;
            current_stale_outcome(&fixture)
        }
        "current_paused_agent_rejected" => current_outcome(&build_evidence(EvidenceConfig {
            lifecycle_status: AgentLifecycleStatus::Paused,
            ..EvidenceConfig::default()
        })?),
        "current_inactive_controller_account_rejected" => {
            current_outcome(&build_evidence(EvidenceConfig {
                controller_eligibility: ControllerAccountEligibility::Inactive,
                controller_status: ControllerAccountStatus::Suspended,
                ..EvidenceConfig::default()
            })?)
        }
        "current_revoked_or_superseded_key_rejected" => {
            current_outcome(&build_evidence(EvidenceConfig {
                authorization_status: AgentAuthorizationStatus::Revoked,
                ..EvidenceConfig::default()
            })?)
        }
        "historical_destination_receipt_preserves_admission" => {
            historical_outcome(&build_evidence(EvidenceConfig::default())?, None, false)
        }
        "historical_current_authority_state_substitution_rejected" => {
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
            current_outcome(&fixture)
        }
        "producer_fetches_controller_gate_from_account_authority"
        | "controller_gate_exact_request_replay_is_byte_identical"
        | "controller_gate_request_id_conflict_is_zero_issuance"
        | "controller_gate_wrong_source_and_unknown_principal_are_indistinguishable"
        | "controller_gate_inactive_status_is_signed_not_forged_by_producer" => {
            execute_controller_gate_case(name, case)
        }
        "agent_genesis_active_witness_binds_admitted_genesis" => {
            let fixture = build_evidence(EvidenceConfig::default())?;
            let witness = &admission(&fixture.current)
                .agent_authority_state_evidence
                .state
                .agent_lifecycle_witness;
            if !matches!(&witness.provenance, AgentLifecycleProvenance::DelegatedPcrGenesis { realm_create_event_id }
                if realm_create_event_id == &witness.accepted_status_event.event_id)
            {
                bail!("active Agent witness does not bind its admitted genesis");
            }
            current_outcome(&fixture)
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
        "historical_mls_leaf_cross_binding_verified" => {
            historical_outcome(&build_evidence(EvidenceConfig::default())?, None, false)
        }
        "duplicate_or_mismatched_mls_leaf_rejected" => {
            let mut fixture = build_evidence(EvidenceConfig::default())?;
            if let AgentSignerEvidence::HistoricalEvent {
                event_admission: AgentEventAdmission::ReceiverReceipt { receipt },
                ..
            } = &mut fixture.historical
            {
                let controller = fixture
                    .verification_method
                    .as_str()
                    .split_once('#')
                    .map(|(controller, _)| controller)
                    .context("fixture verification method has no controller")?;
                receipt.verification_method =
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
        other => execute_reuse_case(other),
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
                "materializer_reads_selector_tuple_before_publishing_root",
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
                "current_service_method_evidence_verified",
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

fn current_outcome(fixture: &ExecutableEvidence) -> Result<OutcomeClass> {
    let verified_state = match verified_state(fixture, &fixture.current, &|_| Ok(())) {
        Ok(state) => state,
        Err(_) => return Ok(OutcomeClass::Rejected),
    };
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
    Ok(verdict_class(validate_current_agent_signer_evidence(
        Some(&fixture.current),
        &CurrentAgentSignerEvidenceValidationContext { common },
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
        },
    );
    match verdict {
        AgentSignerEvidenceVerdict::Unresolved(
            arkret_signatures::agent_evidence::AgentEvidenceUnresolvedReason::Stale,
        ) => Ok(OutcomeClass::Unresolved),
        other => bail!("expired signed current snapshot lease returned {other:?}"),
    }
}

fn current_verified_key(
    fixture: &ExecutableEvidence,
) -> Result<arkret_signatures::agent_evidence::VerifiedAgentSigningKey> {
    let state = verified_state(fixture, &fixture.current, &|_| Ok(()))?;
    let controller = public_key(fixture.controller_public_key);
    let authority = public_key(fixture.authority_public_key);
    let account = public_key(fixture.account_authority_public_key);
    match validate_current_agent_signer_evidence(
        Some(&fixture.current),
        &CurrentAgentSignerEvidenceValidationContext {
            common: common_context(fixture, &state, &controller, &authority, &account),
        },
    ) {
        AgentSignerEvidenceVerdict::Verified(key) => Ok(key),
        other => bail!("current verification returned {other:?}"),
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
    let verified_state = match verified_state(fixture, state_source, &|_| Ok(())) {
        Ok(state) => state,
        Err(_) => return Ok(OutcomeClass::Rejected),
    };
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
            producer_station_id: &fixture.authority_id,
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
    let seal_policy = |seal: &Seal| {
        let error = AgentEvidenceRejectedReason::SigningKeyMismatch;
        let NotarySig::Single(signature) = &seal.notary_signature else {
            return Err(error);
        };
        let state = &admission(evidence).agent_authority_state_evidence.state;
        let genesis: arkret_models_collaboration::events_payloads::realm::RealmCreatePayload =
            serde_json::from_value(
                serde_json::to_value(&state.pcr_genesis_event.payload).map_err(|_| error)?,
            )
            .map_err(|_| error)?;
        let descriptor = genesis
            .object
            .notary
            .signer_descriptor(&signature.verification_method)
            .or_else(|| {
                state
                    .accepted_delegated_notary_signers
                    .iter()
                    .find(|descriptor| {
                        descriptor.verification_method == signature.verification_method
                    })
            })
            .ok_or(error)?;
        descriptor.validate().map_err(|_| error)?;
        let bytes = seal.canonical_bytes_for_id().map_err(|_| error)?;
        if signature.payload_digest.as_str() != arkret_canonical::sha256_digest(&bytes)
            || seal
                .validate_id(arkret_canonical::DigestSuite::Sha256)
                .is_err()
        {
            return Err(error);
        }
        arkret_signatures::Ed25519DetachedJwsVerifier::new()
            .verify_detached_jws(
                &signature.jws,
                &bytes,
                &PublicKeyMaterial::Ed25519Raw {
                    bytes: arkret_canonical::base64url_decode(&descriptor.frozen_public_key_b64u)
                        .map_err(|_| error)?,
                },
            )
            .map_err(|_| error)
    };
    let signature_policy = |event: &arkret_wire::Event| {
        arkret_signatures::agent_evidence::verify_agent_accepted_event_signature(
            event,
            &|candidate| {
                (candidate == &fixture.authority_verification_method).then(|| {
                    PublicKeyMaterial::Ed25519Raw {
                        bytes: fixture.authority_public_key.to_vec(),
                    }
                })
            },
        )?;
        let witness = &admission(evidence)
            .agent_authority_state_evidence
            .state
            .agent_lifecycle_witness;
        if event.event_id == witness.accepted_status_event.event_id {
            lifecycle_policy(witness)
        } else {
            Ok(())
        }
    };
    verify_agent_evidence_state(
        admission(evidence),
        &AgentEvidenceStateVerificationContext {
            signer_id: &fixture.signer_id,
            signer_actor_id: &fixture.signer_actor_id,
            agent_key_id: &fixture.agent_key_id,
            controller_principal_id: &fixture.controller_principal_id,
            agent_key_authorize_event_id: &fixture.authorize_event_id,
            authorize_public_key_digest: &fixture.authorize_public_key_digest,
            verify_seal_signature: &seal_policy,
            verify_control_event_signature: &signature_policy,
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
    let now = issued_at + Duration::minutes(1);
    let expires_at = issued_at + Duration::seconds(300);
    let authority_state_lease_expires_at = if config.stale_authority_state_lease {
        now - Duration::seconds(1)
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
    let account_authority_service_did = authority_service_did.clone();
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
        DidUrl::new(format!("{account_authority_service_did}#account-authority"))
            .map_err(anyhow::Error::msg)?;
    let receiver_verification_method =
        DidUrl::new(format!("{receiver_service_did}#assertion-1")).map_err(anyhow::Error::msg)?;
    let agent_key_id = nes("runtime-1")?;
    let agent_key = agent_signing.verifying_key().to_bytes();
    let pcr_notary_verification_method =
        DidUrl::new(format!("{signer_did}#root")).map_err(anyhow::Error::msg)?;
    let pcr_notary_public_key = SigningKey::from_bytes(&[16; 32]).verifying_key().to_bytes();
    let create_payload = arkret_bootstrap::build_agent_pcr_create_payload(
        arkret_bootstrap::AgentPcrCreatePayloadInput {
            agent_id: signer_id.clone(),
            controller_principal_id: controller_principal_id.clone(),
            notary: arkret_wire::NotaryValue::single_signer(arkret_wire::NotarySignerDescriptor {
                actor_id: signer_actor_id.clone(),
                verification_method: pcr_notary_verification_method.clone(),
                key_kind: arkret_wire::NotaryKeyKind::Ed25519Raw32,
                jose_algorithm: arkret_wire::NotaryJoseAlgorithm::Ed25519,
                frozen_public_key_b64u: arkret_canonical::base64url_encode(pcr_notary_public_key),
                frozen_public_key_digest: Hash::new(arkret_canonical::sha256_digest(
                    pcr_notary_public_key,
                ))?,
            }),
            initial_resolution: arkret_models_identity::ResolutionCommitment {
                did: signer_did.clone(),
                method_history_head: hash_byte(0x31)?.to_string(),
                version_id: "1".to_owned(),
            },
            genesis_salt: arkret_wire::GenesisSalt::new(arkret_canonical::base64url_encode(
                &[0x31; 32],
            ))?,
            trust_domain: arkret_wire::TrustDomainId::new("ak:trust_domain:agent.example")?,
            created_at: issued_at,
        },
    )?;
    let mut genesis = arkret_wire::test_support::raw_event_at(
        EventKind::RealmCreate.as_str(),
        ScopeRef::RealmGenesis,
        signer_id.clone(),
        authority_id.clone(),
        0,
        Hlc::new("01970e589d21-0000-a13f9c2e")?,
        serde_json::to_value(create_payload)?,
        issued_at,
    )?;
    genesis.executed_by = Some(controller_actor_id.clone());
    genesis.authorization_ref = Some(controller_verification_method.clone().into());
    let controller_signer = arkret_signatures::Ed25519PayloadSigner::new(
        controller_signing.clone(),
        controller_did.clone(),
        controller_verification_method.clone(),
    );
    let sign_lifecycle = |event| -> Result<arkret_wire::Event> {
        let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            event,
            arkret_canonical::DigestSuite::Sha256,
        )?;
        arkret_signatures::sign_event(
            &mut authored,
            &controller_signer,
            &controller_verification_method,
            arkret_signatures::SignEventOptions::new().with_created_at(issued_at),
        )?;
        let mut event = authored.into_event();
        let producer = event.proofs[0].as_producer().context("producer proof")?;
        let mut admission = arkret_wire::StationAdmissionProof {
            kind: arkret_wire::StationAdmissionProofKind::StationAdmission,
            verification_method: authority_verification_method.clone(),
            event_digest: event.event_id.event_digest(),
            producer_proof_digest: arkret_wire::StationAdmissionProof::producer_proof_digest(
                producer,
            )?,
            producer_verification_method: producer.verification_method.clone(),
            producer_signing_key_did: arkret_wire::DidKey::new(format!(
                "did:key:{}",
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    &controller_signing.verifying_key().to_bytes()
                )
            ))
            .map_err(anyhow::Error::msg)?,
            producer_signer_resolution_evidence_ref: None,
            signer_resolution_evidence_ref: SignerEvidenceRef::new(format!(
                "ak:signer_evidence:{}",
                hash_byte(0x72)?
            ))?,
            applet_installation_digest: None,
            accepted_at: issued_at,
            jws: String::new(),
        };
        admission.jws =
            sign_ed25519_detached_jws(&authority_signing, &admission.canonical_binding_bytes()?)?;
        event
            .proofs
            .push(arkret_wire::EventProof::StationAdmission(admission));
        Ok(event)
    };
    let genesis = sign_lifecycle(genesis)?;
    let realm_id = genesis.realm_id.clone();
    let (accepted_status_event, lifecycle_provenance) = match config.lifecycle_status {
        AgentLifecycleStatus::Active if !config.resumed => {
            let provenance = AgentLifecycleProvenance::DelegatedPcrGenesis {
                realm_create_event_id: genesis.event_id.clone(),
            };
            (genesis.clone(), provenance)
        }
        status => {
            let (kind, transition) = match status {
                AgentLifecycleStatus::Paused => (EventKind::SelfAgentPause, "pause"),
                AgentLifecycleStatus::Deactivated => (EventKind::SelfAgentDeactivate, "deactivate"),
                AgentLifecycleStatus::Active => (EventKind::SelfAgentResume, "resume"),
            };
            let mut event = arkret_wire::test_support::raw_event_at(
                kind.as_str(),
                ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                signer_id.clone(),
                authority_id.clone(),
                1,
                Hlc::new("01970e589d21-0001-a13f9c2e")?,
                serde_json::json!({"transition": transition, "previous_status":if config.resumed {"paused"} else {"active"}, "status_changed_at":arkret_canonical::format_timestamp_canonical(issued_at)}),
                issued_at,
            )?;
            event.executed_by = Some(controller_actor_id.clone());
            event.authorization_ref = Some(controller_verification_method.clone().into());
            event.prev_refs = vec![genesis.event_id.clone()];
            let event = sign_lifecycle(event)?;
            let provenance = match status {
                AgentLifecycleStatus::Paused => AgentLifecycleProvenance::PauseAccepted {
                    pause_event_id: event.event_id.clone(),
                },
                AgentLifecycleStatus::Active => AgentLifecycleProvenance::ResumeAccepted {
                    resume_event_id: event.event_id.clone(),
                },
                _ => AgentLifecycleProvenance::DeactivateAccepted {
                    deactivate_event_id: event.event_id.clone(),
                },
            };
            (event, provenance)
        }
    };

    let runtime_public_key = arkret_models_collaboration::governance::agent_artifacts::PublicKey {
        kty: nes("OKP")?,
        kid: nes(verification_method.as_str())?,
        algorithm: nes("Ed25519")?,
        key: Base64UrlString::new(arkret_canonical::base64url_encode(agent_key))
            .map_err(anyhow::Error::msg)?,
        key_digest: None,
    };
    let authorize_public_key_digest = arkret_signatures::agent::validate_agent_runtime_public_key(
        &runtime_public_key,
        &verification_method,
    )?
    .authorization_digest;
    use arkret_models_collaboration::events_payloads::agent::{
        AgentKeyApprovalEvidence, AgentKeyApprovalEvidenceKind, AgentKeyAuthorizePayload,
        AgentKeyScope,
    };
    let payload = AgentKeyAuthorizePayload {
        agent_id: signer_id.clone(),
        key_id: agent_key_id.clone(),
        verification_method: verification_method.clone(),
        public_key: runtime_public_key,
        accountable_principal_id: controller_principal_id.clone(),
        agent_key_scope: AgentKeyScope {
            actions: vec!["read".to_owned()],
            resources: Vec::new(),
            constraints: Vec::new(),
        },
        audience: vec![authority_id.to_string()],
        issued_at,
        expires_at: Some(expires_at),
        approval_evidence: AgentKeyApprovalEvidence {
            kind: AgentKeyApprovalEvidenceKind::PairingRequest,
            evidence_ref: None,
            request_canonical_digest: Some(hash_byte(0x51)?),
            pairing_request_id: Some(
                arkret_wire::OpaqueLocalId::new("fixture-pairing").map_err(anyhow::Error::msg)?,
            ),
            approved_by: Some(controller_principal_id.clone()),
        },
        supersedes: Vec::new(),
        revocation_check_ref: None,
        runtime_attestation: None,
    };
    let mut key_authorization = arkret_wire::test_support::raw_event_at(
        EventKind::AgentKeyAuthorize.as_str(),
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        signer_id.clone(),
        authority_id.clone(),
        1,
        Hlc::new("01970e589d21-0001-a13f9c2e")?,
        serde_json::to_value(payload)?,
        issued_at,
    )?;
    key_authorization.prev_refs = vec![genesis.event_id.clone()];
    key_authorization.executed_by = Some(controller_actor_id.clone());
    key_authorization.authorization_ref = Some(controller_verification_method.clone().into());
    let key_authorization = sign_lifecycle(key_authorization)?;
    let authorize_event_id = key_authorization.event_id.clone();
    let tag = if config.bare_authorization_tag {
        authorize_event_id.to_string()
    } else {
        format!("{authorize_event_id}:0")
    };
    let key_cell_value = vec![AgentKeyCellEntry {
        tag: nes(&tag)?,
        value: serde_json::to_value(&key_authorization.payload)?,
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
    // `ak.component.agent.status.v1` is an `fsm` and therefore a causal register
    // (`event-auth-state-resolution.md` §9.3.1.5), so its §6.2.1 leaf hashes the
    // head set rather than the settled status.
    let lifecycle_heads = vec![arkret_models_identity::AgentLifecycleHead {
        event_id: accepted_status_event.event_id.clone(),
        value: config.lifecycle_status,
    }];
    let lifecycle_leaf_digest = arkret_state::state::state_root::state_leaf_hash_from_state_object(
        &arkret_wire::CellRef::new(lifecycle_cell_ref.as_str().to_owned())?,
        serde_json::json!({
            "heads": lifecycle_heads
                .iter()
                .map(|head| serde_json::json!({
                    "event_id": head.event_id.as_str(),
                    "value": head.value,
                }))
                .collect::<Vec<_>>(),
        }),
        arkret_canonical::DigestSuite::Sha256,
    )?;

    let mut key_seal = make_seal(
        &realm_id,
        Vec::new(),
        key_leaf_digest.clone(),
        1,
        issued_at + Duration::seconds(1),
        "01970e589d21-0000-a13f9c2e",
        &pcr_notary_verification_method,
    )?;
    key_seal.delta = vec![authorize_event_id.event_digest()];
    sign_fixture_seal(&mut key_seal)?;
    let mut lifecycle_seal = make_seal(
        &realm_id,
        vec![key_seal.id.clone()],
        lifecycle_leaf_digest.clone(),
        2,
        issued_at + Duration::seconds(2),
        "01970e589d21-0001-a13f9c2e",
        &pcr_notary_verification_method,
    )?;
    lifecycle_seal.delta = vec![accepted_status_event.event_id.event_digest()];
    sign_fixture_seal(&mut lifecycle_seal)?;
    let authorization = AgentAuthorizationEvidence {
        status: config.authorization_status,
        authorized_event_id: authorize_event_id.clone(),
        accepted_seal_id: key_seal.id.clone(),
        accepted_at: key_seal.sealed_at,
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
        provenance: lifecycle_provenance,
        accepted_status_event,
        seal_id: lifecycle_seal.id.clone(),
        state_root: lifecycle_leaf_digest.clone(),
        seal: lifecycle_seal.clone(),
        cell_ref: lifecycle_cell_ref,
        cell_value: config.lifecycle_status,
        cell_heads: lifecycle_heads,
        leaf_digest: lifecycle_leaf_digest,
        leaf_index: 0,
        leaf_count: 1,
        inclusion_proof: Vec::new(),
    };
    let core = AgentAuthorityState {
        authority_id: authority_id.clone(),
        principal_control_realm_id: realm_id.clone(),
        pcr_genesis_event: genesis,
        key_authorization_event: key_authorization,
        frontier_seal_id: lifecycle_seal.id.clone(),
        frontier_state_root: lifecycle_seal.state_root.clone(),
        authorization,
        key_state_witness,
        key_transition_witness: None,
        agent_lifecycle_witness: lifecycle_witness,
        seal_lineages: vec![key_seal, lifecycle_seal],
        accepted_delegated_notary_signers: Vec::new(),
    };
    let state_digest = canonical_hash(&core)?;
    let mut authority_state_evidence = AgentAuthorityStateEvidence {
        state: core,
        state_digest: state_digest.clone(),
        lease: AgentAuthorityStateLease {
            authority_kind: nes("agent_authority")?,
            authority_id: authority_id.clone(),
            verification_method: authority_verification_method.clone(),
            state_digest: state_digest.clone(),
            issued_at,
            expires_at: authority_state_lease_expires_at,
            proof: pending_proof()?,
        },
    };
    arkret_signatures::agent_evidence::sign_agent_authority_state_lease(
        &mut authority_state_evidence.lease,
        &authority_signing,
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
    arkret_signatures::agent_evidence::sign_controller_account_gate_attestation(
        &mut gate,
        &account_signing,
    )?;
    let admission_evidence_digest = canonical_hash(&serde_json::json!({
        "agent_authority_state_evidence": authority_state_evidence,
        "controller_account_gate_attestation": gate,
    }))?;
    let admission = AgentAdmissionEvidence {
        agent_authority_state_evidence: authority_state_evidence,
        controller_account_gate_attestation: gate,
        admission_evidence_digest: admission_evidence_digest.clone(),
    };

    let current = AgentSignerEvidence::CurrentAdmission {
        schema: nes(SchemaId::AGENT_SIGNER_EVIDENCE_V1)?,
        admission_evidence: admission.clone(),
        transparency: None,
    };

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
    arkret_signatures::agent_evidence::sign_agent_event_admission_receipt(
        &mut receipt,
        &receiver_verification_method,
        &receiver_signing,
    )?;
    let historical = AgentSignerEvidence::HistoricalEvent {
        schema: nes(SchemaId::AGENT_SIGNER_EVIDENCE_V1)?,
        admission_evidence: admission,
        event_admission: AgentEventAdmission::ReceiverReceipt { receipt },
        transparency: None,
    };

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
            jws: String::new(),
        }),
        sealed_at,
        hlc: Hlc::new(hlc)?,
    };
    sign_fixture_seal(&mut seal)?;
    Ok(seal)
}

fn sign_fixture_seal(seal: &mut Seal) -> Result<()> {
    let bytes = seal.canonical_bytes_for_id()?;
    let NotarySig::Single(signature) = &mut seal.notary_signature else {
        bail!("fixture requires one signer");
    };
    signature.payload_digest = Hash::new(arkret_canonical::sha256_digest(&bytes))?;
    signature.jws = sign_ed25519_detached_jws(&SigningKey::from_bytes(&[16; 32]), &bytes)?;
    seal.id = seal.derive_id(arkret_canonical::DigestSuite::Sha256)?;
    Ok(())
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
        "verify_authorize_event_controller_producer_proof",
        "recompute_public_key_digest",
        "match_authorize_event_inline_public_key",
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

#[cfg(test)]
mod lifecycle_regressions {
    use super::*;

    #[test]
    fn another_station_valid_gate_cannot_substitute_controller_account_authority() {
        let mut fixture = build_evidence(EvidenceConfig::default()).unwrap();
        let other = Did::new("did:webvh:zother:other.example").unwrap();
        fixture.account_authority_id = project_did_to_core_id(&other).unwrap();
        fixture.account_authority_verification_method =
            DidUrl::new(format!("{other}#account-authority")).unwrap();
        let AgentSignerEvidence::CurrentAdmission {
            admission_evidence, ..
        } = &mut fixture.current
        else {
            unreachable!()
        };
        let gate = &mut admission_evidence.controller_account_gate_attestation;
        gate.authority_id = fixture.account_authority_id.clone();
        gate.verification_method = fixture.account_authority_verification_method.clone();
        arkret_signatures::agent_evidence::sign_controller_account_gate_attestation(
            gate,
            &SigningKey::from_bytes(&[14; 32]),
        )
        .unwrap();
        admission_evidence.admission_evidence_digest =
            arkret_signatures::agent_evidence::agent_admission_evidence_digest(
                &admission_evidence.agent_authority_state_evidence,
                &admission_evidence.controller_account_gate_attestation,
            )
            .unwrap();
        assert_eq!(current_outcome(&fixture).unwrap(), OutcomeClass::Rejected);
    }

    #[test]
    fn current_refresh_reuses_only_verified_unchanged_state_and_checks_new_signatures() {
        use arkret_signatures::agent_evidence::{
            refresh_current_agent_signer_evidence, sign_agent_authority_state_lease,
            sign_controller_account_gate_attestation,
        };
        let fixture = build_evidence(EvidenceConfig::default()).unwrap();
        let previous = current_verified_key(&fixture).unwrap();
        let controller = public_key(fixture.controller_public_key);
        let authority = public_key(fixture.authority_public_key);
        let account = public_key(fixture.account_authority_public_key);
        let context = CurrentAgentSignerEvidenceValidationContext {
            common: common_context(
                &fixture,
                previous.verified_state(),
                &controller,
                &authority,
                &account,
            ),
        };
        let mut refreshed = fixture.current.clone();
        let AgentSignerEvidence::CurrentAdmission {
            admission_evidence, ..
        } = &mut refreshed
        else {
            unreachable!()
        };
        admission_evidence
            .agent_authority_state_evidence
            .lease
            .issued_at += Duration::seconds(30);
        admission_evidence
            .agent_authority_state_evidence
            .lease
            .expires_at += Duration::seconds(30);
        sign_agent_authority_state_lease(
            &mut admission_evidence.agent_authority_state_evidence.lease,
            &SigningKey::from_bytes(&[13; 32]),
        )
        .unwrap();
        admission_evidence
            .controller_account_gate_attestation
            .issued_at += Duration::seconds(30);
        admission_evidence
            .controller_account_gate_attestation
            .expires_at += Duration::seconds(30);
        sign_controller_account_gate_attestation(
            &mut admission_evidence.controller_account_gate_attestation,
            &SigningKey::from_bytes(&[14; 32]),
        )
        .unwrap();
        admission_evidence.admission_evidence_digest =
            arkret_signatures::agent_evidence::agent_admission_evidence_digest(
                &admission_evidence.agent_authority_state_evidence,
                &admission_evidence.controller_account_gate_attestation,
            )
            .unwrap();
        let AgentSignerEvidenceVerdict::Verified(next) =
            refresh_current_agent_signer_evidence(Some(&refreshed), &context, Some(&previous))
        else {
            panic!("legitimate signed lease/gate refresh rejected unchanged verified state");
        };
        assert_eq!(previous.state_digest(), next.state_digest());
        assert_ne!(
            previous.admission_evidence_digest(),
            next.admission_evidence_digest()
        );
        assert_eq!(previous.expires_at(), next.expires_at());
        for mutation in 0..3 {
            let mut changed = refreshed.clone();
            let AgentSignerEvidence::CurrentAdmission {
                admission_evidence, ..
            } = &mut changed
            else {
                unreachable!()
            };
            if mutation == 0 {
                sign_controller_account_gate_attestation(
                    &mut admission_evidence.controller_account_gate_attestation,
                    &SigningKey::from_bytes(&[99; 32]),
                )
                .unwrap();
            } else if mutation == 1 {
                admission_evidence
                    .agent_authority_state_evidence
                    .state_digest = hash_byte(0x77).unwrap();
            } else {
                let gate = &mut admission_evidence.controller_account_gate_attestation;
                gate.expires_at = gate.issued_at + Duration::seconds(301);
                sign_controller_account_gate_attestation(gate, &SigningKey::from_bytes(&[14; 32]))
                    .unwrap();
            }
            admission_evidence.admission_evidence_digest =
                arkret_signatures::agent_evidence::agent_admission_evidence_digest(
                    &admission_evidence.agent_authority_state_evidence,
                    &admission_evidence.controller_account_gate_attestation,
                )
                .unwrap();
            assert!(matches!(
                refresh_current_agent_signer_evidence(Some(&changed), &context, Some(&previous)),
                AgentSignerEvidenceVerdict::Rejected(_)
            ));
        }
    }

    #[test]
    fn lifecycle_witness_has_no_derived_status_field() {
        let fixture = build_evidence(EvidenceConfig::default()).unwrap();
        let witness = &admission(&fixture.current)
            .agent_authority_state_evidence
            .state
            .agent_lifecycle_witness;
        let mut value = serde_json::to_value(witness).unwrap();
        assert!(value.get("status").is_none());
        value["status"] = serde_json::json!("active");
        assert!(serde_json::from_value::<AgentLifecycleWitness>(value).is_err());
    }

    #[test]
    fn authorization_activation_uses_seal_time_independently_of_station_admission() {
        let fixture = build_evidence(EvidenceConfig::default()).unwrap();
        current_verified_key(&fixture).unwrap();
        let mut evidence = fixture.current.clone();
        let AgentSignerEvidence::CurrentAdmission {
            admission_evidence: ref mut admission,
            ..
        } = evidence
        else {
            unreachable!();
        };
        let state = &mut admission.agent_authority_state_evidence.state;
        let station_time = state
            .key_authorization_event
            .proofs
            .iter()
            .find_map(arkret_wire::EventProof::as_station_admission)
            .unwrap()
            .accepted_at;
        assert!(station_time < state.authorization.accepted_at);
        assert_eq!(
            state.authorization.accepted_at,
            state.key_state_witness.seal.sealed_at
        );
        state.authorization.accepted_at = station_time;
        admission.agent_authority_state_evidence.state_digest = canonical_hash(state).unwrap();
        admission.admission_evidence_digest =
            arkret_signatures::agent_evidence::agent_admission_evidence_digest(
                &admission.agent_authority_state_evidence,
                &admission.controller_account_gate_attestation,
            )
            .unwrap();
        assert!(verified_state(&fixture, &evidence, &|_| Ok(())).is_err());
    }

    #[test]
    fn signed_lifecycle_requires_the_exact_provenance_event_and_controller() {
        let fixture = build_evidence(EvidenceConfig::default()).unwrap();
        verified_state(&fixture, &fixture.current, &|_| Ok(())).unwrap();
        for mutation in 0..6 {
            let mut evidence = fixture.current.clone();
            let AgentSignerEvidence::CurrentAdmission {
                admission_evidence: ref mut admission,
                ..
            } = evidence
            else {
                unreachable!();
            };
            let witness = &mut admission
                .agent_authority_state_evidence
                .state
                .agent_lifecycle_witness;
            match mutation {
                0 => {
                    let AgentLifecycleProvenance::DelegatedPcrGenesis {
                        realm_create_event_id,
                        ..
                    } = &mut witness.provenance
                    else {
                        unreachable!();
                    };
                    *realm_create_event_id = event_id(99).unwrap();
                }
                1 => witness.accepted_status_event.event_id = event_id(98).unwrap(),
                2 => {
                    witness.accepted_status_event.executed_by =
                        Some(fixture.signer_actor_id.clone())
                }
                3 => witness.accepted_status_event.created_at += Duration::days(365),
                4 => {
                    let arkret_wire::EventProof::StationAdmission(proof) =
                        &mut witness.accepted_status_event.proofs[1]
                    else {
                        unreachable!();
                    };
                    proof.producer_signing_key_did = arkret_wire::DidKey::new(format!(
                        "did:key:{}",
                        arkret_canonical::ed25519_pubkey_to_did_key_multibase(&[99; 32])
                    ))
                    .unwrap();
                }
                _ => {
                    witness.accepted_status_event.proofs.pop();
                }
            }
            // Rebind the enclosing digests, so rejection cannot be attributed
            // merely to stale outer hashes after the inner witness changed.
            admission.agent_authority_state_evidence.state_digest =
                canonical_hash(&admission.agent_authority_state_evidence.state).unwrap();
            admission.admission_evidence_digest =
                arkret_signatures::agent_evidence::agent_admission_evidence_digest(
                    &admission.agent_authority_state_evidence,
                    &admission.controller_account_gate_attestation,
                )
                .unwrap();
            assert!(
                verified_state(&fixture, &evidence, &|_| Ok(())).is_err(),
                "mutation {mutation}"
            );
        }
    }
}

fn evidence_ref(byte: u8) -> Result<SignerEvidenceRef> {
    Ok(SignerEvidenceRef::new(format!(
        "ak:signer_evidence:{}",
        hash_byte(byte)?
    ))?)
}

fn execute_reuse_case(name: &str) -> Result<OutcomeClass> {
    match name {
        "current_valid_relation_reuses_signed_state_across_signals" => {
            let fixture = build_evidence(EvidenceConfig::default())?;
            let verified = current_verified_key(&fixture)?;
            let original = canonical_hash(&fixture.current)?;
            let key = SigningKey::from_bytes(&[12; 32]);
            let verifying = ed25519_dalek::VerifyingKey::from_bytes(verified.key())?;
            for sequence in 0..100 {
                let message = format!("relation-message-{sequence}");
                if !verified.permits(
                    &fixture.signer_actor_id,
                    &fixture.verification_method,
                    fixture.now,
                ) {
                    bail!("verified relation did not permit the actual sender");
                }
                verifying.verify_strict(message.as_bytes(), &key.sign(message.as_bytes()))?;
            }
            if original != canonical_hash(&fixture.current)? {
                bail!("message processing changed shared evidence");
            }
            Ok(OutcomeClass::Verified)
        }
        "current_shared_state_does_not_share_device_verification" => {
            let fixture = build_evidence(EvidenceConfig::default())?;
            for _ in 0..2 {
                if current_outcome(&fixture)? != OutcomeClass::Verified {
                    return Ok(OutcomeClass::Rejected);
                }
            }
            Ok(OutcomeClass::Verified)
        }
        "current_reconnect_and_trusted_restore_do_not_renew_state" => {
            let mut fixture = build_evidence(EvidenceConfig::default())?;
            let bytes = arkret_canonical::canonical_json_bytes(&fixture.current)?;
            for _ in 0..3 {
                fixture.current = serde_json::from_slice(&bytes)?;
                if current_outcome(&fixture)? != OutcomeClass::Verified {
                    return Ok(OutcomeClass::Rejected);
                }
            }
            if bytes != arkret_canonical::canonical_json_bytes(&fixture.current)? {
                bail!("restore renewed evidence");
            }
            Ok(OutcomeClass::Verified)
        }
        "current_delta_hydrates_same_canonical_root"
        | "current_delta_missing_state_or_dependency_unresolved" => {
            use arkret_models_collaboration::current_signer_evidence::CompactAgentSignerResolutionEvidence;
            let fixture = build_evidence(EvidenceConfig::default())?;
            let state = &admission(&fixture.current).agent_authority_state_evidence;
            let root = arkret_models_identity::AuthenticatedSignerResolutionEvidence::Agent {
                signer_id: fixture.signer_id.clone(),
                verification_method: fixture.verification_method.clone(),
                agent_signer_evidence: Box::new(fixture.current.clone()),
                attester_signer_evidence_ref: evidence_ref(0x81)?,
                account_authority_signer_evidence_ref: evidence_ref(0x83)?,
                receiver_signer_evidence_ref: None,
            };
            let compact = CompactAgentSignerResolutionEvidence::from_full(
                &root,
                &[state.state_digest.clone()],
            )?;
            let mut states = std::collections::BTreeMap::new();
            if name == "current_delta_missing_state_or_dependency_unresolved" {
                if compact.hydrate(&states).is_ok() {
                    bail!("missing state became usable");
                }
                return Ok(OutcomeClass::Unresolved);
            }
            states.insert(state.state_digest.clone(), state.state.clone());
            if compact.hydrate(&states)? != root {
                bail!("hydration changed canonical root");
            }
            Ok(OutcomeClass::Verified)
        }
        "current_state_substitution_rejected" => {
            let mut fixture = build_evidence(EvidenceConfig::default())?;
            let AgentSignerEvidence::CurrentAdmission {
                admission_evidence, ..
            } = &mut fixture.current
            else {
                unreachable!()
            };
            admission_evidence
                .agent_authority_state_evidence
                .state_digest = hash_byte(0xa8)?;
            current_outcome(&fixture)
        }
        "current_cross_account_station_or_scope_rejected" => {
            let mut fixture = build_evidence(EvidenceConfig::default())?;
            let key = current_verified_key(&fixture)?;
            let wrong_station = service_id("did:webvh:zother:other.example")?;
            for actor in [
                ActorId::account(AccountId::new(
                    fixture.signer_id.clone(),
                    wrong_station.clone(),
                )),
                ActorId::account(AccountId::new(
                    fixture.controller_principal_id.clone(),
                    fixture.authority_id.clone(),
                )),
            ] {
                if key.permits(&actor, &fixture.verification_method, fixture.now) {
                    bail!("cached key crossed account binding");
                }
            }
            let wrong_method = DidUrl::new(format!(
                "{}#other-key",
                fixture
                    .verification_method
                    .as_str()
                    .split_once('#')
                    .context("method")?
                    .0
            ))
            .map_err(anyhow::Error::msg)?;
            if key.permits(&fixture.signer_actor_id, &wrong_method, fixture.now) {
                bail!("cached key crossed method binding");
            }
            fixture.authority_id = service_id("did:webvh:zother:other.example")?;
            current_outcome(&fixture)
        }
        "current_state_age_cannot_exceed_300_seconds"
        | "current_repackaging_does_not_extend_original_deadline" => {
            let mut fixture = build_evidence(EvidenceConfig::default())?;
            fixture.now = admission(&fixture.current)
                .agent_authority_state_evidence
                .lease
                .issued_at
                + Duration::seconds(301);
            current_stale_outcome(&fixture)
        }
        "current_gate_expiry_shortens_effective_deadline" => {
            let mut fixture = build_evidence(EvidenceConfig::default())?;
            let now = fixture.now;
            let AgentSignerEvidence::CurrentAdmission {
                admission_evidence, ..
            } = &mut fixture.current
            else {
                unreachable!()
            };
            admission_evidence
                .controller_account_gate_attestation
                .expires_at = now;
            arkret_signatures::agent_evidence::sign_controller_account_gate_attestation(
                &mut admission_evidence.controller_account_gate_attestation,
                &SigningKey::from_bytes(&[14; 32]),
            )?;
            admission_evidence.admission_evidence_digest =
                arkret_signatures::agent_evidence::agent_admission_evidence_digest(
                    &admission_evidence.agent_authority_state_evidence,
                    &admission_evidence.controller_account_gate_attestation,
                )
                .map_err(|error| anyhow!("admission digest rejected: {error:?}"))?;
            current_stale_outcome(&fixture)
        }
        "current_known_revocation_invalidates_before_deadline" => {
            current_outcome(&build_evidence(EvidenceConfig {
                authorization_status: AgentAuthorizationStatus::Revoked,
                ..EvidenceConfig::default()
            })?)
        }
        "historical_original_lease_survives_later_authority_rotation" => {
            let mut fixture = build_evidence(EvidenceConfig::default())?;
            fixture.now += Duration::days(365);
            historical_outcome(&fixture, None, false)
        }
        "agent_pcr_resume_retains_original_genesis_notary" => {
            let fixture = build_evidence(EvidenceConfig {
                resumed: true,
                ..EvidenceConfig::default()
            })?;
            let state = &admission(&fixture.current)
                .agent_authority_state_evidence
                .state;
            if state.pcr_genesis_event.event_id
                == state.agent_lifecycle_witness.accepted_status_event.event_id
                || !matches!(
                    state.agent_lifecycle_witness.provenance,
                    AgentLifecycleProvenance::ResumeAccepted { .. }
                )
            {
                bail!("Resume fixture lost the original genesis");
            }
            current_outcome(&fixture)
        }
        "controller_device_binding_uses_authorization_event_admitted_key" => {
            let fixture = build_evidence(EvidenceConfig::default())?;
            let key = current_verified_key(&fixture)?;
            let mut event = admission(&fixture.current)
                .agent_authority_state_evidence
                .state
                .key_authorization_event
                .clone();
            let Some(arkret_wire::EventProof::StationAdmission(proof)) = event.proofs.get_mut(1)
            else {
                bail!("missing original Station proof")
            };
            proof.producer_signing_key_did = arkret_wire::DidKey::new(format!(
                "did:key:{}",
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                    &SigningKey::from_bytes(&[99; 32]).verifying_key().to_bytes()
                )
            ))
            .map_err(anyhow::Error::msg)?;
            proof.jws = sign_ed25519_detached_jws(
                &SigningKey::from_bytes(&[13; 32]),
                &proof.canonical_binding_bytes()?,
            )?;
            if arkret_signatures::agent_evidence::verify_agent_accepted_event_signature(
                &event,
                &|method| {
                    (method == &fixture.authority_verification_method)
                        .then(|| public_key(fixture.authority_public_key))
                },
            )
            .is_ok()
            {
                bail!("another admitted producer key accepted the original controller signature");
            }
            if !key.permits(
                &fixture.signer_actor_id,
                &fixture.verification_method,
                fixture.now,
            ) {
                bail!("original controller device admission lost its binding");
            }
            Ok(OutcomeClass::Verified)
        }
        "historical_same_station_uses_original_admission"
        | "historical_other_receiver_requires_own_receipt" => {
            let mut fixture = build_evidence(EvidenceConfig::default())?;
            install_original_station_admission(&mut fixture)?;
            let receiver = (name == "historical_other_receiver_requires_own_receipt")
                .then(|| service_id("did:webvh:zother:other.example"))
                .transpose()?;
            historical_outcome(&fixture, receiver, false)
        }
        "historical_same_station_second_receipt_rejected" => {
            let mut fixture = build_evidence(EvidenceConfig::default())?;
            fixture.receiver_id = fixture.authority_id.clone();
            fixture.receiver_verification_method = fixture.authority_verification_method.clone();
            fixture.receiver_public_key = fixture.authority_public_key;
            let AgentSignerEvidence::HistoricalEvent {
                event_admission: AgentEventAdmission::ReceiverReceipt { receipt },
                ..
            } = &mut fixture.historical
            else {
                unreachable!()
            };
            receipt.receiver_id = fixture.receiver_id.clone();
            receipt.accepted_at = fixture.producer_accepted_at;
            arkret_signatures::agent_evidence::sign_agent_event_admission_receipt(
                receipt,
                &fixture.receiver_verification_method,
                &SigningKey::from_bytes(&[13; 32]),
            )?;
            historical_outcome(&fixture, None, false)
        }
        _ => bail!("unimplemented Agent reuse case {name}"),
    }
}

fn install_original_station_admission(fixture: &mut ExecutableEvidence) -> Result<()> {
    let agent_key = SigningKey::from_bytes(&[12; 32]);
    let authority_key = SigningKey::from_bytes(&[13; 32]);
    let did = Did::new(
        fixture
            .verification_method
            .as_str()
            .split_once('#')
            .context("Agent method")?
            .0,
    )?;
    let event = arkret_wire::test_support::raw_event_at(
        EventKind::SelfAgentPause.as_str(),
        ScopeRef::Realm {
            realm_id: fixture.realm_id.clone(),
        },
        fixture.signer_id.clone(),
        fixture.authority_id.clone(),
        4,
        Hlc::new("01970e589d21-0004-a13f9c2e")?,
        serde_json::json!({"transition":"pause"}),
        fixture.producer_accepted_at,
    )?;
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret_canonical::DigestSuite::Sha256,
    )?;
    let signer = arkret_signatures::Ed25519PayloadSigner::new(
        agent_key.clone(),
        did,
        fixture.verification_method.clone(),
    );
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        &fixture.verification_method,
        arkret_signatures::SignEventOptions::new().with_created_at(fixture.producer_accepted_at),
    )?;
    let mut event = authored.into_event();
    let producer = event.proofs[0].as_producer().context("producer")?;
    let mut proof = arkret_wire::StationAdmissionProof {
        kind: arkret_wire::StationAdmissionProofKind::StationAdmission,
        verification_method: fixture.authority_verification_method.clone(),
        event_digest: event.event_id.event_digest(),
        producer_proof_digest: arkret_wire::StationAdmissionProof::producer_proof_digest(producer)?,
        producer_verification_method: fixture.verification_method.clone(),
        producer_signing_key_did: arkret_wire::DidKey::new(format!(
            "did:key:{}",
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                &agent_key.verifying_key().to_bytes()
            )
        ))
        .map_err(anyhow::Error::msg)?,
        producer_signer_resolution_evidence_ref: Some(
            fixture.producer_signer_resolution_evidence_ref.clone(),
        ),
        signer_resolution_evidence_ref: evidence_ref(0x84)?,
        applet_installation_digest: None,
        accepted_at: fixture.producer_accepted_at,
        jws: String::new(),
    };
    proof.jws = sign_ed25519_detached_jws(&authority_key, &proof.canonical_binding_bytes()?)?;
    event
        .proofs
        .push(arkret_wire::EventProof::StationAdmission(proof));
    fixture.event_id = event.event_id.clone();
    fixture.receiver_id = fixture.authority_id.clone();
    fixture.receiver_verification_method = fixture.authority_verification_method.clone();
    fixture.receiver_public_key = fixture.authority_public_key;
    let AgentSignerEvidence::HistoricalEvent {
        event_admission, ..
    } = &mut fixture.historical
    else {
        unreachable!()
    };
    *event_admission = AgentEventAdmission::StationAdmission {
        accepted_event: event,
    };
    Ok(())
}
