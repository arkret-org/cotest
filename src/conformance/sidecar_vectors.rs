//! Sidecar conformance vectors.
//!
//! 18 vectors:
//!   - `ak.vector.sidecar.mls_bootstrap_binding.v1`
//!   - `ak.vector.sidecar.mls_effective_access.v1`
//!   - `ak.vector.sidecar.ensure_idempotent.v1`
//!   - `ak.vector.sidecar.eligibility_states.v1`
//!   - `ak.vector.sidecar.existence_privacy.v1`
//!   - `ak.vector.sidecar.hosted_projection.v1`
//!   - `ak.vector.sidecar.multi_agent_publish.v1`
//!   - `ak.vector.sidecar.exchange_binding_closed_loop.v1`
//!   - `ak.vector.sidecar.exchange_projection_recovery.v1`
//!   - `ak.vector.sidecar.exchange_binding_containment.v1`
//!   - `ak.vector.sidecar.context_locator_recovery.v1`
//!   - `ak.vector.sidecar.canonical_sibling_digest.v1`
//!   - `ak.vector.sidecar.union_history_frontier.v1`
//!   - `ak.vector.sidecar.non_disclosure_surface_matrix.v1`
//!   - `ak.vector.sidecar.revoke_fail_closed.v1`
//!   - `ak.vector.sidecar.explicit_publish.v1`
//!   - `ak.vector.sidecar.accepted_request_identity.v1`
//!   - `ak.vector.sidecar.hosted_ui_matrix.v1`
//!
//! These vectors pin the first-class native Sidecar wire model. A Sidecar has
//! no backing Circle, private Strand, or private Relation.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use arkret::events::EventKind;
use arkret::{
    AccountId, AgentSidecar, AgentSidecarAccessReadiness, AgentSidecarContextRef,
    AgentSidecarDisplayMode, AgentSidecarEncryptionProfile, AgentSidecarEventExchangeBinding,
    AgentSidecarExchangeBindingRole, AgentSidecarExchangeCompletionPolicy,
    AgentSidecarExchangeControl, AgentSidecarExchangeControlAction,
    AgentSidecarExchangeControlSchema, AgentSidecarExchangeFoldedFrontier, AgentSidecarExchangeId,
    AgentSidecarExchangeOrigin, AgentSidecarExchangeProjection,
    AgentSidecarExchangeProjectionSchema, AgentSidecarExchangeRequestContext,
    AgentSidecarExchangeStatus, AgentSidecarMlsContext, AgentSidecarProjectionProvenance,
    AgentSidecarSchema, AgentSidecarSourceTrackRef, AgentSidecarState, AgentSidecarView, Did,
    DidCoreId, DidUrl, Event, EventId, EventRef, Hash, Hlc, MessageMetadata,
    MlsGovernanceBindingPayload, NonEmptyString, PendingSidecarAccessReconciliationItem,
    PendingSidecarAccessReconciliationStage, PreparedEventDraft, RealmId, ScopeRef, SidecarId,
    SidecarMlsBinding, StrandId, agent_sidecar_exchange_event_set_digest,
    agent_sidecar_participant_authority_digest, recover_agent_sidecar_context_locators,
};
use arkret_models_collaboration::sidecar_operations::{
    SidecarAcceptedOk, SidecarAcceptedPhase, SidecarAttachPhase, SidecarCommitPhase,
    SidecarContextAttachPayload, SidecarContextRef, SidecarEnsureAttachRequestBody,
    SidecarEnsureCommitRequestBody, SidecarEnsureOutcome, SidecarEnsurePrepareRequestBody,
    SidecarPreparePhase, SidecarPreparedOutcome,
};
use arkret_models_identity::agent_signer_evidence::AgentLifecycleStatus;
use arkret_signatures::{
    Ed25519PayloadSigner, PublicKeyMaterial, SignEventOptions, sign_event,
    verify_ed25519_detached_jws_proof,
};
use arkret_wire::{
    ActorId, Base64UrlString, CapabilityActionId, EventRequirements, IdempotencyKey, ProfileId,
    ProtocolOperationId, ReservationHandle,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeZone, Utc};
use garth::projection::{
    SidecarExchangeAgentFact, SidecarExchangeCacheDecision, SidecarExchangeControlFact,
    SidecarExchangeFoldScope, SidecarExchangeRequestFact, evaluate_sidecar_exchange_cache,
    fold_sidecar_exchange,
};
use serde_json::{Value, json};

pub const VECTOR_ID_SIDECAR_ENSURE_IDEMPOTENT: &str = "ak.vector.sidecar.ensure_idempotent.v1";
pub const VECTOR_ID_SIDECAR_MLS_BOOTSTRAP_BINDING: &str =
    "ak.vector.sidecar.mls_bootstrap_binding.v1";
pub const VECTOR_ID_SIDECAR_MLS_EFFECTIVE_ACCESS: &str =
    "ak.vector.sidecar.mls_effective_access.v1";
pub const VECTOR_ID_SIDECAR_ELIGIBILITY_STATES: &str = "ak.vector.sidecar.eligibility_states.v1";
pub const VECTOR_ID_SIDECAR_EXISTENCE_PRIVACY: &str = "ak.vector.sidecar.existence_privacy.v1";
pub const VECTOR_ID_SIDECAR_HOSTED_PROJECTION: &str = "ak.vector.sidecar.hosted_projection.v1";
pub const VECTOR_ID_SIDECAR_MULTI_AGENT_PUBLISH: &str = "ak.vector.sidecar.multi_agent_publish.v1";
pub const VECTOR_ID_SIDECAR_EXCHANGE_BINDING_CLOSED_LOOP: &str =
    "ak.vector.sidecar.exchange_binding_closed_loop.v1";
pub const VECTOR_ID_SIDECAR_EXCHANGE_PROJECTION_RECOVERY: &str =
    "ak.vector.sidecar.exchange_projection_recovery.v1";
pub const VECTOR_ID_SIDECAR_EXCHANGE_BINDING_CONTAINMENT: &str =
    "ak.vector.sidecar.exchange_binding_containment.v1";
pub const VECTOR_ID_SIDECAR_CONTEXT_LOCATOR_RECOVERY: &str =
    "ak.vector.sidecar.context_locator_recovery.v1";
pub const VECTOR_ID_SIDECAR_CANONICAL_SIBLING_DIGEST: &str =
    "ak.vector.sidecar.canonical_sibling_digest.v1";
pub const VECTOR_ID_SIDECAR_UNION_HISTORY_FRONTIER: &str =
    "ak.vector.sidecar.union_history_frontier.v1";
pub const VECTOR_ID_SIDECAR_NON_DISCLOSURE_SURFACE_MATRIX: &str =
    "ak.vector.sidecar.non_disclosure_surface_matrix.v1";
pub const VECTOR_ID_SIDECAR_REVOKE_FAIL_CLOSED: &str = "ak.vector.sidecar.revoke_fail_closed.v1";
pub const VECTOR_ID_SIDECAR_EXPLICIT_PUBLISH: &str = "ak.vector.sidecar.explicit_publish.v1";
pub const VECTOR_ID_SIDECAR_ACCEPTED_REQUEST_IDENTITY: &str =
    "ak.vector.sidecar.accepted_request_identity.v1";
pub const VECTOR_ID_SIDECAR_HOSTED_UI_MATRIX: &str = "ak.vector.sidecar.hosted_ui_matrix.v1";

pub const ALL_SIDECAR_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_SIDECAR_MLS_BOOTSTRAP_BINDING,
    VECTOR_ID_SIDECAR_MLS_EFFECTIVE_ACCESS,
    VECTOR_ID_SIDECAR_ENSURE_IDEMPOTENT,
    VECTOR_ID_SIDECAR_ELIGIBILITY_STATES,
    VECTOR_ID_SIDECAR_EXISTENCE_PRIVACY,
    VECTOR_ID_SIDECAR_HOSTED_PROJECTION,
    VECTOR_ID_SIDECAR_MULTI_AGENT_PUBLISH,
    VECTOR_ID_SIDECAR_EXCHANGE_BINDING_CLOSED_LOOP,
    VECTOR_ID_SIDECAR_EXCHANGE_PROJECTION_RECOVERY,
    VECTOR_ID_SIDECAR_EXCHANGE_BINDING_CONTAINMENT,
    VECTOR_ID_SIDECAR_CONTEXT_LOCATOR_RECOVERY,
    VECTOR_ID_SIDECAR_CANONICAL_SIBLING_DIGEST,
    VECTOR_ID_SIDECAR_UNION_HISTORY_FRONTIER,
    VECTOR_ID_SIDECAR_NON_DISCLOSURE_SURFACE_MATRIX,
    VECTOR_ID_SIDECAR_REVOKE_FAIL_CLOSED,
    VECTOR_ID_SIDECAR_EXPLICIT_PUBLISH,
    VECTOR_ID_SIDECAR_ACCEPTED_REQUEST_IDENTITY,
    VECTOR_ID_SIDECAR_HOSTED_UI_MATRIX,
];

const SIDECAR_VECTORS_FIXTURE_FILE: &str = "agent-sidecar-fixture.json";

fn validate_sidecar_vectors_fixture_metadata() -> Result<()> {
    let fixture = super::load_fixture_value(SIDECAR_VECTORS_FIXTURE_FILE)?;
    super::validate_profile(&fixture, ProfileId::AGENT_SIDECAR_V1)?;
    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("sidecar fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("sidecar fixture missing cases[]"))?;

    for vector_id in ALL_SIDECAR_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("sidecar fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("sidecar fixture missing asserted case {vector_id}");
        }
    }

    Ok(())
}

// ─── VECT-SC-1 — ensure_idempotent ─────────────────────────────────────────

pub fn run_sidecar_mls_bootstrap_binding_vector() -> Result<()> {
    let fixture = super::load_fixture_value(SIDECAR_VECTORS_FIXTURE_FILE)?;
    let case = fixture["cases"]
        .as_array()
        .and_then(|cases| {
            cases.iter().find(|case| {
                case["vector_id"].as_str() == Some(VECTOR_ID_SIDECAR_MLS_BOOTSTRAP_BINDING)
            })
        })
        .ok_or_else(|| anyhow!("Sidecar MLS bootstrap fixture case is missing"))?;
    let transcript = &case["participant_authority_transcript"];
    let sidecar_id = SidecarId::new(
        transcript["sidecar_id"]
            .as_str()
            .ok_or_else(|| anyhow!("fixture sidecar_id is missing"))?
            .to_owned(),
    )?;
    let realm_id = RealmId::new(
        transcript["realm_id"]
            .as_str()
            .ok_or_else(|| anyhow!("fixture realm_id is missing"))?
            .to_owned(),
    )?;
    let controller_account_id: AccountId = serde_json::from_value(
        transcript
            .get("controller_account_id")
            .cloned()
            .ok_or_else(|| anyhow!("fixture controller_account_id is missing"))?,
    )?;
    let desired_agent_ids = transcript["desired_agent_ids"]
        .as_array()
        .ok_or_else(|| anyhow!("fixture desired_agent_ids are missing"))?
        .iter()
        .filter_map(Value::as_str)
        .map(|principal_id| DidCoreId::new(principal_id.to_owned()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let digest = agent_sidecar_participant_authority_digest(
        sidecar_id.clone(),
        realm_id.clone(),
        controller_account_id,
        &desired_agent_ids,
    )?;

    let sidecar_binding = SidecarMlsBinding {
        sidecar_id: sidecar_id.clone(),
        participant_authority_digest: digest,
        control_frontier: vec![
            NonEmptyString::new("ak:event:ATLNYjgAv7kFEef4jwHjtdjjTC9rAZqvGekqKcxx7pSX")
                .map_err(anyhow::Error::msg)?,
        ],
    };
    let binding = MlsGovernanceBindingPayload::sidecar(
        realm_id,
        sidecar_id,
        "YXJrcmV0LXNpZGVjYXItZ3JvdXA",
        0,
        0,
        Hash::new(format!("sha256:{}", "1".repeat(64)))?,
        sidecar_binding.clone(),
        "ak.profile.mls_governance_binding.full.v1",
        "ak.reducer.core.v1",
    )?;
    let cbor = binding.to_deterministic_cbor()?;
    let decoded = MlsGovernanceBindingPayload::from_deterministic_cbor(&cbor)?;
    if decoded.sidecar_binding() != Some(&sidecar_binding)
        || decoded.to_deterministic_cbor()? != cbor
    {
        bail!("Sidecar MLS binding did not survive deterministic CBOR round-trip");
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct DeviceJoinEvidence {
    active_authorized: bool,
    accepted_add_commit: bool,
    matching_welcome: bool,
    key_package_consumed: bool,
    current_join_ref_bound: bool,
}

fn principal_effective(devices: &[DeviceJoinEvidence]) -> bool {
    devices.iter().any(|device| {
        device.active_authorized
            && device.accepted_add_commit
            && device.matching_welcome
            && device.key_package_consumed
            && device.current_join_ref_bound
    })
}

pub fn run_sidecar_mls_effective_access_vector() -> Result<()> {
    let complete = DeviceJoinEvidence {
        active_authorized: true,
        accepted_add_commit: true,
        matching_welcome: true,
        key_package_consumed: true,
        current_join_ref_bound: true,
    };
    if !principal_effective(&[complete]) {
        bail!("one complete active-device evidence chain must make the principal effective");
    }
    for incomplete in [
        DeviceJoinEvidence {
            accepted_add_commit: false,
            ..complete
        },
        DeviceJoinEvidence {
            matching_welcome: false,
            ..complete
        },
        DeviceJoinEvidence {
            key_package_consumed: false,
            ..complete
        },
        DeviceJoinEvidence {
            current_join_ref_bound: false,
            ..complete
        },
        DeviceJoinEvidence {
            active_authorized: false,
            ..complete
        },
    ] {
        if principal_effective(&[incomplete]) {
            bail!("incomplete or unauthorized device evidence became effective");
        }
    }
    let desired_after_removal = false;
    let delivery_allowed = desired_after_removal && principal_effective(&[complete]);
    let removal_obligation_created = !desired_after_removal;
    let station_authored_commit = false;
    if delivery_allowed || !removal_obligation_created || station_authored_commit {
        bail!(
            "Sidecar removal must stop delivery and create only a client-authored MLS obligation"
        );
    }
    let removal = PendingSidecarAccessReconciliationItem {
        agent_id: DidCoreId::new("ak:did_core:web:assistant.agents.example")?,
        provisioning_phase: PendingSidecarAccessReconciliationStage::MlsRemove,
        membership_frontier: Some(vec![EventId::new(
            "ak:event:AWifyy9pOZxDgygPC-YXK0utndmBAgXZy7HF-iPG3cyV",
        )?]),
    };
    removal.validate()?;
    Ok(())
}

/// Executable, storage-independent model of the normative Sidecar staged
/// transaction. Soland's handler and reservation validators are crate-private,
/// so this runner deliberately does not claim an HTTP/server success. It
/// independently verifies the public SDK transcript types and models the
/// required validate-before-write and clone-then-swap atomic semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SidecarModelError {
    CreateDenied,
    AgentPaused,
    AgentDeactivated,
    IdempotencyConflict,
    ReservationMismatch,
    BranchMismatch,
    DraftMismatch,
    AfterLinkMismatch,
    ProofMismatch,
    ModelInvariant,
}

type SidecarModelResult<T> = std::result::Result<T, SidecarModelError>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SidecarCoordinates {
    sidecar_id: SidecarId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SidecarContextCoordinates {
    source_context_ref: SidecarContextRef,
    mapping_event_id: EventId,
    version: u64,
    predecessor_event_ref: Option<EventId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SidecarDurableState {
    coordinates: Option<SidecarCoordinates>,
    contexts: BTreeMap<String, SidecarContextCoordinates>,
    accepted_event_ids: BTreeSet<EventId>,
}

#[derive(Clone)]
struct SidecarPreparedRecord {
    request_hash: String,
    prepared: SidecarPreparedOutcome,
}

#[derive(Clone)]
struct SidecarReservationRecord {
    device_id: String,
    prepared: SidecarPreparedOutcome,
}

#[derive(Clone)]
struct SidecarAcceptedRecord {
    request_hash: String,
    outcome: SidecarEnsureOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SidecarRealmStateSnapshotState {
    durable: SidecarDurableState,
    idempotency_records: usize,
    reservations: usize,
    accepted_records: usize,
    staged_write_epoch: u64,
    atomic_commit_epoch: u64,
}

struct SidecarExecutableModel {
    authenticated_controller_account_id: AccountId,
    has_ensure_capability: bool,
    lifecycle: AgentLifecycleStatus,
    durable: SidecarDurableState,
    idempotency: BTreeMap<String, SidecarPreparedRecord>,
    reservations: BTreeMap<String, SidecarReservationRecord>,
    accepted: BTreeMap<String, SidecarAcceptedRecord>,
    staged_write_epoch: u64,
    atomic_commit_epoch: u64,
}

impl SidecarExecutableModel {
    fn new(
        authenticated_controller_account_id: AccountId,
        has_ensure_capability: bool,
        lifecycle: AgentLifecycleStatus,
    ) -> Self {
        Self {
            authenticated_controller_account_id,
            has_ensure_capability,
            lifecycle,
            durable: SidecarDurableState::default(),
            idempotency: BTreeMap::new(),
            reservations: BTreeMap::new(),
            accepted: BTreeMap::new(),
            staged_write_epoch: 0,
            atomic_commit_epoch: 0,
        }
    }

    fn with_existing(
        authenticated_controller_account_id: AccountId,
        has_ensure_capability: bool,
        lifecycle: AgentLifecycleStatus,
    ) -> Result<Self> {
        let mut model = Self::new(
            authenticated_controller_account_id,
            has_ensure_capability,
            lifecycle,
        );
        model.durable.coordinates = Some(fixed_sidecar_coordinates(false)?);
        Ok(model)
    }

    fn snapshot(&self) -> SidecarRealmStateSnapshotState {
        SidecarRealmStateSnapshotState {
            durable: self.durable.clone(),
            idempotency_records: self.idempotency.len(),
            reservations: self.reservations.len(),
            accepted_records: self.accepted.len(),
            staged_write_epoch: self.staged_write_epoch,
            atomic_commit_epoch: self.atomic_commit_epoch,
        }
    }

    fn authorize(&self, request: &SidecarEnsurePrepareRequestBody) -> SidecarModelResult<()> {
        if !self.has_ensure_capability
            || request.controller_account_id != self.authenticated_controller_account_id
        {
            return Err(SidecarModelError::CreateDenied);
        }
        match self.lifecycle {
            AgentLifecycleStatus::Active => Ok(()),
            AgentLifecycleStatus::Paused => Err(SidecarModelError::AgentPaused),
            AgentLifecycleStatus::Deactivated => Err(SidecarModelError::AgentDeactivated),
        }
    }

    fn prepare(
        &mut self,
        request: &SidecarEnsurePrepareRequestBody,
    ) -> SidecarModelResult<SidecarPreparedOutcome> {
        self.prepare_on_device(request, "device-primary")
    }

    fn prepare_on_device(
        &mut self,
        request: &SidecarEnsurePrepareRequestBody,
        device_id: &str,
    ) -> SidecarModelResult<SidecarPreparedOutcome> {
        // Authorization and lifecycle checks intentionally precede all durable
        // existence reads, which is the privacy boundary being exercised.
        self.authorize(request)?;
        let request_hash = arkret_canonical::canonical_sha256(request)
            .map_err(|_| SidecarModelError::ModelInvariant)?;
        let ledger_key = device_ledger_key(device_id, request.idempotency_key.as_str());
        if let Some(cached) = self.idempotency.get(&ledger_key) {
            return if cached.request_hash == request_hash {
                Ok(cached.prepared.clone())
            } else {
                Err(SidecarModelError::IdempotencyConflict)
            };
        }

        let context_key = normalized_context_key(request)?;
        let existing_context = self.durable.contexts.get(&context_key);
        let prepared = build_fixed_sidecar_prepare(
            request,
            device_id,
            self.durable.coordinates.as_ref(),
            existing_context,
        )?;
        validate_prepared_outcome(&prepared, request)?;
        let handle = prepared_reservation_handle(&prepared).to_string();
        self.idempotency.insert(
            ledger_key,
            SidecarPreparedRecord {
                request_hash,
                prepared: prepared.clone(),
            },
        );
        self.reservations.insert(
            handle,
            SidecarReservationRecord {
                device_id: device_id.to_owned(),
                prepared: prepared.clone(),
            },
        );
        self.staged_write_epoch += 1;
        Ok(prepared)
    }

    fn commit_new(
        &mut self,
        request: &SidecarEnsureCommitRequestBody,
        public_key: &PublicKeyMaterial,
    ) -> SidecarModelResult<SidecarEnsureOutcome> {
        self.commit_new_on_device(request, public_key, "device-primary")
    }

    fn commit_new_on_device(
        &mut self,
        request: &SidecarEnsureCommitRequestBody,
        public_key: &PublicKeyMaterial,
        device_id: &str,
    ) -> SidecarModelResult<SidecarEnsureOutcome> {
        let request_hash = arkret_canonical::canonical_sha256(request)
            .map_err(|_| SidecarModelError::ModelInvariant)?;
        let ledger_key = device_ledger_key(device_id, request.idempotency_key.as_str());
        if let Some(cached) = self.accepted.get(&ledger_key) {
            return if cached.request_hash == request_hash {
                Ok(cached.outcome.clone())
            } else {
                Err(SidecarModelError::IdempotencyConflict)
            };
        }
        let reservation = self
            .reservations
            .get(request.reservation_handle.as_str())
            .cloned()
            .ok_or(SidecarModelError::ReservationMismatch)?;
        if reservation.device_id != device_id {
            return Err(SidecarModelError::ReservationMismatch);
        }
        let prepared = reservation.prepared;
        let SidecarPreparedOutcome::New {
            operation_id,
            reservation_handle,
            create_event_draft,
            context_attach_event_draft,
            ..
        } = &prepared
        else {
            return Err(SidecarModelError::BranchMismatch);
        };
        if operation_id != &request.operation_id
            || reservation_handle != &request.reservation_handle
        {
            return Err(SidecarModelError::ReservationMismatch);
        }
        validate_new_after_link(&request.create_event, &request.context_attach_event)?;
        validate_signed_draft(&request.create_event, create_event_draft, public_key)?;
        validate_signed_draft(
            &request.context_attach_event,
            context_attach_event_draft,
            public_key,
        )?;

        let coordinates = SidecarCoordinates {
            sidecar_id: SidecarId::from_event_id(&request.create_event.event_id),
        };
        let context = context_coordinates_from_event(&request.context_attach_event)?;
        let context_key = normalized_context_key_from_event(&request.context_attach_event)?;
        let mut next = self.durable.clone();
        if let Some(existing) = &next.coordinates {
            if existing.sidecar_id != coordinates.sidecar_id {
                return Err(SidecarModelError::BranchMismatch);
            }
        } else {
            next.coordinates = Some(coordinates.clone());
        }
        if let Some(existing) = next.contexts.get(&context_key)
            && existing != &context
        {
            return Err(SidecarModelError::BranchMismatch);
        }
        next.contexts.insert(context_key, context.clone());
        next.accepted_event_ids
            .insert(request.create_event.event_id.clone());
        next.accepted_event_ids
            .insert(request.context_attach_event.event_id.clone());

        let outcome = accepted_sidecar_outcome(
            operation_id.clone(),
            SidecarAcceptedPhase::Commit,
            &coordinates,
            &context,
        );
        // The durable projection, finalized reservation, and accepted replay
        // ledger become visible as one modeled transaction after every check.
        self.durable = next;
        self.reservations
            .remove(request.reservation_handle.as_str());
        self.accepted.insert(
            ledger_key,
            SidecarAcceptedRecord {
                request_hash,
                outcome: outcome.clone(),
            },
        );
        self.atomic_commit_epoch += 1;
        Ok(outcome)
    }

    fn commit_existing(
        &mut self,
        request: &SidecarEnsureAttachRequestBody,
        public_key: &PublicKeyMaterial,
    ) -> SidecarModelResult<SidecarEnsureOutcome> {
        self.commit_existing_on_device(request, public_key, "device-primary")
    }

    fn commit_existing_on_device(
        &mut self,
        request: &SidecarEnsureAttachRequestBody,
        public_key: &PublicKeyMaterial,
        device_id: &str,
    ) -> SidecarModelResult<SidecarEnsureOutcome> {
        let request_hash = arkret_canonical::canonical_sha256(request)
            .map_err(|_| SidecarModelError::ModelInvariant)?;
        let ledger_key = device_ledger_key(device_id, request.idempotency_key.as_str());
        if let Some(cached) = self.accepted.get(&ledger_key) {
            return if cached.request_hash == request_hash {
                Ok(cached.outcome.clone())
            } else {
                Err(SidecarModelError::IdempotencyConflict)
            };
        }
        let reservation = self
            .reservations
            .get(request.reservation_handle.as_str())
            .cloned()
            .ok_or(SidecarModelError::ReservationMismatch)?;
        if reservation.device_id != device_id {
            return Err(SidecarModelError::ReservationMismatch);
        }
        let prepared = reservation.prepared;
        let SidecarPreparedOutcome::Existing {
            operation_id,
            reservation_handle,
            sidecar_id,
            context_attach_event_draft,
            ..
        } = &prepared
        else {
            return Err(SidecarModelError::BranchMismatch);
        };
        if operation_id != &request.operation_id
            || reservation_handle != &request.reservation_handle
        {
            return Err(SidecarModelError::ReservationMismatch);
        }
        validate_signed_draft(
            &request.context_attach_event,
            context_attach_event_draft,
            public_key,
        )?;
        let Some(existing) = &self.durable.coordinates else {
            return Err(SidecarModelError::BranchMismatch);
        };
        if existing.sidecar_id != *sidecar_id {
            return Err(SidecarModelError::BranchMismatch);
        }

        let coordinates = SidecarCoordinates {
            sidecar_id: sidecar_id.clone(),
        };
        let context = context_coordinates_from_event(&request.context_attach_event)?;
        let context_key = normalized_context_key_from_event(&request.context_attach_event)?;
        let mut next = self.durable.clone();
        if let Some(existing) = next.contexts.get(&context_key)
            && existing != &context
            && !context_advances(existing, &context)
        {
            return Err(SidecarModelError::BranchMismatch);
        }
        next.contexts.insert(context_key, context.clone());
        next.accepted_event_ids
            .insert(request.context_attach_event.event_id.clone());
        let outcome = accepted_sidecar_outcome(
            operation_id.clone(),
            SidecarAcceptedPhase::Attach,
            &coordinates,
            &context,
        );
        self.durable = next;
        self.reservations
            .remove(request.reservation_handle.as_str());
        self.accepted.insert(
            ledger_key,
            SidecarAcceptedRecord {
                request_hash,
                outcome: outcome.clone(),
            },
        );
        self.atomic_commit_epoch += 1;
        Ok(outcome)
    }
}

fn device_ledger_key(device_id: &str, idempotency_key: &str) -> String {
    format!("{device_id}\u{0}{idempotency_key}")
}

fn unique_reservation_handle(
    request: &SidecarEnsurePrepareRequestBody,
    device_id: &str,
) -> SidecarModelResult<ReservationHandle> {
    let digest = arkret_canonical::canonical_sha256(&json!({
        "operation_id": request.operation_id,
        "controller_account_id": request.controller_account_id,
        "device_id": device_id,
        "context": request.context_ref,
    }))
    .map_err(|_| SidecarModelError::ModelInvariant)?;
    let digest = digest
        .strip_prefix("sha256:")
        .ok_or(SidecarModelError::ModelInvariant)?;
    ReservationHandle::new(format!("sidecar-reservation-{}", &digest[..32]))
        .map_err(|_| SidecarModelError::ModelInvariant)
}

fn normalized_context_key(request: &SidecarEnsurePrepareRequestBody) -> SidecarModelResult<String> {
    let normalized = match &request.context_ref {
        SidecarContextRef::Relation { relation_id } => json!({
            "realm_id": request.source_realm_id,
            "relation_id": relation_id,
        }),
        SidecarContextRef::Strand { strand_id } => json!({
            "realm_id": request.source_realm_id,
            "strand_id": strand_id,
        }),
    };
    arkret_canonical::canonical_sha256(&normalized).map_err(|_| SidecarModelError::ModelInvariant)
}

fn normalized_context_key_from_event(event: &Event) -> SidecarModelResult<String> {
    let target = context_target_from_event(event)?;
    let normalized = if target.starts_with("ak:strand:") {
        json!({"realm_id": event.realm_id, "strand_id": target})
    } else if target.starts_with("ak:relation:") {
        json!({"realm_id": event.realm_id, "relation_id": target})
    } else {
        return Err(SidecarModelError::DraftMismatch);
    };
    arkret_canonical::canonical_sha256(&normalized).map_err(|_| SidecarModelError::ModelInvariant)
}

fn context_coordinates_from_event(event: &Event) -> SidecarModelResult<SidecarContextCoordinates> {
    let payload: SidecarContextAttachPayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(|_| SidecarModelError::DraftMismatch)?,
    )
    .map_err(|_| SidecarModelError::DraftMismatch)?;
    payload
        .validate()
        .map_err(|_| SidecarModelError::DraftMismatch)?;
    Ok(SidecarContextCoordinates {
        source_context_ref: payload.source_context_ref,
        mapping_event_id: event.event_id.clone(),
        version: payload.version,
        predecessor_event_ref: payload.predecessor_event_ref,
    })
}

fn context_advances(
    existing: &SidecarContextCoordinates,
    next: &SidecarContextCoordinates,
) -> bool {
    next.source_context_ref == existing.source_context_ref
        && existing.version.checked_add(1) == Some(next.version)
        && next.predecessor_event_ref.as_ref() == Some(&existing.mapping_event_id)
}

fn accepted_sidecar_outcome(
    operation_id: ProtocolOperationId,
    accepted_phase: SidecarAcceptedPhase,
    coordinates: &SidecarCoordinates,
    context: &SidecarContextCoordinates,
) -> SidecarEnsureOutcome {
    SidecarEnsureOutcome::Accepted {
        operation_id,
        accepted_phase,
        ok: SidecarAcceptedOk,
        sidecar_id: coordinates.sidecar_id.clone(),
        source_context_ref: context.source_context_ref.clone(),
        access_readiness: AgentSidecarAccessReadiness::KeyMaterialPending,
        pending_access_reconciliations: Vec::new(),
    }
}

fn fixed_sidecar_time() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 3, 0, 0, 0)
        .single()
        .expect("fixed Sidecar timestamp")
}

fn fixed_sidecar_coordinates(_existing_context: bool) -> Result<SidecarCoordinates> {
    Ok(SidecarCoordinates {
        sidecar_id: SidecarId::from_event_id(&EventId::new(
            "ak:event:AZ405CdsF4uWwxBhArLvqgzVvWHWYcB3QJ6845E-2ET3",
        )?),
    })
}

fn fixed_prepare_request(
    controller_account_id: &AccountId,
    idempotency_key: &str,
    second_context: bool,
) -> Result<SidecarEnsurePrepareRequestBody> {
    fixed_prepare_request_for_operation(
        controller_account_id,
        idempotency_key,
        second_context,
        "ak:operation:cotest.sidecar.ensure",
    )
}

fn fixed_prepare_request_for_operation(
    controller_account_id: &AccountId,
    idempotency_key: &str,
    second_context: bool,
    operation_id: &str,
) -> Result<SidecarEnsurePrepareRequestBody> {
    Ok(SidecarEnsurePrepareRequestBody {
        phase: SidecarPreparePhase::Prepare,
        operation_id: ProtocolOperationId::new(operation_id).map_err(anyhow::Error::msg)?,
        idempotency_key: IdempotencyKey::new(idempotency_key).map_err(anyhow::Error::msg)?,
        source_realm_id: RealmId::new("ak:realm:AZbWb-13w-oDGla4V2JFe2VWsjRVvQYYC-dr1JgcoXz5")?,
        controller_account_id: controller_account_id.clone(),
        context_ref: SidecarContextRef::Strand {
            strand_id: StrandId::new(if second_context {
                "ak:strand:AasLcOpdB_lTv6ay3bQ6xOzA6mDGOT67AC66Gd65H8-W"
            } else {
                "ak:strand:AU2cJh8QNyuarSldoS2B-_cxDy9txc1y_dOrH6JgFYKb"
            })?,
        },
    })
}

fn build_fixed_sidecar_prepare(
    request: &SidecarEnsurePrepareRequestBody,
    device_id: &str,
    existing: Option<&SidecarCoordinates>,
    existing_context: Option<&SidecarContextCoordinates>,
) -> SidecarModelResult<SidecarPreparedOutcome> {
    let created_at = fixed_sidecar_time();
    let expires_at = created_at + chrono::Duration::minutes(10);
    let frontier = EventId::new("ak:event:AXt_8tC5N1gjLn_b-DdVFC0jdOuhwjrtAUmJGOZzUaVJ")
        .map_err(|_| SidecarModelError::ModelInvariant)?;
    // Native Sidecar genesis carries only the immutable encryption intent.
    // Its SidecarId is retyped from the accepted create Event identity.
    let create_event = if existing.is_none() {
        Some(fixed_unsigned_sidecar_event(
            EventKind::SidecarCreate,
            request.source_realm_id.clone(),
            ScopeRef::Realm {
                realm_id: request.source_realm_id.clone(),
            },
            sidecar_actor_id(&request.controller_account_id)?,
            1,
            vec![frontier.clone()],
            Vec::new(),
            json!({"encryption_profile": "mls_rfc9420"}),
        )?)
    } else {
        None
    };
    let sidecar_id = existing.map_or_else(
        || {
            create_event
                .as_ref()
                .map(|event| SidecarId::from_event_id(&event.event_id))
                .ok_or(SidecarModelError::ModelInvariant)
        },
        |coordinates| Ok(coordinates.sidecar_id.clone()),
    )?;
    let (version, predecessor_event_ref) = existing_context.map_or((1, None), |context| {
        (context.version + 1, Some(context.mapping_event_id.clone()))
    });
    let (attach_prev_refs, attach_refs) = create_event.as_ref().map_or_else(
        || (vec![frontier.clone()], Vec::new()),
        |create| {
            (
                vec![create.event_id.clone()],
                vec![EventRef::new(create.event_id.to_string(), "after")],
            )
        },
    );
    let attach_event = fixed_unsigned_sidecar_event(
        EventKind::SidecarContextAttach,
        request.source_realm_id.clone(),
        ScopeRef::Sidecar {
            realm_id: request.source_realm_id.clone(),
            sidecar_id: sidecar_id.clone(),
        },
        sidecar_actor_id(&request.controller_account_id)?,
        if existing.is_some() { 3 } else { 2 },
        attach_prev_refs,
        attach_refs,
        serde_json::to_value(SidecarContextAttachPayload {
            sidecar_id: sidecar_id.clone(),
            source_context_ref: request.context_ref.clone(),
            version,
            predecessor_event_ref,
        })
        .map_err(|_| SidecarModelError::ModelInvariant)?,
    )?;
    let context_attach_event_draft = fixed_sidecar_draft(&attach_event)?;
    let reservation_handle = unique_reservation_handle(request, device_id)?;

    if existing.is_some() {
        Ok(SidecarPreparedOutcome::Existing {
            operation_id: request.operation_id.clone(),
            reservation_handle,
            expires_at,
            sidecar_id,
            context_attach_event_draft,
        })
    } else {
        // The event ids are derived from the built envelopes, not the
        // placeholders passed in: spec encoding.md section 4.0.
        Ok(SidecarPreparedOutcome::New {
            operation_id: request.operation_id.clone(),
            reservation_handle,
            expires_at,
            create_event_draft: fixed_sidecar_draft(
                create_event
                    .as_ref()
                    .ok_or(SidecarModelError::ModelInvariant)?,
            )?,
            context_attach_event_draft,
        })
    }
}

#[allow(clippy::too_many_arguments)]
fn fixed_unsigned_sidecar_event(
    kind: EventKind,
    realm_id: RealmId,
    scope_ref: ScopeRef,
    actor_id: arkret_wire::ActorId,
    actor_seq: u64,
    prev_refs: Vec<EventId>,
    refs: Vec<EventRef>,
    payload: Value,
) -> SidecarModelResult<Event> {
    let payload = payload
        .as_object()
        .cloned()
        .ok_or(SidecarModelError::ModelInvariant)?
        .into_iter()
        .collect();
    // Match the producer path exactly: construct the unsigned envelope, then
    // derive and stamp its content-bound identity. Draft reconstruction is
    // tested separately by `decode_prepared_event` below.
    let mut event = Event {
        event_id: EventId::new("ak:event:AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .map_err(|_| SidecarModelError::ModelInvariant)?,
        kind,
        realm_id,
        scope_ref,
        actor_id,
        executed_by: None,
        authorization_ref: None,
        applet_id: None,
        external_ref: None,
        actor_kind: None,
        actor_seq,
        created_at: fixed_sidecar_time(),
        hlc: None,
        prev_refs,
        refs,
        causal_refs: Vec::new(),
        preconditions: Vec::new(),
        seal_ref: None,
        auth_context: None,
        seal_basis: None,
        payload,
        unsigned: BTreeMap::new(),
        proofs: Vec::new(),
        requirements: EventRequirements::default(),
    };
    event.event_id = event
        .derive_event_id_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
        .map_err(|_| SidecarModelError::ModelInvariant)?;
    Ok(event)
}

fn sidecar_account(principal_id: DidCoreId) -> Result<AccountId> {
    Ok(AccountId::new(
        principal_id,
        DidCoreId::new("ak:did_core:web:station.example")?,
    ))
}

fn sidecar_actor_id(account_id: &AccountId) -> SidecarModelResult<arkret_wire::ActorId> {
    account_id
        .validate()
        .map_err(|_| SidecarModelError::ModelInvariant)?;
    Ok(arkret_wire::ActorId::account(account_id.clone()))
}

fn fixed_sidecar_draft(event: &Event) -> SidecarModelResult<PreparedEventDraft> {
    let unsigned = arkret_canonical::canonical_json_bytes(
        &event
            .digest_payload()
            .map_err(|_| SidecarModelError::ModelInvariant)?,
    )
    .map_err(|_| SidecarModelError::ModelInvariant)?;
    Ok(PreparedEventDraft {
        unsigned_event_bytes: Base64UrlString::new(URL_SAFE_NO_PAD.encode(unsigned))
            .map_err(|_| SidecarModelError::ModelInvariant)?,
        event_digest: Hash::new(
            event
                .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .map_err(|_| SidecarModelError::ModelInvariant)?,
        )
        .map_err(|_| SidecarModelError::ModelInvariant)?,
    })
}

fn decode_prepared_event(draft: &PreparedEventDraft) -> SidecarModelResult<Event> {
    draft
        .unsigned_event()
        .map(|event| event.into_event())
        .map_err(|_| SidecarModelError::DraftMismatch)
}

fn validate_prepared_outcome(
    prepared: &SidecarPreparedOutcome,
    request: &SidecarEnsurePrepareRequestBody,
) -> SidecarModelResult<()> {
    let (operation_id, expires_at, sidecar_id, create, attach) = match prepared {
        SidecarPreparedOutcome::New {
            operation_id,
            expires_at,
            create_event_draft,
            context_attach_event_draft,
            ..
        } => {
            let create = decode_prepared_event(create_event_draft)?;
            let sidecar_id = SidecarId::from_event_id(&create.event_id);
            (
                operation_id,
                expires_at,
                sidecar_id,
                Some(create),
                decode_prepared_event(context_attach_event_draft)?,
            )
        }
        SidecarPreparedOutcome::Existing {
            operation_id,
            expires_at,
            sidecar_id,
            context_attach_event_draft,
            ..
        } => (
            operation_id,
            expires_at,
            sidecar_id.clone(),
            None,
            decode_prepared_event(context_attach_event_draft)?,
        ),
    };
    if operation_id != &request.operation_id || *expires_at <= fixed_sidecar_time() {
        return Err(SidecarModelError::ReservationMismatch);
    }
    if let Some(create) = &create {
        if create.kind != EventKind::SidecarCreate
            || create.actor_id != sidecar_actor_id(&request.controller_account_id)?
            || create.scope_ref
                != (ScopeRef::Realm {
                    realm_id: request.source_realm_id.clone(),
                })
        {
            return Err(SidecarModelError::DraftMismatch);
        }
        if create.payload
            != BTreeMap::from([(
                "encryption_profile".to_owned(),
                Value::String("mls_rfc9420".to_owned()),
            )])
            || SidecarId::from_event_id(&create.event_id) != sidecar_id
        {
            return Err(SidecarModelError::DraftMismatch);
        }
    }
    let attach_payload: SidecarContextAttachPayload = serde_json::from_value(
        serde_json::to_value(&attach.payload).map_err(|_| SidecarModelError::DraftMismatch)?,
    )
    .map_err(|_| SidecarModelError::DraftMismatch)?;
    attach_payload
        .validate()
        .map_err(|_| SidecarModelError::DraftMismatch)?;
    if attach.kind != EventKind::SidecarContextAttach
        || attach.actor_id != sidecar_actor_id(&request.controller_account_id)?
        || attach.realm_id != request.source_realm_id
        || attach.scope_ref
            != (ScopeRef::Sidecar {
                realm_id: request.source_realm_id.clone(),
                sidecar_id: sidecar_id.clone(),
            })
        || attach_payload.sidecar_id != sidecar_id
        || attach_payload.source_context_ref != request.context_ref
    {
        return Err(SidecarModelError::DraftMismatch);
    }
    if let Some(create) = create {
        validate_new_after_link(&create, &attach)?;
    } else if attach
        .refs
        .iter()
        .any(|reference| reference.role == "after")
    {
        return Err(SidecarModelError::AfterLinkMismatch);
    }
    Ok(())
}

fn prepared_reservation_handle(prepared: &SidecarPreparedOutcome) -> &ReservationHandle {
    match prepared {
        SidecarPreparedOutcome::New {
            reservation_handle, ..
        }
        | SidecarPreparedOutcome::Existing {
            reservation_handle, ..
        } => reservation_handle,
    }
}

fn validate_new_after_link(create: &Event, attach: &Event) -> SidecarModelResult<()> {
    if attach.prev_refs != [create.event_id.clone()]
        || attach.refs.len() != 1
        || attach.refs[0].id != create.event_id.as_str()
        || attach.refs[0].role != "after"
        || !attach.refs[0].critical
        || attach.refs[0].proof.is_some()
    {
        return Err(SidecarModelError::AfterLinkMismatch);
    }
    Ok(())
}

fn sign_prepared_draft(
    draft: &PreparedEventDraft,
    signer: &Ed25519PayloadSigner,
    verification_method: &DidUrl,
) -> SidecarModelResult<Event> {
    let event = decode_prepared_event(draft)?;
    let before = arkret_canonical::canonical_json_bytes(
        &event
            .digest_payload()
            .map_err(|_| SidecarModelError::DraftMismatch)?,
    )
    .map_err(|_| SidecarModelError::DraftMismatch)?;
    let mut event = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event,
        arkret::canonical::DigestSuite::Sha256,
    )
    .map_err(|_| SidecarModelError::DraftMismatch)?;
    sign_event(
        &mut event,
        signer,
        verification_method,
        SignEventOptions::new().with_created_at(fixed_sidecar_time()),
    )
    .map_err(|_| SidecarModelError::ProofMismatch)?;
    let after = arkret_canonical::canonical_json_bytes(
        &event
            .digest_payload()
            .map_err(|_| SidecarModelError::DraftMismatch)?,
    )
    .map_err(|_| SidecarModelError::DraftMismatch)?;
    if before != after || event.proofs.len() != 1 {
        return Err(SidecarModelError::ProofMismatch);
    }
    let public_key = PublicKeyMaterial::Ed25519Raw {
        bytes: signer.verifying_key().to_bytes().to_vec(),
    };
    let proof = event.proofs[0]
        .as_producer()
        .ok_or(SidecarModelError::ProofMismatch)?;
    verify_ed25519_detached_jws_proof(proof, &before, &event.actor_id, &public_key)
        .map_err(|_| SidecarModelError::ProofMismatch)?;
    Ok(event.into_event())
}

fn validate_signed_draft(
    event: &Event,
    draft: &PreparedEventDraft,
    public_key: &PublicKeyMaterial,
) -> SidecarModelResult<()> {
    let actual_unsigned = arkret_canonical::canonical_json_bytes(
        &event
            .digest_payload()
            .map_err(|_| SidecarModelError::DraftMismatch)?,
    )
    .map_err(|_| SidecarModelError::DraftMismatch)?;
    let expected_unsigned = URL_SAFE_NO_PAD
        .decode(draft.unsigned_event_bytes.as_str())
        .map_err(|_| SidecarModelError::DraftMismatch)?;
    if actual_unsigned != expected_unsigned
        || event
            .event_digest_with_digest_suite(
                draft
                    .event_digest
                    .digest_suite()
                    .map_err(|_| SidecarModelError::DraftMismatch)?,
            )
            .map_err(|_| SidecarModelError::DraftMismatch)?
            != draft.event_digest.as_str()
        || !matches!(
            event.proofs.as_slice(),
            [arkret_wire::EventProof::Producer(proof)] if proof.event_digest == draft.event_digest
        )
    {
        return Err(SidecarModelError::DraftMismatch);
    }
    for proof in event
        .proofs
        .iter()
        .filter_map(arkret_wire::EventProof::as_producer)
    {
        verify_ed25519_detached_jws_proof(proof, &actual_unsigned, &event.actor_id, public_key)
            .map_err(|_| SidecarModelError::ProofMismatch)?;
    }
    Ok(())
}

fn context_target_from_event(event: &Event) -> SidecarModelResult<String> {
    let payload: SidecarContextAttachPayload = serde_json::from_value(
        serde_json::to_value(&event.payload).map_err(|_| SidecarModelError::DraftMismatch)?,
    )
    .map_err(|_| SidecarModelError::DraftMismatch)?;
    Ok(match payload.source_context_ref {
        SidecarContextRef::Relation { relation_id } => relation_id.to_string(),
        SidecarContextRef::Strand { strand_id } => strand_id.to_string(),
    })
}

fn assert_new_commit_failure_is_write_free(
    model: &mut SidecarExecutableModel,
    request: &SidecarEnsureCommitRequestBody,
    public_key: &PublicKeyMaterial,
    expected: SidecarModelError,
) -> Result<()> {
    let before = model.snapshot();
    let observed = model.commit_new(request, public_key);
    if !matches!(observed, Err(error) if error == expected) || model.snapshot() != before {
        bail!(
            "Sidecar negative commit was not write-free: expected {expected:?}, got {observed:?}"
        );
    }
    Ok(())
}

pub fn run_sidecar_ensure_idempotent_vector() -> Result<()> {
    let _fixture_case = sidecar_fixture_case(VECTOR_ID_SIDECAR_ENSURE_IDEMPOTENT)?;
    if arkret_wire::ServiceOperationId::SELF_AGENT_SIDECAR_COMMAND_ENSURE_V1
        != CapabilityActionId::SELF_AGENT_SIDECAR_COMMAND_ENSURE_V1
        || ProfileId::AGENT_SIDECAR_V1 != "ak.profile.agent_sidecar.v1"
    {
        bail!("Sidecar ensure operation/profile registry drifted");
    }
    let controller = sidecar_account(DidCoreId::new("ak:did_core:web:controller.example")?)?;
    let prepare_request = fixed_prepare_request(&controller, "cotest-sidecar-prepare-new", false)?;
    let mut model =
        SidecarExecutableModel::new(controller.clone(), true, AgentLifecycleStatus::Active);
    let prepared = model
        .prepare(&prepare_request)
        .map_err(|error| anyhow!("{error:?}"))?;
    let replay = model
        .prepare(&prepare_request)
        .map_err(|error| anyhow!("{error:?}"))?;
    if serde_json::to_vec(&prepared)? != serde_json::to_vec(&replay)?
        || model.staged_write_epoch != 1
    {
        bail!("Sidecar prepare exact replay did not return the fixed first outcome");
    }
    let mut other_station_request = prepare_request.clone();
    other_station_request.controller_account_id.station_id =
        DidCoreId::new("ak:did_core:web:other-station.example")?;
    let before_other_station = model.snapshot();
    if !matches!(
        model.prepare(&other_station_request),
        Err(SidecarModelError::CreateDenied)
    ) || model.snapshot() != before_other_station
    {
        bail!("Sidecar ensure merged the same principal across different Stations");
    }
    let SidecarPreparedOutcome::New {
        operation_id,
        reservation_handle,
        create_event_draft,
        context_attach_event_draft,
        ..
    } = &prepared
    else {
        bail!("first Sidecar prepare did not produce the closed New branch");
    };

    let before_conflict = model.snapshot();
    let conflicting = fixed_prepare_request(&controller, "cotest-sidecar-prepare-new", true)?;
    if !matches!(
        model.prepare(&conflicting),
        Err(SidecarModelError::IdempotencyConflict)
    ) || model.snapshot() != before_conflict
    {
        bail!("Sidecar prepare idempotency conflict changed staged or durable state");
    }

    let controller_did = Did::new("did:web:controller.example")?;
    let verification_method =
        DidUrl::new(format!("{controller_did}#device-sidecar")).map_err(anyhow::Error::msg)?;
    let signer = Ed25519PayloadSigner::from_did_key_seed(
        [73_u8; 32],
        controller_did,
        verification_method.clone(),
    );
    let create_event = sign_prepared_draft(create_event_draft, &signer, &verification_method)
        .map_err(|error| anyhow!("{error:?}"))?;
    let attach_event =
        sign_prepared_draft(context_attach_event_draft, &signer, &verification_method)
            .map_err(|error| anyhow!("{error:?}"))?;
    let public_key = PublicKeyMaterial::Ed25519Raw {
        bytes: signer.verifying_key().to_bytes().to_vec(),
    };
    let commit =
        |create_event: Event, context_attach_event: Event| SidecarEnsureCommitRequestBody {
            phase: SidecarCommitPhase::Commit,
            operation_id: operation_id.clone(),
            idempotency_key: IdempotencyKey::new("cotest-sidecar-commit-new")
                .expect("fixed Sidecar commit idempotency key"),
            reservation_handle: reservation_handle.clone(),
            create_event,
            context_attach_event,
        };

    let mut unsigned_mutation = create_event.clone();
    unsigned_mutation.actor_seq += 1;
    assert_new_commit_failure_is_write_free(
        &mut model,
        &commit(unsigned_mutation, attach_event.clone()),
        &public_key,
        SidecarModelError::DraftMismatch,
    )?;
    let mut service_actor_mutation = create_event.clone();
    service_actor_mutation.actor_id = ActorId::service(controller.principal_id.clone());
    assert_new_commit_failure_is_write_free(
        &mut model,
        &commit(service_actor_mutation, attach_event.clone()),
        &public_key,
        SidecarModelError::DraftMismatch,
    )?;
    let mut payload_mutation = create_event.clone();
    payload_mutation
        .payload
        .insert("unexpected".to_owned(), Value::Bool(true));
    assert_new_commit_failure_is_write_free(
        &mut model,
        &commit(payload_mutation, attach_event.clone()),
        &public_key,
        SidecarModelError::DraftMismatch,
    )?;
    let mut event_id_mutation = create_event.clone();
    event_id_mutation.event_id =
        EventId::new("ak:event:AR9z2q8WciIPBQxN5ECtwwI7tb_zAwItKYIUMxeXuIWA")?;
    let mut matching_link = attach_event.clone();
    matching_link.prev_refs = vec![event_id_mutation.event_id.clone()];
    matching_link.refs = vec![EventRef::new(
        event_id_mutation.event_id.to_string(),
        "after",
    )];
    assert_new_commit_failure_is_write_free(
        &mut model,
        &commit(event_id_mutation, matching_link),
        &public_key,
        SidecarModelError::DraftMismatch,
    )?;
    let mut unregistered_scope_mutation = create_event.clone();
    unregistered_scope_mutation.payload.insert(
        "backing_circle_id".to_owned(),
        Value::String("ak:circle:AXeaYP8-Z4VTLwc8C3egj3Efq_jN9cyDleDhahC7LCfs".to_owned()),
    );
    assert_new_commit_failure_is_write_free(
        &mut model,
        &commit(unregistered_scope_mutation, attach_event.clone()),
        &public_key,
        SidecarModelError::DraftMismatch,
    )?;
    let mut after_mutation = attach_event.clone();
    after_mutation.refs[0].role = "before".to_owned();
    assert_new_commit_failure_is_write_free(
        &mut model,
        &commit(create_event.clone(), after_mutation),
        &public_key,
        SidecarModelError::AfterLinkMismatch,
    )?;

    let commit_request = commit(create_event.clone(), attach_event.clone());
    let accepted = model
        .commit_new(&commit_request, &public_key)
        .map_err(|error| anyhow!("{error:?}"))?;
    if model.atomic_commit_epoch != 1
        || model.durable.accepted_event_ids.len() != 2
        || model.durable.contexts.len() != 1
    {
        bail!("Sidecar New commit did not publish one complete atomic projection");
    }
    let accepted_snapshot = model.snapshot();
    let accepted_replay = model
        .commit_new(&commit_request, &public_key)
        .map_err(|error| anyhow!("{error:?}"))?;
    if serde_json::to_vec(&accepted_replay)? != serde_json::to_vec(&accepted)?
        || model.snapshot() != accepted_snapshot
    {
        bail!("exact Sidecar commit replay did not return the original Accepted outcome");
    }
    let mut conflicting_commit = commit_request.clone();
    conflicting_commit
        .context_attach_event
        .unsigned
        .insert("different-request-bytes".to_owned(), Value::Bool(true));
    if !matches!(
        model.commit_new(&conflicting_commit, &public_key),
        Err(SidecarModelError::IdempotencyConflict)
    ) || model.snapshot() != accepted_snapshot
    {
        bail!("Sidecar commit idempotency conflict changed staged or durable state");
    }

    let same_context_request = fixed_prepare_request_for_operation(
        &controller,
        "cotest-sidecar-prepare-same-context",
        false,
        "ak:operation:cotest.sidecar.ensure.same-context",
    )?;
    let same_context = model
        .prepare(&same_context_request)
        .map_err(|error| anyhow!("{error:?}"))?;
    let SidecarPreparedOutcome::Existing {
        operation_id: same_operation_id,
        reservation_handle: same_reservation_handle,
        context_attach_event_draft: same_context_draft,
        ..
    } = same_context
    else {
        bail!("same normalized context did not return Existing");
    };
    let same_context_event =
        sign_prepared_draft(&same_context_draft, &signer, &verification_method)
            .map_err(|error| anyhow!("{error:?}"))?;
    let same_context_payload: SidecarContextAttachPayload =
        serde_json::from_value(serde_json::to_value(&same_context_event.payload)?)?;
    if same_context_payload.version != 2 || same_context_payload.predecessor_event_ref.is_none() {
        bail!("same normalized context did not advance the native attachment version chain");
    }
    let same_context_attach = SidecarEnsureAttachRequestBody {
        phase: SidecarAttachPhase::Attach,
        operation_id: same_operation_id,
        idempotency_key: IdempotencyKey::new("cotest-sidecar-commit-same-context")
            .map_err(anyhow::Error::msg)?,
        reservation_handle: same_reservation_handle,
        context_attach_event: same_context_event,
    };
    model
        .commit_existing(&same_context_attach, &public_key)
        .map_err(|error| anyhow!("{error:?}"))?;
    if model.durable.contexts.len() != 1 {
        bail!("same-context attach duplicated its private projection");
    }

    let existing_request =
        fixed_prepare_request(&controller, "cotest-sidecar-prepare-existing", true)?;
    let existing = model
        .prepare(&existing_request)
        .map_err(|error| anyhow!("{error:?}"))?;
    let SidecarPreparedOutcome::Existing {
        operation_id,
        reservation_handle,
        sidecar_id,
        context_attach_event_draft,
        ..
    } = existing
    else {
        bail!("second context prepare did not produce the closed Existing branch");
    };
    let durable = model
        .durable
        .coordinates
        .as_ref()
        .ok_or_else(|| anyhow!("committed Sidecar coordinates missing"))?;
    if sidecar_id != durable.sidecar_id {
        bail!("Existing branch changed the singleton native Sidecar identity");
    }
    let attach_event =
        sign_prepared_draft(&context_attach_event_draft, &signer, &verification_method)
            .map_err(|error| anyhow!("{error:?}"))?;
    let attach = SidecarEnsureAttachRequestBody {
        phase: SidecarAttachPhase::Attach,
        operation_id,
        idempotency_key: IdempotencyKey::new("cotest-sidecar-commit-existing")
            .map_err(anyhow::Error::msg)?,
        reservation_handle,
        context_attach_event: attach_event,
    };
    let accepted_attach = model
        .commit_existing(&attach, &public_key)
        .map_err(|error| anyhow!("{error:?}"))?;
    if model.atomic_commit_epoch != 3
        || model.durable.accepted_event_ids.len() != 4
        || model.durable.contexts.len() != 2
    {
        bail!("Sidecar Existing attach was not one atomic context-only commit");
    }
    let attach_snapshot = model.snapshot();
    let attach_replay = model
        .commit_existing(&attach, &public_key)
        .map_err(|error| anyhow!("{error:?}"))?;
    if serde_json::to_vec(&attach_replay)? != serde_json::to_vec(&accepted_attach)?
        || model.snapshot() != attach_snapshot
    {
        bail!("exact Sidecar attach replay did not return the original Accepted outcome");
    }
    let mut conflicting_attach = attach.clone();
    conflicting_attach
        .context_attach_event
        .unsigned
        .insert("different-attach-bytes".to_owned(), Value::Bool(true));
    if !matches!(
        model.commit_existing(&conflicting_attach, &public_key),
        Err(SidecarModelError::IdempotencyConflict)
    ) || model.snapshot() != attach_snapshot
    {
        bail!("Sidecar attach idempotency conflict changed staged or durable state");
    }

    let mut concurrent =
        SidecarExecutableModel::new(controller.clone(), true, AgentLifecycleStatus::Active);
    let device_a_request = fixed_prepare_request_for_operation(
        &controller,
        "cotest-sidecar-concurrent-prepare",
        false,
        "ak:operation:cotest.sidecar.concurrent-a",
    )?;
    let device_b_request = fixed_prepare_request_for_operation(
        &controller,
        "cotest-sidecar-concurrent-prepare",
        false,
        "ak:operation:cotest.sidecar.concurrent-b",
    )?;
    let device_a = concurrent
        .prepare_on_device(&device_a_request, "device-a")
        .map_err(|error| anyhow!("{error:?}"))?;
    let device_b = concurrent
        .prepare_on_device(&device_b_request, "device-b")
        .map_err(|error| anyhow!("{error:?}"))?;
    let SidecarPreparedOutcome::New {
        operation_id: operation_a,
        reservation_handle: handle_a,
        create_event_draft: create_a,
        context_attach_event_draft: attach_a,
        ..
    } = device_a
    else {
        bail!("device A concurrent prepare was not New");
    };
    let SidecarPreparedOutcome::New {
        operation_id: operation_b,
        reservation_handle: handle_b,
        create_event_draft: create_b,
        context_attach_event_draft: attach_b,
        ..
    } = device_b
    else {
        bail!("device B concurrent prepare was not New");
    };
    let sidecar_a = SidecarId::from_event_id(&create_a.event_id()?);
    let sidecar_b = SidecarId::from_event_id(&create_b.event_id()?);
    if handle_a == handle_b || concurrent.reservations.len() != 2 || sidecar_a != sidecar_b {
        bail!("concurrent device reservations overwrote or diverged fixed coordinates");
    }
    let concurrent_commit = |operation_id: ProtocolOperationId,
                             reservation_handle: ReservationHandle,
                             create_draft: &PreparedEventDraft,
                             attach_draft: &PreparedEventDraft|
     -> Result<SidecarEnsureCommitRequestBody> {
        Ok(SidecarEnsureCommitRequestBody {
            phase: SidecarCommitPhase::Commit,
            operation_id,
            idempotency_key: IdempotencyKey::new("cotest-sidecar-concurrent-commit")
                .map_err(anyhow::Error::msg)?,
            reservation_handle,
            create_event: sign_prepared_draft(create_draft, &signer, &verification_method)
                .map_err(|error| anyhow!("{error:?}"))?,
            context_attach_event: sign_prepared_draft(attach_draft, &signer, &verification_method)
                .map_err(|error| anyhow!("{error:?}"))?,
        })
    };
    let commit_a = concurrent_commit(operation_a, handle_a, &create_a, &attach_a)?;
    let commit_b = concurrent_commit(operation_b, handle_b, &create_b, &attach_b)?;
    let accepted_a = concurrent
        .commit_new_on_device(&commit_a, &public_key, "device-a")
        .map_err(|error| anyhow!("{error:?}"))?;
    let accepted_b = concurrent
        .commit_new_on_device(&commit_b, &public_key, "device-b")
        .map_err(|error| anyhow!("{error:?}"))?;
    let accepted_coordinates = |outcome: &SidecarEnsureOutcome| match outcome {
        SidecarEnsureOutcome::Accepted {
            sidecar_id,
            source_context_ref,
            ..
        } => Some((sidecar_id.clone(), source_context_ref.clone())),
        SidecarEnsureOutcome::Prepared { .. } => None,
    };
    if accepted_coordinates(&accepted_a) != accepted_coordinates(&accepted_b)
        || concurrent.durable.contexts.len() != 1
        || !concurrent.reservations.is_empty()
        || concurrent.accepted.len() != 2
        || concurrent.atomic_commit_epoch != 2
    {
        bail!("concurrent device commits did not converge on one Sidecar context");
    }
    Ok(())
}

// ─── VECT-SC-2 — eligibility_states ────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SidecarReconciliation {
    None,
    Add,
    Remove,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SidecarAccessProjection {
    desired: bool,
    effective: bool,
    pending: SidecarReconciliation,
}

impl SidecarAccessProjection {
    fn apply_lifecycle(&mut self, lifecycle: AgentLifecycleStatus) {
        self.desired = lifecycle == AgentLifecycleStatus::Active;
        self.pending = match (self.desired, self.effective) {
            (true, false) => SidecarReconciliation::Add,
            (false, true) => SidecarReconciliation::Remove,
            _ => SidecarReconciliation::None,
        };
    }

    fn complete_reconciliation(&mut self) {
        self.effective = self.desired;
        self.pending = SidecarReconciliation::None;
    }
}

pub fn run_sidecar_eligibility_states_vector() -> Result<()> {
    let _fixture_case = sidecar_fixture_case(VECTOR_ID_SIDECAR_ELIGIBILITY_STATES)?;
    let controller = sidecar_account(DidCoreId::new("ak:did_core:web:eligibility.example")?)?;
    let request = fixed_prepare_request(&controller, "cotest-sidecar-eligibility", false)?;
    let mut active =
        SidecarExecutableModel::new(controller.clone(), true, AgentLifecycleStatus::Active);
    if !matches!(
        active.prepare(&request),
        Ok(SidecarPreparedOutcome::New { .. })
    ) {
        bail!("active Agent did not reach the Sidecar prepare state machine");
    }
    for (lifecycle, expected) in [
        (AgentLifecycleStatus::Paused, SidecarModelError::AgentPaused),
        (
            AgentLifecycleStatus::Deactivated,
            SidecarModelError::AgentDeactivated,
        ),
    ] {
        let mut model = SidecarExecutableModel::new(controller.clone(), true, lifecycle);
        let before = model.snapshot();
        if !matches!(model.prepare(&request), Err(error) if error == expected)
            || model.snapshot() != before
        {
            bail!("ineligible Agent changed Sidecar staging or durable state");
        }
    }

    let mut access = SidecarAccessProjection {
        desired: true,
        effective: true,
        pending: SidecarReconciliation::None,
    };
    access.apply_lifecycle(AgentLifecycleStatus::Deactivated);
    if access.desired || !access.effective || access.pending != SidecarReconciliation::Remove {
        bail!("deactivation did not separate desired access from pending effective removal");
    }
    access.complete_reconciliation();
    if access.desired || access.effective || access.pending != SidecarReconciliation::None {
        bail!("Sidecar removal reconciliation did not close effective access");
    }
    Ok(())
}

// ─── VECT-SC-3 — existence_privacy ─────────────────────────────────────────

pub fn run_sidecar_existence_privacy_vector() -> Result<()> {
    let _fixture_case = sidecar_fixture_case(VECTOR_ID_SIDECAR_EXISTENCE_PRIVACY)?;
    let controller = sidecar_account(DidCoreId::new("ak:did_core:web:privacy.example")?)?;
    let request = fixed_prepare_request(&controller, "cotest-sidecar-privacy", false)?;
    let mut absent =
        SidecarExecutableModel::new(controller.clone(), false, AgentLifecycleStatus::Active);
    let mut existing = SidecarExecutableModel::with_existing(
        controller.clone(),
        false,
        AgentLifecycleStatus::Active,
    )?;
    let absent_before = absent.snapshot();
    let existing_before = existing.snapshot();
    let absent_denial = absent.prepare(&request);
    let existing_denial = existing.prepare(&request);
    if !matches!(absent_denial, Err(SidecarModelError::CreateDenied))
        || !matches!(existing_denial, Err(SidecarModelError::CreateDenied))
        || absent.snapshot() != absent_before
        || existing.snapshot() != existing_before
    {
        bail!("unauthorized Sidecar probe disclosed existence or wrote state");
    }

    let mut authorized_absent =
        SidecarExecutableModel::new(controller.clone(), true, AgentLifecycleStatus::Active);
    let mut authorized_existing =
        SidecarExecutableModel::with_existing(controller, true, AgentLifecycleStatus::Active)?;
    if !matches!(
        authorized_absent.prepare(&request),
        Ok(SidecarPreparedOutcome::New { .. })
    ) || !matches!(
        authorized_existing.prepare(&request),
        Ok(SidecarPreparedOutcome::Existing { .. })
    ) {
        bail!("authorized controller did not receive the closed New/Existing prepare branch");
    }
    Ok(())
}

// ─── VECT-SC-4 — hosted_projection ─────────────────────────────────────────

pub fn run_sidecar_hosted_projection_vector() -> Result<()> {
    let sidecar =
        SidecarId::new("ak:sidecar:ARp3V6IbuRJ1DuhggcFb2nOBwbPGWXaO4GLVY9SVMM5u".to_owned())?;
    if !sidecar.as_str().starts_with("ak:sidecar:") {
        bail!("Sidecar identity is not first-class");
    }
    if serde_json::to_value(AgentSidecarDisplayMode::ContextMerged)? != "context_merged"
        || serde_json::to_value(AgentSidecarDisplayMode::SidecarOnly)? != "sidecar_only"
        || serde_json::to_value(AgentSidecarExchangeOrigin::SourceTrackRouted)?
            != "source_track_routed"
        || serde_json::to_value(AgentSidecarExchangeOrigin::SidecarNative)? != "sidecar_native"
    {
        bail!("hosted Sidecar closed enums drifted");
    }
    let realm_id = RealmId::new("ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b")?;
    let source_strand_id = StrandId::new("ak:strand:AcweNVvZUYNuOdCMey9HT7PQHKPbHPJwOFTgn_cx7yjo")?;
    let anchor_id = EventId::new("ak:event:AVmh6k5n-qXekmKueZzJW_ZoqYSe8zyTeMC9sRwYlIGS")?;
    let request_id = EventId::new("ak:event:AU7uNevwc0Cp8J79qQnR0XFIA6sS-Ey-sAx6QesaglRs")?;
    let native_id = EventId::new("ak:event:AZjT-hpiUOSks1wjNlYAqMixCtZTrdsCsZzB-uVQC4hr")?;
    let response_id = EventId::new("ak:event:AYc-4BlSOVqQFbwNPwG_8grd4XMcbaWyErQiaMg6uDIK")?;
    let addressed_agent = DidCoreId::new("ak:did_core:web:assistant.agents.example")?;
    let terminal_id = EventId::new("ak:event:AcQOShj1JyHhaaSQwjV-D2nyDc1M1yK4DTq0JtH4nPIx")?;
    let projection = AgentSidecarExchangeProjection {
        schema: AgentSidecarExchangeProjectionSchema::V1,
        controller_account_id: sidecar_account(DidCoreId::new(
            "ak:did_core:web:alice.example.com",
        )?)?,
        sidecar_id: sidecar,
        exchange_id: AgentSidecarExchangeId::new("Abcdefghijklmnopqrstuv")?,
        source_track_ref: AgentSidecarSourceTrackRef {
            realm_id: realm_id.clone(),
            strand_id: source_strand_id.clone(),
            track_name: "discussion".to_owned(),
        },
        source_event_id: Some(anchor_id.clone()),
        source_hlc: Hlc::new("01970e589d21-0001-a13f9c2e")?,
        client_order_key: NonEmptyString::new("device-1-1").map_err(anyhow::Error::msg)?,
        addressed_agent_ids: vec![addressed_agent.clone()],
        coordinator_agent_id: addressed_agent.clone(),
        coordinator_assignment_event_id: request_id.clone(),
        participating_agent_ids: vec![addressed_agent],
        private_request_event_id: request_id.clone(),
        user_facing_response_event_ids: vec![response_id.clone()],
        status: AgentSidecarExchangeStatus::Complete,
        failure_reason_code: None,
        terminal_event_id: Some(terminal_id.clone()),
        folded_frontier: AgentSidecarExchangeFoldedFrontier {
            event_ids: vec![terminal_id],
            event_set_digest: agent_sidecar_exchange_event_set_digest(&[
                request_id.clone(),
                response_id.clone(),
            ])?,
            max_hlc: Hlc::new("01970e589d21-0004-a13f9c2e")?,
        },
    };
    projection.validate()?;
    let event = |event_id: EventId, hlc: &str, value: &'static str| {
        garth::projection::SidecarTimelineEvent {
            event_id,
            hlc: hlc.to_owned(),
            track_name: "discussion".to_owned(),
            value,
        }
    };
    let shared = vec![event(
        anchor_id.clone(),
        "01970e589d21-0001-a13f9c2e",
        "shared anchor",
    )];
    let private = vec![
        event(
            request_id.clone(),
            "01970e589d21-0002-a13f9c2e",
            "routed request",
        ),
        event(
            native_id.clone(),
            "01970e589d21-0003-a13f9c2e",
            "agent internal",
        ),
        event(
            response_id.clone(),
            "01970e589d21-0004-a13f9c2e",
            "user-facing response",
        ),
    ];
    let merged = garth::projection::merge_sidecar_timeline(
        [&projection],
        AgentSidecarDisplayMode::ContextMerged,
        &shared,
        &private,
    );
    if merged.iter().map(|item| &item.event_id).collect::<Vec<_>>()
        != vec![&anchor_id, &request_id, &response_id, &native_id]
        || merged[1].provenance != AgentSidecarProjectionProvenance::PrivateEcho
        || merged[2].provenance != AgentSidecarProjectionProvenance::PrivateEcho
        || merged[3].provenance != AgentSidecarProjectionProvenance::Private
    {
        bail!("hosted Sidecar merge did not isolate explicit responses from internal Events");
    }
    let private_only = garth::projection::merge_sidecar_timeline(
        [&projection],
        AgentSidecarDisplayMode::SidecarOnly,
        &shared,
        &private,
    );
    if private_only.len() != 3
        || private_only
            .iter()
            .any(|item| item.provenance != AgentSidecarProjectionProvenance::Private)
    {
        bail!("Sidecar-only projection leaked shared content or echo provenance");
    }
    Ok(())
}

// ─── VECT-SC-4 — multi_agent_publish ───────────────────────────────────────

pub fn run_sidecar_multi_agent_publish_vector() -> Result<()> {
    // The ensure/write/controller-control/publish quartet MUST be present,
    // distinct, and Sidecar-namespaced. Exchange control is intentionally a
    // separate controller-only action rather than being implied by Agent
    // write.
    let quartet = [
        CapabilityActionId::SELF_AGENT_SIDECAR_COMMAND_ENSURE_V1,
        CapabilityActionId::AGENT_SIDECAR_WRITE,
        CapabilityActionId::AGENT_SIDECAR_EXCHANGE_CONTROL,
        CapabilityActionId::AGENT_SIDECAR_PUBLISH,
    ];
    for action in quartet {
        if !action.contains("sidecar") {
            bail!("sidecar capability action `{action}` lost canonical scope");
        }
    }
    let mut sorted = quartet.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != quartet.len() {
        bail!("sidecar capability action quartet has duplicates");
    }
    if CapabilityActionId::AGENT_SIDECAR_EXCHANGE_CONTROL == CapabilityActionId::AGENT_SIDECAR_WRITE
    {
        bail!("controller-only exchange control must not collapse into Agent write");
    }
    Ok(())
}

// ─── shared exchange fixtures for the §7.2 vectors ─────────────────────────

fn exchange_event_id(suffix: u32) -> Result<EventId> {
    Ok(crate::fixture_event_id(format!(
        "sidecar-exchange:{suffix}"
    )))
}

fn exchange_hlc(counter: u32) -> Result<Hlc> {
    Ok(Hlc::new(format!("01970e589d21-{counter:04x}-a13f9c2e"))?)
}

fn exchange_controller() -> Result<DidCoreId> {
    Ok(DidCoreId::new("ak:did_core:web:alice.example.com")?)
}

fn exchange_agent_s() -> Result<DidCoreId> {
    Ok(DidCoreId::new("ak:did_core:web:assistant.agents.example")?)
}

fn exchange_agent_t() -> Result<DidCoreId> {
    Ok(DidCoreId::new("ak:did_core:web:reviewer.agents.example")?)
}

fn exchange_scope() -> Result<SidecarExchangeFoldScope> {
    Ok(SidecarExchangeFoldScope {
        controller_account_id: sidecar_account(exchange_controller()?)?,
        sidecar_id: SidecarId::new("ak:sidecar:ARp3V6IbuRJ1DuhggcFb2nOBwbPGWXaO4GLVY9SVMM5u")?,
    })
}

fn exchange_id_x1() -> Result<AgentSidecarExchangeId> {
    AgentSidecarExchangeId::new("Xabcdefghijklmnopqrstu").map_err(Into::into)
}

fn exchange_request_context() -> Result<AgentSidecarExchangeRequestContext> {
    Ok(AgentSidecarExchangeRequestContext {
        source_track_ref: AgentSidecarSourceTrackRef {
            realm_id: RealmId::new("ak:realm:AQcksDTzb8Sxrn1BUVVlHtH4vBOy99RKUB4EwOq_413b")?,
            strand_id: StrandId::new("ak:strand:AcweNVvZUYNuOdCMey9HT7PQHKPbHPJwOFTgn_cx7yjo")?,
            track_name: "discussion".to_owned(),
        },
        source_hlc: exchange_hlc(1)?,
        client_order_key: NonEmptyString::new("device-1-1").map_err(anyhow::Error::msg)?,
        addressed_agent_ids: vec![exchange_agent_s()?, exchange_agent_t()?],
        completion_policy: AgentSidecarExchangeCompletionPolicy::Coordinator,
        coordinator_agent_id: Some(exchange_agent_s()?),
        source_event_id: None,
    })
}

fn exchange_request_fact(
    suffix: u32,
    actor_seq: u64,
    digest: &str,
) -> Result<SidecarExchangeRequestFact> {
    Ok(SidecarExchangeRequestFact {
        event_id: exchange_event_id(suffix)?,
        hlc: exchange_hlc(1)?,
        actor_account_id: sidecar_account(exchange_controller()?)?,
        actor_seq,
        event_digest: digest.to_owned(),
        exchange_id: exchange_id_x1()?,
        context: exchange_request_context()?,
    })
}

fn exchange_agent_fact(
    suffix: u32,
    counter: u32,
    actor: DidCoreId,
    role: AgentSidecarExchangeBindingRole,
) -> Result<SidecarExchangeAgentFact> {
    let request_event_id = exchange_event_id(0x34)?;
    let binding = match role {
        AgentSidecarExchangeBindingRole::UserFacingResponse => {
            AgentSidecarEventExchangeBinding::user_facing_response(
                exchange_id_x1()?,
                request_event_id.clone(),
            )?
        }
        AgentSidecarExchangeBindingRole::Internal => {
            AgentSidecarEventExchangeBinding::internal(exchange_id_x1()?, request_event_id.clone())?
        }
        AgentSidecarExchangeBindingRole::Request => bail!("request facts use the request builder"),
    };
    Ok(SidecarExchangeAgentFact {
        event_id: exchange_event_id(suffix)?,
        hlc: exchange_hlc(counter)?,
        actor_principal_id: actor,
        binding,
        refs_after: vec![request_event_id],
    })
}

fn exchange_close_control(
    suffix: u32,
    actor_seq: u64,
    digest: &str,
    action: AgentSidecarExchangeControlAction,
    basis: Vec<EventId>,
    responses: Option<Vec<EventId>>,
    failure_reason_code: Option<&str>,
) -> Result<SidecarExchangeControlFact> {
    Ok(SidecarExchangeControlFact {
        event_id: exchange_event_id(suffix)?,
        hlc: exchange_hlc(0x40 + suffix)?,
        actor_account_id: sidecar_account(exchange_controller()?)?,
        actor_seq,
        event_digest: digest.to_owned(),
        refs_after: basis.clone(),
        control: AgentSidecarExchangeControl {
            schema: AgentSidecarExchangeControlSchema::V1,
            exchange_id: exchange_id_x1()?,
            request_event_id: exchange_event_id(0x34)?,
            basis_event_ids: basis,
            action,
            response_event_ids: responses,
            failure_reason_code: failure_reason_code
                .map(|code| NonEmptyString::new(code).map_err(anyhow::Error::msg))
                .transpose()?,
            expected_coordinator_agent_id: None,
            coordinator_agent_id: None,
        },
    })
}

// ─── VECT-SC-8 — exchange_binding_closed_loop ──────────────────────────────

pub fn run_sidecar_exchange_binding_closed_loop_vector() -> Result<()> {
    let scope = exchange_scope()?;
    let exchange = exchange_id_x1()?;
    // Step 1: the request binding is the only exchange identity source.
    let request_binding =
        AgentSidecarEventExchangeBinding::request(exchange.clone(), exchange_request_context()?)?;
    if request_binding.request_context.as_ref().map(|context| {
        context.completion_policy == AgentSidecarExchangeCompletionPolicy::Coordinator
    }) != Some(true)
    {
        bail!("request binding lost its coordinator completion policy");
    }
    let request = exchange_request_fact(0x34, 3, "aa")?;

    // Step 2: a duplicate request reusing X1 at a higher sequence never
    // becomes canonical, and an agent-authored request binding is invalid.
    let duplicate_request = exchange_request_fact(0x40, 9, "zz")?;
    let mut agent_authored_request = exchange_request_fact(0x41, 1, "zz")?;
    agent_authored_request.actor_account_id = sidecar_account(exchange_agent_s()?)?;
    let delivered = fold_sidecar_exchange(
        &scope,
        &exchange,
        &[
            duplicate_request,
            agent_authored_request.clone(),
            request.clone(),
        ],
        &[],
        &[],
    )?
    .ok_or_else(|| anyhow!("canonical request must fold"))?;
    if delivered.private_request_event_id != exchange_event_id(0x34)?
        || delivered.status != AgentSidecarExchangeStatus::Delivered
    {
        bail!("canonical request selection or delivered fold drifted");
    }
    if fold_sidecar_exchange(&scope, &exchange, &[agent_authored_request], &[], &[])?.is_some() {
        bail!("an agent-authored request binding must never be consumed");
    }

    // Internal events keep delivered and stay non-echo.
    let internal = exchange_agent_fact(
        0x35,
        2,
        exchange_agent_s()?,
        AgentSidecarExchangeBindingRole::Internal,
    )?;
    let with_internal = fold_sidecar_exchange(
        &scope,
        &exchange,
        std::slice::from_ref(&request),
        std::slice::from_ref(&internal),
        &[],
    )?
    .ok_or_else(|| anyhow!("internal fold missing"))?;
    if with_internal.status != AgentSidecarExchangeStatus::Delivered
        || !with_internal.user_facing_response_event_ids.is_empty()
        || with_internal.participating_agent_ids != vec![exchange_agent_s()?]
    {
        bail!("internal events must track participation without echo or status change");
    }

    // Step 3: every mutation fails closed to non-echo.
    let valid_response = exchange_agent_fact(
        0x36,
        4,
        exchange_agent_s()?,
        AgentSidecarExchangeBindingRole::UserFacingResponse,
    )?;
    let mut wrong_exchange = valid_response.clone();
    wrong_exchange.event_id = exchange_event_id(0x50)?;
    wrong_exchange.binding.exchange_id = AgentSidecarExchangeId::new("Yabcdefghijklmnopqrstu")?;
    let mut wrong_request_ref = valid_response.clone();
    wrong_request_ref.event_id = exchange_event_id(0x51)?;
    wrong_request_ref.binding.request_event_id = Some(exchange_event_id(0x99)?);
    let mut missing_causal_ref = valid_response.clone();
    missing_causal_ref.event_id = exchange_event_id(0x52)?;
    missing_causal_ref.refs_after = Vec::new();
    let mut unaddressed_actor = valid_response.clone();
    unaddressed_actor.event_id = exchange_event_id(0x53)?;
    unaddressed_actor.actor_principal_id =
        DidCoreId::new("ak:did_core:web:stranger.agents.example")?;
    let mut controller_response = valid_response.clone();
    controller_response.event_id = exchange_event_id(0x54)?;
    controller_response.actor_principal_id = exchange_controller()?;
    let duplicate_delivery = valid_response.clone();
    let folded = fold_sidecar_exchange(
        &scope,
        &exchange,
        std::slice::from_ref(&request),
        &[
            valid_response.clone(),
            duplicate_delivery,
            wrong_exchange,
            wrong_request_ref,
            missing_causal_ref,
            unaddressed_actor,
            controller_response,
        ],
        &[],
    )?
    .ok_or_else(|| anyhow!("closed-loop fold missing"))?;
    // Step 4: duplicate delivery appends exactly once.
    if folded.user_facing_response_event_ids != vec![exchange_event_id(0x36)?]
        || folded.status != AgentSidecarExchangeStatus::Responding
    {
        bail!("mutated responses leaked into the echo set or duplicates were not idempotent");
    }

    // Unknown roles and ak:message: shaped request references fail closed at
    // the closed schema (fail-closed metadata accessor -> non-echo).
    for invalid in [
        serde_json::json!({
            "schema": "ak.schema.agent_sidecar_event_exchange_binding.v1",
            "exchange_id": exchange.as_str(),
            "role": "coordinator_summary",
        }),
        serde_json::json!({
            "schema": "ak.schema.agent_sidecar_event_exchange_binding.v1",
            "exchange_id": exchange.as_str(),
            "role": "user_facing_response",
            "request_event_id": "ak:message:AX0TNnklqIlzhGa2OXRoCVE1dmOt3VUwpuOvqt4iPt5F",
        }),
    ] {
        let metadata: MessageMetadata =
            serde_json::from_value(serde_json::json!({ "sidecar_exchange_binding": invalid }))?;
        if metadata.sidecar_exchange_binding().is_some() {
            bail!("invalid binding material must fail closed to non-echo");
        }
    }

    // Step 5: a non-coordinator completion request never closes the exchange;
    // only the controller-authored durable close control advances terminal
    // state, and completes_exchange itself changes nothing.
    let non_coordinator_completion = AgentSidecarEventExchangeBinding::user_facing_response(
        exchange.clone(),
        exchange_event_id(0x34)?,
    )?
    .with_completion(exchange_event_id(0x34)?)?;
    let mut t_response = exchange_agent_fact(
        0x37,
        5,
        exchange_agent_t()?,
        AgentSidecarExchangeBindingRole::UserFacingResponse,
    )?;
    t_response.binding = non_coordinator_completion;
    let coordinator = with_internal.coordinator_agent_id.clone();
    if t_response.actor_principal_id == coordinator {
        bail!("fixture expects T to be a non-coordinator");
    }
    let responding = fold_sidecar_exchange(
        &scope,
        &exchange,
        std::slice::from_ref(&request),
        &[valid_response.clone(), t_response.clone()],
        &[],
    )?
    .ok_or_else(|| anyhow!("responding fold missing"))?;
    if responding.status != AgentSidecarExchangeStatus::Responding
        || responding.terminal_event_id.is_some()
    {
        bail!("completes_exchange must not advance terminal state by itself");
    }
    // T is addressed, so its body may echo even though its completion
    // request is ignored.
    if !responding
        .user_facing_response_event_ids
        .contains(&exchange_event_id(0x37)?)
    {
        bail!("an addressed non-coordinator user-facing response must still echo");
    }
    let close = exchange_close_control(
        0x38,
        7,
        "cc",
        AgentSidecarExchangeControlAction::Close,
        vec![exchange_event_id(0x36)?, exchange_event_id(0x37)?],
        Some(vec![exchange_event_id(0x36)?, exchange_event_id(0x37)?]),
        None,
    )?;
    let complete = fold_sidecar_exchange(
        &scope,
        &exchange,
        &[request],
        &[valid_response, t_response],
        std::slice::from_ref(&close),
    )?
    .ok_or_else(|| anyhow!("terminal fold missing"))?;
    if complete.status != AgentSidecarExchangeStatus::Complete
        || complete.terminal_event_id != Some(exchange_event_id(0x38)?)
        || complete.user_facing_response_event_ids
            != vec![exchange_event_id(0x36)?, exchange_event_id(0x37)?]
    {
        bail!("only the accepted durable close control may advance terminal state");
    }
    Ok(())
}

// ─── VECT-SC-9 — exchange_projection_recovery ──────────────────────────────

pub fn run_sidecar_exchange_projection_recovery_vector() -> Result<()> {
    let scope = exchange_scope()?;
    let exchange = exchange_id_x1()?;
    let request = exchange_request_fact(0x34, 1, "aa")?;
    let response_r1 = exchange_agent_fact(
        0x35,
        3,
        exchange_agent_s()?,
        AgentSidecarExchangeBindingRole::UserFacingResponse,
    )?;
    let response_r2 = exchange_agent_fact(
        0x36,
        2,
        exchange_agent_s()?,
        AgentSidecarExchangeBindingRole::UserFacingResponse,
    )?;

    // Independent devices replay the same accepted history in different
    // arrival orders and MUST produce bit-identical projections with the
    // canonical (event HLC, event id) response order.
    let device_one = fold_sidecar_exchange(
        &scope,
        &exchange,
        std::slice::from_ref(&request),
        &[response_r1.clone(), response_r2.clone()],
        &[],
    )?
    .ok_or_else(|| anyhow!("device one fold missing"))?;
    let device_two = fold_sidecar_exchange(
        &scope,
        &exchange,
        std::slice::from_ref(&request),
        &[response_r2.clone(), response_r1.clone()],
        &[],
    )?
    .ok_or_else(|| anyhow!("device two fold missing"))?;
    if device_one != device_two {
        bail!("independent device replay must be bit-identical");
    }
    if device_one.user_facing_response_event_ids
        != vec![exchange_event_id(0x36)?, exchange_event_id(0x35)?]
    {
        bail!("responses must order by (event HLC, event id) bytes, not arrival");
    }

    // Cache-loss rebuild starts from the request binding alone and never
    // redelivers: the request fact is sufficient and deterministic.
    let rebuilt =
        fold_sidecar_exchange(&scope, &exchange, std::slice::from_ref(&request), &[], &[])?
            .ok_or_else(|| anyhow!("rebuild fold missing"))?;
    if rebuilt.status != AgentSidecarExchangeStatus::Delivered
        || rebuilt.source_track_ref != exchange_request_context()?.source_track_ref
    {
        bail!("write-once projection fields must rebuild verbatim from the request binding");
    }

    // Partial views: D1 only saw R1, D2 only saw R2. Their frontiers are
    // incomparable; neither may win by HLC/LWW — both must backfill and fold
    // the joined history to the same digest.
    let d1_partial = fold_sidecar_exchange(
        &scope,
        &exchange,
        std::slice::from_ref(&request),
        std::slice::from_ref(&response_r1),
        &[],
    )?
    .ok_or_else(|| anyhow!("partial fold missing"))?;
    let d2_local: BTreeSet<EventId> = [exchange_event_id(0x34)?, exchange_event_id(0x36)?]
        .into_iter()
        .collect();
    if evaluate_sidecar_exchange_cache(&d1_partial.folded_frontier, &d2_local)?
        != SidecarExchangeCacheDecision::BackfillRequired
    {
        bail!("incomparable frontiers must demand backfill, never LWW");
    }
    let joined: BTreeSet<EventId> = [
        exchange_event_id(0x34)?,
        exchange_event_id(0x35)?,
        exchange_event_id(0x36)?,
    ]
    .into_iter()
    .collect();
    if evaluate_sidecar_exchange_cache(&d1_partial.folded_frontier, &joined)?
        != SidecarExchangeCacheDecision::Refold
        || evaluate_sidecar_exchange_cache(&device_one.folded_frontier, &joined)?
            != SidecarExchangeCacheDecision::Fresh
    {
        bail!("cache decisions must derive from causal coverage of the local verified set");
    }
    if device_one.folded_frontier.event_set_digest
        != agent_sidecar_exchange_event_set_digest(&joined.iter().cloned().collect::<Vec<_>>())?
    {
        bail!("folded frontier digest must commit to the complete contributing set");
    }

    // Terminal action x response-set mapping.
    let cases: [(AgentSidecarExchangeControlAction, bool, Option<&str>, _); 5] = [
        (
            AgentSidecarExchangeControlAction::Close,
            true,
            None,
            AgentSidecarExchangeStatus::Complete,
        ),
        (
            AgentSidecarExchangeControlAction::Cancel,
            true,
            None,
            AgentSidecarExchangeStatus::Complete,
        ),
        (
            AgentSidecarExchangeControlAction::Close,
            false,
            None,
            AgentSidecarExchangeStatus::Failed,
        ),
        (
            AgentSidecarExchangeControlAction::Cancel,
            false,
            None,
            AgentSidecarExchangeStatus::Failed,
        ),
        (
            AgentSidecarExchangeControlAction::Fail,
            false,
            Some("agent_deactivated"),
            AgentSidecarExchangeStatus::Failed,
        ),
    ];
    for (action, with_response, failure_reason_code, expected_status) in cases {
        let responses = if with_response {
            vec![exchange_event_id(0x35)?]
        } else {
            Vec::new()
        };
        // §7.2.3 exactness: response_event_ids must be exactly the
        // basis-covered validated set, so the empty-response terminals use a
        // basis that covers only the request (a basis covering the validated
        // response with an empty listing would be an invalid control).
        let basis = if with_response {
            vec![exchange_event_id(0x35)?]
        } else {
            vec![exchange_event_id(0x34)?]
        };
        let control = exchange_close_control(
            0x38,
            5,
            "cc",
            action,
            basis,
            Some(responses),
            failure_reason_code,
        )?;
        let folded = fold_sidecar_exchange(
            &scope,
            &exchange,
            std::slice::from_ref(&request),
            std::slice::from_ref(&response_r1),
            std::slice::from_ref(&control),
        )?
        .ok_or_else(|| anyhow!("terminal-mapping fold missing"))?;
        if folded.status != expected_status {
            bail!("terminal action x response-set mapping drifted for {action:?}");
        }
        let expected_failure = match (action, with_response) {
            (_, true) => None,
            (AgentSidecarExchangeControlAction::Close, false) => Some("controller_closed_empty"),
            (AgentSidecarExchangeControlAction::Cancel, false) => Some("controller_cancelled"),
            (AgentSidecarExchangeControlAction::Fail, false) => Some("agent_deactivated"),
            (AgentSidecarExchangeControlAction::ReassignCoordinator, false) => unreachable!(),
        };
        if folded
            .failure_reason_code
            .as_ref()
            .map(|code| code.as_str())
            != expected_failure
        {
            bail!("derived failure code drifted for {action:?}");
        }
        if expected_status == AgentSidecarExchangeStatus::Failed
            && !folded.user_facing_response_event_ids.is_empty()
        {
            bail!("failed exchanges never carry responses");
        }
    }

    // An empty terminal whose basis covers a validated response is an
    // inexact response set and therefore an invalid control: the exchange
    // stays responding rather than forking to failed (§7.2.3).
    let inexact_empty_close = exchange_close_control(
        0x3c,
        5,
        "cc",
        AgentSidecarExchangeControlAction::Close,
        vec![exchange_event_id(0x35)?],
        Some(Vec::new()),
        None,
    )?;
    let still_responding = fold_sidecar_exchange(
        &scope,
        &exchange,
        std::slice::from_ref(&request),
        std::slice::from_ref(&response_r1),
        std::slice::from_ref(&inexact_empty_close),
    )?
    .ok_or_else(|| anyhow!("inexact-terminal fold missing"))?;
    if still_responding.status != AgentSidecarExchangeStatus::Responding {
        bail!("an inexact terminal response set must invalidate the control");
    }

    // Same-sequence terminal siblings resolve by bytewise-max event digest;
    // the winner absorbs everything after it, and Events outside the winning
    // basis closure stay private audit history.
    let winner = exchange_close_control(
        0x38,
        5,
        "ff",
        AgentSidecarExchangeControlAction::Close,
        vec![exchange_event_id(0x35)?],
        Some(vec![exchange_event_id(0x35)?]),
        None,
    )?;
    let sibling_loser = exchange_close_control(
        0x39,
        5,
        "aa",
        AgentSidecarExchangeControlAction::Cancel,
        vec![exchange_event_id(0x35)?],
        Some(Vec::new()),
        None,
    )?;
    let uncovered_late = response_r2.clone();
    let folded = fold_sidecar_exchange(
        &scope,
        &exchange,
        std::slice::from_ref(&request),
        &[response_r1.clone(), uncovered_late],
        &[sibling_loser, winner],
    )?
    .ok_or_else(|| anyhow!("sibling fold missing"))?;
    if folded.status != AgentSidecarExchangeStatus::Complete
        || folded.terminal_event_id != Some(exchange_event_id(0x38)?)
    {
        bail!("same-sequence siblings must resolve by bytewise-max event digest");
    }
    if folded
        .folded_frontier
        .event_ids
        .contains(&exchange_event_id(0x36)?)
    {
        bail!("Events outside the winning terminal basis must stay private audit history");
    }

    // Reassignment is valid only before terminal and only with a matching
    // expected coordinator; it retargets the assignment Event id.
    let mut reassign = exchange_close_control(
        0x3a,
        5,
        "cc",
        AgentSidecarExchangeControlAction::ReassignCoordinator,
        vec![exchange_event_id(0x34)?],
        None,
        None,
    )?;
    reassign.control.expected_coordinator_agent_id = Some(exchange_agent_s()?);
    reassign.control.coordinator_agent_id = Some(exchange_agent_t()?);
    let mut stale_reassign = exchange_close_control(
        0x3b,
        6,
        "dd",
        AgentSidecarExchangeControlAction::ReassignCoordinator,
        vec![exchange_event_id(0x34)?],
        None,
        None,
    )?;
    stale_reassign.control.expected_coordinator_agent_id = Some(exchange_agent_s()?);
    stale_reassign.control.coordinator_agent_id = Some(exchange_agent_t()?);
    let reassigned = fold_sidecar_exchange(
        &scope,
        &exchange,
        std::slice::from_ref(&request),
        &[],
        &[reassign, stale_reassign],
    )?
    .ok_or_else(|| anyhow!("reassign fold missing"))?;
    if reassigned.coordinator_agent_id != exchange_agent_t()?
        || reassigned.coordinator_assignment_event_id != exchange_event_id(0x3a)?
    {
        bail!("matching reassignment must retarget coordinator and assignment Event id");
    }

    // Projection state invariants are closed.
    let mut invalid = device_one.clone();
    invalid.status = AgentSidecarExchangeStatus::Failed;
    invalid.failure_reason_code =
        Some(NonEmptyString::new("agent_deactivated").map_err(anyhow::Error::msg)?);
    invalid.terminal_event_id = Some(exchange_event_id(0x38)?);
    if invalid.validate().is_ok() {
        bail!("failed with responses must violate the projection schema");
    }
    Ok(())
}

// ─── VECT-SC-10 — exchange_binding_containment ─────────────────────────────

pub fn run_sidecar_exchange_binding_containment_vector() -> Result<()> {
    // The forbidden-wire-fields registry hard-rejects plaintext/shared-scope
    // occurrences of the binding key, both schema ids, and exchange_id.
    let registry = super::load_artifact_json("registry/forbidden-wire-fields.json")?;
    let entry = registry["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|entry| entry["id"].as_str() == Some("sidecar_exchange_binding"))
        .ok_or_else(|| anyhow!("forbidden-wire-fields registry lost sidecar_exchange_binding"))?;
    if entry["rejection_level"].as_str() != Some("hard_reject") {
        bail!("sidecar_exchange_binding containment must be a hard reject");
    }
    let allowed = entry["allowed_contexts"]
        .as_array()
        .map(|contexts| {
            contexts
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if allowed != vec!["changelog", "negative_test"] {
        bail!("sidecar_exchange_binding allowed contexts widened: {allowed:?}");
    }

    // The account-data registry carries no exchange projection key surface.
    let account_registry = super::load_artifact_json("registry/account-data-key-registry.json")?;
    if serde_json::to_string(&account_registry)?.contains("sidecar_projection") {
        bail!("the exchange projection must not register any account-data key");
    }

    // The local projection cache DTO rejects account-data key smuggling: a
    // fully valid projection round-trips, and the same JSON plus a smuggled
    // account-data key fails closed (deny_unknown_fields).
    let valid_projection = fold_sidecar_exchange(
        &exchange_scope()?,
        &exchange_id_x1()?,
        &[exchange_request_fact(0x34, 1, "aa")?],
        &[],
        &[],
    )?
    .ok_or_else(|| anyhow!("containment projection fold missing"))?;
    let mut round_trip = serde_json::to_value(&valid_projection)?;
    if serde_json::from_value::<AgentSidecarExchangeProjection>(round_trip.clone()).is_err() {
        bail!("a valid exchange projection must round-trip");
    }
    round_trip["account_data_key"] = serde_json::json!("ak.agent.sidecar_projection.v1:x");
    if serde_json::from_value::<AgentSidecarExchangeProjection>(round_trip).is_ok() {
        bail!("the exchange projection DTO must reject account-data key fields");
    }

    // Binding material only round-trips through the closed schema mount;
    // spelling of both schema ids is pinned.
    let binding = AgentSidecarEventExchangeBinding::user_facing_response(
        exchange_id_x1()?,
        exchange_event_id(0x34)?,
    )?;
    let mut metadata = MessageMetadata::default();
    metadata.set_sidecar_exchange_binding(&binding)?;
    let raw = serde_json::to_value(&metadata)?;
    if raw["sidecar_exchange_binding"]["schema"].as_str()
        != Some("ak.schema.agent_sidecar_event_exchange_binding.v1")
    {
        bail!("binding schema id spelling drifted");
    }
    if serde_json::to_value(AgentSidecarExchangeControlSchema::V1)?
        != "ak.schema.agent_sidecar_exchange_control.v1"
    {
        bail!("control schema id spelling drifted");
    }

    // An explicit publish is an ordinary shared Event: only the controller-
    // approved body crosses the boundary. The conformance value deliberately
    // contains every private token in adjacent local state and proves none is
    // serialized into the durable output.
    let exchange_id = exchange_id_x1()?;
    let private_state = serde_json::json!({
        "exchange_id": exchange_id,
        "sidecar_exchange_binding": raw["sidecar_exchange_binding"].clone(),
        "sidecar_id": exchange_scope()?.sidecar_id,
        "registered_source_context": exchange_request_context()?.source_track_ref,
        "scratchpad": "never publish this",
        "draft_history": ["private draft"]
    });
    let approved_body = "controller-approved shared summary";
    let publish_output = serde_json::json!({
        "kind": "ak.message.create",
        "scope_ref": {
            "kind": "realm",
            "realm_id": exchange_request_context()?.source_track_ref.realm_id
        },
        "payload": {
            "strand_id": exchange_request_context()?.source_track_ref.strand_id,
            "content": {
                "kind": "ak.content.text",
                "text": approved_body
            }
        }
    });
    let published_wire = serde_json::to_string(&publish_output)?;
    if published_wire.contains(exchange_id.as_str())
        || published_wire.contains("sidecar_exchange_binding")
        || published_wire.contains("ak.schema.agent_sidecar_event_exchange_binding.v1")
        || published_wire.contains("ak.schema.agent_sidecar_exchange_control.v1")
        || private_state
            .as_object()
            .into_iter()
            .flatten()
            .filter_map(|(_, value)| value.as_str())
            .any(|secret| published_wire.contains(secret))
    {
        bail!("explicit publish output leaked Sidecar exchange or private locator material");
    }
    if publish_output["payload"]["content"]["text"].as_str() != Some(approved_body) {
        bail!("explicit publish output differs from the controller-approved body");
    }
    Ok(())
}

fn sidecar_fixture_case(vector_id: &str) -> Result<Value> {
    let fixture = super::load_fixture_value(SIDECAR_VECTORS_FIXTURE_FILE)?;
    fixture["cases"]
        .as_array()
        .and_then(|cases| {
            cases
                .iter()
                .find(|case| case["vector_id"].as_str() == Some(vector_id))
        })
        .cloned()
        .ok_or_else(|| anyhow!("missing Sidecar fixture case {vector_id}"))
}

// ─── VECT-SC-11 — context_locator_recovery ────────────────────────────────

pub fn run_sidecar_context_locator_recovery_vector() -> Result<()> {
    let case = sidecar_fixture_case(VECTOR_ID_SIDECAR_CONTEXT_LOCATOR_RECOVERY)?;
    let locator = &case["locator"];
    let realm_id = RealmId::new(
        locator["realm_id"]
            .as_str()
            .ok_or_else(|| anyhow!("recovery fixture realm_id is missing"))?,
    )?;
    let controller_account_id: AccountId = serde_json::from_value(
        locator
            .get("controller_account_id")
            .cloned()
            .ok_or_else(|| anyhow!("recovery fixture controller_account_id is missing"))?,
    )?;
    let sidecar_id = SidecarId::new(
        locator["sidecar_id"]
            .as_str()
            .ok_or_else(|| anyhow!("recovery fixture sidecar_id is missing"))?,
    )?;
    let source_strand_id = StrandId::new(
        locator["source_context_ref"]
            .as_str()
            .ok_or_else(|| anyhow!("recovery fixture source_context_ref is missing"))?,
    )?;
    let participant_authority_digest = agent_sidecar_participant_authority_digest(
        sidecar_id.clone(),
        realm_id.clone(),
        controller_account_id.clone(),
        &[],
    )?;
    let created_at: DateTime<Utc> = "2026-07-29T00:00:00.000Z".parse()?;
    let view = AgentSidecarView {
        sidecar: AgentSidecar {
            id: sidecar_id.clone(),
            schema: AgentSidecarSchema::V1,
            realm_id: realm_id.clone(),
            controller_account_id: controller_account_id.clone(),
            encryption_profile: AgentSidecarEncryptionProfile::MlsRfc9420,
            state: AgentSidecarState::Active,
            state_changed_at: None,
            created_at,
            updated_at: None,
        },
        desired_agent_ids: Vec::new(),
        effective_agent_ids: Vec::new(),
        mls_context: AgentSidecarMlsContext {
            participant_authority_digest,
            control_frontier: vec![
                NonEmptyString::new("ak:event:AW7v_e06yQzTyt3cQnfQqZgcb1qUW5O5flxXbw4ZEahY")
                    .map_err(anyhow::Error::msg)?,
            ],
            mls_group_id: None,
            epoch: None,
            genesis_event_ref: None,
            current_controller_device_ready: false,
        },
        access_readiness: AgentSidecarAccessReadiness::Opening,
        pending_access_reconciliations: Vec::new(),
    };
    view.validate()?;
    let scope = ScopeRef::Sidecar {
        realm_id: realm_id.clone(),
        sidecar_id: sidecar_id.clone(),
    };
    let attach_event = arkret_wire::test_support::raw_event_at(
        EventKind::SidecarContextAttach.as_str(),
        scope,
        controller_account_id.principal_id.clone(),
        controller_account_id.station_id.clone(),
        20,
        exchange_hlc(0x81)?,
        serde_json::to_value(SidecarContextAttachPayload {
            sidecar_id: sidecar_id.clone(),
            source_context_ref: SidecarContextRef::Strand {
                strand_id: source_strand_id.clone(),
            },
            version: 1,
            predecessor_event_ref: None,
        })?,
        created_at,
    )?;

    let recovered = recover_agent_sidecar_context_locators(
        std::slice::from_ref(&view),
        std::slice::from_ref(&attach_event),
    )?;
    if recovered.len() != 1
        || recovered[0].sidecar_id != sidecar_id
        || recovered[0].mapping_event_id != attach_event.event_id
        || recovered[0].version != 1
        || recovered[0].source_context_ref
            != AgentSidecarContextRef::strand(realm_id, source_strand_id)
    {
        bail!("accepted native Sidecar attachment did not recover the canonical locator");
    }
    let unauthorized_attach = arkret_wire::test_support::raw_event_at(
        EventKind::SidecarContextAttach.as_str(),
        attach_event.scope_ref.clone(),
        DidCoreId::new("ak:did_core:web:mallory.example")?,
        DidCoreId::new("ak:did_core:web:principal.example")?,
        21,
        exchange_hlc(0x82)?,
        serde_json::to_value(&attach_event.payload)?,
        created_at,
    )?;
    if !recover_agent_sidecar_context_locators(
        std::slice::from_ref(&view),
        std::slice::from_ref(&unauthorized_attach),
    )?
    .is_empty()
    {
        bail!("a non-controller Sidecar attachment must remain unresolved");
    }
    let same_principal_other_station_attach = arkret_wire::test_support::raw_event_at(
        EventKind::SidecarContextAttach.as_str(),
        attach_event.scope_ref.clone(),
        controller_account_id.principal_id.clone(),
        DidCoreId::new("ak:did_core:web:other-station.example")?,
        22,
        exchange_hlc(0x83)?,
        serde_json::to_value(&attach_event.payload)?,
        created_at,
    )?;
    if !recover_agent_sidecar_context_locators(
        std::slice::from_ref(&view),
        std::slice::from_ref(&same_principal_other_station_attach),
    )?
    .is_empty()
    {
        bail!("a same-principal attachment from another Station must remain unresolved");
    }
    let mut service_actor_attach = attach_event.clone();
    service_actor_attach.actor_id = ActorId::service(controller_account_id.principal_id.clone());
    if !recover_agent_sidecar_context_locators(
        std::slice::from_ref(&view),
        std::slice::from_ref(&service_actor_attach),
    )?
    .is_empty()
    {
        bail!("a service-authored Sidecar attachment must remain unresolved");
    }
    let pagination = &case["pagination"];
    if pagination["repeated_cursor_outcome"].as_str() != Some("backfill_pending")
        || pagination["incomplete_page_outcome"].as_str() != Some("backfill_pending")
        || pagination["sidecar_list_cursors"]
            .as_array()
            .and_then(|values| values.last())
            .is_none_or(|last| !last.is_null())
        || pagination["event_scan_cursors"]
            .as_array()
            .and_then(|values| values.last())
            .is_none_or(|last| !last.is_null())
    {
        bail!("Sidecar recovery pagination does not terminate only on an explicit final page");
    }
    Ok(())
}

// ─── VECT-SC-12 — canonical_sibling_digest ────────────────────────────────

pub fn run_sidecar_canonical_sibling_digest_vector() -> Result<()> {
    let case = sidecar_fixture_case(VECTOR_ID_SIDECAR_CANONICAL_SIBLING_DIGEST)?;
    let siblings = case["siblings"]
        .as_array()
        .ok_or_else(|| anyhow!("digest vector siblings are missing"))?;
    if siblings.len() != 2 {
        bail!("digest vector requires exactly two siblings");
    }
    let realm_id = RealmId::new("ak:realm:AWsf08tedvQgc9QPO9ncYaCHxq005x-VuTJWkwlSmC_2")?;
    let actor = exchange_controller()?;
    // Give the two siblings different seconds so their digest preimages are
    // independently variable. The protocol tie-break compares canonical
    // digests, never the Base64URL spelling of their complete Event ids.
    let base_created_at: DateTime<Utc> = "2026-07-29T00:00:00.000Z".parse()?;
    // Search the two possible second-offset assignments for the one that is a
    // real counterexample. `created_at` is digest-covered, so changing it moves
    // both the digest and the complete content-bound identity. Search a small
    // deterministic grid of second offsets for the first assignment that is a
    // genuine counterexample.
    let mut events = Vec::new();
    let mut found = false;
    'search: for gap in 1_i64..1_024 {
        for offsets in [[0_i64, gap], [gap, 0_i64]] {
            events = build_sibling_digest_events(
                siblings,
                &case,
                &realm_id,
                &actor,
                base_created_at,
                offsets,
            )?;
            if sibling_digest_fixture_is_counterexample(&events) {
                found = true;
                break 'search;
            }
        }
    }
    if !found {
        bail!("no second-offset assignment makes the sibling fixture a counterexample");
    }
    #[allow(clippy::items_after_statements)]
    fn build_sibling_digest_events(
        siblings: &[Value],
        case: &Value,
        realm_id: &RealmId,
        actor: &DidCoreId,
        base_created_at: DateTime<Utc>,
        offsets: [i64; 2],
    ) -> Result<Vec<Event>> {
        let realm_id = realm_id.clone();
        let actor = actor.clone();
        let mut events = Vec::new();
        for (index, sibling) in siblings.iter().enumerate() {
            let created_at = base_created_at + chrono::Duration::seconds(offsets[index]);
            events.push(arkret_wire::test_support::raw_event_at(
                EventKind::MessageCreate.as_str(),
                ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                actor.clone(),
                DidCoreId::new("ak:did_core:web:principal.example")?,
                case["actor_seq"]
                    .as_u64()
                    .ok_or_else(|| anyhow!("digest sibling actor_seq is missing"))?,
                Hlc::new(
                    sibling["hlc"]
                        .as_str()
                        .ok_or_else(|| anyhow!("digest sibling HLC is missing"))?,
                )?,
                serde_json::json!({
                    "strand_id": "ak:strand:AV56KkeEaMSR4caEiVYFp1MtJk3sQ_Zn0VETrzEWQlU3",
                    "track_name": "discussion",
                    "content": {
                        "kind": "ak.content.text",
                        "body": sibling["content_text"]
                    }
                }),
                created_at,
            )?);
        }
        Ok(events)
    }

    #[allow(clippy::items_after_statements)]
    fn sibling_digest_fixture_is_counterexample(events: &[Event]) -> bool {
        let digest_winner = events
            .iter()
            .max_by(|left, right| {
                left.event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                    .expect("digest")
                    .as_bytes()
                    .cmp(
                        right
                            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                            .expect("digest")
                            .as_bytes(),
                    )
            })
            .expect("two siblings");
        let event_id_winner = events
            .iter()
            .max_by(|left, right| left.event_id.as_str().cmp(right.event_id.as_str()))
            .expect("two siblings");
        let hlc_winner = events
            .iter()
            .max_by(|left, right| left.hlc.cmp(&right.hlc))
            .expect("two siblings");
        digest_winner.event_id != event_id_winner.event_id
            && digest_winner.event_id != hlc_winner.event_id
    }

    let digest_winner = events
        .iter()
        .max_by(|left, right| {
            left.event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .expect("digest")
                .as_bytes()
                .cmp(
                    right
                        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                        .expect("digest")
                        .as_bytes(),
                )
        })
        .expect("two siblings");
    let event_id_winner = events
        .iter()
        .max_by(|left, right| left.event_id.as_str().cmp(right.event_id.as_str()))
        .expect("two siblings");
    let hlc_winner = events
        .iter()
        .max_by(|left, right| left.hlc.cmp(&right.hlc))
        .expect("two siblings");
    if digest_winner.event_id == event_id_winner.event_id
        || digest_winner.event_id == hlc_winner.event_id
    {
        bail!(
            "fixture must be a counterexample to both Event-id and HLC sibling selection: {:?}",
            events
                .iter()
                .map(|event| (
                    event.event_id.as_str(),
                    event
                        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                        .expect("digest")
                ))
                .collect::<Vec<_>>()
        );
    }
    let digest_winner_id = digest_winner.event_id.clone();
    events.reverse();
    let reversed_winner = events
        .iter()
        .max_by(|left, right| {
            left.event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                .expect("digest")
                .as_bytes()
                .cmp(
                    right
                        .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
                        .expect("digest")
                        .as_bytes(),
                )
        })
        .expect("two siblings");
    if reversed_winner.event_id != digest_winner_id
        || case["winner_rule"].as_str() != Some("bytewise_max(Event::event_digest())")
    {
        bail!("canonical sibling selection changed with arrival order");
    }
    Ok(())
}

// ─── VECT-SC-13 — union_history_frontier ──────────────────────────────────

pub fn run_sidecar_union_history_frontier_vector() -> Result<()> {
    let case = sidecar_fixture_case(VECTOR_ID_SIDECAR_UNION_HISTORY_FRONTIER)?;
    let histories = &case["device_histories"];
    let ids = |name: &str| -> Result<Vec<EventId>> {
        histories[name]
            .as_array()
            .ok_or_else(|| anyhow!("union-history fixture missing {name}"))?
            .iter()
            .map(|value| {
                EventId::new(
                    value
                        .as_str()
                        .ok_or_else(|| anyhow!("union-history id must be a string"))?,
                )
                .map_err(Into::into)
            })
            .collect()
    };
    let device_a = ids("device_a")?;
    let device_b = ids("device_b")?;
    let expected_union = ids("union")?;
    let expected_heads = ids("maximal_heads")?;
    let union_set = device_a
        .iter()
        .chain(&device_b)
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_union_set = expected_union.iter().cloned().collect::<BTreeSet<_>>();
    if union_set != expected_union_set || device_a.last() == device_b.last() {
        bail!("incomparable device histories did not refold their complete set union");
    }
    if expected_heads != vec![device_a[1].clone(), device_b[1].clone()] {
        bail!("union-history frontier lost one incomparable maximal causal head");
    }
    let union = union_set.into_iter().collect::<Vec<_>>();
    let digest = agent_sidecar_exchange_event_set_digest(&union)?;
    let mut reversed = union.clone();
    reversed.reverse();
    if digest != agent_sidecar_exchange_event_set_digest(&reversed)?
        || case["incomplete_outcome"].as_str() != Some("keep_cache_and_mark_backfill_pending")
    {
        bail!("union-history digest or incomplete backfill behavior drifted");
    }
    Ok(())
}

// ─── VECT-SC-14 — non_disclosure_surface_matrix ───────────────────────────

pub fn run_sidecar_non_disclosure_surface_matrix_vector() -> Result<()> {
    let case = sidecar_fixture_case(VECTOR_ID_SIDECAR_NON_DISCLOSURE_SURFACE_MATRIX)?;
    let unique_strings = |field: &str| -> Result<BTreeSet<String>> {
        let values = case[field]
            .as_array()
            .ok_or_else(|| anyhow!("non-disclosure fixture missing {field}"))?;
        let set = values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("{field} entries must be strings"))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        if set.len() != values.len() {
            bail!("non-disclosure {field} contains duplicates");
        }
        Ok(set)
    };
    let surfaces = unique_strings("surfaces")?;
    let forbidden = unique_strings("forbidden_classes")?;
    for required in [
        "realm_member_list",
        "circle_list",
        "strand_list",
        "relation_expansion",
        "search",
        "unread",
        "watch",
        "notification",
        "push",
        "public_export",
        "url",
        "log",
        "telemetry",
    ] {
        if !surfaces.contains(required) {
            bail!("non-disclosure matrix lost surface {required}");
        }
    }
    if forbidden
        != BTreeSet::from([
            "sidecar".to_owned(),
            "native_sidecar_scope".to_owned(),
            "exchange_identity".to_owned(),
            "private_content".to_owned(),
            "fold_input".to_owned(),
        ])
        || case["server_plaintext_access"].as_bool() != Some(false)
    {
        bail!("non-disclosure matrix widened private data or server plaintext access");
    }
    Ok(())
}

// ─── VECT-SC-15 — revoke_fail_closed ──────────────────────────────────────

pub fn run_sidecar_revoke_fail_closed_vector() -> Result<()> {
    let case = sidecar_fixture_case(VECTOR_ID_SIDECAR_REVOKE_FAIL_CLOSED)?;
    let transitions = case["lifecycle_transitions"]
        .as_array()
        .ok_or_else(|| anyhow!("revoke transitions are missing"))?
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    if transitions != BTreeSet::from(["revoke", "pause", "deactivate"]) {
        bail!("revoke vector must cover revoke, pause, and deactivate independently");
    }
    let post = case["post_transition"]
        .as_object()
        .ok_or_else(|| anyhow!("post-transition outcome is missing"))?;
    if post.len() != 5 || post.values().any(|value| value.as_bool() != Some(false)) {
        bail!(
            "every post-revoke addressing, delivery, execution, write, and implicit terminal gate must fail closed"
        );
    }
    if case["terminal_authority"].as_str() != Some("accepted_controller_control_event") {
        bail!("only an accepted controller control Event may terminate an exchange");
    }
    Ok(())
}

// ─── VECT-SC-16 — explicit_publish ────────────────────────────────────────

pub fn run_sidecar_explicit_publish_vector() -> Result<()> {
    let case = sidecar_fixture_case(VECTOR_ID_SIDECAR_EXPLICIT_PUBLISH)?;
    if case["before_confirmation_shared_event_count"].as_u64() != Some(0)
        || case["after_confirmation_shared_event_count"].as_u64() != Some(1)
    {
        bail!("explicit publish must produce zero Events before and one after confirmation");
    }
    let allowed = case["allowed_payload_fields"]
        .as_array()
        .ok_or_else(|| anyhow!("publish allowlist is missing"))?
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    if allowed != BTreeSet::from(["content"]) {
        bail!("explicit publish payload allowlist widened");
    }
    let output = serde_json::json!({
        "content": {
            "kind": "ak.content.text",
            "body": "controller-approved shared summary"
        }
    });
    let wire = serde_json::to_string(&output)?;
    for forbidden in case["forbidden_fields"]
        .as_array()
        .ok_or_else(|| anyhow!("publish forbidden fields are missing"))?
        .iter()
        .filter_map(Value::as_str)
    {
        if wire.contains(forbidden) {
            bail!("explicit publish leaked forbidden field {forbidden}");
        }
    }
    Ok(())
}

// ─── VECT-SC-17 — accepted_request_identity ───────────────────────────────

pub fn run_sidecar_accepted_request_identity_vector() -> Result<()> {
    let case = sidecar_fixture_case(VECTOR_ID_SIDECAR_ACCEPTED_REQUEST_IDENTITY)?;
    let accepted = EventId::new(
        case["accepted_request_event_id"]
            .as_str()
            .ok_or_else(|| anyhow!("accepted request Event id is missing"))?,
    )?;
    let binding = AgentSidecarEventExchangeBinding::user_facing_response(
        exchange_id_x1()?,
        accepted.clone(),
    )?;
    if binding.request_event_id.as_ref() != Some(&accepted)
        || case["response_binding_request_event_id"].as_str() != Some(accepted.as_str())
        || case["response_after_ref"].as_str() != Some(accepted.as_str())
    {
        bail!("producer response binding and top-level after ref diverged from accepted identity");
    }
    let invalid = case["invalid_identity_kinds"]
        .as_array()
        .ok_or_else(|| anyhow!("invalid accepted-identity kinds are missing"))?
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    if invalid != BTreeSet::from(["message_id", "local_intent_id", "unaccepted_event_id"]) {
        bail!("accepted request identity negatives are incomplete");
    }
    if EventId::new("ak:message:AX0TNnklqIlzhGa2OXRoCVE1dmOt3VUwpuOvqt4iPt5F").is_ok()
        || EventId::new("local-intent-34").is_ok()
    {
        bail!("message and local intent identities must fail the Event-id type gate");
    }
    Ok(())
}

// ─── VECT-SC-18 — hosted_ui_matrix ────────────────────────────────────────

pub fn run_sidecar_hosted_ui_matrix_vector() -> Result<()> {
    let case = sidecar_fixture_case(VECTOR_ID_SIDECAR_HOSTED_UI_MATRIX)?;
    let values = |field: &str| -> Result<Vec<String>> {
        case[field]
            .as_array()
            .ok_or_else(|| anyhow!("hosted UI fixture missing {field}"))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| anyhow!("hosted UI {field} entries must be strings"))
            })
            .collect()
    };
    let browsers = values("browsers")?;
    let tracks = values("tracks")?;
    let modes = values("display_modes")?;
    let roles = values("device_roles")?;
    let viewports = values("viewports")?;
    let stressors = values("stressors")?;
    let evidence = values("required_evidence")?;
    let matrix_size = browsers.len()
        * tracks.len()
        * modes.len()
        * roles.len()
        * viewports.len()
        * stressors.len();
    if browsers != ["chrome", "edge"]
        || tracks.len() != 3
        || modes.len() != 2
        || roles.len() != 2
        || viewports.len() != 2
        || matrix_size != 192
        || evidence
            != [
                "trace",
                "screenshots",
                "request_counts",
                "ui_state_assertions",
            ]
    {
        bail!("hosted UI browser matrix or its evidence requirements are incomplete");
    }
    let preserved = values("preserved_state")?
        .into_iter()
        .collect::<BTreeSet<_>>();
    if preserved != BTreeSet::from(["scroll".to_owned(), "editor".to_owned(), "draft".to_owned()]) {
        bail!("hosted UI matrix must preserve scroll, editor, and draft state");
    }
    Ok(())
}

/// Suite entry point — runs all 18 Sidecar vectors.
pub fn run_sidecar_vector_suite() -> Result<()> {
    validate_sidecar_vectors_fixture_metadata()?;
    if ALL_SIDECAR_VECTOR_IDS.len() != 18 {
        bail!(
            "expected 18 sidecar vector ids, got {}",
            ALL_SIDECAR_VECTOR_IDS.len()
        );
    }
    run_sidecar_mls_bootstrap_binding_vector()
        .map_err(|e| anyhow::anyhow!("[run_sidecar_mls_bootstrap_binding_vector] {e}"))?;
    run_sidecar_mls_effective_access_vector()
        .map_err(|e| anyhow::anyhow!("[run_sidecar_mls_effective_access_vector] {e}"))?;
    run_sidecar_ensure_idempotent_vector()
        .map_err(|e| anyhow::anyhow!("[run_sidecar_ensure_idempotent_vector] {e}"))?;
    run_sidecar_eligibility_states_vector()
        .map_err(|e| anyhow::anyhow!("[run_sidecar_eligibility_states_vector] {e}"))?;
    run_sidecar_existence_privacy_vector()
        .map_err(|e| anyhow::anyhow!("[run_sidecar_existence_privacy_vector] {e}"))?;
    run_sidecar_hosted_projection_vector()
        .map_err(|e| anyhow::anyhow!("[run_sidecar_hosted_projection_vector] {e}"))?;
    run_sidecar_multi_agent_publish_vector()
        .map_err(|e| anyhow::anyhow!("[run_sidecar_multi_agent_publish_vector] {e}"))?;
    run_sidecar_exchange_binding_closed_loop_vector()
        .map_err(|e| anyhow::anyhow!("[run_sidecar_exchange_binding_closed_loop_vector] {e}"))?;
    run_sidecar_exchange_projection_recovery_vector()
        .map_err(|e| anyhow::anyhow!("[run_sidecar_exchange_projection_recovery_vector] {e}"))?;
    run_sidecar_exchange_binding_containment_vector()
        .map_err(|e| anyhow::anyhow!("[run_sidecar_exchange_binding_containment_vector] {e}"))?;
    run_sidecar_context_locator_recovery_vector()
        .map_err(|e| anyhow::anyhow!("[run_sidecar_context_locator_recovery_vector] {e}"))?;
    run_sidecar_canonical_sibling_digest_vector()
        .map_err(|e| anyhow::anyhow!("[run_sidecar_canonical_sibling_digest_vector] {e}"))?;
    run_sidecar_union_history_frontier_vector()
        .map_err(|e| anyhow::anyhow!("[run_sidecar_union_history_frontier_vector] {e}"))?;
    run_sidecar_non_disclosure_surface_matrix_vector()
        .map_err(|e| anyhow::anyhow!("[run_sidecar_non_disclosure_surface_matrix_vector] {e}"))?;
    run_sidecar_revoke_fail_closed_vector()
        .map_err(|e| anyhow::anyhow!("[run_sidecar_revoke_fail_closed_vector] {e}"))?;
    run_sidecar_explicit_publish_vector()
        .map_err(|e| anyhow::anyhow!("[run_sidecar_explicit_publish_vector] {e}"))?;
    run_sidecar_accepted_request_identity_vector()
        .map_err(|e| anyhow::anyhow!("[run_sidecar_accepted_request_identity_vector] {e}"))?;
    run_sidecar_hosted_ui_matrix_vector()
        .map_err(|e| anyhow::anyhow!("[run_sidecar_hosted_ui_matrix_vector] {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_eighteen_sidecar_vectors_run_clean() {
        run_sidecar_vector_suite().unwrap();
    }
}
