//! `ak.vector.federation.authority_forward_producer_device_evidence.v1` — the
//! single human-device producer rule and the `authority_forward`
//! `producer_device_evidence` carrier (`device-lifecycle.md` §8.2.2).
//!
//! Every Event signed by a human Account device resolves its actual signer the
//! same way, whatever its kind. The same Station reads its own PCR device
//! authorization and generation at the acceptance cut and carries no evidence;
//! a governance Station admitting a forwarded Event accepts only the fresh
//! `producer_device_evidence` the account Station signed for that attempt.
//!
//! The protocol decisions are the SDK's: `Event::human_device_producer`, the
//! validating `PeerAuthorityForward*Request` constructors, the untagged
//! `PeerAuthoritySubmitRequest` wire parser and
//! `arkret_identity::verify_forwarded_human_producer`. This module adds an
//! independent model of the two Stations around them — the account Station's
//! live gate, fresh signing and persist-before-send ledger, and the governance
//! Station's duplicate check, zero-write rejection and acceptance transaction —
//! replays every registered variant against real Ed25519 keys and WebVH Service
//! histories, and compares the full rendered outcome with the fixture's
//! `expected` object.

use std::collections::BTreeSet;
use std::fmt;

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use arkret_canonical::DigestSuite;
use arkret_identity::account_device_signer_evidence::verify_forwarded_human_producer;
use arkret_identity::build_authenticated_webvh_service_resolution;
use arkret_models_collaboration::authority_commit::{
    AuthorityForwardBranch, PeerAuthorityForwardEventRequest, PeerAuthorityForwardMlsRequest,
    PeerAuthoritySubmitRequest,
};
use arkret_models_collaboration::governance::membership_invite::MembershipPayload;
use arkret_models_crypto::{
    DeviceAuthorizationWindow, DeviceStatus, ForwardDeviceProjectionAttestationCore,
    HumanEventAuthorization,
};
use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
use arkret_models_identity::{AuthenticatedServiceResolution, ForwardAccountDeviceSignerEvidence};
use arkret_signatures::device_projection::sign_forward_device_projection_attestation;
use arkret_signatures::webvh::{
    ServiceRegistrationInceptionInput, prepare_service_registration_inception,
};
use arkret_signatures::{
    Ed25519DetachedJwsSigner, EventProofBuilder, PublicKeyMaterial, SignEventOptions, sign_event,
};
use arkret_wire::{
    AccountId, ActorId, AuthoredEvent, DeviceId, DeviceRevocationAdmissionDecision, Did, DidCoreId,
    DidKey, DidUrl, ErrorCode, Event, EventAdmissionSubmission, EventId, EventKind, Hash,
    HumanDeviceProducer, MlsCommitSubmission, NonEmptyString, RealmId, ScopeRef, ServiceKind,
};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::SeedableRng as _;
use serde_json::{Value, json};

use super::authority_event_submit_carriers::{
    committed_replication_request_baseline, registered_atomic_unit_request_baseline,
};
use super::schema_validation_fixture::{schema_invalid, schema_valid};
use super::{load_artifact_json, load_fixture_value, required_str};
use crate::transcripts::record_vector_event;

pub const VECTOR_ID_AUTHORITY_FORWARD_PRODUCER_DEVICE_EVIDENCE: &str =
    "ak.vector.federation.authority_forward_producer_device_evidence.v1";

const FIXTURE: &str = "peer-event-submit-semantic-union-fixture.json";
const CASE_NAME: &str = "authority_forward_producer_device_evidence";
const EVIDENCE_MEMBER: &str = "producer_device_evidence";
const EVIDENCE_SCHEMA_REF: &str = "schemas/account-device-signer-evidence.schema.json#/$defs/forward_account_device_signer_evidence";
const PEER_REQUEST: &str =
    "schemas/authority-commit-operations.schema.json#/$defs/peer_submit_request";
const LOCAL_PCR_RESOLUTION: &str =
    "local_pcr_device_authorization_and_device_generation_at_acceptance_cut";

const PRINCIPAL_DID: &str = "did:webvh:z6mkfixture:alice.example";
const AGENT_DID: &str = "did:webvh:z6mkagent:agent.example";
const AGENT_FRAGMENT: &str = "agent-runtime-1";
const DEVICE: &str = "ak:device:019a8500-0000-7000-8000-000000000001";
const OTHER_DEVICE: &str = "ak:device:019a8500-0000-7000-8000-000000000002";
const DEVICE_SEED: [u8; 32] = [0x51; 32];
const FOREIGN_DEVICE_SEED: [u8; 32] = [0x52; 32];
const ROGUE_STATION_SEED: [u8; 32] = [0x53; 32];
const AGENT_SEED: [u8; 32] = [0x54; 32];
const MLS_IDEMPOTENCY_KEY: &str = "019a8500-0000-7000-8000-0000000000a1";
/// The Stations register well before the fixture clock so that every honest
/// attestation lies inside their Service history.
const STATION_REGISTERED_AT: &str = "2026-09-25T09:00:00.000Z";

const REGISTERED_VARIANTS: [&str; 26] = [
    "same_station_control_event_accepted",
    "same_station_data_event_uses_same_rule",
    "cross_station_forward_with_fresh_evidence_accepted",
    "cross_station_mls_commit_forward_uses_commit_event_producer",
    "exact_replay_after_evidence_expiry_returns_original_outcome",
    "new_attempt_with_fresh_evidence_for_committed_event_returns_original_outcome",
    "same_station_device_revoked",
    "same_station_device_revocation_pending",
    "same_station_generation_fenced",
    "forwarder_device_revoked_not_forwarded",
    "forwarder_device_revocation_pending_not_forwarded",
    "forwarder_generation_fenced_not_forwarded",
    "forwarder_cannot_obtain_material",
    "authorization_window_not_yet_valid",
    "authorization_window_expired_before_now",
    "evidence_expired",
    "proof_fragment_differs_from_attested_device",
    "attested_key_does_not_verify_producer_proof",
    "source_station_differs_from_attested_account_station",
    "attestation_signed_by_non_account_station_key",
    "service_history_lacks_method_at_attested_at",
    "agent_producer_carries_evidence",
    "service_producer_carries_evidence",
    "human_producer_without_evidence",
    "evidence_on_committed_replication_branch",
    "evidence_on_registered_atomic_unit_branch",
];

pub fn run_authority_forward_producer_device_evidence_vector() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    ensure!(
        fixture["covers_vectors"].as_array().is_some_and(|ids| ids
            .iter()
            .any(|id| id == VECTOR_ID_AUTHORITY_FORWARD_PRODUCER_DEVICE_EVIDENCE)),
        "{FIXTURE} does not cover {VECTOR_ID_AUTHORITY_FORWARD_PRODUCER_DEVICE_EVIDENCE}"
    );
    ensure!(
        fixture["required_schema_refs"]
            .as_array()
            .is_some_and(|refs| refs.iter().any(|value| value == EVIDENCE_SCHEMA_REF)),
        "{FIXTURE} does not require the evidence schema"
    );
    let case = fixture["cases"]
        .as_array()
        .context("peer event submit fixture cases")?
        .iter()
        .find(|case| case["name"] == CASE_NAME)
        .cloned()
        .with_context(|| format!("{FIXTURE} publishes no {CASE_NAME} case"))?;
    ensure!(case["vector_id"] == VECTOR_ID_AUTHORITY_FORWARD_PRODUCER_DEVICE_EVIDENCE);
    ensure!(
        case["producer_resolution"] == "single_rule_for_every_event_kind",
        "producer resolution is no longer a single rule"
    );
    ensure!(
        case["evidence_member"] == EVIDENCE_MEMBER
            && case["evidence_schema_ref"] == EVIDENCE_SCHEMA_REF,
        "the forwarded evidence member or its type drifted"
    );
    assert_evidence_member_is_the_signer_evidence_root()?;

    let world = World::new(&case["setup"])?;
    world.assert_single_signer_selector()?;

    let variants = case["variants"]
        .as_array()
        .context("authority_forward evidence variants")?;
    let names = variants
        .iter()
        .map(|variant| variant["name"].as_str().map(str::to_owned))
        .collect::<Option<BTreeSet<_>>>()
        .context("authority_forward evidence variant name")?;
    ensure!(
        names.len() == variants.len()
            && names
                == REGISTERED_VARIANTS
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
        "authority_forward evidence variants drifted from the executed set: {names:?}"
    );

    for variant in variants {
        let name = required_str(variant, "name")?;
        let actual = execute_variant(&world, variant)
            .with_context(|| format!("execute authority_forward evidence variant {name}"))?;
        ensure!(
            actual == variant["expected"],
            "authority_forward evidence variant {name} produced {actual}, fixture expects {}",
            variant["expected"]
        );
        record_vector_event(
            "federation.authority_forward_producer_device_evidence",
            &json!({
                "vector_id": VECTOR_ID_AUTHORITY_FORWARD_PRODUCER_DEVICE_EVIDENCE,
                "variant": name,
            }),
            &variant["expected"],
            &actual,
        );
    }
    ensure!(
        case["assertions"]
            .as_array()
            .is_some_and(|assertions| !assertions.is_empty()),
        "authority_forward evidence case publishes no assertions"
    );
    Ok(())
}

/// The carried member is the complete, closed forwarding sibling root, and the schema confines it
/// to the `authority_forward` branch.
fn assert_evidence_member_is_the_signer_evidence_root() -> Result<()> {
    let schema_document = load_artifact_json("schemas/account-device-signer-evidence.schema.json")?;
    let schema = schema_document
        .pointer("/$defs/forward_account_device_signer_evidence")
        .context("the closed Forward signer evidence definition is missing")?;
    ensure!(
        schema["additionalProperties"] == false
            && schema["required"] == json!(["device_projection_attestation", "service_resolution"]),
        "account-device signer evidence is no longer the closed two-member root"
    );
    let operations = load_artifact_json("schemas/authority-commit-operations.schema.json")?;
    let request = &operations["$defs"]["peer_submit_request"];
    ensure!(
        request
            .pointer("/properties/producer_device_evidence/$ref")
            .and_then(Value::as_str)
            == Some(
                "./account-device-signer-evidence.schema.json#/$defs/forward_account_device_signer_evidence"
            ),
        "producer_device_evidence is not the account-device signer evidence type"
    );
    let required_somewhere = |schema: &Value| {
        schema["required"]
            .as_array()
            .is_some_and(|required| required.iter().any(|name| name == EVIDENCE_MEMBER))
    };
    ensure!(
        !required_somewhere(request),
        "the schema must not decide presence; the Event does"
    );
    let mut forward_branches = 0;
    for branch in request["oneOf"]
        .as_array()
        .context("peer_submit_request is no longer a oneOf of branches")?
    {
        let forbids_evidence = branch
            .pointer("/not/anyOf")
            .and_then(Value::as_array)
            .is_some_and(|forbidden| {
                forbidden
                    .iter()
                    .any(|item| item == &json!({"required": [EVIDENCE_MEMBER]}))
            });
        ensure!(!required_somewhere(branch));
        if branch.pointer("/properties/branch/const") == Some(&json!("authority_forward")) {
            ensure!(
                !forbids_evidence,
                "an authority_forward branch forbids producer_device_evidence"
            );
            forward_branches += 1;
        } else {
            ensure!(
                forbids_evidence,
                "a non-forward branch admits producer_device_evidence: {}",
                branch["properties"]["branch"]
            );
        }
    }
    ensure!(
        forward_branches == 2,
        "authority_forward no longer has exactly the Event and MLS branches"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Rejections
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RejectedBy {
    Schema,
    AccountStation,
    GovernanceStation,
}

impl RejectedBy {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Schema => "schema",
            Self::AccountStation => "account_station",
            Self::GovernanceStation => "governance_station",
        }
    }
}

/// A protocol rejection, as opposed to a broken model. Only this error type is
/// rendered into an outcome; anything else fails the run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rejected {
    by: RejectedBy,
    code: ErrorCode,
}

impl fmt::Display for Rejected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} rejected with {}",
            self.by.as_str(),
            self.code.as_str()
        )
    }
}

impl std::error::Error for Rejected {}

fn rejected(by: RejectedBy, code: ErrorCode) -> anyhow::Error {
    anyhow::Error::new(Rejected { by, code })
}

/// Split a model step into its protocol decision and genuine model failures.
fn decide<T>(step: Result<T>) -> Result<std::result::Result<T, Rejected>> {
    match step {
        Ok(value) => Ok(Ok(value)),
        Err(error) => match error.downcast::<Rejected>() {
            Ok(rejection) => Ok(Err(rejection)),
            Err(error) => Err(error),
        },
    }
}

fn expect_rejection<T>(step: Result<T>) -> Result<Rejected> {
    match decide(step)? {
        Ok(_) => bail!("the model admitted what the variant rejects"),
        Err(rejection) => Ok(rejection),
    }
}

fn render_rejection(rejection: Rejected, durable_writes: usize, forwarded: Option<bool>) -> Value {
    let mut rendered = json!({
        "decision": "reject",
        "error_code": rejection.code.as_str(),
        "rejected_by": rejection.by.as_str(),
        "durable_writes": durable_writes,
    });
    if let Some(forwarded) = forwarded {
        rendered["forwarded"] = json!(forwarded);
    }
    rendered
}

// ---------------------------------------------------------------------------
// The two Stations
// ---------------------------------------------------------------------------

/// One registered Station: its WebVH inception and the key its assertion
/// method publishes.
struct StationKeys {
    service_id: DidCoreId,
    method: DidUrl,
    signing_key: SigningKey,
    signing_seed: [u8; 32],
    log_entry: Value,
    registered_at: DateTime<Utc>,
}

impl StationKeys {
    fn register(seed: u8, host: &str, registered_at: DateTime<Utc>) -> Result<Self> {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let registration = ServiceRegistrationKey::new(
            ServiceKind::Station,
            CanonicalServiceUrl::new(format!("https://{host}/"))?,
        )?;
        let inception = prepare_service_registration_inception(
            &mut rng,
            &ServiceRegistrationInceptionInput {
                provider_endpoint: &"https://identity.example/".parse()?,
                registration_key: &registration,
                also_known_as: &[],
                version_time: registered_at,
                did_key_fragment: None,
            },
        )
        .map_err(|error| anyhow!("Station inception: {error}"))?;
        let did = Did::new(inception.did.clone())?;
        Ok(Self {
            service_id: arkret_wire::project_did_to_core_id(&did)?,
            method: DidUrl::new(inception.did_key_id.clone())
                .map_err(|error| anyhow!("{error}"))?,
            signing_key: SigningKey::from_bytes(&inception.did_key_seed),
            signing_seed: inception.did_key_seed,
            log_entry: inception.log_entry.clone(),
            registered_at,
        })
    }

    /// The Station's own authenticated Service resolution, carried unchanged
    /// in every evidence object it signs.
    fn resolution(&self) -> Result<AuthenticatedServiceResolution> {
        build_authenticated_webvh_service_resolution(
            self.service_id.clone(),
            "station".into(),
            serde_json::from_value(self.log_entry["state"].clone())?,
            vec![self.log_entry.clone()],
            Vec::new(),
            self.registered_at + Duration::seconds(10),
        )
        .map_err(|error| anyhow!("Station resolution: {error}"))
    }
}

/// Local device state read at one durable cut of a Station's live gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiveDeviceState {
    Active,
    Revoked,
    RevocationPending,
    GenerationFenced,
    /// The account Station cannot read its own gate right now.
    MaterialUnavailable,
}

impl LiveDeviceState {
    fn parse(value: &Value) -> Result<Self> {
        Ok(match value.as_str() {
            None => Self::Active,
            Some("revoked") => Self::Revoked,
            Some("revocation_pending") => Self::RevocationPending,
            Some("generation_fenced") => Self::GenerationFenced,
            Some(other) => bail!("unknown device_state {other}"),
        })
    }

    /// The current-device admission decision this state yields at one durable
    /// cut, or `None` when the Station cannot read its gate at all.
    const fn admission_decision(self) -> Option<DeviceRevocationAdmissionDecision> {
        match self {
            Self::Active => Some(DeviceRevocationAdmissionDecision::Allow),
            Self::Revoked => Some(DeviceRevocationAdmissionDecision::Revoked),
            Self::RevocationPending => Some(DeviceRevocationAdmissionDecision::RevocationPending),
            Self::GenerationFenced => Some(DeviceRevocationAdmissionDecision::GenerationMismatch),
            Self::MaterialUnavailable => None,
        }
    }
}

/// Gate one exact human-device producer against a Station's own device
/// record at every instant the admission must cover.
///
/// The decision is the model's; the protocol code it surfaces is the SDK's
/// single mapping (`DeviceRevocationAdmissionDecision::error_code`). A missing
/// or foreign record and an instant outside the authorization window are the
/// "no complete current accepted authorization" decision. A Station that cannot
/// read its own gate is `temporarily_unavailable` (decision 0107 section 4).
fn device_gate(
    record: Option<&DeviceRecord>,
    producer: &HumanDeviceProducer,
    instants: &[DateTime<Utc>],
) -> std::result::Result<(), ErrorCode> {
    let decision = match record.filter(|record| record.is(producer)) {
        None => DeviceRevocationAdmissionDecision::AuthorityMismatch,
        Some(record) => match record.state.admission_decision() {
            None => return Err(ErrorCode::TemporarilyUnavailable),
            Some(DeviceRevocationAdmissionDecision::Allow)
                if !instants.iter().all(|at| record.covers(*at)) =>
            {
                DeviceRevocationAdmissionDecision::AuthorityMismatch
            }
            Some(decision) => decision,
        },
    };
    decision.error_code().map_or(Ok(()), Err)
}

/// The typed current device authorization of one exact device.
#[derive(Clone)]
struct DeviceRecord {
    account_id: AccountId,
    device_id: DeviceId,
    signing_key_did: DidKey,
    hpke_key: NonEmptyString,
    authorize_event_id: EventId,
    original: arkret_wire::CommittedEventFullView,
    generation: u64,
    window: DeviceAuthorizationWindow,
    state: LiveDeviceState,
}

impl DeviceRecord {
    fn covers(&self, at: DateTime<Utc>) -> bool {
        at >= self.window.not_before && self.window.expires_at.is_none_or(|end| at < end)
    }

    fn is(&self, producer: &HumanDeviceProducer) -> bool {
        self.account_id == producer.account_id && self.device_id == producer.device_id
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ForwardStep {
    Persisted(Hash),
    Sent(Option<Hash>),
}

/// Station A: the producer's account Station, forwarding to the governance
/// Station.
struct AccountStation<'a> {
    keys: &'a StationKeys,
    destination: DidCoreId,
    device: DeviceRecord,
    attestation_ttl: Duration,
    persisted: Vec<(Hash, ForwardAccountDeviceSignerEvidence)>,
    steps: Vec<ForwardStep>,
}

impl<'a> AccountStation<'a> {
    fn new(world: &'a World, device: DeviceRecord) -> Self {
        Self {
            keys: &world.station_a,
            destination: world.station_b.service_id.clone(),
            device,
            attestation_ttl: world.setup.attestation_ttl,
            persisted: Vec::new(),
            steps: Vec::new(),
        }
    }

    fn durable_writes(&self) -> usize {
        self.persisted.len()
    }

    fn forwarded(&self) -> bool {
        self.steps
            .iter()
            .any(|step| matches!(step, ForwardStep::Sent(_)))
    }

    /// Sign fresh evidence for this attempt from the live gate, and persist
    /// the complete object with its ref before anything is sent.
    fn fresh_evidence(
        &mut self,
        event: &Event,
        attempt_at: DateTime<Utc>,
        body: &Value,
    ) -> Result<Option<ForwardAccountDeviceSignerEvidence>> {
        let producer = event.human_device_producer().map_err(|error| {
            rejected(
                RejectedBy::AccountStation,
                error.error_code().unwrap_or(ErrorCode::SchemaViolation),
            )
        })?;
        let Some(producer) = producer else {
            return Ok(None);
        };
        device_gate(Some(&self.device), &producer, &[attempt_at])
            .map_err(|code| rejected(RejectedBy::AccountStation, code))?;
        let expires_at = match self.device.window.expires_at {
            Some(end) => (attempt_at + self.attestation_ttl).min(end),
            None => attempt_at + self.attestation_ttl,
        };
        let attestation = sign_forward_device_projection_attestation(
            ForwardDeviceProjectionAttestationCore {
                account_id: self.device.account_id.clone(),
                device_id: self.device.device_id.clone(),
                device_signing_key_did: self.device.signing_key_did.clone(),
                hpke_key: self.device.hpke_key.clone(),
                device_authorize_event_id: self.device.authorize_event_id.clone(),
                authorized_generation_ref: self.device.generation,
                device_status: DeviceStatus::Active,
                authorization_window: self.device.window.clone(),
                attested_at: attempt_at,
                expires_at,
                event_authorization: original_authorization(
                    &self.device,
                    event,
                    &self.destination,
                    body,
                )?,
            },
            self.keys.method.clone(),
            &self.keys.signing_key,
        )?;
        let evidence = ForwardAccountDeviceSignerEvidence {
            device_projection_attestation: attestation,
            service_resolution: self.keys.resolution()?,
        };
        let reference = evidence_digest(&evidence)?;
        self.persisted.push((reference.clone(), evidence.clone()));
        self.steps.push(ForwardStep::Persisted(reference));
        Ok(Some(evidence))
    }

    fn send(&mut self, request: PeerAuthoritySubmitRequest) -> Result<Value> {
        let reference = match &request {
            PeerAuthoritySubmitRequest::AuthorityForwardEvent(request) => {
                request.producer_device_evidence.as_ref()
            }
            PeerAuthoritySubmitRequest::AuthorityForwardMls(request) => {
                request.producer_device_evidence.as_ref()
            }
            _ => bail!("the account Station only sends authority_forward"),
        }
        .map(evidence_digest)
        .transpose()?;
        self.steps.push(ForwardStep::Sent(reference));
        Ok(serde_json::to_value(request)?)
    }

    fn forward_event(&mut self, event: Event, attempt_at: DateTime<Utc>) -> Result<Value> {
        let unsigned = event_forward_body(&event, None)?;
        let evidence = self.fresh_evidence(&event, attempt_at, &unsigned)?;
        let request = PeerAuthorityForwardEventRequest::new(
            EventAdmissionSubmission::new(event),
            None,
            evidence,
        )?;
        self.send(PeerAuthoritySubmitRequest::AuthorityForwardEvent(request))
    }

    fn forward_mls(
        &mut self,
        submission: MlsCommitSubmission,
        attempt_at: DateTime<Utc>,
    ) -> Result<Value> {
        let unsigned = json!({"branch":"authority_forward", "mls_submission": &submission});
        let evidence = self.fresh_evidence(&submission.commit_event, attempt_at, &unsigned)?;
        let request = PeerAuthorityForwardMlsRequest::new(submission, evidence)?;
        self.send(PeerAuthoritySubmitRequest::AuthorityForwardMls(request))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResolutionSource {
    LocalPcr,
    ForwardedEvidence,
}

impl ResolutionSource {
    const fn as_str(self) -> &'static str {
        match self {
            Self::LocalPcr => LOCAL_PCR_RESOLUTION,
            Self::ForwardedEvidence => "authority_forward_producer_device_evidence",
        }
    }
}

/// Everything one acceptance writes, in one transaction.
struct AcceptanceTransaction {
    event_id: EventId,
    resolution: ResolutionSource,
    retained_evidence: Option<(Hash, ForwardAccountDeviceSignerEvidence)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Admission {
    Committed(usize),
    Original(usize),
}

/// Station B: the Realm's governance Station.
struct GovernanceStation {
    station_id: DidCoreId,
    local_pcr: Vec<DeviceRecord>,
    transactions: Vec<AcceptanceTransaction>,
}

impl GovernanceStation {
    fn new(station_id: DidCoreId, local_pcr: Vec<DeviceRecord>) -> Self {
        Self {
            station_id,
            local_pcr,
            transactions: Vec::new(),
        }
    }

    fn realm_commits(&self) -> usize {
        self.transactions.len()
    }

    fn durable_writes(&self) -> usize {
        self.transactions.len()
            + self
                .transactions
                .iter()
                .filter(|transaction| transaction.retained_evidence.is_some())
                .count()
    }

    fn original(&self, event_id: &EventId) -> Option<usize> {
        self.transactions
            .iter()
            .position(|transaction| &transaction.event_id == event_id)
    }

    /// Same-Station admission: the producer's own PCR at the acceptance cut
    /// is the only source, and the submission carries no device evidence.
    fn admit_local(
        &mut self,
        submission: &EventAdmissionSubmission,
        now: DateTime<Utc>,
    ) -> Result<Admission> {
        submission.validate()?;
        let event = &submission.event;
        let producer = event
            .human_device_producer()?
            .context("the same-Station model admits human-device producers only")?;
        ensure!(
            producer.account_id.station_id == self.station_id,
            "a same-Station admission needs a producer of this Station"
        );
        if let Some(index) = self.original(&event.event_id) {
            return Ok(Admission::Original(index));
        }
        let record = self.local_pcr.iter().find(|record| record.is(&producer));
        device_gate(record, &producer, &[event.created_at, now])
            .map_err(|code| rejected(RejectedBy::GovernanceStation, code))?;
        let record = record.context("an admitted producer has a local PCR record")?;
        verify_producer_proof(event, &record.signing_key_did)
            .map_err(|_| rejected(RejectedBy::GovernanceStation, ErrorCode::SignatureInvalid))?;
        self.transactions.push(AcceptanceTransaction {
            event_id: event.event_id.clone(),
            resolution: ResolutionSource::LocalPcr,
            retained_evidence: None,
        });
        Ok(Admission::Committed(self.transactions.len() - 1))
    }

    /// Cross-Station admission of the exact bytes an account Station sent.
    fn admit_forward(
        &mut self,
        body: &Value,
        source: &DidCoreId,
        now: DateTime<Utc>,
    ) -> Result<Admission> {
        let request: PeerAuthoritySubmitRequest = serde_json::from_value(body.clone())
            .map_err(|_| rejected(RejectedBy::Schema, ErrorCode::SchemaViolation))?;
        let (event, evidence) = match &request {
            PeerAuthoritySubmitRequest::AuthorityForwardEvent(request) => (
                &request.event_submission.event,
                request.producer_device_evidence.as_ref(),
            ),
            PeerAuthoritySubmitRequest::AuthorityForwardMls(request) => (
                &request.mls_submission.commit_event,
                request.producer_device_evidence.as_ref(),
            ),
            _ => bail!("the governance model admits authority_forward only"),
        };
        request.validate().map_err(|error| {
            rejected(
                RejectedBy::GovernanceStation,
                error.error_code().unwrap_or(ErrorCode::SchemaViolation),
            )
        })?;
        // An exact duplicate returns its original outcome before evidence
        // freshness is looked at.
        if let Some(index) = self.original(&event.event_id) {
            return Ok(Admission::Original(index));
        }
        let evidence =
            evidence.context("the governance model admits human-device producers only")?;
        let body_digest =
            arkret_models_collaboration::authority_commit::authority_forward_body_digest(body)?;
        match verify_forwarded_human_producer(
            evidence,
            event,
            source,
            &self.station_id,
            &body_digest,
            DigestSuite::Sha256,
            now,
        ) {
            Ok(producer) => ensure!(
                producer == event.human_device_producer()?.context("human producer")?,
                "verified producer differs from the Event's actual signer"
            ),
            Err(error) => {
                let code = error
                    .error_code()
                    .ok_or_else(|| anyhow!("uncoded producer verification failure: {error}"))?;
                return Err(rejected(RejectedBy::GovernanceStation, code));
            }
        }
        let reference = evidence_digest(&evidence)?;
        ensure!(evidence_digest(evidence)? == reference);
        self.transactions.push(AcceptanceTransaction {
            event_id: event.event_id.clone(),
            resolution: ResolutionSource::ForwardedEvidence,
            retained_evidence: Some((reference, evidence.clone())),
        });
        Ok(Admission::Committed(self.transactions.len() - 1))
    }
}

pub(super) fn verify_producer_proof(event: &Event, key: &DidKey) -> Result<()> {
    let proof = event
        .producer_proof
        .as_ref()
        .context("Event lost its producer proof")?;
    let multibase = key
        .as_str()
        .strip_prefix("did:key:")
        .context("device key is not did:key")?;
    let envelope = EventProofBuilder::new().envelope_bytes(event)?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &envelope,
        &event.actor_id,
        &PublicKeyMaterial::Ed25519Multibase {
            value: multibase.to_owned(),
        },
        DigestSuite::Sha256,
    )
    .map_err(|error| anyhow!("producer proof does not verify: {error}"))
}

// ---------------------------------------------------------------------------
// Fixture world
// ---------------------------------------------------------------------------

struct Setup {
    now: DateTime<Utc>,
    event_created_at: DateTime<Utc>,
    attested_at: DateTime<Utc>,
    attestation_ttl: Duration,
    window: DeviceAuthorizationWindow,
}

struct World {
    setup: Setup,
    station_a: StationKeys,
    station_b: StationKeys,
    station_c: StationKeys,
    account: AccountId,
    realm_id: RealmId,
}

impl World {
    fn new(setup: &Value) -> Result<Self> {
        let window = &setup["authorization_window"];
        let attested_at = timestamp(&setup["attested_at"])?;
        let setup = Setup {
            now: timestamp(&setup["now"])?,
            event_created_at: timestamp(&setup["event_created_at"])?,
            attested_at,
            attestation_ttl: timestamp(&setup["attestation_expires_at"])? - attested_at,
            window: DeviceAuthorizationWindow {
                not_before: timestamp(&window["not_before"])?,
                expires_at: match &window["expires_at"] {
                    Value::Null => None,
                    value => Some(timestamp(value)?),
                },
            },
        };
        ensure!(
            setup.event_created_at < setup.attested_at
                && setup.attested_at < setup.now
                && setup.now < setup.attested_at + setup.attestation_ttl,
            "the fixture clock no longer orders created_at < attested_at < now < expires_at"
        );
        let registered_at = timestamp(&json!(STATION_REGISTERED_AT))?;
        ensure!(registered_at < setup.event_created_at);
        let station_a = StationKeys::register(0xa1, "station-a.example", registered_at)?;
        let station_b = StationKeys::register(0xb2, "station-b.example", registered_at)?;
        let station_c = StationKeys::register(0xc3, "station-c.example", registered_at)?;
        let account = AccountId::new(
            arkret_wire::project_did_to_core_id(&Did::new(PRINCIPAL_DID)?)?,
            station_a.service_id.clone(),
        );
        let realm_id =
            RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [0x41; 32]));
        Ok(Self {
            setup,
            station_a,
            station_b,
            station_c,
            account,
            realm_id,
        })
    }

    /// An independently signed original PCR authorization for this transport
    /// model. It is not a PG registration/admission or live PCR permission test.
    fn original_device_authorization(
        &self,
        public: &[u8; 32],
    ) -> Result<arkret_wire::CommittedEventFullView> {
        let genesis_ref = EventId::from_digest(DigestSuite::Sha256, [0x61; 32]);
        let pcr = RealmId::from_event_id(&genesis_ref);
        ensure!(pcr != self.realm_id);
        let at = self.station_a.registered_at + Duration::seconds(30);
        let mut payload: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
            serde_json::from_value(json!({
                "device_id": DEVICE,
                "device_public_key_did": format!("did:key:{}", arkret_canonical::ed25519_pubkey_to_did_key_multibase(public)),
                "hpke_key": "hpke-forward-fixture",
                "algorithms": ["Ed25519", "HPKE-X25519-HKDF-SHA256-AES128GCM"],
                "device_key_algorithm": "Ed25519",
                "authorized_by": self.account.principal_id,
                "not_before": arkret_canonical::format_timestamp_canonical(self.setup.window.not_before),
                "expires_at": self.setup.window.expires_at.map(arkret_canonical::format_timestamp_canonical),
                "authorization_binding_kind": "registration_anchor",
                "authorized_generation_ref": 1,
                "device_signature": "c2lnbmF0dXJl"
            }))?;
        let possession = SigningKey::from_bytes(&DEVICE_SEED)
            .sign(&payload.device_possession_signature_input(&self.account)?);
        payload.device_signature = serde_json::from_value(json!(
            arkret_canonical::base64url_encode(possession.to_bytes())
        ))?;
        arkret_signatures::verify_device_authorize_possession(&payload, &self.account)?;
        let event = sign(
            arkret_wire::test_support::raw_event_for_actor_at(
                EventKind::DeviceAuthorize.as_str(),
                ScopeRef::Realm {
                    realm_id: pcr.clone(),
                },
                ActorId::account(self.account.clone()),
                serde_json::to_value(payload)?,
                at,
            )?,
            &format!("{PRINCIPAL_DID}#{DEVICE}"),
            DEVICE_SEED,
            at,
        )?;
        verify_producer_proof(
            &event,
            &DidKey::new(format!(
                "did:key:{}",
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(public)
            ))
            .map_err(|error| anyhow!("{error}"))?,
        )?;
        let body = json!({
            "realm_id": pcr, "stream_ref": arkret_wire::CommitStreamRef::Realm { realm_id: pcr.clone() },
            "stream_position": 1, "previous_commit_ref": arkret_wire::RealmCommitId::from_digest([0x62; 32]),
            "event_ref": event.event_id, "governance_generation": 0,
            "authority_ref": genesis_ref, "committed_at": arkret_canonical::format_timestamp_canonical(at + Duration::seconds(1)),
        });
        let commit_id = arkret_wire::RealmCommitId::from_digest(arkret_canonical::sha256_bytes(
            &arkret_canonical::canonical_json_bytes(&body)?,
        ));
        let mut body = body;
        body["commit_id"] = json!(commit_id);
        let signature = arkret_signatures::detached_object::sign_detached_object(
            &body,
            arkret_wire::DetachedSignatureContext::RealmCommit,
            self.station_a.method.clone(),
            at + Duration::seconds(1),
            &self.station_a.signing_key,
        )?;
        arkret_signatures::detached_object::verify_detached_object_signature(
            &signature,
            &body,
            arkret_wire::DetachedSignatureContext::RealmCommit,
            &PublicKeyMaterial::Ed25519Raw {
                bytes: self
                    .station_a
                    .signing_key
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            },
        )?;
        let mut value = body;
        value["signature"] = serde_json::to_value(signature)?;
        let commit: arkret_wire::RealmCommit = serde_json::from_value(value)?;
        commit.validate_content_address()?;
        Ok(arkret_wire::CommittedEventFullView { event, commit })
    }

    fn device_record(&self, state: LiveDeviceState) -> Result<DeviceRecord> {
        let public = SigningKey::from_bytes(&DEVICE_SEED)
            .verifying_key()
            .to_bytes();
        let original = self.original_device_authorization(&public)?;
        Ok(DeviceRecord {
            account_id: self.account.clone(),
            device_id: DeviceId::new(DEVICE)?,
            signing_key_did: DidKey::new(format!(
                "did:key:{}",
                arkret_canonical::ed25519_pubkey_to_did_key_multibase(&public)
            ))
            .map_err(|error| anyhow!("{error}"))?,
            hpke_key: NonEmptyString::new("hpke-forward-fixture").map_err(anyhow::Error::msg)?,
            authorize_event_id: original.event.event_id.clone(),
            original,
            generation: 1,
            window: self.setup.window.clone(),
            state,
        })
    }

    fn account_station(&self, state: LiveDeviceState) -> Result<AccountStation<'_>> {
        Ok(AccountStation::new(self, self.device_record(state)?))
    }

    /// Station B governs the Realm and has no copy of A's PCR.
    fn remote_governance(&self) -> GovernanceStation {
        GovernanceStation::new(self.station_b.service_id.clone(), Vec::new())
    }

    /// Station A governs the Realm itself and reads its own PCR.
    fn local_governance(&self, state: LiveDeviceState) -> Result<GovernanceStation> {
        Ok(GovernanceStation::new(
            self.station_a.service_id.clone(),
            vec![self.device_record(state)?],
        ))
    }

    fn payload(&self, kind: &str) -> Result<Value> {
        let strand_id = format!("ak:strand:{}", "A".repeat(44));
        Ok(match kind {
            "ak.member.state" => MembershipPayload::join(
                self.realm_id.clone(),
                ActorId::account(AccountId::new(
                    DidCoreId::new("ak:did_core:webvh:z6mkcarol")?,
                    self.station_a.service_id.clone(),
                )),
                "authority_forward fixture join",
            )
            .to_value()?,
            "ak.message.create" => json!({
                "strand_id": strand_id,
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "forwarded"},
            }),
            "ak.capability.grant" => json!({
                "grant": {
                    "schema": "ak.schema.capability_grant.v1",
                    "issuer_id": ActorId::account(self.account.clone()),
                    "subject": ActorId::account(AccountId::new(
                        DidCoreId::new("ak:did_core:webvh:z6mkcarol")?,
                        self.station_a.service_id.clone(),
                    )),
                    "actions": ["ak.message.create"],
                    "resources": [{"kind": "realm", "realm_id": self.realm_id}],
                    "issued_at": "2026-09-25T09:59:00.000Z",
                    "issuer_authority_refs": [],
                },
            }),
            "ak.mls.commit" => json!({
                "base_group_state_ref": EventId::from_digest(DigestSuite::Sha256, [0x42; 32]),
                "previous_epoch": 1,
                "next_epoch": 2,
                "covers_key_access_revision": 1,
                "commit_bytes_b64": "Y29tbWl0",
            }),
            other => bail!("no fixture payload for {other}"),
        })
    }

    fn signed_event(
        &self,
        kind: &str,
        actor: ActorId,
        verification_method: &str,
        seed: [u8; 32],
        created_at: DateTime<Utc>,
    ) -> Result<Event> {
        let event = arkret_wire::test_support::raw_event_for_actor_at(
            kind,
            ScopeRef::Realm {
                realm_id: self.realm_id.clone(),
            },
            actor,
            self.payload(kind)?,
            created_at,
        )?;
        sign(event, verification_method, seed, created_at)
    }

    fn human_event(&self, kind: &str, created_at: DateTime<Utc>) -> Result<Event> {
        self.signed_event(
            kind,
            ActorId::account(self.account.clone()),
            &format!("{PRINCIPAL_DID}#{DEVICE}"),
            DEVICE_SEED,
            created_at,
        )
    }

    fn agent_event(&self) -> Result<Event> {
        let agent = AccountId::new(
            arkret_wire::project_did_to_core_id(&Did::new(AGENT_DID)?)?,
            self.station_a.service_id.clone(),
        );
        self.signed_event(
            "ak.message.create",
            ActorId::account(agent),
            &format!("{AGENT_DID}#{AGENT_FRAGMENT}"),
            AGENT_SEED,
            self.setup.event_created_at,
        )
    }

    fn service_event(&self) -> Result<Event> {
        self.signed_event(
            "ak.message.create",
            ActorId::service(self.station_a.service_id.clone()),
            self.station_a.method.as_str(),
            self.station_a.signing_seed,
            self.setup.event_created_at,
        )
    }

    fn expected_producer(&self) -> Result<HumanDeviceProducer> {
        Ok(HumanDeviceProducer {
            account_id: self.account.clone(),
            device_id: DeviceId::new(DEVICE)?,
        })
    }

    /// `executed_by` when present, else `actor_id`, names the signer; an
    /// Agent or Service key never makes a human-device producer.
    fn assert_single_signer_selector(&self) -> Result<()> {
        let created_at = self.setup.event_created_at;
        for kind in [
            "ak.member.state",
            "ak.message.create",
            "ak.capability.grant",
        ] {
            ensure!(
                self.human_event(kind, created_at)?
                    .human_device_producer()?
                    == Some(self.expected_producer()?),
                "{kind} resolved its human-device producer differently"
            );
        }
        // A Service-authored Event executed by the human device resolves to
        // the executor; resolution reads the envelope, not the signature.
        let mut delegated = self.human_event("ak.message.create", created_at)?;
        delegated.executed_by = Some(delegated.actor_id.clone());
        delegated.actor_id = ActorId::service(self.station_a.service_id.clone());
        ensure!(
            delegated.human_device_producer()? == Some(self.expected_producer()?),
            "an Account executor did not make the Event a human-device producer"
        );
        ensure!(
            self.agent_event()?.human_device_producer()?.is_none()
                && self.service_event()?.human_device_producer()?.is_none(),
            "an Agent or Service signer resolved as a human device"
        );
        Ok(())
    }
}

pub(super) fn sign(
    event: Event,
    verification_method: &str,
    seed: [u8; 32],
    created_at: DateTime<Utc>,
) -> Result<Event> {
    let mut authored = AuthoredEvent::finalize_with_digest_suite(event, DigestSuite::Sha256)?;
    sign_event(
        &mut authored,
        &Ed25519DetachedJwsSigner::from_seed(seed, verification_method),
        SignEventOptions::new().with_created_at(created_at),
    )?;
    Ok(authored.into_event())
}

fn timestamp(value: &Value) -> Result<DateTime<Utc>> {
    let text = value.as_str().context("timestamp must be a string")?;
    Ok(DateTime::parse_from_rfc3339(text)
        .with_context(|| format!("parse timestamp {text}"))?
        .to_utc())
}

fn event_forward_body(
    event: &Event,
    material: Option<arkret_models_collaboration::authority_commit::MlsGenesisMaterial>,
) -> Result<Value> {
    Ok(serde_json::to_value(PeerAuthorityForwardEventRequest {
        branch: AuthorityForwardBranch::AuthorityForward,
        event_submission: EventAdmissionSubmission::new(event.clone()),
        mls_genesis_material: material,
        producer_device_evidence: None,
        producer_agent_evidence: None,
    })?)
}

fn evidence_digest(evidence: &ForwardAccountDeviceSignerEvidence) -> arkret_wire::Result<Hash> {
    Ok(Hash::new(arkret_canonical::canonical_sha256(evidence)?)?)
}

fn original_authorization(
    device: &DeviceRecord,
    event: &Event,
    destination: &DidCoreId,
    body: &Value,
) -> Result<HumanEventAuthorization> {
    let original = &device.original;
    ensure!(original.event.event_id == device.authorize_event_id);
    ensure!(original.event.actual_signer() == &ActorId::account(device.account_id.clone()));
    ensure!(
        original.commit.stream_ref
            != arkret_wire::CommitStreamRef::from_scope(&event.scope_ref, None)?
    );
    Ok(HumanEventAuthorization {
        event_id: event.event_id.clone(),
        verification_method: event
            .producer_proof
            .as_ref()
            .context("human proof")?
            .verification_method
            .clone(),
        destination_service_id: destination.clone(),
        forward_body_digest:
            arkret_models_collaboration::authority_commit::authority_forward_body_digest(body)?,
        authorization_ref: arkret_wire::CommittedEventRef {
            event_id: original.event.event_id.clone(),
            commit_id: original.commit.commit_id.clone(),
            stream_ref: original.commit.stream_ref.clone(),
            stream_position: original.commit.stream_position,
        },
        revision: arkret_wire::CurrentRevision {
            commit_id: original.commit.commit_id.clone(),
            stream_position: original.commit.stream_position,
        },
        governance_generation: original.commit.governance_generation,
        accepted_at: original.commit.committed_at,
    })
}

fn body_evidence(body: &Value) -> Result<ForwardAccountDeviceSignerEvidence> {
    Ok(serde_json::from_value(
        body.get(EVIDENCE_MEMBER)
            .cloned()
            .context("forward body carries no producer_device_evidence")?,
    )?)
}

fn event_kind(variant: &Value, default: &str) -> String {
    variant["event_kind"].as_str().unwrap_or(default).to_owned()
}

// ---------------------------------------------------------------------------
// Variants
// ---------------------------------------------------------------------------

fn execute_variant(world: &World, variant: &Value) -> Result<Value> {
    let name = required_str(variant, "name")?;
    match name {
        "same_station_control_event_accepted" | "same_station_data_event_uses_same_rule" => {
            same_station_accepted(world, variant)
        }
        "same_station_device_revoked"
        | "same_station_device_revocation_pending"
        | "same_station_generation_fenced" => same_station_rejected(world, variant),
        "cross_station_forward_with_fresh_evidence_accepted" => {
            cross_station_accepted(world, variant)
        }
        "cross_station_mls_commit_forward_uses_commit_event_producer" => mls_forward(world),
        "exact_replay_after_evidence_expiry_returns_original_outcome" => {
            exact_replay_after_expiry(world, variant)
        }
        "new_attempt_with_fresh_evidence_for_committed_event_returns_original_outcome" => {
            new_attempt_for_committed_event(world)
        }
        "forwarder_device_revoked_not_forwarded"
        | "forwarder_device_revocation_pending_not_forwarded"
        | "forwarder_generation_fenced_not_forwarded" => {
            forwarder_rejects(world, LiveDeviceState::parse(&variant["device_state"])?)
        }
        "forwarder_cannot_obtain_material" => {
            forwarder_rejects(world, LiveDeviceState::MaterialUnavailable)
        }
        "authorization_window_not_yet_valid" => window_not_yet_valid(world),
        "authorization_window_expired_before_now" => window_expired_before_now(world),
        "evidence_expired" => evidence_expired(world),
        "proof_fragment_differs_from_attested_device" => {
            substituted_event(world, OTHER_DEVICE, DEVICE_SEED)
        }
        "attested_key_does_not_verify_producer_proof" => {
            substituted_event(world, DEVICE, FOREIGN_DEVICE_SEED)
        }
        "source_station_differs_from_attested_account_station" => source_station_differs(world),
        "attestation_signed_by_non_account_station_key" => foreign_attestation_signer(world),
        "service_history_lacks_method_at_attested_at" => history_lacks_method(world),
        "agent_producer_carries_evidence" => {
            non_human_carries_evidence(world, world.agent_event()?)
        }
        "service_producer_carries_evidence" => {
            non_human_carries_evidence(world, world.service_event()?)
        }
        "human_producer_without_evidence" => human_without_evidence(world),
        "evidence_on_committed_replication_branch" => {
            evidence_on_other_branch(world, committed_replication_request_baseline()?)
        }
        "evidence_on_registered_atomic_unit_branch" => {
            evidence_on_other_branch(world, registered_atomic_unit_request_baseline()?)
        }
        other => bail!("no executor for authority_forward evidence variant {other}"),
    }
}

fn same_station_accepted(world: &World, variant: &Value) -> Result<Value> {
    ensure!(variant["topology"] == "same_station");
    ensure!(variant["carries_producer_device_evidence"] == false);
    let kind = event_kind(variant, EventKind::MemberState.as_str());
    let event = world.human_event(&kind, world.setup.event_created_at)?;
    ensure!(event.human_device_producer()? == Some(world.expected_producer()?));
    let submission = EventAdmissionSubmission::new(event);
    ensure!(
        serde_json::to_value(&submission)?
            .get(EVIDENCE_MEMBER)
            .is_none(),
        "a same-Station submission carries device evidence"
    );
    let mut station = world.local_governance(LiveDeviceState::Active)?;
    let Admission::Committed(index) = station.admit_local(&submission, world.setup.now)? else {
        bail!("a fresh same-Station Event was treated as a duplicate");
    };
    ensure!(station.transactions[index].retained_evidence.is_none());
    Ok(json!({
        "decision": "accept",
        "resolution_source": station.transactions[index].resolution.as_str(),
        "realm_commits": station.realm_commits(),
    }))
}

fn same_station_rejected(world: &World, variant: &Value) -> Result<Value> {
    ensure!(variant["topology"] == "same_station");
    let state = LiveDeviceState::parse(&variant["device_state"])?;
    let kind = event_kind(variant, EventKind::MemberState.as_str());
    let submission =
        EventAdmissionSubmission::new(world.human_event(&kind, world.setup.event_created_at)?);
    // Positive control: the identical submission is admitted while active.
    let mut control = world.local_governance(LiveDeviceState::Active)?;
    ensure!(matches!(
        control.admit_local(&submission, world.setup.now)?,
        Admission::Committed(_)
    ));
    let mut station = world.local_governance(state)?;
    let rejection = expect_rejection(station.admit_local(&submission, world.setup.now))?;
    Ok(render_rejection(rejection, station.durable_writes(), None))
}

fn cross_station_accepted(world: &World, variant: &Value) -> Result<Value> {
    ensure!(variant["topology"] == "cross_station");
    ensure!(variant["carries_producer_device_evidence"] == true);
    let kind = event_kind(variant, EventKind::MemberState.as_str());
    let event = world.human_event(&kind, world.setup.event_created_at)?;
    let mut account = world.account_station(LiveDeviceState::Active)?;
    let body = account.forward_event(event.clone(), world.setup.attested_at)?;
    let mut governance = world.remote_governance();
    let Admission::Committed(index) =
        governance.admit_forward(&body, &world.station_a.service_id, world.setup.now)?
    else {
        bail!("a fresh forward was treated as a duplicate");
    };

    let evidence = body_evidence(&body)?;
    let reference = evidence_digest(&evidence)?;
    let fresh = evidence
        .device_projection_attestation
        .attestation
        .attested_at
        == world.setup.attested_at
        && account.persisted.len() == 1
        && account.persisted[0].0 == reference;
    let persisted_before_send = account.steps
        == [
            ForwardStep::Persisted(reference.clone()),
            ForwardStep::Sent(Some(reference.clone())),
        ]
        && account.persisted[0].1 == evidence;
    let transaction = &governance.transactions[index];
    let retained_in_acceptance = transaction.event_id == event.event_id
        && transaction.resolution == ResolutionSource::ForwardedEvidence
        && transaction
            .retained_evidence
            .as_ref()
            .is_some_and(|(retained_ref, retained)| {
                retained_ref == &reference && retained == &evidence
            });
    Ok(json!({
        "decision": "accept",
        "evidence_signed_fresh_for_this_attempt": fresh,
        "evidence_and_ref_persisted_by_a_before_send": persisted_before_send,
        "evidence_and_ref_persisted_by_b_in_acceptance_transaction": retained_in_acceptance,
        "realm_commits": governance.realm_commits(),
    }))
}

fn mls_forward(world: &World) -> Result<Value> {
    let commit_event =
        world.human_event(EventKind::MlsCommit.as_str(), world.setup.event_created_at)?;
    let submission: MlsCommitSubmission = serde_json::from_value(json!({
        "commit_event": commit_event,
        "welcomes": [],
        "idempotency_key": MLS_IDEMPOTENCY_KEY,
    }))?;
    // The Commit Event's producer decides presence for the MLS branch too.
    let missing = PeerAuthorityForwardMlsRequest::new(submission.clone(), None)
        .err()
        .context("an MLS forward of a human Commit Event validated without evidence")?;
    ensure!(missing.error_code() == Some(ErrorCode::SchemaViolation));

    let mut account = world.account_station(LiveDeviceState::Active)?;
    let body = account.forward_mls(submission, world.setup.attested_at)?;
    ensure!(body.get("mls_submission").is_some() && body.get(EVIDENCE_MEMBER).is_some());
    let mut governance = world.remote_governance();
    ensure!(matches!(
        governance.admit_forward(&body, &world.station_a.service_id, world.setup.now)?,
        Admission::Committed(_)
    ));
    Ok(json!({
        "decision": "accept",
        "realm_commits": governance.realm_commits(),
    }))
}

fn exact_replay_after_expiry(world: &World, variant: &Value) -> Result<Value> {
    ensure!(variant["replay"] == "byte_identical_full_body");
    let retry_clock = timestamp(&variant["station_clock_at_retry"])?;
    let event = world.human_event(
        EventKind::MemberState.as_str(),
        world.setup.event_created_at,
    )?;
    let mut account = world.account_station(LiveDeviceState::Active)?;
    let body = account.forward_event(event, world.setup.attested_at)?;
    let evidence = body_evidence(&body)?;
    ensure!(
        retry_clock
            >= evidence
                .device_projection_attestation
                .attestation
                .expires_at,
        "the retry clock must lie past the evidence expiry for the vector to mean anything"
    );

    let mut governance = world.remote_governance();
    let Admission::Committed(original) =
        governance.admit_forward(&body, &world.station_a.service_id, world.setup.now)?
    else {
        bail!("the first attempt was not committed");
    };
    let commits_before = governance.realm_commits();
    let replay = body.clone();
    ensure!(
        arkret_canonical::canonical_json_bytes(&replay)?
            == arkret_canonical::canonical_json_bytes(&body)?
    );
    let admission = governance.admit_forward(&replay, &world.station_a.service_id, retry_clock)?;
    ensure!(
        admission == Admission::Original(original),
        "an exact replay did not return the original outcome"
    );

    // The same bytes at the same clock on a Station that never committed the
    // Event are judged on freshness: expiry only failed to matter above
    // because the duplicate check ran first.
    let mut unseen = world.remote_governance();
    let fresh_judgement =
        expect_rejection(unseen.admit_forward(&replay, &world.station_a.service_id, retry_clock))?;
    let freshness_after_duplicate = fresh_judgement
        == Rejected {
            by: RejectedBy::GovernanceStation,
            code: ErrorCode::DeviceUnauthorized,
        }
        && unseen.durable_writes() == 0;
    Ok(json!({
        "decision": "original_outcome",
        "evidence_freshness_checked_after_duplicate_detection": freshness_after_duplicate,
        "additional_realm_commits": governance.realm_commits() - commits_before,
    }))
}

fn new_attempt_for_committed_event(world: &World) -> Result<Value> {
    let event = world.human_event(
        EventKind::MemberState.as_str(),
        world.setup.event_created_at,
    )?;
    let mut account = world.account_station(LiveDeviceState::Active)?;
    let first = account.forward_event(event.clone(), world.setup.attested_at)?;
    let mut governance = world.remote_governance();
    let Admission::Committed(original) =
        governance.admit_forward(&first, &world.station_a.service_id, world.setup.now)?
    else {
        bail!("the first attempt was not committed");
    };
    let commits_before = governance.realm_commits();

    let second_attempt_at = world.setup.now + Duration::seconds(30);
    let second = account.forward_event(event, second_attempt_at)?;
    let first_evidence = body_evidence(&first)?;
    let second_evidence = body_evidence(&second)?;
    ensure!(
        second_evidence
            .device_projection_attestation
            .attestation
            .attested_at
            == second_attempt_at
            && evidence_digest(&second_evidence)? != evidence_digest(&first_evidence)?
            && account.persisted.len() == 2,
        "a new forwarding attempt reused cached evidence"
    );
    let admission = governance.admit_forward(
        &second,
        &world.station_a.service_id,
        second_attempt_at + Duration::seconds(1),
    )?;
    ensure!(
        admission == Admission::Original(original),
        "a new attempt for a committed Event did not return the original outcome"
    );
    Ok(json!({
        "decision": "original_outcome",
        "additional_realm_commits": governance.realm_commits() - commits_before,
    }))
}

fn forwarder_rejects(world: &World, state: LiveDeviceState) -> Result<Value> {
    let event = world.human_event(
        EventKind::MemberState.as_str(),
        world.setup.event_created_at,
    )?;
    let mut account = world.account_station(state)?;
    let rejection = expect_rejection(account.forward_event(event, world.setup.attested_at))?;
    let governance = world.remote_governance();
    Ok(render_rejection(
        rejection,
        account.durable_writes() + governance.durable_writes(),
        Some(account.forwarded()),
    ))
}

/// Forward `event` honestly from an account Station holding `device`, then
/// let the governance Station judge it at `now`.
fn judge_honest_forward(
    world: &World,
    device: DeviceRecord,
    event: Event,
    now: DateTime<Utc>,
) -> Result<Value> {
    let mut account = AccountStation::new(world, device);
    let body = account.forward_event(event, world.setup.attested_at)?;
    judge(world, &body, &world.station_a.service_id, now)
}

fn judge(world: &World, body: &Value, source: &DidCoreId, now: DateTime<Utc>) -> Result<Value> {
    let mut governance = world.remote_governance();
    let rejection = expect_rejection(governance.admit_forward(body, source, now))?;
    Ok(render_rejection(
        rejection,
        governance.durable_writes(),
        None,
    ))
}

fn window_not_yet_valid(world: &World) -> Result<Value> {
    let mut device = world.device_record(LiveDeviceState::Active)?;
    device.window.not_before = world.setup.event_created_at + Duration::seconds(1);
    ensure!(device.window.not_before <= world.setup.attested_at);
    let event = world.human_event(
        EventKind::MemberState.as_str(),
        world.setup.event_created_at,
    )?;
    judge_honest_forward(world, device, event, world.setup.now)
}

fn window_expired_before_now(world: &World) -> Result<Value> {
    let mut device = world.device_record(LiveDeviceState::Active)?;
    device.window.expires_at = Some(world.setup.now - Duration::milliseconds(1));
    ensure!(world.setup.attested_at < world.setup.now - Duration::milliseconds(1));
    let event = world.human_event(
        EventKind::MemberState.as_str(),
        world.setup.event_created_at,
    )?;
    judge_honest_forward(world, device, event, world.setup.now)
}

fn evidence_expired(world: &World) -> Result<Value> {
    let event = world.human_event(
        EventKind::MemberState.as_str(),
        world.setup.event_created_at,
    )?;
    let expires_at = world.setup.attested_at + world.setup.attestation_ttl;
    // Positive control one millisecond earlier.
    let mut control = world.account_station(LiveDeviceState::Active)?;
    let body = control.forward_event(event.clone(), world.setup.attested_at)?;
    let mut governance = world.remote_governance();
    ensure!(matches!(
        governance.admit_forward(
            &body,
            &world.station_a.service_id,
            expires_at - Duration::milliseconds(1)
        )?,
        Admission::Committed(_)
    ));
    judge_honest_forward(
        world,
        world.device_record(LiveDeviceState::Active)?,
        event,
        expires_at,
    )
}

/// An honest forward of the attested device's Event, whose Event is then
/// replaced in transit by one signed as `fragment` with `seed`.
fn substituted_event(world: &World, fragment: &str, seed: [u8; 32]) -> Result<Value> {
    let honest = world.human_event(
        EventKind::MemberState.as_str(),
        world.setup.event_created_at,
    )?;
    let mut account = world.account_station(LiveDeviceState::Active)?;
    let mut body = account.forward_event(honest, world.setup.attested_at)?;
    let substituted = world.signed_event(
        EventKind::MemberState.as_str(),
        ActorId::account(world.account.clone()),
        &format!("{PRINCIPAL_DID}#{fragment}"),
        seed,
        world.setup.event_created_at,
    )?;
    ensure!(substituted.human_device_producer()?.is_some());
    body["event_submission"] = serde_json::to_value(EventAdmissionSubmission::new(substituted))?;
    judge(world, &body, &world.station_a.service_id, world.setup.now)
}

fn source_station_differs(world: &World) -> Result<Value> {
    let event = world.human_event(
        EventKind::MemberState.as_str(),
        world.setup.event_created_at,
    )?;
    let mut account = world.account_station(LiveDeviceState::Active)?;
    let body = account.forward_event(event, world.setup.attested_at)?;
    judge(world, &body, &world.station_c.service_id, world.setup.now)
}

fn foreign_attestation_signer(world: &World) -> Result<Value> {
    let event = world.human_event(
        EventKind::MemberState.as_str(),
        world.setup.event_created_at,
    )?;
    let mut account = world.account_station(LiveDeviceState::Active)?;
    let body = account.forward_event(event, world.setup.attested_at)?;
    let evidence = body_evidence(&body)?;
    let core = evidence.device_projection_attestation.attestation.clone();

    // A key A never published, under A's own method.
    let mut rogue_key = body.clone();
    rogue_key[EVIDENCE_MEMBER]["device_projection_attestation"] =
        serde_json::to_value(sign_forward_device_projection_attestation(
            core.clone(),
            world.station_a.method.clone(),
            &SigningKey::from_bytes(&ROGUE_STATION_SEED),
        )?)?;
    // Another Station's genuinely registered key and method.
    let mut other_station = body;
    other_station[EVIDENCE_MEMBER]["device_projection_attestation"] =
        serde_json::to_value(sign_forward_device_projection_attestation(
            core,
            world.station_c.method.clone(),
            &world.station_c.signing_key,
        )?)?;
    let rendered = judge(
        world,
        &rogue_key,
        &world.station_a.service_id,
        world.setup.now,
    )?;
    ensure!(
        judge(
            world,
            &other_station,
            &world.station_a.service_id,
            world.setup.now
        )? == rendered,
        "an attestation signed by another Station's key was judged differently"
    );
    Ok(rendered)
}

/// Evidence attested one second before A's Service history contains the
/// asserting method. Every other check is satisfied: the clock sits inside
/// the attestation lifetime and the window covers the Event.
fn history_lacks_method(world: &World) -> Result<Value> {
    let judge_attested_at = |attested_at: DateTime<Utc>| -> Result<Value> {
        let created_at = attested_at - Duration::seconds(30);
        let now = attested_at + Duration::seconds(60);
        let event = world.human_event(EventKind::MemberState.as_str(), created_at)?;
        let device = world.device_record(LiveDeviceState::Active)?;
        ensure!(device.covers(created_at) && device.covers(now));
        let attestation = sign_forward_device_projection_attestation(
            ForwardDeviceProjectionAttestationCore {
                account_id: device.account_id.clone(),
                device_id: device.device_id.clone(),
                device_signing_key_did: device.signing_key_did.clone(),
                hpke_key: device.hpke_key.clone(),
                device_authorize_event_id: device.authorize_event_id.clone(),
                authorized_generation_ref: device.generation,
                device_status: DeviceStatus::Active,
                authorization_window: device.window.clone(),
                attested_at,
                expires_at: attested_at + world.setup.attestation_ttl,
                event_authorization: original_authorization(
                    &device,
                    &event,
                    &world.station_b.service_id,
                    &event_forward_body(&event, None)?,
                )?,
            },
            world.station_a.method.clone(),
            &world.station_a.signing_key,
        )?;
        let request = PeerAuthorityForwardEventRequest::new(
            EventAdmissionSubmission::new(event),
            None,
            Some(ForwardAccountDeviceSignerEvidence {
                device_projection_attestation: attestation,
                service_resolution: world.station_a.resolution()?,
            }),
        )?;
        let body =
            serde_json::to_value(PeerAuthoritySubmitRequest::AuthorityForwardEvent(request))?;
        let mut governance = world.remote_governance();
        Ok(
            match decide(governance.admit_forward(&body, &world.station_a.service_id, now))? {
                Ok(_) => json!({"decision": "accept"}),
                Err(rejection) => render_rejection(rejection, governance.durable_writes(), None),
            },
        )
    };
    // Positive control: the same construction just after registration.
    ensure!(
        judge_attested_at(world.station_a.registered_at + Duration::seconds(20))?
            == json!({"decision": "accept"}),
        "evidence attested inside the Service history was not admitted"
    );
    judge_attested_at(world.station_a.registered_at - Duration::seconds(1))
}

/// A non-human producer's Event forwarded with a human device's evidence.
fn non_human_carries_evidence(world: &World, event: Event) -> Result<Value> {
    ensure!(event.human_device_producer()?.is_none());
    // A Service has no Human evidence. An Agent additionally requires its
    // independent Agent carrier, so absence is not a valid Agent forward.
    let without_human = PeerAuthorityForwardEventRequest::new(
        EventAdmissionSubmission::new(event.clone()),
        None,
        None,
    );
    if event.actual_signer().as_account_id().is_some() {
        let missing_agent = without_human
            .err()
            .context("an Agent forward validated without its required Agent carrier")?;
        ensure!(missing_agent.error_code() == Some(ErrorCode::SchemaViolation));
    } else {
        without_human?;
    }
    ensure!(
        arkret_models_collaboration::authority_commit::validate_producer_device_evidence_presence(
            &event, None,
        )?
        .is_none()
    );
    let mut account = world.account_station(LiveDeviceState::Active)?;
    let honest = account.forward_event(
        world.human_event(
            EventKind::MemberState.as_str(),
            world.setup.event_created_at,
        )?,
        world.setup.attested_at,
    )?;
    // Check the Human sibling's forbidden presence directly, independently of
    // the separate missing-Agent-carrier gate, before the actual zero-write refusal.
    let evidence = body_evidence(&honest)?;
    let wrong_human =
        arkret_models_collaboration::authority_commit::validate_producer_device_evidence_presence(
            &event,
            Some(&evidence),
        )
        .err()
        .context("a non-Human producer accepted the Human sibling")?;
    ensure!(wrong_human.error_code() == Some(ErrorCode::SchemaViolation));
    let body = json!({
        "branch": "authority_forward",
        "event_submission": EventAdmissionSubmission::new(event),
        EVIDENCE_MEMBER: honest[EVIDENCE_MEMBER].clone(),
    });
    judge(world, &body, &world.station_a.service_id, world.setup.now)
}

fn human_without_evidence(world: &World) -> Result<Value> {
    let event = world.human_event(
        EventKind::MemberState.as_str(),
        world.setup.event_created_at,
    )?;
    let body = serde_json::to_value(PeerAuthorityForwardEventRequest {
        branch: AuthorityForwardBranch::AuthorityForward,
        event_submission: EventAdmissionSubmission::new(event),
        mls_genesis_material: None,
        producer_device_evidence: None,
        producer_agent_evidence: None,
    })?;
    ensure!(body.get(EVIDENCE_MEMBER).is_none());
    judge(world, &body, &world.station_a.service_id, world.setup.now)
}

fn evidence_on_other_branch(world: &World, baseline: Value) -> Result<Value> {
    schema_valid(PEER_REQUEST, &baseline)?;
    // Positive control: without the member the baseline parses as the SDK
    // request; only the carried evidence makes it unrepresentable.
    serde_json::from_value::<PeerAuthoritySubmitRequest>(baseline.clone())?;
    let mut account = world.account_station(LiveDeviceState::Active)?;
    let honest = account.forward_event(
        world.human_event(
            EventKind::MemberState.as_str(),
            world.setup.event_created_at,
        )?,
        world.setup.attested_at,
    )?;
    let mut carried = baseline;
    carried[EVIDENCE_MEMBER] = honest[EVIDENCE_MEMBER].clone();
    schema_invalid(PEER_REQUEST, &carried)?;
    let mut governance = world.remote_governance();
    let rejection = expect_rejection(governance.admit_forward(
        &carried,
        &world.station_a.service_id,
        world.setup.now,
    ))?;
    Ok(render_rejection(
        rejection,
        governance.durable_writes(),
        None,
    ))
}

// ---------------------------------------------------------------------------
// Shared forwarding world
// ---------------------------------------------------------------------------

/// This vector's account Station (A) and human-device producer, for other
/// suites whose Events ride `authority_forward` to a governance Station with
/// the fresh `producer_device_evidence` the rule above requires.
pub(super) struct ForwardingWorld(World);

impl ForwardingWorld {
    pub(super) fn load() -> Result<Self> {
        let fixture = load_fixture_value(FIXTURE)?;
        let case = fixture["cases"]
            .as_array()
            .context("peer event submit fixture cases")?
            .iter()
            .find(|case| case["name"] == CASE_NAME)
            .with_context(|| format!("{FIXTURE} publishes no {CASE_NAME} case"))?;
        Ok(Self(World::new(&case["setup"])?))
    }

    pub(super) fn producer_account(&self) -> &AccountId {
        &self.0.account
    }

    pub(super) fn producer_device(&self) -> Result<DeviceId> {
        Ok(DeviceId::new(DEVICE)?)
    }

    /// The producer device's Ed25519 key, which also signs its MLS leaf.
    pub(super) fn producer_device_key(&self) -> SigningKey {
        SigningKey::from_bytes(&DEVICE_SEED)
    }

    /// The accepted authorization Event for the producer device in this fixture.
    pub(super) fn producer_device_authorize_event_id(&self) -> Result<EventId> {
        Ok(self
            .0
            .device_record(LiveDeviceState::Active)?
            .authorize_event_id)
    }

    pub(super) fn realm_id(&self) -> &RealmId {
        &self.0.realm_id
    }

    /// One Event of `kind` carrying `payload`, signed by the producer device.
    pub(super) fn producer_event(&self, kind: &str, payload: Value) -> Result<Event> {
        let created_at = self.0.setup.event_created_at;
        let event = arkret_wire::test_support::raw_event_for_actor_at(
            kind,
            ScopeRef::Realm {
                realm_id: self.0.realm_id.clone(),
            },
            ActorId::account(self.0.account.clone()),
            payload,
            created_at,
        )?;
        sign(
            event,
            &format!("{PRINCIPAL_DID}#{DEVICE}"),
            DEVICE_SEED,
            created_at,
        )
    }

    /// A producer Event of the fixture's own payload for `kind`.
    pub(super) fn fixture_event(&self, kind: &str) -> Result<Event> {
        self.0.human_event(kind, self.0.setup.event_created_at)
    }

    /// Evidence the forwarding Station signs fresh for one attempt from its
    /// live device gate.
    pub(super) fn fresh_evidence(
        &self,
        event: &Event,
        request: &PeerAuthorityForwardEventRequest,
    ) -> Result<ForwardAccountDeviceSignerEvidence> {
        ensure!(request.event_submission.event == *event);
        let mut station = self.0.account_station(LiveDeviceState::Active)?;
        station
            .fresh_evidence(
                event,
                self.0.setup.attested_at,
                &serde_json::to_value(request)?,
            )?
            .context("the forwarded Event has a human-device producer")
    }

    /// The governance Station's resolution of the forwarded producer, the
    /// step between request validation and the Event's own admission.
    pub(super) fn verify_forwarded_producer(
        &self,
        request: &PeerAuthorityForwardEventRequest,
    ) -> std::result::Result<(), ErrorCode> {
        let event = &request.event_submission.event;
        let evidence = request
            .producer_device_evidence
            .as_ref()
            .ok_or(ErrorCode::SchemaViolation)?;
        let body = serde_json::to_value(request).map_err(|_| ErrorCode::SchemaViolation)?;
        let producer = verify_forwarded_human_producer(
            evidence,
            event,
            &self.0.station_a.service_id,
            &self.0.station_b.service_id,
            &arkret_models_collaboration::authority_commit::authority_forward_body_digest(&body)
                .map_err(|_| ErrorCode::SchemaViolation)?,
            DigestSuite::Sha256,
            self.0.setup.now,
        )
        .map_err(|error| error.error_code().unwrap_or(ErrorCode::SignatureInvalid))?;
        match event.human_device_producer() {
            Ok(Some(signer)) if signer == producer => Ok(()),
            _ => Err(ErrorCode::SignatureInvalid),
        }
    }
}
