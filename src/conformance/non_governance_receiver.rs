//! `ak.vector.federation.non_governance_receiver_trusts_governance_commit.v1`
//! — a committed-Event consumer that does not govern the Realm relies on the
//! governance `RealmCommit` for a foreign human device (`federation.md` §3,
//! decision 0107 §6).
//!
//! A `committed_replication` member Station and an invite delivery receiver
//! check exactly three things: the producer proof is self-consistent, the
//! RealmCommit is validly signed by the governance Station that the verified
//! genesis/handoff chain names for its generation, and the ref / position /
//! `previous_commit_ref` continuity holds. They never resolve or fetch a
//! foreign human device key. A producer whose Account the receiver hosts is
//! still verified against the receiver's own PCR.
//!
//! The protocol decisions are the SDK's: `Event::verify_producer_proof_self_consistency`,
//! `arkret_identity::verify_realm_authority_bundle` and
//! `VerifiedRealmAuthority::verify_commit`, over a real two-generation chain
//! (genesis under Station A, a doubly signed handoff to Station B) with real
//! Ed25519 keys, the `PeerAuthoritySubmitRequest` wire parser and the
//! `CommittedEventSubmission` binding check. This module models the receiver
//! around them — its replica stream head, its local PCR and its write ledger —
//! and compares the rendered outcome of every registered variant with the
//! fixture's `expected` object.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use arkret_canonical::DigestSuite;
use arkret_canonical::canonical::unsigned_value;
use arkret_identity::{
    DidDocument, RealmAuthorityChainError, RealmAuthorityFreshness, RealmAuthorityKeyMap,
    VerifiedRealmAuthority, build_authenticated_did_web_service_resolution,
    verify_realm_authority_bundle,
};
use arkret_models_collaboration::authority_commit::PeerAuthoritySubmitRequest;
use arkret_signatures::PublicKeyMaterial;
use arkret_signatures::detached_object::sign_detached_object;
use arkret_wire::{
    AccountId, ActorId, Base64UrlString, CommitStreamHead, CommitStreamRef,
    DetachedObjectSignature, DetachedSignatureAlgorithm, DetachedSignatureContext, DeviceId, Did,
    DidCoreId, DidKey, DidUrl, ErrorCode, Event, EventAdmissionSubmission, EventId, EventKind,
    Hash, HumanDeviceProducer, RealmAuthorityBundle, RealmAuthorityCurrentAssertion,
    RealmAuthorityHandoff, RealmAuthorityHandoffId, RealmAuthorityTransition, RealmCommit,
    RealmCommitAuthorityRef, RealmCommitId, RealmId, RealmSnapshotId, ScopeRef,
    project_did_to_core_id,
};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use super::authority_forward_producer_device_evidence::{sign, verify_producer_proof};
use super::{load_fixture_value, required_str};
use crate::transcripts::record_vector_event;

pub const VECTOR_ID_NON_GOVERNANCE_RECEIVER_TRUSTS_GOVERNANCE_COMMIT: &str =
    "ak.vector.federation.non_governance_receiver_trusts_governance_commit.v1";

const FIXTURE: &str = "peer-event-submit-semantic-union-fixture.json";
const CASE_NAME: &str = "non_governance_receiver_trusts_governance_commit";
const LOCAL_PCR_RESOLUTION: &str = "local_pcr_device_authorization_and_device_generation";

/// Generation 0 governance Station (genesis), handed off to Station B.
const STATION_A: &str = "did:web:station-a.example";
/// Current governance Station (generation 1).
const STATION_B: &str = "did:web:station-b.example";
/// The non-governance receiver: a member Station or an invite receiver.
const STATION_R: &str = "did:web:station-r.example";
/// The foreign producer's account Station; the receiver never talks to it.
const STATION_F: &str = "did:web:station-f.example";

const FOREIGN_PRINCIPAL_DID: &str = "did:webvh:z6mkfixture:alice.example";
const FOREIGN_DEVICE: &str = "ak:device:019a8600-0000-7000-8000-000000000001";
const LOCAL_PRINCIPAL_DID: &str = "did:webvh:z6mkbob:bob.example";
const LOCAL_DEVICE: &str = "ak:device:019a8600-0000-7000-8000-000000000002";
const OTHER_PRINCIPAL_DID: &str = "did:webvh:z6mkmallory:mallory.example";
const TRUNCATED_DEVICE_FRAGMENT: &str = "ak:device:019a8600";

const FOREIGN_DEVICE_SEED: [u8; 32] = [0x61; 32];
const LOCAL_DEVICE_SEED: [u8; 32] = [0x62; 32];
const WRONG_LOCAL_DEVICE_SEED: [u8; 32] = [0x63; 32];
const STATION_A_SEED: [u8; 32] = [0xa1; 32];
const STATION_B_SEED: [u8; 32] = [0xb2; 32];

const NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAA";
const CHAIN_START: &str = "2026-09-25T10:00:00.000Z";

const REGISTERED_VARIANTS: [&str; 9] = [
    "foreign_human_producer_replica_stored",
    "foreign_human_invite_delivery_verified",
    "proof_event_digest_mismatch",
    "fragment_differs_from_device_id",
    "verification_method_projection_differs_from_signer",
    "governance_commit_signature_invalid",
    "commit_signed_by_non_current_governance_station",
    "local_account_producer_verified_against_local_pcr",
    "local_account_producer_key_mismatch",
];

pub fn run_non_governance_receiver_trusts_governance_commit_vector() -> Result<()> {
    let fixture = load_fixture_value(FIXTURE)?;
    ensure!(
        fixture["covers_vectors"].as_array().is_some_and(|ids| ids
            .iter()
            .any(|id| id == VECTOR_ID_NON_GOVERNANCE_RECEIVER_TRUSTS_GOVERNANCE_COMMIT)),
        "{FIXTURE} does not cover {VECTOR_ID_NON_GOVERNANCE_RECEIVER_TRUSTS_GOVERNANCE_COMMIT}"
    );
    let case = fixture["cases"]
        .as_array()
        .context("peer event submit fixture cases")?
        .iter()
        .find(|case| case["name"] == CASE_NAME)
        .cloned()
        .with_context(|| format!("{FIXTURE} publishes no {CASE_NAME} case"))?;
    ensure!(case["vector_id"] == VECTOR_ID_NON_GOVERNANCE_RECEIVER_TRUSTS_GOVERNANCE_COMMIT);
    ensure!(
        case["receivers"]
            == json!([
                "committed_replication_member_station",
                "invite_delivery_receiver"
            ]),
        "the non-governance receiver set drifted"
    );
    ensure!(
        case["checks"].as_array().map(Vec::len) == Some(3),
        "a non-governance receiver runs exactly three checks"
    );
    ensure!(
        case["foreign_human_device_key_resolution"]
            .as_str()
            .is_some_and(|rule| rule.starts_with("none")),
        "the fixture no longer forbids foreign human device key resolution"
    );

    let world = World::new()?;
    world.assert_positive_controls()?;

    let variants = case["variants"]
        .as_array()
        .context("non-governance receiver variants")?;
    let names = variants
        .iter()
        .map(|variant| variant["name"].as_str().map(str::to_owned))
        .collect::<Option<BTreeSet<_>>>()
        .context("non-governance receiver variant name")?;
    ensure!(
        names.len() == variants.len()
            && names
                == REGISTERED_VARIANTS
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
        "non-governance receiver variants drifted from the executed set: {names:?}"
    );

    for variant in variants {
        let name = required_str(variant, "name")?;
        let actual = execute_variant(&world, name)
            .with_context(|| format!("execute non-governance receiver variant {name}"))?;
        ensure!(
            actual == variant["expected"],
            "non-governance receiver variant {name} produced {actual}, fixture expects {}",
            variant["expected"]
        );
        record_vector_event(
            "federation.non_governance_receiver_trusts_governance_commit",
            &json!({
                "vector_id": VECTOR_ID_NON_GOVERNANCE_RECEIVER_TRUSTS_GOVERNANCE_COMMIT,
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
        "non-governance receiver case publishes no assertions"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Rejections
// ---------------------------------------------------------------------------

/// A protocol rejection, as opposed to a broken model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rejected(ErrorCode);

impl std::fmt::Display for Rejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "receiver rejected with {}", self.0.as_str())
    }
}

impl std::error::Error for Rejected {}

fn rejected(code: ErrorCode) -> anyhow::Error {
    anyhow::Error::new(Rejected(code))
}

/// A governance signature that does not verify, or verifies under a Station
/// the verified chain does not name for that generation, is a
/// `signature_invalid` Commit. Any other chain failure is outside this vector
/// and fails the model rather than being given a code here.
fn commit_rejection(error: RealmAuthorityChainError) -> anyhow::Error {
    match error {
        RealmAuthorityChainError::SignatureInvalid(_)
        | RealmAuthorityChainError::StationMismatch(_) => rejected(ErrorCode::SignatureInvalid),
        other => anyhow!("governance Commit failed outside this vector: {other}"),
    }
}

// ---------------------------------------------------------------------------
// The receiver
// ---------------------------------------------------------------------------

/// One device the receiver's own PCR accepted, for an Account it hosts.
struct LocalDevice {
    producer: HumanDeviceProducer,
    signing_key_did: DidKey,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeySource {
    /// No device key was resolved: the governance RealmCommit vouches.
    GovernanceCommit,
    /// The receiver hosts the producer's Account and verified the proof
    /// against its own PCR.
    LocalPcr,
}

/// A non-governance Station. It holds a verified authority chain, its
/// replica stream head and its own PCR. It deliberately has no peer device
/// directory and no evidence store: a foreign human device key has nowhere to
/// come from.
struct Receiver {
    station_id: DidCoreId,
    authority: VerifiedRealmAuthority,
    governance_keys: RealmAuthorityKeyMap,
    local_pcr: Vec<LocalDevice>,
    head: (RealmCommitId, u64),
    replicas: Vec<EventId>,
    deliveries: Vec<EventId>,
}

impl Receiver {
    fn writes(&self) -> usize {
        self.replicas.len() + self.deliveries.len()
    }

    /// The `federation.md` §3 non-governance rule for one committed Event.
    fn verify_committed(&self, event: &Event, commit: &RealmCommit) -> Result<KeySource> {
        // Continuity: exact ref, own Realm stream, next position, predecessor.
        ensure!(
            commit.event_ref == event.event_id
                && commit.realm_id == *self.authority.realm_id()
                && commit.stream_ref
                    == CommitStreamRef::Realm {
                        realm_id: self.authority.realm_id().clone(),
                    }
                && commit.stream_position == self.head.1 + 1
                && commit.previous_commit_ref.as_ref() == Some(&self.head.0),
            "committed Event breaks ref / position / previous_commit_ref continuity"
        );
        event
            .verify_event_id_matches_content_with_digest_suite(DigestSuite::Sha256)
            .context("committed Event id does not bind its content")?;
        // Producer proof self-consistency, key-free.
        let producer = event
            .verify_producer_proof_self_consistency(DigestSuite::Sha256)
            .map_err(|error| {
                error.error_code().map_or_else(
                    || anyhow!("uncoded self-consistency failure: {error}"),
                    rejected,
                )
            })?;
        // The governance Station of that generation signed the Commit.
        self.authority
            .verify_commit(commit, &self.governance_keys)
            .map_err(commit_rejection)?;
        // Only a producer this Station hosts is resolved, from its own PCR.
        match producer {
            Some(producer) if producer.account_id.station_id == self.station_id => {
                let device = self
                    .local_pcr
                    .iter()
                    .find(|device| device.producer == producer)
                    .context("a hosted producer has a local PCR record")?;
                verify_producer_proof(event, &device.signing_key_did)
                    .map_err(|_| rejected(ErrorCode::SignatureInvalid))?;
                Ok(KeySource::LocalPcr)
            }
            _ => Ok(KeySource::GovernanceCommit),
        }
    }

    /// Receive the exact `committed_replication` bytes the governance Station
    /// sent.
    fn replicate(&mut self, body: &Value) -> Result<Vec<KeySource>> {
        let request: PeerAuthoritySubmitRequest = serde_json::from_value(body.clone())
            .context("committed_replication body does not parse")?;
        let PeerAuthoritySubmitRequest::CommittedReplication(request) = &request else {
            bail!("the member Station model receives committed_replication only");
        };
        PeerAuthoritySubmitRequest::CommittedReplication(request.clone())
            .validate()
            .context("committed_replication request is not valid")?;
        let mut sources = Vec::new();
        for replication in &request.replications {
            let event = &replication.event_submission.event;
            let source = self.verify_committed(event, &replication.source_commit)?;
            self.replicas.push(event.event_id.clone());
            self.head = (
                replication.source_commit.commit_id.clone(),
                replication.source_commit.stream_position,
            );
            sources.push(source);
        }
        Ok(sources)
    }

    /// `invite-addressing.md` step 4: the same rule, applied verbatim
    /// against `invite_commit`. Passing hands the notification to the
    /// receive policy.
    fn receive_invite(
        &mut self,
        invite_event: &Event,
        invite_commit: &RealmCommit,
    ) -> Result<KeySource> {
        ensure!(
            invite_event.kind == EventKind::InviteCreate,
            "invite delivery carries a non-invite Event"
        );
        let source = self.verify_committed(invite_event, invite_commit)?;
        self.deliveries.push(invite_event.event_id.clone());
        Ok(source)
    }
}

// ---------------------------------------------------------------------------
// Fixture world
// ---------------------------------------------------------------------------

struct World {
    start: DateTime<Utc>,
    realm_id: RealmId,
    key_a: SigningKey,
    key_b: SigningKey,
    bundle: RealmAuthorityBundle,
    handoff_id: RealmAuthorityHandoffId,
    head: (RealmCommitId, u64),
    foreign_account: AccountId,
    local_account: AccountId,
}

impl World {
    fn new() -> Result<Self> {
        let start = DateTime::parse_from_rfc3339(CHAIN_START)?.to_utc();
        let realm_id =
            RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [0x71; 32]));
        let key_a = SigningKey::from_bytes(&STATION_A_SEED);
        let key_b = SigningKey::from_bytes(&STATION_B_SEED);
        let stream = CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        };

        let founder = ActorId::service(core_id(STATION_A)?);
        let genesis_event = arkret_wire::test_support::raw_event_for_actor_at(
            EventKind::RealmCreate.as_str(),
            ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            founder.clone(),
            json!({}),
            start,
        )?;
        let genesis_commit = seal_commit(
            RealmCommit {
                commit_id: RealmCommitId::from_digest([0x01; 32]),
                realm_id: realm_id.clone(),
                stream_ref: stream.clone(),
                stream_position: 0,
                previous_commit_ref: None,
                event_ref: genesis_event.event_id.clone(),
                governance_generation: 0,
                authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    genesis_event.event_id.clone(),
                ),
                committed_at: start,
                producer_signer_fact_digest: None,
                signature: placeholder_signature(DetachedSignatureContext::RealmCommit)?,
            },
            STATION_A,
            &key_a,
        )?;
        let change_event = arkret_wire::test_support::raw_event_for_actor_at(
            EventKind::MessageCreate.as_str(),
            ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            founder,
            json!({}),
            start + Duration::seconds(1),
        )?;
        let change_commit = seal_commit(
            RealmCommit {
                commit_id: RealmCommitId::from_digest([0x02; 32]),
                realm_id: realm_id.clone(),
                stream_ref: stream.clone(),
                stream_position: 1,
                previous_commit_ref: Some(genesis_commit.commit_id.clone()),
                event_ref: change_event.event_id.clone(),
                governance_generation: 0,
                authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(
                    genesis_event.event_id.clone(),
                ),
                committed_at: start + Duration::seconds(1),
                producer_signer_fact_digest: None,
                signature: placeholder_signature(DetachedSignatureContext::RealmCommit)?,
            },
            STATION_A,
            &key_a,
        )?;
        let handoff = seal_handoff(
            RealmAuthorityHandoff {
                handoff_id: RealmAuthorityHandoffId::from_digest([0x21; 32]),
                realm_id: realm_id.clone(),
                from_generation: 0,
                to_generation: 1,
                from_service_id: core_id(STATION_A)?,
                to_service_id: core_id(STATION_B)?,
                final_stream_heads_digest: hash('a')?,
                snapshot_ref: RealmSnapshotId::from_digest([0x44; 32]),
                historical_signer_facts_digest: Some(
                    arkret_models_collaboration::authority_commit::historical_signer_facts_digest(
                        &[],
                    )?,
                ),
                change_event_ref: change_event.event_id.clone(),
                change_commit_id: change_commit.commit_id.clone(),
                old_authority_signature: placeholder_signature(
                    DetachedSignatureContext::RealmAuthorityHandoffOld,
                )?,
                new_authority_acceptance_signature: placeholder_signature(
                    DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
                )?,
            },
            &key_a,
            &key_b,
        )?;
        let head = CommitStreamHead {
            stream_ref: stream,
            stream_position: 1,
            commit_id: change_commit.commit_id.clone(),
        };
        let mut assertion = RealmAuthorityCurrentAssertion {
            realm_id: realm_id.clone(),
            current_generation: 1,
            current_service_id: core_id(STATION_B)?,
            last_handoff_ref: Some(handoff.handoff_id.clone()),
            realm_stream_head: head.clone(),
            nonce: b64u(NONCE.to_owned())?,
            expires_at: start + Duration::minutes(10),
            signature: placeholder_signature(
                DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            )?,
        };
        assertion.signature = sign_detached_object(
            &unsigned_value(&assertion, &["signature"])?,
            DetachedSignatureContext::RealmAuthorityCurrentAssertion,
            method(STATION_B)?,
            start + Duration::seconds(2),
            &key_b,
        )?;
        let handoff_id = handoff.handoff_id.clone();
        let chain_head = (change_commit.commit_id.clone(), 1);
        let bundle = RealmAuthorityBundle {
            realm_id: realm_id.clone(),
            genesis_event,
            genesis_commit,
            authority_transitions: vec![RealmAuthorityTransition {
                change_event,
                change_commit,
                handoff,
            }],
            current_generation: 1,
            current_service_id: core_id(STATION_B)?,
            current_route_record: route_record(STATION_B, &key_b, start)?,
            realm_stream_head: head,
            bundle_issued_at: start + Duration::seconds(2),
            current_assertion: assertion,
        };
        Ok(Self {
            start,
            realm_id,
            key_a,
            key_b,
            bundle,
            handoff_id,
            head: chain_head,
            foreign_account: AccountId::new(
                project_did_to_core_id(&Did::new(FOREIGN_PRINCIPAL_DID)?)?,
                core_id(STATION_F)?,
            ),
            local_account: AccountId::new(
                project_did_to_core_id(&Did::new(LOCAL_PRINCIPAL_DID)?)?,
                core_id(STATION_R)?,
            ),
        })
    }

    fn now(&self) -> DateTime<Utc> {
        self.start + Duration::seconds(30)
    }

    /// A fresh receiver: it verified the authority chain itself and has
    /// replicated the stream through the handoff.
    fn receiver(&self) -> Result<Receiver> {
        let governance_keys = RealmAuthorityKeyMap::new()
            .with_key(&method(STATION_A)?, public(&self.key_a))
            .with_key(&method(STATION_B)?, public(&self.key_b));
        let freshness = RealmAuthorityFreshness::new(self.now(), b64u(NONCE.to_owned())?);
        let authority = verify_realm_authority_bundle(&self.bundle, &freshness, &governance_keys)
            .map_err(|error| anyhow!("authority chain does not verify: {error}"))?;
        ensure!(authority.current_service_id() == &core_id(STATION_B)?);
        Ok(Receiver {
            station_id: core_id(STATION_R)?,
            authority,
            governance_keys,
            local_pcr: vec![LocalDevice {
                producer: HumanDeviceProducer {
                    account_id: self.local_account.clone(),
                    device_id: DeviceId::new(LOCAL_DEVICE)?,
                },
                signing_key_did: did_key(&SigningKey::from_bytes(&LOCAL_DEVICE_SEED))?,
            }],
            head: self.head.clone(),
            replicas: Vec::new(),
            deliveries: Vec::new(),
        })
    }

    fn event(
        &self,
        kind: &str,
        account: &AccountId,
        verification_method: &str,
        seed: [u8; 32],
        payload: Value,
    ) -> Result<Event> {
        let created_at = self.start + Duration::seconds(10);
        let event = arkret_wire::test_support::raw_event_for_actor_at(
            kind,
            ScopeRef::Realm {
                realm_id: self.realm_id.clone(),
            },
            ActorId::account(account.clone()),
            payload,
            created_at,
        )?;
        sign(event, verification_method, seed, created_at)
    }

    fn message_payload() -> Value {
        json!({
            "strand_id": format!("ak:strand:{}", "A".repeat(44)),
            "track_name": "discussion",
            "content": {"kind": "ak.content.text", "body": "replicated"},
        })
    }

    fn foreign_message(&self) -> Result<Event> {
        self.event(
            EventKind::MessageCreate.as_str(),
            &self.foreign_account,
            &format!("{FOREIGN_PRINCIPAL_DID}#{FOREIGN_DEVICE}"),
            FOREIGN_DEVICE_SEED,
            Self::message_payload(),
        )
    }

    fn local_message(&self, seed: [u8; 32]) -> Result<Event> {
        self.event(
            EventKind::MessageCreate.as_str(),
            &self.local_account,
            &format!("{LOCAL_PRINCIPAL_DID}#{LOCAL_DEVICE}"),
            seed,
            Self::message_payload(),
        )
    }

    fn foreign_invite(&self) -> Result<Event> {
        self.event(
            EventKind::InviteCreate.as_str(),
            &self.foreign_account,
            &format!("{FOREIGN_PRINCIPAL_DID}#{FOREIGN_DEVICE}"),
            FOREIGN_DEVICE_SEED,
            json!({
                "invitee_account_id": self.local_account,
                "introduction_evidence_digest": hash('c')?,
                "expires_at": "2026-10-02T10:00:00.000Z",
            }),
        )
    }

    /// The Commit the current governance Station (generation 1) makes for
    /// `event` at the next stream position.
    fn governance_commit(&self, event: &Event) -> Result<RealmCommit> {
        self.commit_signed_by(event, STATION_B, &self.key_b)
    }

    fn commit_signed_by(
        &self,
        event: &Event,
        station: &str,
        key: &SigningKey,
    ) -> Result<RealmCommit> {
        seal_commit(
            RealmCommit {
                commit_id: RealmCommitId::from_digest([0x03; 32]),
                realm_id: self.realm_id.clone(),
                stream_ref: CommitStreamRef::Realm {
                    realm_id: self.realm_id.clone(),
                },
                stream_position: self.head.1 + 1,
                previous_commit_ref: Some(self.head.0.clone()),
                event_ref: event.event_id.clone(),
                governance_generation: 1,
                authority_ref: RealmCommitAuthorityRef::Handoff(self.handoff_id.clone()),
                committed_at: self.start + Duration::seconds(11),
                producer_signer_fact_digest: None,
                signature: placeholder_signature(DetachedSignatureContext::RealmCommit)?,
            },
            station,
            key,
        )
    }

    /// Positive and negative controls that are not fixture variants: the
    /// honest replica passes, and a continuity break or a foreign Commit
    /// generation is refused before anything is written.
    fn assert_positive_controls(&self) -> Result<()> {
        let event = self.foreign_message()?;
        let commit = self.governance_commit(&event)?;
        ensure!(
            event
                .verify_producer_proof_self_consistency(DigestSuite::Sha256)?
                .is_some_and(|producer| producer.account_id == self.foreign_account),
            "the honest foreign replica is not a self-consistent human-device producer"
        );

        let mut gap = commit.clone();
        gap.stream_position += 1;
        let gap = seal_commit(gap, STATION_B, &self.key_b)?;
        let mut receiver = self.receiver()?;
        ensure!(
            receiver
                .replicate(&replication_body(&event, &gap)?)
                .is_err()
                && receiver.writes() == 0,
            "a replica that skips a stream position was stored"
        );

        let mut orphan = commit;
        orphan.previous_commit_ref = Some(RealmCommitId::from_digest([0x09; 32]));
        let orphan = seal_commit(orphan, STATION_B, &self.key_b)?;
        let mut receiver = self.receiver()?;
        ensure!(
            receiver
                .replicate(&replication_body(&event, &orphan)?)
                .is_err()
                && receiver.writes() == 0,
            "a replica with a foreign previous_commit_ref was stored"
        );
        Ok(())
    }
}

fn replication_body(event: &Event, commit: &RealmCommit) -> Result<Value> {
    Ok(json!({
        "branch": "committed_replication",
        "replications": [{
            "event_submission": EventAdmissionSubmission::new(event.clone()),
            "source_commit": commit,
        }],
    }))
}

// ---------------------------------------------------------------------------
// Variants
// ---------------------------------------------------------------------------

fn execute_variant(world: &World, name: &str) -> Result<Value> {
    match name {
        "foreign_human_producer_replica_stored" => {
            let event = world.foreign_message()?;
            let commit = world.governance_commit(&event)?;
            replicate(world, &event, &commit)
        }
        "foreign_human_invite_delivery_verified" => {
            let invite = world.foreign_invite()?;
            let commit = world.governance_commit(&invite)?;
            let mut receiver = world.receiver()?;
            let source = receiver.receive_invite(&invite, &commit)?;
            ensure!(receiver.deliveries.len() == 1 && receiver.replicas.is_empty());
            Ok(json!({
                "decision": "continue_to_receive_policy",
                "device_key_resolved": source == KeySource::LocalPcr,
            }))
        }
        "proof_event_digest_mismatch" => {
            let mut event = world.foreign_message()?;
            let proof = event.producer_proof.as_mut().context("producer proof")?;
            proof.event_digest = Hash::new(format!("sha256:{}", "0".repeat(64)))?;
            let commit = world.governance_commit(&event)?;
            replicate(world, &event, &commit)
        }
        "fragment_differs_from_device_id" => {
            let event = with_method(
                world.foreign_message()?,
                &format!("{FOREIGN_PRINCIPAL_DID}#{TRUNCATED_DEVICE_FRAGMENT}"),
            )?;
            let commit = world.governance_commit(&event)?;
            replicate(world, &event, &commit)
        }
        "verification_method_projection_differs_from_signer" => {
            let event = with_method(
                world.foreign_message()?,
                &format!("{OTHER_PRINCIPAL_DID}#{FOREIGN_DEVICE}"),
            )?;
            let commit = world.governance_commit(&event)?;
            replicate(world, &event, &commit)
        }
        "governance_commit_signature_invalid" => {
            let event = world.foreign_message()?;
            let mut commit = world.governance_commit(&event)?;
            commit.signature.sig = flip_first_char(&commit.signature.sig)?;
            replicate(world, &event, &commit)
        }
        "commit_signed_by_non_current_governance_station" => {
            let event = world.foreign_message()?;
            // Station A's own valid key, but generation 1 belongs to B.
            let commit = world.commit_signed_by(&event, STATION_A, &world.key_a)?;
            replicate(world, &event, &commit)
        }
        "local_account_producer_verified_against_local_pcr" => {
            let event = world.local_message(LOCAL_DEVICE_SEED)?;
            let commit = world.governance_commit(&event)?;
            replicate(world, &event, &commit)
        }
        "local_account_producer_key_mismatch" => {
            let event = world.local_message(WRONG_LOCAL_DEVICE_SEED)?;
            ensure!(
                event
                    .verify_producer_proof_self_consistency(DigestSuite::Sha256)?
                    .is_some(),
                "the mismatched key must be the only defect"
            );
            let commit = world.governance_commit(&event)?;
            replicate(world, &event, &commit)
        }
        other => bail!("no model for non-governance receiver variant {other}"),
    }
}

fn replicate(world: &World, event: &Event, commit: &RealmCommit) -> Result<Value> {
    let mut receiver = world.receiver()?;
    match receiver.replicate(&replication_body(event, commit)?) {
        Ok(sources) => {
            let [source] = sources.as_slice() else {
                bail!("one replication item produced {} outcomes", sources.len());
            };
            ensure!(receiver.replicas.as_slice() == std::slice::from_ref(&event.event_id));
            let mut rendered = json!({
                "decision": "store",
                "device_key_resolved": *source == KeySource::LocalPcr,
            });
            if *source == KeySource::LocalPcr {
                rendered["resolution_source"] = json!(LOCAL_PCR_RESOLUTION);
            }
            Ok(rendered)
        }
        Err(error) => {
            let Rejected(code) = error.downcast::<Rejected>()?;
            Ok(json!({
                "decision": "reject",
                "rejected_as": code.as_str(),
                "replica_writes": receiver.writes(),
            }))
        }
    }
}

fn with_method(mut event: Event, verification_method: &str) -> Result<Event> {
    event
        .producer_proof
        .as_mut()
        .context("producer proof")?
        .verification_method =
        DidUrl::new(verification_method).map_err(|error| anyhow!("{error}"))?;
    Ok(event)
}

fn flip_first_char(value: &Base64UrlString) -> Result<Base64UrlString> {
    let text = value.as_str();
    let first = text.chars().next().context("empty signature")?;
    let replacement = if first == 'A' { 'B' } else { 'A' };
    b64u(format!("{replacement}{}", &text[1..]))
}

// ---------------------------------------------------------------------------
// Sealing helpers
// ---------------------------------------------------------------------------

fn core_id(did: &str) -> Result<DidCoreId> {
    Ok(project_did_to_core_id(&Did::new(did)?)?)
}

fn method(did: &str) -> Result<DidUrl> {
    DidUrl::new(format!("{did}#realm-authority")).map_err(|error| anyhow!("{error}"))
}

fn public(key: &SigningKey) -> PublicKeyMaterial {
    PublicKeyMaterial::Ed25519Raw {
        bytes: key.verifying_key().to_bytes().to_vec(),
    }
}

fn did_key(key: &SigningKey) -> Result<DidKey> {
    DidKey::new(format!(
        "did:key:{}",
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes())
    ))
    .map_err(|error| anyhow!("{error}"))
}

fn hash(byte: char) -> Result<Hash> {
    Ok(Hash::new(format!(
        "sha256:{}",
        format!("{byte}{byte}").repeat(32)
    ))?)
}

fn placeholder_signature(context: DetachedSignatureContext) -> Result<DetachedObjectSignature> {
    Ok(DetachedObjectSignature {
        context,
        signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
        verification_method: method(STATION_A)?,
        signed_digest: hash('1')?,
        created_at: DateTime::parse_from_rfc3339(CHAIN_START)?.to_utc(),
        sig: b64u("A".repeat(86))?,
    })
}

/// Seal a Commit the way the verifier reconstructs it: the unsigned
/// projection is the object without its `signature` member.
fn seal_commit(mut commit: RealmCommit, station: &str, key: &SigningKey) -> Result<RealmCommit> {
    commit.signature = sign_detached_object(
        &unsigned_value(&commit, &["signature"])?,
        DetachedSignatureContext::RealmCommit,
        method(station)?,
        commit.committed_at,
        key,
    )?;
    Ok(commit)
}

/// Both handoff signatures seal the same unsigned body, each in its own
/// domain.
fn seal_handoff(
    mut handoff: RealmAuthorityHandoff,
    old_key: &SigningKey,
    new_key: &SigningKey,
) -> Result<RealmAuthorityHandoff> {
    let unsigned = unsigned_value(
        &handoff,
        &[
            "old_authority_signature",
            "new_authority_acceptance_signature",
        ],
    )?;
    let at = DateTime::parse_from_rfc3339(CHAIN_START)?.to_utc() + Duration::seconds(1);
    handoff.old_authority_signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityHandoffOld,
        method(STATION_A)?,
        at,
        old_key,
    )?;
    handoff.new_authority_acceptance_signature = sign_detached_object(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
        method(STATION_B)?,
        at,
        new_key,
    )?;
    Ok(handoff)
}

/// The current governance Station's authenticated route record.
fn route_record(did: &str, key: &SigningKey, now: DateTime<Utc>) -> Result<Value> {
    let multibase =
        arkret_canonical::ed25519_pubkey_to_did_key_multibase(key.verifying_key().as_bytes());
    let document: DidDocument = serde_json::from_value(json!({
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [{
            "id": format!("{did}#realm-authority"),
            "controller": did,
            "type": "Multikey",
            "publicKeyMultibase": multibase,
        }],
        "authentication": [format!("{did}#realm-authority")],
        "assertionMethod": [format!("{did}#realm-authority")],
        "service": [{
            "id": format!("{did}#station"),
            "type": "ArkretService",
            "serviceEndpoint": "https://station-b.example/",
            "serviceKind": "station",
        }],
    }))?;
    let resolution = build_authenticated_did_web_service_resolution(
        core_id(did)?,
        "station".into(),
        document,
        now,
    )
    .map_err(|error| anyhow!("route record: {error}"))?;
    Ok(serde_json::to_value(resolution)?)
}

fn b64u(value: String) -> Result<Base64UrlString> {
    Base64UrlString::new(value).map_err(anyhow::Error::msg)
}
