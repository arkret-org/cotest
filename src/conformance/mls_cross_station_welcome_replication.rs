//! Executable semantics for `ak.vector.mls.cross_station_welcome_replication.v1`
//! (`encryption-and-audit.md` §2.2, `device-lifecycle.md` §9.2.3,
//! `client-sync.md` §10.1, decisions 0119 and 0121).
//!
//! alice, a member on the governance Station, submits real signed
//! `ak.mls.commit` Events with producer-signed Welcome deliveries. The SDK
//! decides every wire question: the closed `MlsCommitSubmission` (Welcomes
//! sorted by `welcome_id` and bound to the exact Commit), the Welcome
//! producer proof, each recipient's routing service, and the committed
//! replication item (`CommittedEventSubmission`, whose `welcomes` exists only
//! for an `ak.mls.commit` and is never empty) under both the SDK DTO and the
//! published `peer_submit_request` schema. The two Station models own only
//! their durable state: the governance Station's acceptance transaction
//! (joined members, its own claim ledger, the recipient queues and one
//! replication intent per remote target) and Station Y's replica transaction
//! (its claim ledger, Welcome bindings and recipient queues). Every rendered
//! outcome is compared with the fixture's `expected` object and every
//! refusal is checked to leave the Station exactly as it was.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use arkret_canonical::DigestSuite;
use arkret_models_collaboration::authority_commit::{
    CommittedEventSubmission, CommittedReplicationBranch, PeerAuthoritySubmitRequest,
    PeerCommittedReplicationRequest,
};
use arkret_models_collaboration::governance::membership_invite::MembershipPayload;
use arkret_signatures::PublicKeyMaterial;
use arkret_signatures::detached_object::{sign_detached_object, verify_detached_object_signature};
use arkret_wire::{
    AccountId, ActorId, Base64UrlString, DetachedSignatureAlgorithm, DetachedSignatureContext,
    DeviceId, DidCoreId, DidUrl, ErrorCode, Event, EventAdmissionSubmission, EventId, EventKind,
    Hash, KeypackageClaimId, MlsCommitSubmission, MlsWelcomeDelivery, MlsWelcomeDeliveryId,
    MlsWelcomeRecipientEndpoint, RealmCommit, RealmId, ScopeRef, UuidV7,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use serde_json::{Map, Value, json};

use super::authority_forward_producer_device_evidence::sign;
use super::schema_validation_fixture::{schema_rejects, schema_validator};
use super::{
    CaseExecutionResult, SuiteExecutionResult, fixture_runner_entrypoint, load_fixture_value,
    required_field, required_str, scripted_cases, value_array, verify_decision_point_evidence,
};

pub const VECTOR_ID_MLS_CROSS_STATION_WELCOME_REPLICATION: &str =
    "ak.vector.mls.cross_station_welcome_replication.v1";
pub const MLS_CROSS_STATION_WELCOME_REPLICATION_ENTRYPOINT: &str =
    "ak.suite.mls.cross_station_welcome_replication.v1";

const FIXTURE: &str = "mls-cross-station-welcome-replication-fixture.json";
const SUITE: &str = "mls_cross_station_welcome_replication";
const PEER_REQUEST: &str =
    "schemas/authority-commit-operations.schema.json#/$defs/peer_submit_request";
const ALICE_SEED: [u8; 32] = [0x91; 32];
const COMMITTED_AT: &str = "2026-09-26T02:00:00.000Z";

const EXECUTED_CASES: [(&str, &[&str]); 7] = [
    (
        "immutable_genesis_ref_on_later_add_replication",
        &[
            "later_epoch_signed_ref_installs_attestation",
            "wrong_genesis_ref_conflicts_with_held_group",
            "replay_changes_genesis_ref",
        ],
    ),
    (
        "governance_routes_remote_welcomes_into_their_intents",
        &[
            "add_local_and_remote_recipients",
            "add_remote_recipients_only",
        ],
    ),
    (
        "recipient_station_outside_the_target_set",
        &[
            "welcome_for_a_station_that_is_no_target",
            "same_commit_without_that_recipient",
        ],
    ),
    (
        "welcomes_ride_only_an_mls_commit_item",
        &[
            "mls_commit_item_with_its_welcomes",
            "member_state_item_with_welcomes",
            "mls_commit_item_with_empty_welcomes",
        ],
    ),
    (
        "destination_reverifies_each_claim_in_the_replica_transaction",
        &[
            "both_claims_live",
            "claim_absent_from_the_destination_ledger",
            "claim_expired",
            "claim_already_consumed",
            "claim_bound_to_another_welcome",
            "claim_names_another_endpoint",
            "no_welcome_passes",
        ],
    ),
    (
        "replay_after_scan_queues_the_missing_welcomes",
        &[
            "commit_held_through_scan",
            "item_replay_queues_the_welcomes",
            "second_replay_queues_nothing",
        ],
    ),
    (
        "replicated_welcomes_count_toward_but_are_not_refused_by_capacity",
        &[
            "local_first_admission_at_capacity",
            "replicated_welcome_at_capacity",
            "only_ack_removes_the_replicated_welcome",
        ],
    ),
];

const DECISION_POINTS: [&str; 6] = [
    "remote_welcome_intent",
    "target_set_closure",
    "welcomes_only_on_mls_commit",
    "destination_reverification",
    "scan_replay_fills_welcomes",
    "capacity_and_ack_only",
];

pub fn run_mls_cross_station_welcome_replication_suite() -> Result<SuiteExecutionResult> {
    let fixture = load_fixture_value(FIXTURE)?;
    verify_fixture_identity(&fixture)?;
    verify_decision_point_evidence(&fixture, &DECISION_POINTS)?;
    verify_schema_cases(&fixture)?;
    let world = World::load(required_field(&fixture, "world")?)?;
    let mut results = Vec::new();
    for (name, variants) in scripted_cases(&fixture, &EXECUTED_CASES)? {
        let mut member_y: Option<MemberStation> = None;
        for variant in variants {
            let variant_name = required_str(variant, "name")?;
            let actual = execute(&world, &mut member_y, variant)
                .with_context(|| format!("{name}/{variant_name}"))?;
            let expected = required_field(variant, "expected")?;
            ensure!(
                &actual == expected,
                "{name}/{variant_name} produced {actual}, fixture expects {expected}"
            );
        }
        results.push(CaseExecutionResult {
            case_id: name.to_owned(),
            assertions: variants.len(),
        });
    }
    Ok(SuiteExecutionResult {
        entrypoint: MLS_CROSS_STATION_WELCOME_REPLICATION_ENTRYPOINT,
        fixture: FIXTURE,
        cases: results,
    })
}

pub fn run_mls_cross_station_welcome_replication_vector() -> Result<()> {
    run_mls_cross_station_welcome_replication_suite().map(drop)
}

fn verify_fixture_identity(fixture: &Value) -> Result<()> {
    ensure!(
        required_str(fixture, "suite")? == SUITE,
        "fixture suite drifted"
    );
    ensure!(
        fixture_runner_entrypoint(fixture)? == MLS_CROSS_STATION_WELCOME_REPLICATION_ENTRYPOINT,
        "fixture entrypoint drifted"
    );
    ensure!(
        value_array(required_field(fixture, "covers_vectors")?, "covers_vectors")?
            .iter()
            .any(|id| id == VECTOR_ID_MLS_CROSS_STATION_WELCOME_REPLICATION),
        "fixture no longer covers {VECTOR_ID_MLS_CROSS_STATION_WELCOME_REPLICATION}"
    );
    Ok(())
}

/// The published schema and the SDK item agree on every schema case: a
/// `welcomes` member only on an `ak.mls.commit` item and never empty.
fn verify_schema_cases(fixture: &Value) -> Result<()> {
    let mut instances = BTreeMap::<String, Value>::new();
    for case in value_array(
        required_field(fixture, "schema_validation_cases")?,
        "schema_validation_cases",
    )? {
        let name = required_str(case, "name")?;
        let schema_ref = required_str(case, "schema_ref")?;
        let expect_valid = case["expect_valid"]
            .as_bool()
            .with_context(|| format!("{name}: expect_valid"))?;
        let instance = match case.get("instance") {
            Some(instance) => instance.clone(),
            None => {
                let mut instance = instances
                    .get(required_str(case, "instance_from")?)
                    .cloned()
                    .with_context(|| format!("{name}: instance_from"))?;
                for mutation in value_array(required_field(case, "mutations")?, "mutations")? {
                    let path = required_str(mutation, "path")?;
                    let (parent_path, member) = path
                        .rsplit_once('/')
                        .context("JSON Pointer mutation path")?;
                    let object = instance
                        .pointer_mut(parent_path)
                        .with_context(|| format!("{name}: mutation parent {parent_path}"))?
                        .as_object_mut()
                        .context("mutation parent is not an object")?;
                    match required_str(mutation, "op")? {
                        "add" => {
                            object.insert(member.to_owned(), mutation["value"].clone());
                        }
                        "replace" => {
                            ensure!(object.contains_key(member), "{name}: no member at {path}");
                            object.insert(member.to_owned(), mutation["value"].clone());
                        }
                        "remove" => {
                            ensure!(
                                object.remove(member).is_some(),
                                "{name}: no member at {path}"
                            );
                        }
                        other => bail!("{name}: unsupported mutation {other}"),
                    }
                }
                instance
            }
        };
        let schema_valid = !schema_rejects(schema_ref, &instance)?;
        let sdk_valid = serde_json::from_value::<CommittedEventSubmission>(instance.clone())
            .ok()
            .and_then(|item| item.validate().ok())
            .is_some();
        ensure!(
            schema_valid == expect_valid,
            "{name}: schema returned valid={schema_valid}, fixture expects {expect_valid}"
        );
        // The SDK additionally binds each Welcome to the exact source Event;
        // the fixture instances are schema instances, so only a refusal must
        // agree.
        ensure!(
            expect_valid || !sdk_valid,
            "{name}: the SDK item accepted what the schema refuses"
        );
        instances.insert(name.to_owned(), instance);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// World
// ---------------------------------------------------------------------------

struct Member {
    account: AccountId,
    station: String,
    joined: bool,
    device_id: DeviceId,
    claim_id: Option<String>,
    welcome_id: Option<String>,
}

struct World {
    realm_id: RealmId,
    scope: ScopeRef,
    stations: BTreeMap<String, DidCoreId>,
    members: BTreeMap<String, Member>,
    default_capacity: usize,
    alice_key: SigningKey,
    alice_method: DidUrl,
    peer_request: jsonschema::Validator,
}

impl World {
    fn load(world: &Value) -> Result<Self> {
        let realm_id = RealmId::new(required_str(world, "realm_id")?)?;
        let stations = required_field(world, "stations")?
            .as_object()
            .context("stations")?
            .iter()
            .map(|(name, id)| {
                Ok((
                    name.clone(),
                    DidCoreId::new(id.as_str().context("station id")?)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let mut members = BTreeMap::new();
        for row in value_array(required_field(world, "members")?, "members")? {
            let account: AccountId = serde_json::from_value(row["account_id"].clone())?;
            let station = required_str(row, "station")?.to_owned();
            ensure!(
                stations.get(&station) == Some(&account.station_id),
                "member account and station disagree"
            );
            members.insert(
                required_str(row, "name")?.to_owned(),
                Member {
                    account,
                    station,
                    joined: row["joined"].as_bool().context("joined")?,
                    device_id: DeviceId::new(required_str(row, "device_id")?)?,
                    claim_id: row["claim_id"].as_str().map(ToOwned::to_owned),
                    welcome_id: row["welcome_id"].as_str().map(ToOwned::to_owned),
                },
            );
        }
        let alice = members.get("alice").context("alice")?;
        let alice_method = DidUrl::new(format!(
            "did:web:alice.example#{}",
            alice
                .device_id
                .as_str()
                .rsplit(':')
                .next()
                .unwrap_or("device")
        ))
        .map_err(|error| anyhow!("{error}"))?;
        Ok(Self {
            scope: ScopeRef::Realm {
                realm_id: realm_id.clone(),
            },
            realm_id,
            stations,
            members,
            default_capacity: usize::try_from(
                world["queue_capacity_default"]
                    .as_u64()
                    .context("queue_capacity_default")?,
            )?,
            alice_key: SigningKey::from_bytes(&ALICE_SEED),
            alice_method,
            peer_request: schema_validator(PEER_REQUEST)?,
        })
    }

    fn member(&self, name: &str) -> Result<&Member> {
        self.members
            .get(name)
            .with_context(|| format!("unknown member {name}"))
    }

    fn station_name(&self, id: &DidCoreId) -> Result<&str> {
        self.stations
            .iter()
            .find(|(_, station)| *station == id)
            .map(|(name, _)| name.as_str())
            .with_context(|| format!("unknown Station {id}"))
    }

    fn created_at(&self) -> Result<DateTime<Utc>> {
        Ok(DateTime::parse_from_rfc3339(COMMITTED_AT)?.to_utc())
    }

    fn genesis_event_ref(&self) -> EventId {
        EventId::from_digest(DigestSuite::Sha256, [0x91; 32])
    }

    fn fixture_genesis_event_ref(&self, name: &str) -> Result<EventId> {
        match name {
            "accepted_genesis_event" => Ok(self.genesis_event_ref()),
            "other_group_genesis_event" => {
                Ok(EventId::from_digest(DigestSuite::Sha256, [0x93; 32]))
            }
            other => bail!("unknown Genesis Event fixture ref {other}"),
        }
    }

    /// alice's signed `ak.mls.commit` whose inline Adds are `adds`.
    fn commit_event(&self, adds: &[&str]) -> Result<Event> {
        self.commit_event_at_epoch(adds, 1)
    }

    fn commit_event_at_epoch(&self, adds: &[&str], previous_epoch: u64) -> Result<Event> {
        let base = EventId::from_digest(DigestSuite::Sha256, [0x92; 32]);
        let payload = json!({
            "base_group_state_ref": base,
            "previous_epoch": previous_epoch,
            "next_epoch": previous_epoch + 1,
            "covers_key_access_revision": previous_epoch,
            "commit_bytes_b64": arkret_canonical::base64url_encode(
                format!("commit adding {}", adds.join(",")).as_bytes()
            ),
            "governance_binding": {
                "effective_scope": self.scope,
                "base_group_state_ref": base,
                "previous_epoch": previous_epoch,
                "next_epoch": previous_epoch + 1,
                "key_access_revision": previous_epoch,
            },
        });
        self.signed_event(EventKind::MlsCommit, payload)
    }

    /// alice's signed `ak.member.state` join of `name`.
    fn member_state_event(&self, name: &str) -> Result<Event> {
        let payload = MembershipPayload::join(
            self.realm_id.clone(),
            ActorId::account(self.member(name)?.account.clone()),
            "welcome replication fixture",
        )
        .to_value()?;
        self.signed_event(EventKind::MemberState, payload)
    }

    fn signed_event(&self, kind: EventKind, payload: Value) -> Result<Event> {
        let created_at = self.created_at()?;
        let event = arkret_wire::test_support::raw_event_for_actor_at(
            kind.as_str(),
            self.scope.clone(),
            ActorId::account(self.member("alice")?.account.clone()),
            payload,
            created_at,
        )?;
        sign(event, self.alice_method.as_str(), ALICE_SEED, created_at)
    }

    /// alice's producer-signed Welcome for `name`, bound to `event`.
    fn welcome(&self, event: &Event, name: &str) -> Result<MlsWelcomeDelivery> {
        let member = self.member(name)?;
        let mut delivery = MlsWelcomeDelivery {
            welcome_id: MlsWelcomeDeliveryId::new(
                member.welcome_id.clone().context("recipient Welcome id")?,
            )?,
            realm_id: event.realm_id.clone(),
            effective_scope: event.scope_ref.clone(),
            commit_event_ref: event.event_id.clone(),
            recipient_actor_id: ActorId::account(member.account.clone()),
            recipient_endpoint: MlsWelcomeRecipientEndpoint::Device {
                device_id: member.device_id.clone(),
            },
            keypackage_claim_ref: KeypackageClaimId::new(
                member.claim_id.clone().context("recipient claim id")?,
            )?,
            ciphertext_b64: Base64UrlString::new(arkret_canonical::base64url_encode(
                format!("welcome for {name}").as_bytes(),
            ))
            .map_err(anyhow::Error::msg)?,
            producer_proof: arkret_wire::DetachedObjectSignature {
                context: DetachedSignatureContext::MlsWelcomeDelivery,
                signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
                verification_method: self.alice_method.clone(),
                signed_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
                created_at: self.created_at()?,
                sig: Base64UrlString::new("AA").map_err(anyhow::Error::msg)?,
            },
        };
        delivery.producer_proof = sign_detached_object(
            &unsigned_welcome(&delivery)?,
            DetachedSignatureContext::MlsWelcomeDelivery,
            self.alice_method.clone(),
            self.created_at()?,
            &self.alice_key,
        )?;
        delivery.validate_shape()?;
        Ok(delivery)
    }

    /// Welcomes of `names` for `event`, sorted by `welcome_id` as the
    /// submission orders them.
    fn welcomes(&self, event: &Event, names: &[&str]) -> Result<Vec<MlsWelcomeDelivery>> {
        let mut welcomes = names
            .iter()
            .map(|name| self.welcome(event, name))
            .collect::<Result<Vec<_>>>()?;
        welcomes.sort_by(|left, right| left.welcome_id.cmp(&right.welcome_id));
        Ok(welcomes)
    }

    /// The governance Station's RealmCommit of `event`.
    fn source_commit(&self, event: &Event) -> Result<RealmCommit> {
        let commit_id = format!(
            "ak:realm_commit:{}",
            event.event_id.as_str().trim_start_matches("ak:event:")
        );
        Ok(serde_json::from_value(json!({
            "commit_id": commit_id,
            "realm_id": event.realm_id,
            "stream_ref": event.scope_ref,
            "stream_position": 7,
            "previous_commit_ref": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            "event_ref": event.event_id,
            "governance_generation": 0,
            "authority_ref": event.event_id,
            "committed_at": COMMITTED_AT,
            "signature": {
                "context": "ak.realm_commit_signature.v1",
                "signature_algorithm": "Ed25519",
                "verification_method": "did:web:governance-x.example#authority",
                "signed_digest": format!("sha256:{}", "4".repeat(64)),
                "created_at": COMMITTED_AT,
                "sig": "A".repeat(86),
            },
        }))?)
    }

    fn recipient_name(&self, welcome: &MlsWelcomeDelivery) -> Result<&str> {
        self.members
            .iter()
            .find(|(_, member)| {
                ActorId::account(member.account.clone()) == welcome.recipient_actor_id
            })
            .map(|(name, _)| name.as_str())
            .context("Welcome for an unknown recipient")
    }
}

fn unsigned_welcome(delivery: &MlsWelcomeDelivery) -> Result<Value> {
    let mut unsigned = serde_json::to_value(delivery)?;
    unsigned
        .as_object_mut()
        .context("a Welcome delivery is an object")?
        .remove("producer_proof");
    Ok(unsigned)
}

// ---------------------------------------------------------------------------
// Recipient queues and claim ledgers
// ---------------------------------------------------------------------------

/// One endpoint queue item: an earlier delivery or a queued Welcome.
#[derive(Clone, Debug, PartialEq, Eq)]
enum QueueItem {
    Earlier,
    Welcome(String),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Queues {
    capacity: usize,
    by_recipient: BTreeMap<String, Vec<QueueItem>>,
}

impl Queues {
    fn new(capacity: usize, preloaded: &[(&str, usize)]) -> Self {
        let mut queues = Self {
            capacity,
            by_recipient: BTreeMap::new(),
        };
        for (name, count) in preloaded {
            queues
                .by_recipient
                .insert((*name).to_owned(), vec![QueueItem::Earlier; *count]);
        }
        queues
    }

    fn outstanding(&self, name: &str) -> usize {
        self.by_recipient.get(name).map_or(0, Vec::len)
    }

    fn welcomes(&self) -> Vec<String> {
        let mut names = self
            .by_recipient
            .iter()
            .flat_map(|(name, items)| {
                items.iter().filter_map(move |item| match item {
                    QueueItem::Welcome(_) => Some(name.clone()),
                    QueueItem::Earlier => None,
                })
            })
            .collect::<Vec<_>>();
        names.dedup();
        names
    }

    fn holds(&self, name: &str, welcome_id: &str) -> bool {
        self.by_recipient
            .get(name)
            .is_some_and(|items| items.contains(&QueueItem::Welcome(welcome_id.to_owned())))
    }

    fn push(&mut self, name: &str, welcome_id: &str) {
        self.by_recipient
            .entry(name.to_owned())
            .or_default()
            .push(QueueItem::Welcome(welcome_id.to_owned()));
    }

    /// ACK through the Welcome of `name`: everything up to and including it
    /// leaves the queue.
    fn ack_through_welcome(&mut self, name: &str) -> Result<()> {
        let items = self.by_recipient.get_mut(name).context("no queue to ACK")?;
        let position = items
            .iter()
            .rposition(|item| matches!(item, QueueItem::Welcome(_)))
            .context("no Welcome to ACK through")?;
        items.drain(..=position);
        Ok(())
    }
}

/// One claim of a destination's ledger, as its Welcome re-verification
/// reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Claim {
    state: ClaimState,
    endpoint: DeviceId,
    /// The Welcome the claim is bound to, if its Welcome was queued.
    bound_welcome: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClaimState {
    Live,
    Expired,
    Consumed,
}

// ---------------------------------------------------------------------------
// Variants
// ---------------------------------------------------------------------------

fn names<'v>(variant: &'v Value, field: &str) -> Result<Vec<&'v str>> {
    value_array(required_field(variant, field)?, field)?
        .iter()
        .map(|name| name.as_str().context("name"))
        .collect()
}

fn capacity_setup(world: &World, variant: &Value, recipients: &[&str]) -> Result<Queues> {
    let capacity = variant["queue_capacity"]
        .as_u64()
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(world.default_capacity);
    let preloaded = variant["preloaded_deliveries"]
        .as_u64()
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(0);
    Ok(Queues::new(
        capacity,
        &recipients
            .iter()
            .map(|name| (*name, preloaded))
            .collect::<Vec<_>>(),
    ))
}

fn execute(world: &World, member_y: &mut Option<MemberStation>, variant: &Value) -> Result<Value> {
    match (
        required_str(variant, "station")?,
        required_str(variant, "operation_id")?,
    ) {
        ("governance", "ak.self.events.command.submit.v1") => governance_submit(world, variant),
        ("member_y", operation) => {
            if variant.get("claims").is_some() {
                *member_y = Some(MemberStation::new(world, variant)?);
            }
            let station = member_y
                .as_mut()
                .context("a Station Y variant continues a Station no earlier variant set up")?;
            match operation {
                "ak.peer.events.command.submit.v1" => station.replicate(world, variant),
                "ak.peer.committed_event.read.scan.v1" => station.scan(world),
                "ak.self.device_messages.command.ack.v1" => {
                    station
                        .queues
                        .ack_through_welcome(required_str(variant, "ack_through")?)?;
                    Ok(json!({
                        "decision": "accept",
                        "queue": station.queues.welcomes(),
                        "outstanding": station.outstanding(variant)?,
                    }))
                }
                other => bail!("no Station Y executor for {other}"),
            }
        }
        (station, operation) => bail!("no executor for {operation} on {station}"),
    }
}

/// The governance Station's acceptance transaction of one MLS Commit.
fn governance_submit(world: &World, variant: &Value) -> Result<Value> {
    let adds = names(variant, "adds")?;
    ensure!(variant["committer"] == "alice" && variant["submission"] == "mls_commit");
    let governance = &world.stations["governance"];
    let local = adds
        .iter()
        .copied()
        .filter(|name| world.members[*name].station == "governance")
        .collect::<Vec<_>>();
    let mut queues = capacity_setup(world, variant, &local)?;
    let before = queues.clone();

    let event = world.commit_event(&adds)?;
    let welcomes = world.welcomes(&event, &adds)?;
    let submission = MlsCommitSubmission {
        commit_event: event.clone(),
        welcomes: welcomes.clone(),
        idempotency_key: UuidV7::new("0199d000-0000-7000-8000-0000000009a1".parse()?)?,
    };
    submission.validate()?;

    let refused = |code: ErrorCode, queues: &Queues| -> Result<Value> {
        ensure!(
            queues == &before,
            "a refused Commit wrote a recipient queue"
        );
        Ok(json!({
            "decision": "reject",
            "error_code": code.as_str(),
            "reason_code": null,
            "realm_commits": 0,
            "local_queue": [],
            "claim_bindings": [],
            "replication_intents": {},
        }))
    };

    // Every non-claim binding of every Welcome: the Commit producer's proof
    // and a recipient that is a current joined member.
    let alice_key = PublicKeyMaterial::Ed25519Multibase {
        value: arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            &world.alice_key.verifying_key().to_bytes(),
        ),
    };
    for welcome in &welcomes {
        verify_detached_object_signature(
            &welcome.producer_proof,
            &unsigned_welcome(welcome)?,
            DetachedSignatureContext::MlsWelcomeDelivery,
            &alice_key,
        )?;
    }
    // The committed-replication target set: every routing service of a
    // current joined member but this Station.
    let targets = world
        .members
        .values()
        .filter(|member| member.joined)
        .map(|member| {
            ActorId::account(member.account.clone())
                .route_service_id()
                .clone()
        })
        .filter(|service| service != governance)
        .collect::<BTreeSet<_>>();
    let mut routed = BTreeMap::<DidCoreId, Vec<MlsWelcomeDelivery>>::new();
    let mut bindings = Vec::new();
    for welcome in &welcomes {
        let name = world.recipient_name(welcome)?;
        let service = welcome.recipient_actor_id.route_service_id().clone();
        if service == *governance {
            // A hosted recipient: its claim in this Station's own ledger and
            // the first-admission capacity bound.
            if !world.members[name].joined {
                return refused(ErrorCode::FailedPrecondition, &queues);
            }
            if queues.outstanding(name) >= queues.capacity {
                return refused(ErrorCode::QuotaExceeded, &queues);
            }
            queues.push(name, welcome.welcome_id.as_str());
            bindings.push(name.to_owned());
        } else if targets.contains(&service) {
            routed.entry(service).or_default().push(welcome.clone());
        } else {
            return refused(ErrorCode::FailedPrecondition, &before);
        }
    }

    let source_commit = world.source_commit(&event)?;
    let mut intents = Map::new();
    for target in &targets {
        let carried = routed.remove(target);
        let request =
            PeerAuthoritySubmitRequest::CommittedReplication(PeerCommittedReplicationRequest {
                branch: CommittedReplicationBranch::CommittedReplication,
                replications: vec![CommittedEventSubmission {
                    event_submission: EventAdmissionSubmission::new(event.clone()),
                    source_commit: source_commit.clone(),
                    genesis_event_ref: Some(world.genesis_event_ref()),
                    welcomes: carried.clone(),
                }],
            });
        request.validate()?;
        let body = serde_json::to_value(&request)?;
        ensure!(
            world.peer_request.is_valid(&body),
            "the replication intent to {target} is not a valid peer_submit_request"
        );
        intents.insert(
            world.station_name(target)?.to_owned(),
            match carried {
                None => Value::Null,
                Some(welcomes) => Value::Array(
                    welcomes
                        .iter()
                        .map(|welcome| Ok(json!(world.recipient_name(welcome)?)))
                        .collect::<Result<Vec<_>>>()?,
                ),
            },
        );
    }
    ensure!(routed.is_empty(), "a routed Welcome has no intent");
    Ok(json!({
        "decision": "accept",
        "status": "committed",
        "realm_commits": 1,
        "local_queue": queues.welcomes(),
        "claim_bindings": bindings,
        "replication_intents": intents,
    }))
}

/// Station Y: a member Station and the claim destination of its hosted
/// recipients.
#[derive(Clone)]
struct MemberStation {
    station_id: DidCoreId,
    /// Held replicas by Commit id, with their exact Event.
    replicas: BTreeMap<String, Event>,
    /// Genesis refs installed by signed Commit replication, keyed by Commit.
    genesis_refs: BTreeMap<String, EventId>,
    claims: BTreeMap<String, Claim>,
    queues: Queues,
    /// The Commit Event every item of this case replicates.
    commit: Option<Event>,
}

impl PartialEq for MemberStation {
    fn eq(&self, other: &Self) -> bool {
        self.replicas.keys().eq(other.replicas.keys())
            && self.genesis_refs == other.genesis_refs
            && self.claims == other.claims
            && self.queues == other.queues
    }
}

impl MemberStation {
    fn new(world: &World, variant: &Value) -> Result<Self> {
        let mut claims = BTreeMap::new();
        for (name, state) in required_field(variant, "claims")?
            .as_object()
            .context("claims")?
        {
            let member = world.member(name)?;
            let claim_id = member.claim_id.clone().context("claim id")?;
            let mut claim = Claim {
                state: ClaimState::Live,
                endpoint: member.device_id.clone(),
                bound_welcome: None,
            };
            match state.as_str().context("claim state")? {
                "live" => {}
                "absent" => continue,
                "expired" => claim.state = ClaimState::Expired,
                "consumed" => claim.state = ClaimState::Consumed,
                "bound_to_other_welcome" => {
                    claim.bound_welcome =
                        Some("ak:mls_welcome_delivery:0199d000-0000-7000-8000-0000000002ff".into());
                }
                "other_endpoint" => {
                    claim.endpoint =
                        DeviceId::new("ak:device:0199d000-0000-7000-8000-0000000000ff")?;
                }
                other => bail!("unknown claim state {other}"),
            }
            claims.insert(claim_id, claim);
        }
        Ok(Self {
            station_id: world.stations["member_y"].clone(),
            replicas: BTreeMap::new(),
            genesis_refs: BTreeMap::new(),
            claims,
            // Earlier deliveries wait only on the endpoints this variant
            // delivers to.
            queues: capacity_setup(
                world,
                variant,
                &match variant.get("welcomes") {
                    Some(_) => names(variant, "welcomes")?,
                    None => Vec::new(),
                },
            )?,
            commit: None,
        })
    }

    fn outstanding(&self, variant: &Value) -> Result<Value> {
        let mut outstanding = Map::new();
        for (name, _) in self.queues.by_recipient.iter().filter(|_| {
            variant.get("queue_capacity").is_some() || variant.get("ack_through").is_some()
        }) {
            outstanding.insert(name.clone(), json!(self.queues.outstanding(name)));
        }
        Ok(Value::Object(outstanding))
    }

    fn commit_event(&mut self, world: &World) -> Result<Event> {
        if self.commit.is_none() {
            self.commit = Some(world.commit_event(&["bob", "carol"])?);
        }
        self.commit.clone().context("commit")
    }

    fn render(
        &self,
        variant: &Value,
        item: Option<(&str, usize, Map<String, Value>)>,
    ) -> Result<Value> {
        let mut rendered = json!({
            "decision": "accept",
            "replicas": self.replicas.len(),
            "queue": self.queues.welcomes(),
            "claim_bindings": self.bindings(),
        });
        if let Some((outcome, queued_now, decisions)) = item {
            rendered["replication_outcome"] = json!(outcome);
            rendered["queued_now"] = json!(queued_now);
            rendered["welcome_decisions"] = Value::Object(decisions);
        }
        if variant.get("queue_capacity").is_some() {
            rendered["outstanding"] = self.outstanding(variant)?;
        }
        Ok(rendered)
    }

    fn bindings(&self) -> Vec<String> {
        self.queues
            .by_recipient
            .iter()
            .filter(|(_, items)| {
                items.iter().any(|item| match item {
                    QueueItem::Welcome(id) => self
                        .claims
                        .values()
                        .any(|claim| claim.bound_welcome.as_deref() == Some(id)),
                    QueueItem::Earlier => false,
                })
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// `ak.peer.committed_event.read.scan.v1` hands Station Y the exact
    /// Commit, which carries no Welcome.
    fn scan(&mut self, world: &World) -> Result<Value> {
        let event = self.commit_event(world)?;
        let commit = world.source_commit(&event)?;
        self.replicas.insert(commit.commit_id.to_string(), event);
        self.render(&json!({}), None)
    }

    fn replicate(&mut self, world: &World, variant: &Value) -> Result<Value> {
        let welcome_names = match variant.get("welcomes") {
            Some(_) => Some(names(variant, "welcomes")?),
            None => None,
        };
        let event = match required_str(variant, "item_event_kind")? {
            "ak.mls.commit" => match variant.get("commit_previous_epoch") {
                Some(epoch) => world.commit_event_at_epoch(
                    &["bob", "carol"],
                    epoch.as_u64().context("commit_previous_epoch")?,
                )?,
                None => self.commit_event(world)?,
            },
            "ak.member.state" => world.member_state_event("bob")?,
            other => bail!("unknown item_event_kind {other}"),
        };
        let item = CommittedEventSubmission {
            event_submission: EventAdmissionSubmission::new(event.clone()),
            source_commit: world.source_commit(&event)?,
            genesis_event_ref: if event.kind == EventKind::MlsCommit {
                Some(match variant.get("genesis_event_ref") {
                    Some(value) => world
                        .fixture_genesis_event_ref(value.as_str().context("genesis_event_ref")?)?,
                    None => world.genesis_event_ref(),
                })
            } else {
                None
            },
            welcomes: welcome_names
                .as_deref()
                .map(|names| world.welcomes(&event, names))
                .transpose()?,
        };
        let body = serde_json::to_value(PeerAuthoritySubmitRequest::CommittedReplication(
            PeerCommittedReplicationRequest {
                branch: CommittedReplicationBranch::CommittedReplication,
                replications: vec![item],
            },
        ))?;
        let before = self.clone();

        // The request: the published schema and the SDK DTO both decide.
        let schema_ok = world.peer_request.is_valid(&body);
        let parsed = serde_json::from_value::<PeerAuthoritySubmitRequest>(body)
            .map_err(anyhow::Error::from)
            .and_then(|request| request.validate().map(|()| request).map_err(Into::into));
        let request = match parsed {
            Ok(request) if schema_ok => request,
            Ok(_) => bail!("the SDK accepted a replication request the schema refuses"),
            Err(_) => {
                ensure!(!schema_ok, "the schema accepted what the SDK refuses");
                ensure!(*self == before, "a refused request changed Station Y");
                return Ok(json!({
                    "decision": "reject",
                    "error_code": ErrorCode::SchemaViolation.as_str(),
                    "replicas": self.replicas.len(),
                    "queue": self.queues.welcomes(),
                    "claim_bindings": self.bindings(),
                }));
            }
        };
        let PeerAuthoritySubmitRequest::CommittedReplication(request) = request else {
            bail!("not a committed_replication request");
        };
        let item = request
            .replications
            .into_iter()
            .next()
            .context("one replication item")?;
        let commit_id = item.source_commit.commit_id.to_string();
        if let Some(genesis_event_ref) = item.genesis_event_ref.as_ref() {
            let held_group_ref = variant
                .get("held_group_genesis_event_ref")
                .map(|value| {
                    world.fixture_genesis_event_ref(
                        value.as_str().context("held_group_genesis_event_ref")?,
                    )
                })
                .transpose()?;
            let previously_stored_ref = variant
                .get("previously_stored_genesis_event_ref")
                .map(|value| {
                    world.fixture_genesis_event_ref(
                        value
                            .as_str()
                            .context("previously_stored_genesis_event_ref")?,
                    )
                })
                .transpose()?;
            let conflicts = [held_group_ref.as_ref(), previously_stored_ref.as_ref()]
                .into_iter()
                .flatten()
                .chain(self.genesis_refs.get(&commit_id))
                .any(|held| held != genesis_event_ref);
            if conflicts {
                ensure!(*self == before, "a Genesis-ref conflict changed Station Y");
                return Ok(json!({
                    "decision": "reject",
                    "replicas": self.replicas.len(),
                    "queue": self.queues.welcomes(),
                    "claim_bindings": self.bindings(),
                    "attestations": self.genesis_refs.len(),
                }));
            }
        }
        let event = item.event_submission.event;

        // One replica transaction: the Commit (or the held one) and every
        // Welcome that passes this Station's own claim re-verification.
        let outcome = match self.replicas.get(&commit_id) {
            Some(held) => {
                ensure!(held == &event, "the Commit id is held with other content");
                "duplicate"
            }
            None => {
                self.replicas.insert(commit_id, event);
                "stored"
            }
        };
        if let Some(genesis_ref) = item.genesis_event_ref {
            self.genesis_refs
                .insert(item.source_commit.commit_id.to_string(), genesis_ref);
        }
        let mut queued_now = 0;
        let mut decisions = Map::new();
        for welcome in item.welcomes.iter().flatten() {
            let name = world.recipient_name(welcome)?.to_owned();
            let passes = self.reverify(world, &name, welcome);
            if passes {
                let claim = self
                    .claims
                    .get_mut(welcome.keypackage_claim_ref.as_str())
                    .context("verified claim")?;
                if claim.bound_welcome.is_none() {
                    claim.bound_welcome = Some(welcome.welcome_id.as_str().to_owned());
                    self.queues.push(&name, welcome.welcome_id.as_str());
                    queued_now += 1;
                }
            }
            decisions.insert(
                name,
                json!({"decision": if passes { "accept" } else { "reject" }}),
            );
        }
        let mut rendered = self.render(variant, Some((outcome, queued_now, decisions)))?;
        if variant.get("genesis_event_ref").is_some() {
            ensure!(
                self.genesis_refs
                    .get(&item.source_commit.commit_id.to_string())
                    == Some(&world.genesis_event_ref()),
                "the attestation must retain the accepted Genesis Event ref"
            );
            rendered["attestation_genesis_event_ref"] = json!("accepted_genesis_event");
            // The new fixture focuses on the signed provenance and durable
            // binding; its expected result does not enumerate queue counts.
            rendered
                .as_object_mut()
                .context("rendered result")?
                .remove("queued_now");
            rendered
                .as_object_mut()
                .context("rendered result")?
                .remove("welcome_decisions");
        }
        Ok(rendered)
    }

    /// device-lifecycle.md §9.2.3 as the claim destination: the recipient is
    /// hosted here and joined, its claim is in this ledger, live, names the
    /// Welcome's exact endpoint and is bound to no other Welcome. A Welcome
    /// already queued and bound to this claim passes without a second queue
    /// row.
    fn reverify(&self, world: &World, name: &str, welcome: &MlsWelcomeDelivery) -> bool {
        let member = &world.members[name];
        if welcome.recipient_actor_id.route_service_id() != &self.station_id || !member.joined {
            return false;
        }
        let Some(claim) = self.claims.get(welcome.keypackage_claim_ref.as_str()) else {
            return false;
        };
        let MlsWelcomeRecipientEndpoint::Device { device_id } = &welcome.recipient_endpoint else {
            return false;
        };
        match &claim.bound_welcome {
            Some(bound) => {
                bound == welcome.welcome_id.as_str()
                    && self.queues.holds(name, welcome.welcome_id.as_str())
            }
            None => claim.state == ClaimState::Live && &claim.endpoint == device_id,
        }
    }
}
