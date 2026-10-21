//! Executable semantics for
//! `ak.vector.federation.authority_forward_genesis_material.v1`
//! (`encryption-and-audit.md` §5.1.1 and §5.1.2, decisions 0119 and 0123).
//!
//! The creator is the human-device producer of the shared forwarding world:
//! its Account Station forwards the creator's `ak.mls.genesis` to the Realm's
//! governance Station. The epoch-0 group is a real RFC 9420 group the SDK
//! creates for that device, and every protocol decision is the SDK's: the
//! validating `PeerAuthorityForwardEventRequest` (material presence by Event
//! kind and the canonical, bounded member shape of `MlsGenesisMaterial`), the
//! published `peer_submit_request` schema, the forwarded producer resolution,
//! the ref's own digest suite (`verify_digest`), the RFC 9420 public state
//! (`MlsPublicGroupTracker`) and the group-state-material response binding.
//! The two Station models below own only their stores: the forwarding
//! Station's content-addressed Blobs and the governance Station's accepted
//! Genesis Commits and public Blobs. Every variant's rendered outcome is
//! compared with the fixture's `expected` object, and every refusal is
//! checked to leave both Stations exactly as they were.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use arkret::mls::MlsPublicGroupTracker;
use arkret::{
    ArkretMlsIdentity, ArkretMlsSigner, MlsEndpointIdentity, MlsGovernanceBindingPayload,
};
use arkret_models_collaboration::authority_commit::{
    AuthorityForwardBranch, MLS_GENESIS_MATERIAL_MAX_BLOB_BYTES, MlsGenesisMaterial,
    PeerAuthorityForwardEventRequest, PeerAuthoritySubmitRequest,
};
use arkret_models_collaboration::events_payloads::{
    MlsGenesisCreatorLeafAuthority, MlsGenesisPayload,
};
use arkret_models_collaboration::mls_group_state_material::{
    MlsGroupStateMaterialOutcome, MlsGroupStateMaterialRequestBody,
};
use arkret_wire::{
    ActorId, Base64UrlString, BlobRef, ErrorCode, Event, EventAdmissionSubmission, EventId,
    EventKind, MlsWelcomeRecipientEndpoint, ScopeRef,
};
use serde_json::{Value, json};

use super::authority_forward_producer_device_evidence::ForwardingWorld;
use super::schema_validation_fixture::schema_validator;
use super::{
    CaseExecutionResult, SuiteExecutionResult, fixture_runner_entrypoint, load_fixture_value,
    required_field, required_str, scripted_cases, value_array, verify_decision_point_evidence,
};

pub const VECTOR_ID_AUTHORITY_FORWARD_GENESIS_MATERIAL: &str =
    "ak.vector.federation.authority_forward_genesis_material.v1";
pub const AUTHORITY_FORWARD_GENESIS_MATERIAL_ENTRYPOINT: &str =
    "ak.suite.federation.authority_forward_genesis_material.v1";

const FIXTURE: &str = "federation-authority-forward-genesis-material-fixture.json";
const SUITE: &str = "federation_authority_forward_genesis_material";
const PEER_REQUEST: &str =
    "schemas/authority-commit-operations.schema.json#/$defs/peer_submit_request";
const MATERIAL_SCHEMA: &str =
    "schemas/authority-commit-operations.schema.json#/$defs/mls_genesis_material";
const CIPHER_SUITE: &str = "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519";
const MEMBER_MAX_ENCODED_CHARS: usize = 5_592_406;
const RESPONSE_BOUND: usize = 8_388_608;

/// The executed script: every case and variant the fixture must carry, in
/// order.
const EXECUTED_CASES: [(&str, &[&str]); 6] = [
    (
        "forwarded_genesis_is_admitted_stored_and_served",
        &[
            "forward_with_both_blobs_held",
            "group_state_material_serves_the_carried_bytes",
            "exact_replay_returns_the_original_commit",
        ],
    ),
    (
        "the_forwarding_station_must_hold_both_blobs",
        &[
            "neither_blob_held",
            "refused_genesis_resubmitted_unchanged",
            "ratchet_tree_not_held",
            "held_bytes_do_not_address_the_ref",
            "both_blobs_held",
        ],
    ),
    (
        "material_presence_follows_the_event_kind",
        &[
            "genesis_without_material",
            "non_genesis_with_material",
            "genesis_with_its_material",
        ],
    ),
    (
        "carried_bytes_address_the_genesis_refs",
        &[
            "members_swapped",
            "ratchet_tree_byte_flipped",
            "refs_under_the_blake3_suite",
        ],
    ),
    (
        "member_length_bounds_the_carrier",
        &[
            "both_members_at_the_bound",
            "group_info_one_byte_over",
            "ratchet_tree_one_byte_over",
            "padded_member",
        ],
    ),
    (
        "addressed_bytes_must_be_the_epoch_zero_public_state",
        &[
            "addressed_bytes_are_not_a_group_info",
            "addressed_epoch_zero_state",
        ],
    ),
];

const DECISION_POINTS: [&str; 6] = [
    "admit_store_and_serve",
    "material_presence",
    "content_addresses",
    "member_bound",
    "forwarding_station_holds_blobs",
    "exact_replay",
];

/// Execute every declared case and report one assertion-bearing result per
/// case.
pub fn run_authority_forward_genesis_material_suite() -> Result<SuiteExecutionResult> {
    let fixture = load_fixture_value(FIXTURE)?;
    verify_fixture_identity(&fixture)?;
    verify_decision_point_evidence(&fixture, &DECISION_POINTS)?;
    let world = World::load(&fixture)?;
    let mut results = Vec::new();
    for (name, variants) in scripted_cases(&fixture, &EXECUTED_CASES)? {
        let mut run = CaseRun::new(&world);
        for variant in variants {
            let variant_name = required_str(variant, "name")?;
            let actual = run
                .execute(variant)
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
        entrypoint: AUTHORITY_FORWARD_GENESIS_MATERIAL_ENTRYPOINT,
        fixture: FIXTURE,
        cases: results,
    })
}

/// The vector-level entry point.
pub fn run_authority_forward_genesis_material_vector() -> Result<()> {
    run_authority_forward_genesis_material_suite().map(drop)
}

fn verify_fixture_identity(fixture: &Value) -> Result<()> {
    ensure!(
        required_str(fixture, "suite")? == SUITE,
        "fixture suite drifted"
    );
    ensure!(
        fixture_runner_entrypoint(fixture)? == AUTHORITY_FORWARD_GENESIS_MATERIAL_ENTRYPOINT,
        "fixture entrypoint drifted"
    );
    ensure!(
        value_array(required_field(fixture, "covers_vectors")?, "covers_vectors")?
            .iter()
            .any(|id| id == VECTOR_ID_AUTHORITY_FORWARD_GENESIS_MATERIAL),
        "fixture no longer covers {VECTOR_ID_AUTHORITY_FORWARD_GENESIS_MATERIAL}"
    );
    let world = required_field(fixture, "world")?;
    ensure!(
        world["cipher_suite"] == CIPHER_SUITE
            && world["member_max_encoded_chars"] == MEMBER_MAX_ENCODED_CHARS
            && world["member_max_decoded_bytes"] == MLS_GENESIS_MATERIAL_MAX_BLOB_BYTES
            && world["group_state_material_response_bound"] == RESPONSE_BOUND,
        "the fixture world no longer states the carrier bounds the SDK enforces"
    );
    ensure!(
        2 * MLS_GENESIS_MATERIAL_MAX_BLOB_BYTES == RESPONSE_BOUND,
        "two full members no longer decode to exactly the response bound"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// World
// ---------------------------------------------------------------------------

/// The public epoch-0 state of one group and the refs naming it.
#[derive(Clone)]
struct GroupState {
    group_info: Vec<u8>,
    ratchet_tree: Vec<u8>,
}

impl GroupState {
    fn refs(&self, suite: RefSuite) -> Result<(BlobRef, BlobRef)> {
        Ok((
            suite.blob_ref(&self.group_info)?,
            suite.blob_ref(&self.ratchet_tree)?,
        ))
    }
}

#[derive(Clone, Copy)]
enum RefSuite {
    Sha256,
    Blake3,
}

impl RefSuite {
    fn blob_ref(self, bytes: &[u8]) -> Result<BlobRef> {
        let digest = match self {
            Self::Sha256 => arkret_canonical::sha256_digest(bytes),
            Self::Blake3 => arkret_canonical::blake3_digest(bytes),
        };
        Ok(BlobRef::new(format!("ak:blob:{digest}"))?)
    }
}

struct World {
    forwarding: ForwardingWorld,
    scope: ScopeRef,
    binding: MlsGovernanceBindingPayload,
    creator_state: GroupState,
    creator_leaf_authority: MlsGenesisCreatorLeafAuthority,
    peer_request: jsonschema::Validator,
}

impl World {
    fn load(fixture: &Value) -> Result<Self> {
        ensure!(fixture["world"].is_object(), "fixture world");
        let forwarding = ForwardingWorld::load()?;
        let scope = ScopeRef::Realm {
            realm_id: forwarding.realm_id().clone(),
        };
        let binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
        let identity = ArkretMlsIdentity::new_human_device(
            ActorId::account(forwarding.producer_account().clone()),
            forwarding.producer_device()?,
            ArkretMlsSigner::from_ed25519_signing_key(forwarding.producer_device_key()),
        )?;
        let mut group = identity.create_group_with_governance_binding(&scope, &binding)?;
        group.install_local_creator_binding(
            ActorId::account(forwarding.producer_account().clone()),
            Some(forwarding.producer_device_authorize_event_id()?),
        )?;
        let bindings = group.verified_leaf_bindings()?;
        let [creator] = bindings.as_slice() else {
            bail!("Genesis fixture must have exactly one verified creator leaf");
        };
        ensure!(
            creator.leaf_index == 0
                && creator.actor_id == ActorId::account(forwarding.producer_account().clone()),
            "Genesis fixture creator leaf differs from its producer",
        );
        let endpoint = match &creator.endpoint {
            MlsEndpointIdentity::HumanDevice { device_id, .. } => {
                ensure!(*device_id == forwarding.producer_device()?);
                MlsWelcomeRecipientEndpoint::Device {
                    device_id: device_id.clone(),
                }
            }
            _ => bail!("Genesis fixture creator leaf is not the producer device"),
        };
        let creator_leaf_authority = MlsGenesisCreatorLeafAuthority {
            leaf_signature_key_b64u: creator.signature_key.clone(),
            endpoint,
            authorization_event_ref: creator
                .device_authorize_event_id
                .clone()
                .context("verified creator leaf lacks accepted device authorization")?,
        };
        creator_leaf_authority.validate()?;
        let (group_info, ratchet_tree) = group.public_group_state_bytes()?;
        Ok(Self {
            forwarding,
            scope,
            binding,
            creator_state: GroupState {
                group_info,
                ratchet_tree,
            },
            creator_leaf_authority,
            peer_request: schema_validator(PEER_REQUEST)?,
        })
    }

    /// The creator's signed Genesis naming `refs`.
    fn genesis(&self, refs: &(BlobRef, BlobRef)) -> Result<Event> {
        let payload = json!({
            "cipher_suite": CIPHER_SUITE,
            "group_info_ref": refs.0,
            "ratchet_tree_ref": refs.1,
            "governance_binding": self.binding,
            "creator_leaf_authority": self.creator_leaf_authority,
            "created_at": "2026-09-25T09:59:00.000Z",
        });
        let typed: MlsGenesisPayload = serde_json::from_value(payload.clone())?;
        typed.validate()?;
        self.forwarding
            .producer_event(EventKind::MlsGenesis.as_str(), payload)
    }
}

// ---------------------------------------------------------------------------
// Stations
// ---------------------------------------------------------------------------

/// One committed Genesis, as its exact replay returns it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CommittedGenesis {
    event_id: EventId,
    commit_position: usize,
}

/// A refusal with the Station that decided it.
struct Refusal {
    code: ErrorCode,
    by: &'static str,
    forwarded: bool,
}

enum Admission {
    Committed(CommittedGenesis),
    Duplicate(CommittedGenesis),
}

#[derive(Clone, Default, PartialEq)]
struct GovernanceStore {
    commits: Vec<(EventId, Event)>,
    public_blobs: BTreeMap<String, Vec<u8>>,
}

struct CaseRun<'a> {
    world: &'a World,
    /// The forwarding Station's own content-addressed Blob store.
    forwarding_blobs: BTreeMap<String, Vec<u8>>,
    governance: GovernanceStore,
    outcomes: BTreeMap<String, CommittedGenesis>,
    /// The Genesis each earlier variant submitted, by variant name.
    submitted: BTreeMap<String, Event>,
    /// The bytes the last accepted forward carried.
    carried: Option<GroupState>,
}

impl<'a> CaseRun<'a> {
    fn new(world: &'a World) -> Self {
        Self {
            world,
            forwarding_blobs: BTreeMap::new(),
            governance: GovernanceStore::default(),
            outcomes: BTreeMap::new(),
            submitted: BTreeMap::new(),
            carried: None,
        }
    }

    fn execute(&mut self, variant: &Value) -> Result<Value> {
        let name = required_str(variant, "name")?.to_owned();
        if variant["operation"] == "material_shape" {
            return material_shape(variant);
        }
        match required_str(variant, "operation_id")? {
            "ak.peer.mls.read.group_state_material.v1" => self.serve(variant),
            "ak.self.events.command.submit.v1" => self.submit(&name, variant),
            other => bail!("no executor for operation {other}"),
        }
    }

    fn render(&self) -> (usize, usize) {
        (
            self.governance.commits.len(),
            self.governance.public_blobs.len(),
        )
    }

    fn submit(&mut self, name: &str, variant: &Value) -> Result<Value> {
        let state = match variant["group_state"].as_str() {
            None | Some("creator_epoch_zero") => self.world.creator_state.clone(),
            Some("opaque_bytes") => GroupState {
                group_info: b"these bytes are no RFC 9420 GroupInfo".to_vec(),
                ratchet_tree: self.world.creator_state.ratchet_tree.clone(),
            },
            Some(other) => bail!("unknown group_state {other}"),
        };
        let suite = match variant["blob_ref_suite"].as_str() {
            None | Some("sha256") => RefSuite::Sha256,
            Some("blake3") => RefSuite::Blake3,
            Some(other) => bail!("unknown blob_ref_suite {other}"),
        };
        let refs = state.refs(suite)?;
        let event = match variant["retry_of"].as_str() {
            Some(original) => self
                .submitted
                .get(original)
                .cloned()
                .with_context(|| format!("retry_of {original} names no earlier submission"))?,
            None => match variant["event_kind"].as_str() {
                Some("ak.mls.genesis") | None => self.world.genesis(&refs)?,
                Some(kind) => self.world.forwarding.fixture_event(kind)?,
            },
        };
        self.submitted.insert(name.to_owned(), event.clone());
        self.stock_forwarding_store(variant, &state, &refs)?;

        let before_forwarding = self.forwarding_blobs.clone();
        let before_governance = self.governance.clone();
        let body = match self.forward_body(variant, &event, &state)? {
            Ok(body) => body,
            Err(refusal) => {
                ensure!(
                    self.forwarding_blobs == before_forwarding
                        && self.governance == before_governance,
                    "a forwarding refusal changed a Station"
                );
                return Ok(self.render_refusal(&refusal));
            }
        };
        match self.admit(&body)? {
            Ok(Admission::Committed(committed)) => {
                self.outcomes.insert(name.to_owned(), committed);
                self.carried = Some(state);
                let (commits, blobs) = self.render();
                Ok(json!({
                    "decision": "accept",
                    "status": "committed",
                    "forwarded": true,
                    "realm_commits": commits,
                    "public_blobs": blobs,
                }))
            }
            Ok(Admission::Duplicate(original)) => {
                ensure!(
                    self.governance == before_governance,
                    "an exact replay wrote to the governance Station"
                );
                let original_of = required_str(variant, "retry_of")?;
                ensure!(
                    self.outcomes.get(original_of) == Some(&original),
                    "the replay did not return {original_of}'s Commit"
                );
                let (commits, blobs) = self.render();
                Ok(json!({
                    "decision": "replay",
                    "status": "duplicate",
                    "outcome_of": original_of,
                    "realm_commits": commits,
                    "public_blobs": blobs,
                }))
            }
            Err(refusal) => {
                ensure!(
                    self.governance == before_governance,
                    "a governance refusal wrote to the governance Station"
                );
                Ok(self.render_refusal(&refusal))
            }
        }
    }

    fn render_refusal(&self, refusal: &Refusal) -> Value {
        let (commits, blobs) = self.render();
        json!({
            "decision": "reject",
            "error_code": refusal.code.as_str(),
            "reason_code": null,
            "rejected_by": refusal.by,
            "forwarded": refusal.forwarded,
            "realm_commits": commits,
            "public_blobs": blobs,
        })
    }

    /// Put exactly the Blobs the variant says the creator's Account Station
    /// holds into its store; by default it holds both.
    fn stock_forwarding_store(
        &mut self,
        variant: &Value,
        state: &GroupState,
        refs: &(BlobRef, BlobRef),
    ) -> Result<()> {
        let held = match variant.get("forwarding_station_holds") {
            Some(held) => value_array(held, "forwarding_station_holds")?
                .iter()
                .map(|member| member.as_str().context("held member"))
                .collect::<Result<Vec<_>>>()?,
            None => vec!["group_info", "ratchet_tree"],
        };
        self.forwarding_blobs.clear();
        for member in held {
            let (blob_ref, bytes) = match member {
                "group_info" => (&refs.0, &state.group_info),
                "ratchet_tree" => (&refs.1, &state.ratchet_tree),
                other => bail!("unknown held member {other}"),
            };
            self.forwarding_blobs
                .insert(blob_ref.as_str().to_owned(), bytes.clone());
        }
        match variant["held_object_mutation"].as_str() {
            None => {}
            Some("ratchet_tree_last_byte_flipped") => {
                let bytes = self
                    .forwarding_blobs
                    .get_mut(refs.1.as_str())
                    .context("the mutated ratchet tree Blob is held")?;
                *bytes.last_mut().context("non-empty ratchet tree")? ^= 0x01;
            }
            Some(other) => bail!("unknown held_object_mutation {other}"),
        }
        Ok(())
    }

    /// The forwarding Station: read both Blobs of a Genesis from its own
    /// store under one member's bound and check each content address before
    /// anything leaves; then build the validated forward with fresh evidence.
    /// A variant that replaces what the forward carries stands for a
    /// forwarding Station that does not follow these rules, so its body is
    /// handed to the governance Station unchecked.
    fn forward_body(
        &self,
        variant: &Value,
        event: &Event,
        state: &GroupState,
    ) -> Result<std::result::Result<Value, Refusal>> {
        if let Some(mut request) = self.crafted_body(variant, event, state)? {
            // Sign the final carried material, including intentionally invalid variants.
            // The governance Station must still decide their original schema/Blob gates.
            let evidence = self.world.forwarding.fresh_evidence(event, &request)?;
            request.producer_device_evidence = Some(evidence);
            return Ok(Ok(serde_json::to_value(
                PeerAuthoritySubmitRequest::AuthorityForwardEvent(request),
            )?));
        }
        let refused = |code| Ok(Err(Refusal::forwarding(code)));
        let material = if event.kind == EventKind::MlsGenesis {
            let payload: MlsGenesisPayload =
                serde_json::from_value(serde_json::to_value(&event.payload)?)?;
            let mut bytes = Vec::with_capacity(2);
            for blob_ref in [&payload.group_info_ref, &payload.ratchet_tree_ref] {
                let Some(held) = self
                    .forwarding_blobs
                    .get(blob_ref.as_str())
                    .filter(|held| held.len() <= MLS_GENESIS_MATERIAL_MAX_BLOB_BYTES)
                else {
                    return refused(ErrorCode::FailedPrecondition);
                };
                let addressed = blob_ref
                    .as_str()
                    .strip_prefix("ak:blob:")
                    .is_some_and(|digest| arkret_canonical::verify_digest(held, digest).is_ok());
                if !addressed {
                    return refused(ErrorCode::FailedPrecondition);
                }
                bytes.push(held.clone());
            }
            Some(MlsGenesisMaterial::from_bytes(&bytes[0], &bytes[1]))
        } else {
            None
        };
        let unsigned_request = PeerAuthorityForwardEventRequest {
            branch: AuthorityForwardBranch::AuthorityForward,
            event_submission: EventAdmissionSubmission::new(event.clone()),
            mls_genesis_material: material,
            producer_device_evidence: None,
            producer_agent_evidence: None,
        };
        let evidence = self
            .world
            .forwarding
            .fresh_evidence(event, &unsigned_request)?;
        let request = match PeerAuthorityForwardEventRequest::new(
            unsigned_request.event_submission,
            unsigned_request.mls_genesis_material,
            Some(evidence),
        ) {
            Ok(request) => request,
            Err(error) => {
                return refused(error.error_code().unwrap_or(ErrorCode::SchemaViolation));
            }
        };
        Ok(Ok(serde_json::to_value(
            PeerAuthoritySubmitRequest::AuthorityForwardEvent(request),
        )?))
    }

    /// The exact body a non-conforming forwarding Station sends, or `None`
    /// when the variant carries what the honest Station would.
    fn crafted_body(
        &self,
        variant: &Value,
        event: &Event,
        state: &GroupState,
    ) -> Result<Option<PeerAuthorityForwardEventRequest>> {
        let honest = || {
            (
                arkret_canonical::base64url_encode(&state.group_info),
                arkret_canonical::base64url_encode(&state.ratchet_tree),
            )
        };
        let material = match (
            variant["carried"].as_str(),
            variant["carried_mutation"].as_str(),
            variant.get("carried_decoded_bytes"),
        ) {
            (None, None, None) => return Ok(None),
            (Some("none"), None, None) => None,
            (Some("genesis_material"), None, None) => Some(honest()),
            (None, Some("swap_members"), None) => {
                let (group_info, tree) = honest();
                Some((tree, group_info))
            }
            (None, Some("ratchet_tree_last_byte_flipped"), None) => {
                let mut tree = state.ratchet_tree.clone();
                *tree.last_mut().context("non-empty ratchet tree")? ^= 0x01;
                Some((
                    arkret_canonical::base64url_encode(&state.group_info),
                    arkret_canonical::base64url_encode(&tree),
                ))
            }
            (None, Some("pad_group_info"), None) => {
                let (group_info, tree) = honest();
                Some((format!("{group_info}=="), tree))
            }
            (None, None, Some(sizes)) => {
                let zeros = |member: &str| -> Result<String> {
                    let len = sizes[member]
                        .as_u64()
                        .with_context(|| format!("carried_decoded_bytes.{member}"))?;
                    Ok(arkret_canonical::base64url_encode(vec![
                        0;
                        usize::try_from(
                            len
                        )?
                    ]))
                };
                Some((zeros("group_info")?, zeros("ratchet_tree")?))
            }
            other => bail!("unsupported carried override {other:?}"),
        };
        let request = PeerAuthorityForwardEventRequest {
            branch: AuthorityForwardBranch::AuthorityForward,
            event_submission: EventAdmissionSubmission::new(event.clone()),
            mls_genesis_material: material.map(|(group_info, tree)| MlsGenesisMaterial {
                group_info_bytes_b64: group_info,
                ratchet_tree_bytes_b64: tree,
            }),
            producer_device_evidence: None,
            producer_agent_evidence: None,
        };
        Ok(Some(request))
    }

    /// The governance Station, in the order it decides: the request (schema
    /// and SDK validation, which decide material presence and member shape),
    /// the exact duplicate, the forwarded producer, then the Genesis itself
    /// -- content addresses, the RFC 9420 epoch-0 public state and the
    /// creator-only roster -- and finally one acceptance transaction that
    /// stores the Commit with both Blobs.
    fn admit(&mut self, body: &Value) -> Result<std::result::Result<Admission, Refusal>> {
        Ok(self.admit_checked(body))
    }

    fn admit_checked(&mut self, body: &Value) -> std::result::Result<Admission, Refusal> {
        let schema_ok = self.world.peer_request.is_valid(body);
        let Ok(PeerAuthoritySubmitRequest::AuthorityForwardEvent(request)) =
            serde_json::from_value::<PeerAuthoritySubmitRequest>(body.clone())
        else {
            return Err(Refusal::governance(ErrorCode::SchemaViolation));
        };
        if let Err(error) = request.validate() {
            return Err(Refusal::governance(
                error.error_code().unwrap_or(ErrorCode::SchemaViolation),
            ));
        }
        // The published schema is an independent guard: a request the SDK
        // accepts is schema-valid.
        if !schema_ok {
            return Err(Refusal::schema_disagreement());
        }
        let event = &request.event_submission.event;
        if let Some(position) = self
            .governance
            .commits
            .iter()
            .position(|(id, _)| id == &event.event_id)
        {
            return Ok(Admission::Duplicate(CommittedGenesis {
                event_id: event.event_id.clone(),
                commit_position: position,
            }));
        }
        self.world
            .forwarding
            .verify_forwarded_producer(&request)
            .map_err(Refusal::governance)?;
        let material = request
            .mls_genesis_material
            .as_ref()
            .ok_or(Refusal::governance(ErrorCode::SchemaViolation))?;
        let payload: MlsGenesisPayload = serde_json::to_value(&event.payload)
            .and_then(serde_json::from_value)
            .map_err(|_| Refusal::governance(ErrorCode::SchemaViolation))?;
        payload
            .validate()
            .map_err(|_| Refusal::governance(ErrorCode::SchemaViolation))?;
        let (group_info, tree) = material.decode().map_err(|error| {
            Refusal::governance(error.error_code().unwrap_or(ErrorCode::SchemaViolation))
        })?;
        for (blob_ref, bytes) in [
            (&payload.group_info_ref, &group_info),
            (&payload.ratchet_tree_ref, &tree),
        ] {
            let digest = blob_ref
                .as_str()
                .strip_prefix("ak:blob:")
                .ok_or(Refusal::governance(ErrorCode::SchemaViolation))?;
            arkret_canonical::verify_digest(bytes, digest)
                .map_err(|_| Refusal::governance(ErrorCode::DigestMismatch))?;
        }
        let group_id = payload
            .mls_group_id()
            .map_err(|_| Refusal::governance(ErrorCode::SchemaViolation))?;
        let tracker =
            MlsPublicGroupTracker::from_external(&group_info, &tree, group_id.as_str(), 0)
                .map_err(|_| Refusal::governance(ErrorCode::SchemaViolation))?;
        let leaves = tracker
            .leaves()
            .map_err(|_| Refusal::governance(ErrorCode::SchemaViolation))?;
        if leaves.len() != 1 || leaves[0].actor_id != event.actor_id {
            return Err(Refusal::governance(ErrorCode::FailedPrecondition));
        }
        if self
            .governance
            .commits
            .iter()
            .any(|(_, held)| held.kind == EventKind::MlsGenesis)
        {
            return Err(Refusal::governance(ErrorCode::FailedPrecondition));
        }
        self.governance
            .commits
            .push((event.event_id.clone(), event.clone()));
        self.governance
            .public_blobs
            .insert(payload.group_info_ref.as_str().to_owned(), group_info);
        self.governance
            .public_blobs
            .insert(payload.ratchet_tree_ref.as_str().to_owned(), tree);
        Ok(Admission::Committed(CommittedGenesis {
            event_id: event.event_id.clone(),
            commit_position: self.governance.commits.len() - 1,
        }))
    }

    /// `ak.peer.mls.read.group_state_material.v1` from the forwarding
    /// Station, a member Station whose replication covers the Genesis.
    fn serve(&self, variant: &Value) -> Result<Value> {
        ensure!(variant["requester"] == "forwarding_station");
        let (event_id, event) = self
            .governance
            .commits
            .last()
            .context("no accepted Genesis to serve")?;
        let payload: MlsGenesisPayload =
            serde_json::to_value(&event.payload).and_then(serde_json::from_value)?;
        let request = MlsGroupStateMaterialRequestBody {
            realm_id: event.realm_id.clone(),
            effective_scope: self.world.scope.clone(),
            mls_group_id: payload.mls_group_id()?,
            epoch: 0u64.try_into().map_err(|error| anyhow!("{error:?}"))?,
            group_state_event_id: event_id.clone(),
            caller_actor_id: None,
            target_commit_event_ref: None,
            target_epoch: None,
            group_info_ref: payload.group_info_ref.clone(),
            ratchet_tree_ref: payload.ratchet_tree_ref.clone(),
            max_response_bytes: None,
        };
        request.validate()?;
        let stored = |blob_ref: &BlobRef| -> Result<Base64UrlString> {
            let bytes = self
                .governance
                .public_blobs
                .get(blob_ref.as_str())
                .with_context(|| format!("the governance Station stores no {blob_ref}"))?;
            Base64UrlString::new(arkret_canonical::base64url_encode(bytes))
                .map_err(anyhow::Error::msg)
        };
        let outcome = MlsGroupStateMaterialOutcome {
            realm_id: request.realm_id.clone(),
            effective_scope: request.effective_scope.clone(),
            mls_group_id: request.mls_group_id.clone(),
            epoch: request.epoch,
            group_state_event_id: request.group_state_event_id.clone(),
            group_info_ref: request.group_info_ref.clone(),
            group_info_bytes_b64: stored(&request.group_info_ref)?,
            ratchet_tree_ref: request.ratchet_tree_ref.clone(),
            ratchet_tree_bytes_b64: stored(&request.ratchet_tree_ref)?,
        };
        let validated = outcome.validate_for_request(&request)?;
        let carried = self.carried.as_ref().context("nothing was carried")?;
        ensure!(
            validated.group_info_bytes == carried.group_info
                && validated.ratchet_tree_bytes == carried.ratchet_tree,
            "the served bytes are not the bytes the forward carried"
        );
        let (commits, blobs) = self.render();
        Ok(json!({
            "decision": "accept",
            "served": "carried_bytes",
            "realm_commits": commits,
            "public_blobs": blobs,
        }))
    }
}

impl Refusal {
    const fn forwarding(code: ErrorCode) -> Self {
        Self {
            code,
            by: "forwarding_station",
            forwarded: false,
        }
    }

    const fn governance(code: ErrorCode) -> Self {
        Self {
            code,
            by: "governance_station",
            forwarded: true,
        }
    }

    /// The schema and the SDK disagree; rendered so the variant fails.
    const fn schema_disagreement() -> Self {
        Self {
            code: ErrorCode::SchemaViolation,
            by: "schema_and_sdk_disagree",
            forwarded: true,
        }
    }
}

/// Two members at the bound are a valid carrier that decodes to exactly the
/// response bound.
fn material_shape(variant: &Value) -> Result<Value> {
    let sizes = required_field(variant, "decoded_bytes")?;
    let bytes = |member: &str| -> Result<Vec<u8>> {
        Ok(vec![
            0;
            usize::try_from(sizes[member].as_u64().with_context(
                || format!("decoded_bytes.{member}")
            )?)?
        ])
    };
    let material = MlsGenesisMaterial::from_bytes(&bytes("group_info")?, &bytes("ratchet_tree")?);
    material.validate()?;
    super::schema_validation_fixture::schema_valid(
        MATERIAL_SCHEMA,
        &serde_json::to_value(&material)?,
    )?;
    let (group_info, tree) = material.decode()?;
    Ok(json!({
        "decision": "accept",
        "encoded_chars": {
            "group_info": material.group_info_bytes_b64.len(),
            "ratchet_tree": material.ratchet_tree_bytes_b64.len(),
        },
        "decoded_total": group_info.len() + tree.len(),
    }))
}
