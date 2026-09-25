//! Executable semantics for `ak.vector.actor_private_events.submit.v1`
//! (`actor-private-effects.md` §2.1, decisions 0110 and 0114).
//!
//! The canonical fixture scripts one Station per case. Every variant authors a
//! real, signed Event with the SDK (content-bound `event_id`, detached producer
//! proof), wraps it in the SDK `ActorPrivateEventSubmitRequestBody` and submits
//! it to the Station model below. The model owns only what the SDK cannot
//! decide on its own -- the private registers, the exact-retry ledger and the
//! transaction order -- and delegates every protocol decision to shared code:
//! the request kind closure (`ActorPrivateEventSubmitRequestBody::validate`
//! and the published request schema), the closed typed payloads, the owner
//! source read from `actor_private_contracts.event_writes`, the push-route
//! `decide_server_revision_cas`, the wire-scope classification that makes the
//! shared self submit refuse actor-private kinds, and the closed
//! `ActorPrivateEventSubmitOutcome`. The observed outcome of each variant is
//! rendered and compared with the fixture's `expected` object, and every
//! refusal or replay is checked to leave the whole Station byte-for-byte
//! unchanged.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use arkret_canonical::DigestSuite;
use arkret_models_collaboration::events_payloads::agent::{
    AgentActionRejectPayload, AgentActionRequestPayload, AgentDraftProposePayload,
};
use arkret_models_identity::device_push_route::{
    DevicePushRoutePayload, ServerRevisionCasDecision, decide_server_revision_cas,
};
use arkret_wire::events::kinds::{EventWireScope, event_wire_scope};
use arkret_wire::generated::ServiceOperationId;
use arkret_wire::{
    AccountId, ActorId, ActorPrivateEventSubmitOutcome, ActorPrivateEventSubmitRequestBody,
    DidCoreId, ErrorCode, Event, EventKind, RealmId, ScopeRef,
};
use chrono::{DateTime, Duration, Utc};
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};

use super::authority_forward_producer_device_evidence::sign;
use super::schema_validation_fixture::schema_rejects;
use super::{
    CaseExecutionResult, SuiteExecutionResult, fixture_runner_entrypoint, load_artifact_json,
    load_fixture_value, required_field, required_str, value_array,
};

pub const VECTOR_ID_ACTOR_PRIVATE_EVENTS_SUBMIT: &str = "ak.vector.actor_private_events.submit.v1";
pub const ACTOR_PRIVATE_EVENTS_SUBMIT_ENTRYPOINT: &str = "ak.suite.actor_private_events.submit.v1";

const FIXTURE: &str = "actor-private-events-submit-fixture.json";
const SUITE: &str = "actor_private_events_submit";
const REQUEST_SCHEMA: &str =
    "schemas/service-operation-dtos.schema.json#/$defs/ActorPrivateEventSubmitRequestBody";
const OUTCOME_SCHEMA: &str =
    "schemas/service-operation-dtos.schema.json#/$defs/ActorPrivateEventSubmitOutcome";

/// The executed script: every case and variant the fixture must carry, in
/// order. A renamed, added or dropped variant fails instead of being skipped.
const EXECUTED_CASES: [(&str, &[&str]); 6] = [
    (
        "push_route_revision_cas_and_exact_retry",
        &[
            "push_route_create",
            "push_route_create_exact_retry",
            "push_route_create_same_event_id_different_bytes",
            "push_route_stale_revision",
            "push_route_skipped_revision",
            "push_route_revoke_at_current_revision",
            "push_route_create_exact_retry_after_successor",
        ],
    ),
    (
        "agent_action_request_and_rejection",
        &[
            "action_request_create",
            "action_request_exact_retry",
            "action_request_same_event_id_different_bytes",
            "action_request_key_occupied_by_other_bytes",
            "action_request_expired_at_admission",
            "action_reject_missing_target",
            "action_reject_requested_target",
            "action_reject_exact_retry",
            "action_reject_terminal_target",
            "action_reject_rejection_id_reused_by_other_bytes",
        ],
    ),
    (
        "agent_draft_proposal",
        &[
            "draft_propose_create",
            "draft_propose_exact_retry",
            "draft_propose_same_event_id_different_bytes",
            "draft_propose_key_occupied_by_other_bytes",
        ],
    ),
    (
        "owner_account_station_binding",
        &[
            "push_route_owner_on_other_station",
            "action_request_controller_on_other_station",
            "draft_propose_controller_on_other_station",
            "action_reject_signer_on_other_station",
            "push_route_owner_on_this_station",
        ],
    ),
    (
        "shared_submit_refuses_actor_private_kinds",
        &[
            "push_route_on_shared_submit",
            "action_request_on_shared_submit",
            "action_reject_on_shared_submit",
            "draft_propose_on_shared_submit",
            "push_route_after_shared_refusal",
        ],
    ),
    (
        "closed_request_and_payload_shapes",
        &[
            "account_data_set_on_actor_private_submit",
            "action_reject_without_request_id",
            "action_reject_naming_a_draft",
            "action_request_without_draft_link",
        ],
    ),
];

/// The decision points the vector obligates, each of which must be evidenced
/// by at least one accepting and one refusing variant.
const DECISION_POINTS: [&str; 7] = [
    "submit_surface",
    "exact_retry_first_outcome",
    "duplicate_conflict_zero_writes",
    "push_route_cas",
    "owner_station",
    "shared_submit_refusal",
    "rejection_target",
];

/// Execute every declared case and report one assertion-bearing result per
/// case, so the named-suite audit can match `cases[]` one for one.
pub fn run_actor_private_events_submit_suite() -> Result<SuiteExecutionResult> {
    let fixture = load_fixture_value(FIXTURE)?;
    verify_fixture_identity(&fixture)?;
    let payloads = verify_schema_cases(&fixture)?;
    verify_decision_points(&fixture)?;
    let world = World::load(&fixture, payloads)?;

    let cases = value_array(required_field(&fixture, "cases")?, "cases")?;
    ensure!(
        cases.len() == EXECUTED_CASES.len(),
        "actor-private submit fixture carries {} cases, the runner executes {}",
        cases.len(),
        EXECUTED_CASES.len()
    );
    let mut results = Vec::with_capacity(cases.len());
    for (case, (case_name, variant_names)) in cases.iter().zip(EXECUTED_CASES) {
        let name = required_str(case, "name")?;
        ensure!(
            name == case_name,
            "fixture case {name} is not the executed case {case_name}"
        );
        let variants = value_array(required_field(case, "variants")?, "variants")?;
        let declared = variants
            .iter()
            .map(|variant| required_str(variant, "name"))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            declared == variant_names,
            "{name}: variants drifted from the executed script: {declared:?}"
        );
        let assertions = run_case(&world, name, variants)?;
        results.push(CaseExecutionResult {
            case_id: name.to_owned(),
            assertions,
        });
    }
    Ok(SuiteExecutionResult {
        entrypoint: ACTOR_PRIVATE_EVENTS_SUBMIT_ENTRYPOINT,
        fixture: FIXTURE,
        cases: results,
    })
}

/// Execute every canonical variant; the vector-level entry point.
pub fn run_actor_private_events_submit_vector() -> Result<()> {
    run_actor_private_events_submit_suite().map(|_| ())
}

// ---------------------------------------------------------------------------
// Fixture identity, schema cases and decision points
// ---------------------------------------------------------------------------

fn verify_fixture_identity(fixture: &Value) -> Result<()> {
    ensure!(
        required_str(fixture, "suite")? == SUITE,
        "fixture suite drifted"
    );
    ensure!(
        fixture_runner_entrypoint(fixture)? == ACTOR_PRIVATE_EVENTS_SUBMIT_ENTRYPOINT,
        "fixture entrypoint drifted"
    );
    let covers = value_array(required_field(fixture, "covers_vectors")?, "covers_vectors")?;
    ensure!(
        covers
            .iter()
            .any(|value| value.as_str() == Some(VECTOR_ID_ACTOR_PRIVATE_EVENTS_SUBMIT)),
        "fixture no longer covers {VECTOR_ID_ACTOR_PRIVATE_EVENTS_SUBMIT}"
    );
    Ok(())
}

/// Run every `schema_validation_cases` entry against both the published JSON
/// Schema and the SDK's closed type for that schema, and return the positive
/// instances by name so variants can author their payloads from them.
fn verify_schema_cases(fixture: &Value) -> Result<BTreeMap<String, Value>> {
    let cases = value_array(
        required_field(fixture, "schema_validation_cases")?,
        "schema_validation_cases",
    )?;
    let mut instances = BTreeMap::<String, Value>::new();
    for case in cases {
        let name = required_str(case, "name")?;
        let schema_ref = required_str(case, "schema_ref")?;
        let expect_valid = case
            .get("expect_valid")
            .and_then(Value::as_bool)
            .with_context(|| format!("{name}: expect_valid"))?;
        let instance = match case.get("instance") {
            Some(instance) => instance.clone(),
            None => {
                let base = instances
                    .get(required_str(case, "instance_from")?)
                    .with_context(|| format!("{name}: instance_from names no earlier case"))?;
                apply_mutations(base, required_field(case, "mutations")?)?
            }
        };
        let schema_valid = !schema_rejects(schema_ref, &instance)?;
        ensure!(
            schema_valid == expect_valid,
            "{name}: {schema_ref} returned valid={schema_valid}, fixture expects {expect_valid}"
        );
        let sdk_valid = sdk_accepts(schema_ref, &instance)
            .with_context(|| format!("{name}: no SDK type bound to {schema_ref}"))?;
        ensure!(
            sdk_valid == expect_valid,
            "{name}: the SDK closed type returned valid={sdk_valid}, the schema says {expect_valid}"
        );
        ensure!(
            instances.insert(name.to_owned(), instance).is_none(),
            "duplicate schema case {name}"
        );
    }
    let missing_reject_request_id = instances
        .get("action_reject_without_request_id_rejected")
        .is_some_and(|instance| instance.get("request_id").is_none());
    ensure!(
        missing_reject_request_id,
        "the fixture must prove an action_reject without request_id is refused"
    );
    Ok(instances)
}

fn sdk_accepts(schema_ref: &str, instance: &Value) -> Option<bool> {
    let fragment = schema_ref.rsplit('/').next()?;
    Some(match fragment {
        "device_push_route_payload" => decodes::<DevicePushRoutePayload>(instance),
        "agent_action_request_payload" => decodes::<AgentActionRequestPayload>(instance),
        "agent_action_reject_payload" => decodes::<AgentActionRejectPayload>(instance),
        "agent_draft_propose_payload" => decodes::<AgentDraftProposePayload>(instance),
        "account_data_set_payload" => decodes::<
            arkret_models_collaboration::events_payloads::account_data::AccountDataSetPayload,
        >(instance),
        "ActorPrivateEventSubmitOutcome" => decodes::<ActorPrivateEventSubmitOutcome>(instance),
        _ => return None,
    })
}

fn decodes<T: DeserializeOwned>(instance: &Value) -> bool {
    serde_json::from_value::<T>(instance.clone()).is_ok()
}

/// Every decision point is evidenced by at least one accepting and one
/// refusing variant, and each pointer resolves to a variant whose expected
/// decision is on the claimed side.
fn verify_decision_points(fixture: &Value) -> Result<()> {
    let points = value_array(
        required_field(fixture, "decision_points")?,
        "decision_points",
    )?;
    let ids = points
        .iter()
        .map(|point| required_str(point, "id"))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        ids == DECISION_POINTS.into_iter().collect(),
        "decision points drifted: {ids:?}"
    );
    for point in points {
        let id = required_str(point, "id")?;
        ensure!(
            !required_str(point, "requirement")?.trim().is_empty(),
            "{id}: empty requirement"
        );
        for (side, allowed) in [
            ("accept", &["accept", "replay"][..]),
            ("reject", &["reject"]),
        ] {
            let pointers = value_array(required_field(point, side)?, side)?;
            ensure!(!pointers.is_empty(), "{id}: no {side} evidence");
            for pointer in pointers {
                let pointer = pointer
                    .as_str()
                    .with_context(|| format!("{id}: {side} pointer is not a string"))?;
                let variant = fixture
                    .pointer(pointer)
                    .with_context(|| format!("{id}: unresolved evidence pointer {pointer}"))?;
                let decision = required_str(required_field(variant, "expected")?, "decision")?;
                ensure!(
                    allowed.contains(&decision),
                    "{id}: {pointer} is {decision}, not {side} evidence"
                );
            }
        }
    }
    Ok(())
}

fn apply_mutations(base: &Value, mutations: &Value) -> Result<Value> {
    let mut instance = base.clone();
    for mutation in value_array(mutations, "mutations")? {
        let op = required_str(mutation, "op")?;
        let path = required_str(mutation, "path")?;
        let (parent, leaf) = path
            .rsplit_once('/')
            .with_context(|| format!("mutation path {path} is not a JSON pointer"))?;
        let target = if parent.is_empty() {
            &mut instance
        } else {
            instance
                .pointer_mut(parent)
                .with_context(|| format!("mutation parent {parent} does not resolve"))?
        };
        let object = target
            .as_object_mut()
            .with_context(|| format!("mutation parent {parent} is not an object"))?;
        match op {
            "add" => {
                object.insert(leaf.to_owned(), required_field(mutation, "value")?.clone());
            }
            "replace" => {
                ensure!(object.contains_key(leaf), "replace target {path} is absent");
                object.insert(leaf.to_owned(), required_field(mutation, "value")?.clone());
            }
            "remove" => {
                ensure!(
                    object.remove(leaf).is_some(),
                    "remove target {path} is absent"
                );
            }
            other => bail!("unsupported mutation op {other}"),
        }
    }
    Ok(instance)
}

// ---------------------------------------------------------------------------
// World: signers, owner sources and payload material
// ---------------------------------------------------------------------------

struct Signer {
    principal_id: DidCoreId,
    seed: [u8; 32],
    active_controller: Option<String>,
}

struct World {
    local_station: DidCoreId,
    foreign_station: DidCoreId,
    station_time: DateTime<Utc>,
    scope_realm: RealmId,
    signers: BTreeMap<String, Signer>,
    controller_devices: BTreeSet<String>,
    owner_sources: BTreeMap<String, String>,
    payloads: BTreeMap<String, Value>,
}

impl World {
    fn load(fixture: &Value, payloads: BTreeMap<String, Value>) -> Result<Self> {
        let world = required_field(fixture, "world")?;
        let station_time =
            DateTime::parse_from_rfc3339(required_str(world, "station_protocol_time")?)?.to_utc();
        let mut signers = BTreeMap::new();
        let declared = required_field(world, "signers")?
            .as_object()
            .context("world.signers must be an object")?;
        for (index, (name, row)) in declared.iter().enumerate() {
            let seed_byte = u8::try_from(0x41 + index).context("too many fixture signers")?;
            signers.insert(
                name.clone(),
                Signer {
                    principal_id: DidCoreId::new(required_str(row, "principal_id")?)?,
                    seed: [seed_byte; 32],
                    active_controller: row
                        .get("active_controller")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                },
            );
        }
        ensure!(
            ["device_owner", "controller", "agent"]
                .iter()
                .all(|name| signers.contains_key(*name)),
            "world.signers must name device_owner, controller and agent"
        );
        let controller_devices = value_array(
            required_field(world, "controller_accepted_devices")?,
            "controller_accepted_devices",
        )?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .context("controller device id")
        })
        .collect::<Result<BTreeSet<_>>>()?;

        let registry = load_artifact_json("registry/event-kind-registry.json")?;
        let writes = registry
            .pointer("/actor_private_contracts/event_writes")
            .and_then(Value::as_object)
            .context("event-kind registry lost actor_private_contracts.event_writes")?;
        let mut owner_sources = BTreeMap::new();
        for kind in ActorPrivateEventSubmitRequestBody::SUBMIT_KINDS {
            let source = writes
                .get(kind.as_str())
                .and_then(|row| row.pointer("/storage_owner/account_id_source"))
                .and_then(Value::as_str)
                .with_context(|| {
                    format!("{} has no storage_owner.account_id_source", kind.as_str())
                })?;
            owner_sources.insert(kind.as_str().to_owned(), source.to_owned());
        }

        Ok(Self {
            local_station: DidCoreId::new(required_str(world, "local_station_id")?)?,
            foreign_station: DidCoreId::new(required_str(world, "foreign_station_id")?)?,
            station_time,
            scope_realm: RealmId::new(required_str(world, "event_scope_realm_id")?)?,
            signers,
            controller_devices,
            owner_sources,
            payloads,
        })
    }

    fn signer(&self, name: &str) -> Result<&Signer> {
        self.signers
            .get(name)
            .with_context(|| format!("unknown fixture signer {name}"))
    }

    /// Author and sign one Event exactly as a client would: the id is bound
    /// to the content and the producer proof is attached last.
    fn author(&self, variant: &Value) -> Result<Authored> {
        let kind = required_str(variant, "event_kind")?;
        let signer = self.signer(required_str(variant, "signer")?)?;
        let station = match variant.get("signer_station").and_then(Value::as_str) {
            Some(station) => {
                let station = DidCoreId::new(station)?;
                ensure!(
                    station == self.foreign_station || station == self.local_station,
                    "signer_station {station} is not a world Station"
                );
                station
            }
            None => self.local_station.clone(),
        };
        let account = AccountId::new(signer.principal_id.clone(), station);
        let base = self
            .payloads
            .get(required_str(variant, "payload_from")?)
            .context("payload_from names no schema case")?;
        let payload = match variant.get("payload_mutations") {
            Some(mutations) => apply_mutations(base, mutations)?,
            None => base.clone(),
        };
        let created_at = self.station_time - Duration::minutes(1);
        let unsigned = arkret_wire::test_support::raw_event_for_actor_at(
            kind,
            ScopeRef::Realm {
                realm_id: self.scope_realm.clone(),
            },
            ActorId::account(account.clone()),
            payload,
            created_at,
        )?;
        let method = verification_method(&signer.principal_id)?;
        let event = sign(unsigned.clone(), &method, signer.seed, created_at)?;
        Ok(Authored {
            caller: account,
            unsigned,
            method,
            seed: signer.seed,
            proof_time: created_at,
            event,
        })
    }
}

fn verification_method(principal: &DidCoreId) -> Result<String> {
    let did = principal
        .as_str()
        .strip_prefix("ak:did_core:")
        .map(|rest| format!("did:{rest}"))
        .with_context(|| format!("{principal} is not a did_core id"))?;
    Ok(format!(
        "{did}#ak:device:01964137-0000-7000-8000-00000000000a"
    ))
}

#[derive(Clone)]
struct Authored {
    caller: AccountId,
    unsigned: Event,
    method: String,
    seed: [u8; 32],
    proof_time: DateTime<Utc>,
    event: Event,
}

impl Authored {
    /// The same content re-signed later: `event_id` is unchanged because it
    /// binds only the content, while the canonical Event bytes differ.
    fn resigned(&self) -> Result<Self> {
        let proof_time = self.proof_time + Duration::seconds(1);
        let event = sign(self.unsigned.clone(), &self.method, self.seed, proof_time)?;
        ensure!(
            event.event_id == self.event.event_id,
            "re-signing changed the content-bound event_id"
        );
        ensure!(
            canonical_digest(&event)? != canonical_digest(&self.event)?,
            "re-signing kept identical canonical Event bytes"
        );
        Ok(Self {
            proof_time,
            event,
            ..self.clone()
        })
    }
}

fn canonical_digest(event: &Event) -> Result<[u8; 32]> {
    Ok(arkret_canonical::sha256_bytes(
        arkret_canonical::canonical_json_bytes(event)?,
    ))
}

// ---------------------------------------------------------------------------
// Station model
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
struct LedgerRow {
    canonical_digest: [u8; 32],
    outcome: ActorPrivateEventSubmitOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PushRouteRow {
    route_value: Value,
    revision: u64,
    accepted_event_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestState {
    Requested,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RequestRow {
    state: RequestState,
    expires_at: DateTime<Utc>,
    accepted_event_id: String,
    rejection_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingIntentRow {
    canonical_event_digest: [u8; 32],
    accepted_event_id: String,
    state: &'static str,
}

type RegisterKey = (String, String, String);

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Station {
    ledger: BTreeMap<String, LedgerRow>,
    push_routes: BTreeMap<RegisterKey, PushRouteRow>,
    requests: BTreeMap<RegisterKey, RequestRow>,
    rejections: BTreeMap<RegisterKey, String>,
    pending_intents: BTreeMap<RegisterKey, PendingIntentRow>,
    private_transactions: u64,
    realm_commits: u64,
}

#[derive(Debug)]
enum Observed {
    Accepted(ActorPrivateEventSubmitOutcome),
    Replayed(ActorPrivateEventSubmitOutcome),
}

enum Decoded {
    PushRoute(DevicePushRoutePayload),
    ActionRequest(AgentActionRequestPayload),
    ActionReject(AgentActionRejectPayload),
    DraftPropose(AgentDraftProposePayload),
}

fn account_key(account: &AccountId) -> String {
    format!("{}|{}", account.principal_id, account.station_id)
}

/// The closed SDK payload of one of the four admitted kinds.
fn decode_payload(event: &Event) -> Result<Decoded, ErrorCode> {
    Ok(match event.kind {
        EventKind::DevicePushRoute => Decoded::PushRoute(decode(event)?),
        EventKind::AgentActionRequest => Decoded::ActionRequest(decode(event)?),
        EventKind::AgentActionReject => Decoded::ActionReject(decode(event)?),
        EventKind::AgentDraftPropose => Decoded::DraftPropose(decode(event)?),
        _ => return Err(ErrorCode::SchemaViolation),
    })
}

fn decode<T: DeserializeOwned>(event: &Event) -> Result<T, ErrorCode> {
    serde_json::to_value(&event.payload)
        .and_then(serde_json::from_value)
        .map_err(|_| ErrorCode::SchemaViolation)
}

impl Station {
    fn submit(
        &mut self,
        world: &World,
        operation: &str,
        caller: &AccountId,
        event: &Event,
    ) -> Result<Result<Observed, ErrorCode>> {
        match operation {
            ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1 => {
                // The shared self submit and peer ingress accept only shared
                // durable Events (actor-private-effects.md §2.1).
                ensure!(
                    event_wire_scope(event.kind.as_str()) == EventWireScope::ActorPrivateEvent,
                    "the model only executes the shared submit refusal of actor-private kinds"
                );
                Ok(Err(ErrorCode::UnsupportedEventKind))
            }
            ServiceOperationId::SELF_ACTOR_PRIVATE_EVENTS_COMMAND_SUBMIT_V1 => {
                Ok(self.submit_actor_private(world, caller, event))
            }
            other => bail!("fixture names an operation outside this vector: {other}"),
        }
    }

    /// `ak.self.actor_private_events.command.submit.v1`: request closure,
    /// typed payload, owner Station, signer binding and branch admission are
    /// decided before the private transaction; exact retry, concurrency and
    /// the write happen inside it.
    fn submit_actor_private(
        &mut self,
        world: &World,
        caller: &AccountId,
        event: &Event,
    ) -> Result<Observed, ErrorCode> {
        // The published request schema closes both the kind set and, through
        // the envelope, each kind's payload; the SDK splits the same decision
        // between the request closure and the closed typed payload. Both
        // sides must reach the same verdict before either one is trusted.
        let body = ActorPrivateEventSubmitRequestBody::new(event.clone());
        let wire = serde_json::to_value(&body).map_err(|_| ErrorCode::SchemaViolation)?;
        let schema_admits =
            !schema_rejects(REQUEST_SCHEMA, &wire).map_err(|_| ErrorCode::InternalError)?;
        let decoded = body
            .validate()
            .ok()
            .and_then(|()| decode_payload(event).ok());
        if decoded.is_some() != schema_admits {
            return Err(ErrorCode::InternalError);
        }
        let decoded = decoded.ok_or(ErrorCode::SchemaViolation)?;
        let owner = select_owner(world, event)?;
        if owner.station_id != world.local_station {
            return Err(ErrorCode::ParamInvalid);
        }
        if event.actor_id.as_account_id() != Some(caller)
            || event
                .validate_proof_bindings_with_digest_suite(DigestSuite::Sha256)
                .is_err()
        {
            return Err(ErrorCode::CapabilityDenied);
        }
        admit_branch(world, event, &owner, &decoded)?;
        let digest = canonical_digest(event).map_err(|_| ErrorCode::SchemaViolation)?;
        self.transaction(world, event, &owner, &decoded, digest)
    }

    fn transaction(
        &mut self,
        world: &World,
        event: &Event,
        owner: &AccountId,
        decoded: &Decoded,
        digest: [u8; 32],
    ) -> Result<Observed, ErrorCode> {
        let event_id = event.event_id.as_str().to_owned();
        if let Some(row) = self.ledger.get(&event_id) {
            if row.canonical_digest != digest {
                return Err(ErrorCode::DuplicateConflict);
            }
            return Ok(Observed::Replayed(row.outcome.clone()));
        }
        let owner_key = account_key(owner);
        let now = world.station_time;
        let outcome = match decoded {
            Decoded::PushRoute(payload) => {
                let scope = payload.scope();
                let key = (
                    owner_key,
                    scope.device_id.as_str().to_owned(),
                    scope.push_route.clone(),
                );
                let current = self.push_routes.get(&key).map(|row| row.revision);
                let ServerRevisionCasDecision::Accepted { next_revision } =
                    decide_server_revision_cas(current, payload.expected_server_revision())
                else {
                    return Err(ErrorCode::CasConflict);
                };
                self.push_routes.insert(
                    key,
                    PushRouteRow {
                        route_value: serde_json::to_value(payload)
                            .map_err(|_| ErrorCode::InternalError)?,
                        revision: next_revision,
                        accepted_event_id: event_id.clone(),
                    },
                );
                ActorPrivateEventSubmitOutcome::DevicePushRoute {
                    accepted_event_id: event.event_id.clone(),
                    revision: next_revision,
                }
            }
            Decoded::ActionRequest(payload) => {
                let key = (
                    owner_key,
                    payload.agent_id.as_str().to_owned(),
                    payload.request_id.clone(),
                );
                if self.requests.contains_key(&key) {
                    return Err(ErrorCode::DuplicateConflict);
                }
                if now >= payload.expires_at {
                    return Err(ErrorCode::FailedPrecondition);
                }
                self.requests.insert(
                    key,
                    RequestRow {
                        state: RequestState::Requested,
                        expires_at: payload.expires_at,
                        accepted_event_id: event_id.clone(),
                        rejection_id: None,
                    },
                );
                ActorPrivateEventSubmitOutcome::AgentActionRequest {
                    accepted_event_id: event.event_id.clone(),
                }
            }
            Decoded::ActionReject(payload) => {
                let agent = payload.agent_id.as_str().to_owned();
                let rejection_key = (
                    owner_key.clone(),
                    agent.clone(),
                    payload.rejection_id.clone(),
                );
                if self.rejections.contains_key(&rejection_key) {
                    return Err(ErrorCode::DuplicateConflict);
                }
                let request_key = (owner_key, agent, payload.request_id.clone());
                let Some(target) = self.requests.get_mut(&request_key) else {
                    return Err(ErrorCode::FailedPrecondition);
                };
                if target.state != RequestState::Requested || now >= target.expires_at {
                    return Err(ErrorCode::FailedPrecondition);
                }
                target.state = RequestState::Rejected;
                target.rejection_id = Some(payload.rejection_id.clone());
                self.rejections
                    .insert(rejection_key, payload.request_id.clone());
                ActorPrivateEventSubmitOutcome::AgentActionReject {
                    accepted_event_id: event.event_id.clone(),
                }
            }
            Decoded::DraftPropose(payload) => {
                let key = (
                    owner_key,
                    payload.agent_id.as_str().to_owned(),
                    payload.draft_id.clone(),
                );
                if self.pending_intents.contains_key(&key) {
                    return Err(ErrorCode::DuplicateConflict);
                }
                if now >= payload.expires_at {
                    return Err(ErrorCode::FailedPrecondition);
                }
                self.pending_intents.insert(
                    key,
                    PendingIntentRow {
                        canonical_event_digest: digest,
                        accepted_event_id: event_id.clone(),
                        state: "available",
                    },
                );
                ActorPrivateEventSubmitOutcome::AgentDraftPropose {
                    accepted_event_id: event.event_id.clone(),
                }
            }
        };
        self.ledger.insert(
            event_id,
            LedgerRow {
                canonical_digest: digest,
                outcome: outcome.clone(),
            },
        );
        self.private_transactions += 1;
        Ok(Observed::Accepted(outcome))
    }
}

/// Resolve the kind's registered `storage_owner.account_id_source`.
fn select_owner(world: &World, event: &Event) -> Result<AccountId, ErrorCode> {
    let source = world
        .owner_sources
        .get(event.kind.as_str())
        .ok_or(ErrorCode::SchemaViolation)?;
    if source == "envelope.actor_id" {
        return event
            .actor_id
            .as_account_id()
            .cloned()
            .ok_or(ErrorCode::CapabilityDenied);
    }
    let field = source
        .strip_prefix("payload.")
        .ok_or(ErrorCode::InternalError)?;
    let value = event.payload.get(field).ok_or(ErrorCode::SchemaViolation)?;
    serde_json::from_value(value.clone()).map_err(|_| ErrorCode::SchemaViolation)
}

/// Branch admission that precedes the transaction: the push-route owner is the
/// signing account, an Agent request or proposal is signed by the Agent, the
/// named controller is the Agent's active controller, and every handoff
/// recipient is a distinct accepted controller device.
fn admit_branch(
    world: &World,
    event: &Event,
    owner: &AccountId,
    decoded: &Decoded,
) -> Result<(), ErrorCode> {
    let signer = event
        .actor_id
        .as_account_id()
        .ok_or(ErrorCode::CapabilityDenied)?;
    let controller_of = |agent: &DidCoreId| -> Result<(), ErrorCode> {
        let agent = world
            .signers
            .values()
            .find(|row| &row.principal_id == agent)
            .ok_or(ErrorCode::CapabilityDenied)?;
        let controller = agent
            .active_controller
            .as_deref()
            .and_then(|name| world.signers.get(name))
            .ok_or(ErrorCode::CapabilityDenied)?;
        if controller.principal_id != owner.principal_id {
            return Err(ErrorCode::CapabilityDenied);
        }
        Ok(())
    };
    match decoded {
        Decoded::PushRoute(_) => {
            if signer != owner {
                return Err(ErrorCode::CapabilityDenied);
            }
        }
        Decoded::ActionRequest(payload) => {
            if signer.principal_id != payload.agent_id {
                return Err(ErrorCode::CapabilityDenied);
            }
            controller_of(&payload.agent_id)?;
            if payload.expires_at <= payload.created_at {
                return Err(ErrorCode::ParamInvalid);
            }
        }
        Decoded::ActionReject(payload) => controller_of(&payload.agent_id)?,
        Decoded::DraftPropose(payload) => {
            if signer.principal_id != payload.agent_id {
                return Err(ErrorCode::CapabilityDenied);
            }
            controller_of(&payload.agent_id)?;
            if payload.expires_at <= payload.created_at {
                return Err(ErrorCode::ParamInvalid);
            }
            let mut seen = BTreeSet::new();
            for recipient in &payload.content_handoff.recipients {
                let device = recipient.recipient_device_id.as_str();
                if !seen.insert(device) || !world.controller_devices.contains(device) {
                    return Err(ErrorCode::ParamInvalid);
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Case execution
// ---------------------------------------------------------------------------

fn run_case(world: &World, case_name: &str, variants: &[Value]) -> Result<usize> {
    let mut station = Station::default();
    let mut authored = BTreeMap::<String, (String, Authored)>::new();
    let mut first_outcomes = FirstOutcomes::new();
    let mut assertions = 0;
    for variant in variants {
        let name = required_str(variant, "name")?;
        let (operation, event) = match variant.get("retry_of").and_then(Value::as_str) {
            Some(original) => {
                let (operation, first) = authored
                    .get(original)
                    .with_context(|| format!("{name}: retry_of names no earlier variant"))?;
                let event = match required_str(variant, "retry_bytes")? {
                    "identical" => first.clone(),
                    "same_event_id_new_producer_proof" => first.resigned()?,
                    other => bail!("{name}: unknown retry_bytes {other}"),
                };
                (operation.clone(), event)
            }
            None => (
                required_str(variant, "operation_id")?.to_owned(),
                world.author(variant)?,
            ),
        };
        let before = station.clone();
        let observed = station.submit(world, &operation, &event.caller, &event.event)?;
        let rendered = render(
            name,
            &operation,
            &event.event,
            &before,
            &station,
            &observed,
            &first_outcomes,
        )?;
        let expected = required_field(variant, "expected")?;
        ensure!(
            &rendered == expected,
            "{case_name}/{name}: expected {expected}, observed {rendered}"
        );
        if let Ok(Observed::Accepted(outcome)) = &observed {
            first_outcomes.insert(
                event.event.event_id.as_str().to_owned(),
                (name.to_owned(), outcome.clone()),
            );
        }
        authored.insert(name.to_owned(), (operation, event));
        assertions += 1;
    }
    Ok(assertions)
}

/// The first accepted outcome per `event_id`, with the accepting variant.
type FirstOutcomes = BTreeMap<String, (String, ActorPrivateEventSubmitOutcome)>;

/// Render one observation in the fixture's `expected` vocabulary after
/// checking the invariants the vocabulary does not spell out.
fn render(
    name: &str,
    operation: &str,
    event: &Event,
    before: &Station,
    after: &Station,
    observed: &Result<Observed, ErrorCode>,
    first_outcomes: &FirstOutcomes,
) -> Result<Value> {
    let private_writes = after.private_transactions - before.private_transactions;
    let realm_commits = after.realm_commits - before.realm_commits;
    let mut rendered = Map::new();
    match observed {
        Ok(Observed::Accepted(outcome)) => {
            let request = ActorPrivateEventSubmitRequestBody::new(event.clone());
            outcome
                .validate_for_request(&request)
                .map_err(|error| anyhow!("{name}: outcome does not bind its Event: {error}"))?;
            let mut wire = serde_json::to_value(outcome)?;
            ensure!(
                !schema_rejects(OUTCOME_SCHEMA, &wire)?,
                "{name}: the SDK outcome violates the closed outcome schema"
            );
            ensure!(
                operation == ServiceOperationId::SELF_ACTOR_PRIVATE_EVENTS_COMMAND_SUBMIT_V1,
                "{name}: an actor-private kind was accepted on {operation}"
            );
            ensure!(
                after.ledger.len() == before.ledger.len() + 1,
                "{name}: the acceptance did not record exactly one ledger row"
            );
            let object = wire.as_object_mut().context("outcome is not an object")?;
            object.remove("accepted_event_id");
            rendered.insert("decision".to_owned(), json!("accept"));
            rendered.insert("outcome".to_owned(), wire);
        }
        Ok(Observed::Replayed(outcome)) => {
            ensure!(
                after == before,
                "{name}: an exact retry changed the Station"
            );
            let (first, stored) = first_outcomes
                .get(outcome.accepted_event_id().as_str())
                .with_context(|| format!("{name}: replayed an outcome no variant accepted"))?;
            ensure!(
                stored == outcome,
                "{name}: the replay differs from the first stored outcome"
            );
            rendered.insert("decision".to_owned(), json!("replay"));
            rendered.insert("outcome_of".to_owned(), json!(first));
        }
        Err(code) => {
            ensure!(
                after == before,
                "{name}: a refused submission changed the Station"
            );
            rendered.insert("decision".to_owned(), json!("reject"));
            rendered.insert("rejected_as".to_owned(), json!(code.as_str()));
        }
    }
    rendered.insert("private_writes".to_owned(), json!(private_writes));
    rendered.insert("realm_commits".to_owned(), json!(realm_commits));
    Ok(Value::Object(rendered))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_draft_rejection_target_is_not_a_request_payload() {
        let without_request = json!({
            "rejection_id": "rejection-001",
            "draft_id": "draft-001",
            "agent_id": "ak:did_core:web:agent.example",
            "rejected_at": "2026-09-26T00:58:00.000Z"
        });
        assert!(!decodes::<AgentActionRejectPayload>(&without_request));
    }
}
