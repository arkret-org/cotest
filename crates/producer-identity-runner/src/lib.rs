//! Executable producer-allocated identity collision conformance.
//!
//! Every registry-selected ID kind is parsed by its production SDK newtype.
//! The runner then applies the canonical `(mint_authority, typed_id)` atomic
//! reservation rule across the fixture's first-write, replay, collision,
//! cross-authority, and unauthorized/bare-lookup cases.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use arkret_identifiers::{
    AppletId, BackupId, BackupSeriesId, BatchId, BlobId, BlockId, CapabilityId, ChunkId, ClaimId,
    ConsentId, DeviceId, DeviceMessageId, Did, FilterId, FrameId, InviteLocatorId,
    KeypackageClaimId, MessageStreamId, MlsWelcomeDeliveryId, NotificationId, OperationId,
    PolicyId, PresentationId, ReceiptId, RecoverySessionId, RequestId, RtcParticipantId,
    ScheduledSendId, SubscriptionId, TransactionId,
};
use arkret_schema::REGISTERED_ID_KINDS;
use serde::Deserialize;

pub const PRODUCER_IDENTITY_ENTRYPOINT: &str = "ak.suite.identity.producer_allocated_collision.v1";
pub const FIXTURE: &str = "producer-allocated-identity-fixture.json";
const VECTOR_ID: &str = "ak.vector.identity.producer_allocated_collision.v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRoot {
    version: String,
    runner: Runner,
    suite: String,
    vector_id: String,
    driver: Driver,
    parameters: Parameters,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Runner {
    kind: String,
    entrypoint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Driver {
    registry_ref: String,
    selector: Selector,
    selected_id_kinds: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Selector {
    id_form: String,
    identity_authority: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Parameters {
    uuid: String,
    typed_id_template: String,
    authority_a: String,
    authority_b: String,
    binding_a: String,
    binding_b: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    #[serde(default)]
    mint_authority: Option<String>,
    typed_id: String,
    canonical_binding: String,
    proof_signer: String,
    expected: String,
    #[serde(default)]
    overwrite: Option<bool>,
    #[serde(default)]
    merge: Option<bool>,
    #[serde(default)]
    last_writer_wins: Option<bool>,
    #[serde(default)]
    identity_key_template: Option<Vec<String>>,
    #[serde(default)]
    lookup_key: Option<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProducerIdentityExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
    pub id_kinds_executed: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReservationOutcome {
    Accepted,
    Idempotent,
    RejectAndQuarantine,
    DistinctIdentity,
    Rejected,
}

#[derive(Default)]
struct ReservationStore {
    bindings: BTreeMap<(String, String), String>,
    quarantined: BTreeSet<(String, String)>,
}

impl ReservationStore {
    fn reserve(
        &mut self,
        authority: &Did,
        typed_id: &str,
        binding: &str,
        proof_signer: &Did,
    ) -> ReservationOutcome {
        if authority != proof_signer {
            return ReservationOutcome::Rejected;
        }
        let key = (authority.as_str().to_owned(), typed_id.to_owned());
        match self.bindings.get(&key) {
            None => {
                let same_id_exists = self
                    .bindings
                    .keys()
                    .any(|(_, existing_id)| existing_id == typed_id);
                self.bindings.insert(key, binding.to_owned());
                if same_id_exists {
                    ReservationOutcome::DistinctIdentity
                } else {
                    ReservationOutcome::Accepted
                }
            }
            Some(existing) if existing == binding => ReservationOutcome::Idempotent,
            Some(_) => {
                self.quarantined.insert(key);
                ReservationOutcome::RejectAndQuarantine
            }
        }
    }

    fn lookup(&self, key: &[String]) -> ReservationOutcome {
        if key.len() != 2 {
            return ReservationOutcome::Rejected;
        }
        if self
            .bindings
            .contains_key(&(key[0].clone(), key[1].clone()))
        {
            ReservationOutcome::Idempotent
        } else {
            ReservationOutcome::Rejected
        }
    }
}

fn spec_artifacts_root() -> PathBuf {
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
    let path = spec_artifacts_root().join("fixtures").join(FIXTURE);
    serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("parse fixture {}", path.display()))
}

macro_rules! parse_id {
    ($ty:ty, $value:expr) => {
        <$ty>::new($value.to_owned())
            .map(|_| ())
            .map_err(Into::into)
    };
}

fn parse_typed_id(kind: &str, value: &str) -> Result<()> {
    match kind {
        "applet" => parse_id!(AppletId, value),
        "backup" => parse_id!(BackupId, value),
        "backup_series" => parse_id!(BackupSeriesId, value),
        "batch" => parse_id!(BatchId, value),
        "blob" => parse_id!(BlobId, value),
        "block" => parse_id!(BlockId, value),
        "capability" => parse_id!(CapabilityId, value),
        "chunk" => parse_id!(ChunkId, value),
        "claim" => parse_id!(ClaimId, value),
        "consent" => parse_id!(ConsentId, value),
        "device" => parse_id!(DeviceId, value),
        "device_message" => parse_id!(DeviceMessageId, value),
        "filter" => parse_id!(FilterId, value),
        "frame" => parse_id!(FrameId, value),
        "invite_locator" => parse_id!(InviteLocatorId, value),
        "keypackage_claim" => parse_id!(KeypackageClaimId, value),
        "message_stream" => parse_id!(MessageStreamId, value),
        "mls_welcome_delivery" => parse_id!(MlsWelcomeDeliveryId, value),
        "notification" => parse_id!(NotificationId, value),
        "operation" => parse_id!(OperationId, value),
        "policy" => parse_id!(PolicyId, value),
        "presentation" => parse_id!(PresentationId, value),
        "receipt" => parse_id!(ReceiptId, value),
        "recovery_session" => parse_id!(RecoverySessionId, value),
        "request" => parse_id!(RequestId, value),
        "rtc_participant" => parse_id!(RtcParticipantId, value),
        "scheduled_send" => parse_id!(ScheduledSendId, value),
        "subscription" => parse_id!(SubscriptionId, value),
        "transaction" => parse_id!(TransactionId, value),
        other => bail!("fixture selected unsupported producer ID kind {other}"),
    }
}

fn substitute(value: &str, kind: &str, parameters: &Parameters) -> String {
    match value {
        "$authority_a" => parameters.authority_a.clone(),
        "$authority_b" => parameters.authority_b.clone(),
        "$binding_a" => parameters.binding_a.clone(),
        "$binding_b" => parameters.binding_b.clone(),
        "$typed_id_template" => parameters.typed_id_template.replace("{kind}", kind),
        other => other.to_owned(),
    }
}

fn expected_outcome(value: &str) -> Result<ReservationOutcome> {
    match value {
        "accepted" => Ok(ReservationOutcome::Accepted),
        "idempotent" => Ok(ReservationOutcome::Idempotent),
        "reject_and_quarantine" => Ok(ReservationOutcome::RejectAndQuarantine),
        "distinct_identity" => Ok(ReservationOutcome::DistinctIdentity),
        "rejected" => Ok(ReservationOutcome::Rejected),
        other => bail!("unknown expected reservation outcome {other}"),
    }
}

fn run_case_for_kind(
    case: &Case,
    kind: &str,
    parameters: &Parameters,
    store: &mut ReservationStore,
) -> Result<usize> {
    let typed_id = substitute(&case.typed_id, kind, parameters);
    parse_typed_id(kind, &typed_id)
        .with_context(|| format!("{kind} did not accept its registered typed ID"))?;
    ensure!(typed_id.ends_with(&parameters.uuid));

    if let Some(lookup_key) = &case.lookup_key {
        let key = lookup_key
            .iter()
            .map(|value| substitute(value, kind, parameters))
            .collect::<Vec<_>>();
        ensure!(store.lookup(&key) == expected_outcome(&case.expected)?);
        let authority = Did::new(parameters.authority_a.clone())?;
        let proof_signer = Did::new(substitute(&case.proof_signer, kind, parameters))?;
        let before = store.bindings.clone();
        ensure!(
            store.reserve(
                &authority,
                &typed_id,
                &substitute(&case.canonical_binding, kind, parameters),
                &proof_signer,
            ) == ReservationOutcome::Rejected,
            "unauthorized allocator was accepted"
        );
        ensure!(store.bindings == before);
        return Ok(5);
    }

    let authority = Did::new(substitute(
        case.mint_authority
            .as_deref()
            .context("reservation case missing mint_authority")?,
        kind,
        parameters,
    ))?;
    let proof_signer = Did::new(substitute(&case.proof_signer, kind, parameters))?;
    let binding = substitute(&case.canonical_binding, kind, parameters);
    let before = store.bindings.clone();
    let outcome = store.reserve(&authority, &typed_id, &binding, &proof_signer);
    ensure!(outcome == expected_outcome(&case.expected)?);

    let mut assertions = 3;
    if outcome == ReservationOutcome::RejectAndQuarantine {
        ensure!(case.overwrite == Some(false));
        ensure!(case.merge == Some(false));
        ensure!(case.last_writer_wins == Some(false));
        ensure!(
            store.bindings == before,
            "collision mutated reserved binding"
        );
        ensure!(
            store
                .quarantined
                .contains(&(authority.as_str().to_owned(), typed_id.clone()))
        );
        assertions += 5;
    }
    if let Some(identity_key) = &case.identity_key_template {
        let expected_key = identity_key
            .iter()
            .map(|value| substitute(value, kind, parameters))
            .collect::<Vec<_>>();
        ensure!(
            expected_key == [authority.as_str(), typed_id.as_str()],
            "cross-authority identity key drifted"
        );
        assertions += 1;
    }
    Ok(assertions)
}

fn validate_driver(fixture: &FixtureRoot) -> Result<()> {
    ensure!(fixture.driver.registry_ref == "registry/id-kind-registry.json#/id_kinds");
    ensure!(fixture.driver.selector.id_form == "producer_allocated");
    ensure!(fixture.driver.selector.identity_authority == "producer_signature");
    let generated = REGISTERED_ID_KINDS
        .iter()
        .filter(|entry| entry.wire_form.ends_with(":<uuidv7>"))
        .map(|entry| entry.kind)
        .collect::<BTreeSet<_>>();
    let selected = fixture
        .driver
        .selected_id_kinds
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    ensure!(
        selected == generated,
        "fixture producer ID selection drifted from SDK registry"
    );
    Ok(())
}

pub fn run_producer_identity_suite() -> Result<ProducerIdentityExecution> {
    let fixture = load_fixture()?;
    ensure!(fixture.version == "2026-09-22.1");
    ensure!(fixture.runner.kind == "named_suite");
    ensure!(fixture.runner.entrypoint == PRODUCER_IDENTITY_ENTRYPOINT);
    ensure!(fixture.suite == "producer_allocated_identity");
    ensure!(fixture.vector_id == VECTOR_ID);
    validate_driver(&fixture)?;

    let mut stores = fixture
        .driver
        .selected_id_kinds
        .iter()
        .map(|kind| (kind.as_str(), ReservationStore::default()))
        .collect::<BTreeMap<_, _>>();
    let mut results = Vec::with_capacity(fixture.cases.len());
    for case in &fixture.cases {
        let mut assertions = 0;
        for kind in &fixture.driver.selected_id_kinds {
            assertions += run_case_for_kind(
                case,
                kind,
                &fixture.parameters,
                stores
                    .get_mut(kind.as_str())
                    .context("ID kind store missing")?,
            )?;
        }
        results.push(CaseExecutionResult {
            case_id: case.name.clone(),
            assertions,
        });
    }
    Ok(ProducerIdentityExecution {
        entrypoint: PRODUCER_IDENTITY_ENTRYPOINT,
        fixture: FIXTURE,
        cases: results,
        id_kinds_executed: fixture.driver.selected_id_kinds.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_all_cases_for_every_registry_selected_id_kind() {
        let execution = run_producer_identity_suite().unwrap();
        assert_eq!(execution.cases.len(), 5);
        assert_eq!(execution.id_kinds_executed, 29);
        assert!(execution.cases.iter().all(|case| case.assertions > 0));
    }

    #[test]
    fn typed_parser_rejects_non_v7_uuid() {
        assert!(
            parse_typed_id("device", "ak:device:0196419b-0000-4000-8000-000000000001").is_err()
        );
    }

    #[test]
    fn same_uuid_under_another_authority_is_distinct() {
        let mut store = ReservationStore::default();
        let a = Did::new("did:webvh:z6mkfixtureproduceraexample:producer-a.example").unwrap();
        let b = Did::new("did:webvh:z6mkfixtureproducerbexample:producer-b.example").unwrap();
        let id = "ak:device:019b5c20-0000-7000-8000-000000000001";
        assert_eq!(
            store.reserve(&a, id, "binding-a", &a),
            ReservationOutcome::Accepted
        );
        assert_eq!(
            store.reserve(&b, id, "binding-b", &b),
            ReservationOutcome::DistinctIdentity
        );
    }
}
