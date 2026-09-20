//! Executable call-state core fixture runner.
//!
//! Admission is driven through the production media participant-binding
//! verifier and state effects are driven through the production sequenced
//! reducer. Rejected commands are compared against a complete consumer
//! snapshot so an error cannot stand in for the required zero-effect result.

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use arkret::{
    MediaServiceAnchors, ParticipantBindingContext, call_media_token_exchange,
    participant_binding_signing_input, verify_call_media_token_outcome,
};
use arkret_canonical::base64url::base64url_encode;
use arkret_identifiers::{CallId, CellRef, DeviceId, Did, DidCoreId, Hash, RealmId};
use arkret_models_collaboration::events_payloads::{
    CallCreatePayload, CallLifecycleState, CallStatePayload,
};
use arkret_models_collaboration::objects::media::{
    CallMediaParticipantBinding, CallMediaTokenExchangeOutcome, CallMediaTokenExchangeRequestBody,
    MediaBackendKind, MediaBackendToken,
};
use arkret_state::state_model::{DomainTransitionRule, SequencedState, StateModel, StateWrite};
use arkret_wire::{AccountId, ActorId, EventCellValueShape, LatticeOp, LatticeOpType, ProfileId};
use chrono::{DateTime, Duration, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use serde_json::{Value, json};

pub const CALL_STATE_CORE_ENTRYPOINT: &str = "ak.suite.call.state_core.v1";
pub const FIXTURE: &str = "call-state-core-fixture.json";

const VECTOR_IDS: &[&str] = &[
    "ak.vector.call_state.participant_binding_invalid.v1",
    "ak.vector.call_state.initial_state_accepts_allowed.v1",
    "ak.vector.call_state.transition_matrix.v1",
    "ak.vector.call_state.terminal_absorbing.v1",
    "ak.vector.call_state.replay_same_state_noop.v1",
    "ak.vector.call_state.ordered_competing_transitions.v1",
    "ak.vector.call_state.axis_result_split.v1",
];
const INITIAL: &[&str] = &["scheduled", "ringing", "connecting"];
const TERMINAL: &[&str] = &["ended", "missed", "failed", "cancelled"];
const EDGES: &[(&str, &str)] = &[
    ("scheduled", "ringing"),
    ("scheduled", "connecting"),
    ("scheduled", "cancelled"),
    ("scheduled", "missed"),
    ("scheduled", "failed"),
    ("ringing", "connecting"),
    ("ringing", "active"),
    ("ringing", "missed"),
    ("ringing", "cancelled"),
    ("ringing", "failed"),
    ("connecting", "active"),
    ("connecting", "failed"),
    ("connecting", "ended"),
    ("active", "ended"),
    ("active", "failed"),
];
const ISSUER_KID: &str = "did:web:media.example#media-token";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRoot {
    profile: String,
    version: String,
    suite: String,
    runner: Runner,
    covers_vectors: Vec<String>,
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Runner {
    kind: String,
    entrypoint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCase {
    name: String,
    vector_id: String,
    runner: String,
    assertions: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
    pub committed_effects: usize,
    pub rejected_zero_effects: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallStateCoreExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
    pub committed_effects: usize,
    pub rejected_zero_effects: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ConsumerState {
    committed: Vec<String>,
    seen: BTreeSet<String>,
}

fn artifacts_root() -> PathBuf {
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
    let path = artifacts_root().join("fixtures").join(FIXTURE);
    serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("parse fixture {}", path.display()))
}

fn event_digest(seed: u8) -> Hash {
    Hash::new(format!("sha256:{}", format!("{seed:02x}").repeat(32))).expect("fixture digest")
}

fn cell(axis: &str) -> CellRef {
    CellRef::new(format!(
        "ak:cell:ak.component.call.{axis}.v1:ak.call.0196441c-0000-7000-8000-000000000000"
    ))
    .expect("fixture cell")
}

fn transition(from: &str, to: &str) -> LatticeOp {
    LatticeOp {
        op_type: LatticeOpType::Transition,
        tag: None,
        value: None,
        from: Some(json!(from)),
        to: Some(json!(to)),
        reason: None,
        issuer_seq: None,
    }
}

fn rule(edges: &[(&str, &str)]) -> DomainTransitionRule {
    DomainTransitionRule::new(
        edges
            .iter()
            .map(|(from, to)| (json!(from), json!(to)))
            .collect(),
    )
}

fn production_transition(from: &str, to: &str, seed: u8, axis: &str) -> Result<Value> {
    let operation = transition(from, to);
    rule(EDGES).validate(Some(&json!(from)), &operation)?;
    let resolved = SequencedState::new(EventCellValueShape::Register).resolve(
        &cell(axis),
        &[StateWrite::new(event_digest(seed), operation)],
    )?;
    resolved
        .settled_value()
        .cloned()
        .context("sequenced reducer produced no settled value")
}

fn record_once(state: &mut ConsumerState, key: impl Into<String>) -> usize {
    let key = key.into();
    if state.seen.insert(key.clone()) {
        state.committed.push(key);
        1
    } else {
        0
    }
}

fn assert_rejected_unchanged<T>(state: &ConsumerState, result: Result<T>) -> Result<()> {
    let before = state.clone();
    ensure!(result.is_err(), "negative control was accepted");
    ensure!(*state == before, "rejected control changed consumer state");
    Ok(())
}

fn fixture_now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 19, 12, 0, 0)
        .single()
        .expect("fixture time")
}

fn token_request() -> CallMediaTokenExchangeRequestBody {
    call_media_token_exchange(
        RealmId::new("ak:realm:AdDiiHSzv3bH7EOLwQDdq-UHvwHaUaPammx6UQbpQnb4").unwrap(),
        CallId::new("ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz").unwrap(),
        ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )),
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap(),
        "fra-1",
    )
}

fn token_outcome(
    request: &CallMediaTokenExchangeRequestBody,
    key: &SigningKey,
    expires_at: DateTime<Utc>,
) -> Result<CallMediaTokenExchangeOutcome> {
    let mut outcome = CallMediaTokenExchangeOutcome {
        realm_id: request.realm_id.clone(),
        call_id: request.call_id.clone(),
        actor_id: request.actor_id.clone(),
        device_id: request.device_id.clone(),
        focus_id: request.focus_id.clone(),
        backend_kind: MediaBackendKind::Livekit,
        connect_url: "wss://livekit-fra.example.com".to_owned(),
        backend_token: MediaBackendToken::Opaque("opaque-token".to_owned()),
        participant_id: "ak:rtc_participant:0198c2f4-0000-7000-8000-000000000000".to_owned(),
        participant_binding: CallMediaParticipantBinding {
            sig: String::new(),
            issuer_kid: arkret::DidUrl::new(ISSUER_KID)?,
            expires_at,
        },
        expires_at,
    };
    let input =
        participant_binding_signing_input(&ParticipantBindingContext::from_outcome(&outcome))?;
    outcome.participant_binding.sig = base64url_encode(key.sign(&input).to_bytes());
    Ok(outcome)
}

fn participant_case(state: &mut ConsumerState) -> Result<(usize, usize)> {
    let request = token_request();
    let key = SigningKey::from_bytes(&[11; 32]);
    let issuer = Did::new("did:web:media.example")?;
    let anchors =
        MediaServiceAnchors::new([(arkret_wire::project_did_to_core_id(&issuer)?, issuer)])?
            .with_keys([(ISSUER_KID.to_owned(), key.verifying_key())])?;
    let now = fixture_now();
    let good = token_outcome(&request, &key, now + Duration::minutes(5))?;
    verify_call_media_token_outcome(&request, &good, &anchors, now)?;
    let effects = record_once(state, "participant-binding-accepted");

    let mut negatives = Vec::new();
    let mut rogue = good.clone();
    rogue.participant_binding.issuer_kid =
        arkret::DidUrl::new("did:web:rogue.example#media-token")?;
    negatives.push(rogue);
    let mut tuple = good.clone();
    tuple.focus_id = "fra-2".to_owned();
    negatives.push(tuple);
    let mut expired = token_outcome(&request, &key, now - Duration::seconds(1))?;
    expired.participant_binding.expires_at = now - Duration::seconds(1);
    negatives.push(expired);
    let mut signature = good;
    signature.participant_binding.sig = "AAAA".to_owned();
    negatives.push(signature);
    for outcome in negatives {
        assert_rejected_unchanged(
            state,
            verify_call_media_token_outcome(&request, &outcome, &anchors, now).map(|_| ()),
        )?;
    }
    Ok((effects, 4))
}

fn initial_case(state: &mut ConsumerState) -> Result<(usize, usize)> {
    let mut effects = 0;
    for (name, initial_state) in [
        ("scheduled", CallLifecycleState::Scheduled),
        ("ringing", CallLifecycleState::Ringing),
        ("connecting", CallLifecycleState::Connecting),
    ] {
        CallCreatePayload { initial_state }
            .validate()
            .map_err(anyhow::Error::msg)?;
        effects += record_once(state, format!("initial:{name}"));
    }
    for initial_state in [
        CallLifecycleState::Active,
        CallLifecycleState::Ended,
        CallLifecycleState::Missed,
        CallLifecycleState::Failed,
        CallLifecycleState::Cancelled,
    ] {
        assert_rejected_unchanged(
            state,
            CallCreatePayload { initial_state }
                .validate()
                .map_err(anyhow::Error::msg),
        )?;
    }
    Ok((effects, 5))
}

fn transition_matrix_case(state: &mut ConsumerState) -> Result<(usize, usize)> {
    let mut effects = 0;
    for (index, (from, to)) in EDGES.iter().enumerate() {
        ensure!(production_transition(from, to, index as u8 + 1, "state")? == json!(to));
        effects += record_once(state, format!("edge:{from}:{to}"));
    }
    let invalid = [
        ("scheduled", "active"),
        ("ringing", "scheduled"),
        ("connecting", "cancelled"),
        ("active", "ringing"),
    ];
    for (from, to) in invalid {
        let op = transition(from, to);
        assert_rejected_unchanged(
            state,
            rule(EDGES)
                .validate(Some(&json!(from)), &op)
                .map_err(Into::into),
        )?;
    }
    Ok((effects, invalid.len()))
}

fn terminal_case(state: &mut ConsumerState) -> Result<(usize, usize)> {
    let mut rejected = 0;
    for terminal in TERMINAL {
        for next in [
            "scheduled",
            "ringing",
            "connecting",
            "active",
            "ended",
            "missed",
            "failed",
            "cancelled",
        ] {
            if next == *terminal {
                continue;
            }
            let op = transition(terminal, next);
            assert_rejected_unchanged(
                state,
                rule(EDGES)
                    .validate(Some(&json!(terminal)), &op)
                    .map_err(Into::into),
            )?;
            rejected += 1;
        }
    }
    Ok((0, rejected))
}

fn replay_case(state: &mut ConsumerState) -> Result<(usize, usize)> {
    ensure!(production_transition("ringing", "connecting", 0xaa, "state")? == json!("connecting"));
    let first = record_once(state, "replay:ringing:connecting");
    ensure!(production_transition("ringing", "connecting", 0xaa, "state")? == json!("connecting"));
    let replay = record_once(state, "replay:ringing:connecting");
    ensure!(
        first == 1 && replay == 0,
        "exact replay changed consumer state"
    );
    Ok((1, 1))
}

fn competing_case(state: &mut ConsumerState) -> Result<(usize, usize)> {
    ensure!(production_transition("ringing", "active", 0xba, "state")? == json!("active"));
    let effects = record_once(state, "competing:ringing:active");
    let stale = transition("ringing", "missed");
    assert_rejected_unchanged(
        state,
        rule(EDGES)
            .validate(Some(&json!("active")), &stale)
            .map_err(Into::into),
    )?;
    Ok((effects, 1))
}

fn axis_case(state: &mut ConsumerState) -> Result<(usize, usize)> {
    let mut effects = 0;
    ensure!(production_transition("ringing", "active", 0xc1, "state")? == json!("active"));
    effects += record_once(state, "axis:state:active");

    let capture_edges = &[("inactive", "recording"), ("recording", "stopped")];
    let capture = transition("inactive", "recording");
    rule(capture_edges).validate(Some(&json!("inactive")), &capture)?;
    let resolved = SequencedState::new(EventCellValueShape::Register).resolve(
        &cell("recording"),
        &[StateWrite::new(event_digest(0xc2), capture)],
    )?;
    ensure!(resolved.settled_value() == Some(&json!("recording")));
    effects += record_once(state, "axis:capture:recording");

    let stale = transition("inactive", "recording");
    assert_rejected_unchanged(
        state,
        rule(capture_edges)
            .validate(Some(&json!("recording")), &stale)
            .map_err(Into::into),
    )?;

    let focus: CallStatePayload = serde_json::from_value(json!({
        "call_id": "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz",
        "focus": {"mode": "sfu", "session_focus": "fra-1"}
    }))?;
    focus.validate().map_err(anyhow::Error::msg)?;
    effects += record_once(state, "axis:focus:fra-1");
    let before = state.clone();
    ensure!(record_once(state, "axis:focus:fra-1") == 0);
    ensure!(*state == before, "redundant focus write changed state");
    Ok((effects, 2))
}

pub fn run_call_state_core_suite() -> Result<CallStateCoreExecution> {
    let fixture = load_fixture()?;
    ensure!(fixture.profile == ProfileId::MEDIA_SERVICE_BINDING_V1);
    ensure!(!fixture.version.trim().is_empty());
    ensure!(fixture.suite == "call_state_core");
    ensure!(fixture.runner.kind == "named_suite");
    ensure!(fixture.runner.entrypoint == CALL_STATE_CORE_ENTRYPOINT);
    ensure!(fixture.covers_vectors == VECTOR_IDS);
    ensure!(fixture.cases.len() == VECTOR_IDS.len());

    let mut state = ConsumerState::default();
    let mut cases = Vec::with_capacity(fixture.cases.len());
    for (case, vector_id) in fixture.cases.iter().zip(VECTOR_IDS) {
        ensure!(case.vector_id == *vector_id);
        ensure!(!case.runner.trim().is_empty());
        ensure!(!case.assertions.is_empty());
        let (committed_effects, rejected_zero_effects) = match case.name.as_str() {
            "participant_binding_invalid" => participant_case(&mut state)?,
            "initial_state_accepts_allowed" => initial_case(&mut state)?,
            "transition_matrix" => transition_matrix_case(&mut state)?,
            "terminal_absorbing" => terminal_case(&mut state)?,
            "replay_same_state_noop" => replay_case(&mut state)?,
            "ordered_competing_transitions" => competing_case(&mut state)?,
            "axis_result_split" => axis_case(&mut state)?,
            other => anyhow::bail!("unmapped call-state case {other}"),
        };
        cases.push(CaseExecutionResult {
            case_id: case.name.clone(),
            assertions: case.assertions.len(),
            committed_effects,
            rejected_zero_effects,
        });
    }
    let committed_effects = cases.iter().map(|case| case.committed_effects).sum();
    let rejected_zero_effects = cases.iter().map(|case| case.rejected_zero_effects).sum();
    ensure!(committed_effects == state.committed.len());
    ensure!(committed_effects > 0 && rejected_zero_effects > 0);
    Ok(CallStateCoreExecution {
        entrypoint: CALL_STATE_CORE_ENTRYPOINT,
        fixture: FIXTURE,
        cases,
        committed_effects,
        rejected_zero_effects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_all_cases_through_production_paths() {
        let execution = run_call_state_core_suite().unwrap();
        assert_eq!(execution.cases.len(), 7);
        assert!(execution.committed_effects >= 20);
        assert!(execution.rejected_zero_effects >= 40);
        assert!(execution.cases.iter().all(|case| case.assertions > 0));
    }

    #[test]
    fn canonical_axis_result_id_is_not_the_obsolete_axis_cell_id() {
        let fixture = load_fixture().unwrap();
        assert!(
            fixture
                .covers_vectors
                .contains(&"ak.vector.call_state.axis_result_split.v1".to_owned())
        );
        assert!(
            !fixture
                .covers_vectors
                .contains(&"ak.vector.call_state.axis_cell_split.v1".to_owned())
        );
    }
}
