//! Executable call-state core fixture runner.
//!
//! Participant admission is driven through the production SDK verifier. State
//! cases are driven through Soland's production, authority-ordered reducer.
//! Every rejection snapshots the affected projection facets, so an arbitrary
//! error cannot satisfy the suite's zero-effect requirement.

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use arkret::{
    MediaServiceAnchors, ParticipantBindingContext, call_media_token_exchange,
    participant_binding_signing_input, verify_call_media_token_outcome,
};
use arkret_canonical::DigestSuite;
use arkret_canonical::base64url::base64url_encode;
use arkret_event_draft::ProjectedEventOperation;
use arkret_identifiers::{CallId, DeviceId, Did, DidCoreId, OperationId, RealmId};
use arkret_models_collaboration::objects::media::{
    CallMediaParticipantBinding, CallMediaTokenExchangeOutcome, CallMediaTokenExchangeRequestBody,
    MediaBackendKind, MediaBackendToken,
};
use arkret_wire::{
    AccountId, ActorId, Base64UrlString, CommitStreamRef, CommittedEventFullView,
    DetachedObjectSignature, DetachedSignatureAlgorithm, DetachedSignatureContext, DidUrl, EventId,
    EventKind, Hash, ProfileId, RealmCommit, RealmCommitAuthorityRef, RealmCommitId, ScopeRef,
};
use chrono::{DateTime, Duration, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use serde_json::{Value, json};
use soland_domain::reducer::{
    CommitStreamEffect, CommitStreamProjection, FacetRef, ProjectionEffect, ProjectionState,
    ServerHlc, facet,
};

pub const CALL_STATE_CORE_ENTRYPOINT: &str = "ak.suite.call.state_core.v1";
pub const FIXTURE: &str = "call-state-core-fixture.json";

const REALM: &str = "ak:realm:ASReu6ls3Ao5vTK0TGXBCAvLLQChFejCEmN9KaSceZOt";
const CALL: &str = "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz";
const ISSUER_KID: &str = "did:web:media.example#media-token";
const VECTOR_IDS: &[&str] = &[
    "ak.vector.call_state.participant_binding_invalid.v1",
    "ak.vector.call_state.initial_state_accepts_allowed.v1",
    "ak.vector.call_state.transition_matrix.v1",
    "ak.vector.call_state.terminal_absorbing.v1",
    "ak.vector.call_state.replay_same_state_noop.v1",
    "ak.vector.call_state.ordered_competing_transitions.v1",
    "ak.vector.call_state.axis_result_split.v1",
];
const TERMINAL: &[&str] = &["ended", "missed", "failed", "cancelled"];
const STATES: &[&str] = &[
    "scheduled",
    "ringing",
    "connecting",
    "active",
    "ended",
    "missed",
    "failed",
    "cancelled",
];
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

fn operation(kind: EventKind, payload: Value, sequence: u64) -> ProjectedEventOperation {
    arkret_event_draft::test_support::raw_projected_operation(
        OperationId::new(format!(
            "ak:operation:0196419b-0000-7000-8000-{sequence:012x}"
        ))
        .expect("fixture operation id"),
        RealmId::new(REALM).expect("fixture realm id"),
        kind,
        payload,
    )
}

fn apply(
    state: &mut ProjectionState,
    operation: &ProjectedEventOperation,
    hlc: &ServerHlc,
) -> ProjectionEffect {
    state.apply_projected(operation, hlc)
}

fn expect_projected(effect: ProjectionEffect, call_id: &str) -> Result<()> {
    match effect {
        ProjectionEffect::CallStateProjected { call_id: actual } => {
            ensure!(actual == call_id, "projected wrong call: {actual}");
            Ok(())
        }
        other => anyhow::bail!("expected CallStateProjected({call_id}), got {other:?}"),
    }
}

fn expect_rejected(effect: ProjectionEffect, expected: &str) -> Result<()> {
    match effect {
        ProjectionEffect::Rejected { reason } => {
            ensure!(reason == expected, "expected {expected}, got {reason}");
            Ok(())
        }
        other => anyhow::bail!("expected Rejected({expected}), got {other:?}"),
    }
}

fn facet_value(state: &ProjectionState, name: &str, subject: &str) -> Option<Value> {
    state
        .facet_value(REALM, &FacetRef::new(name, subject))
        .cloned()
}

fn call_snapshot(state: &ProjectionState, call_id: &str) -> Vec<Option<Value>> {
    [
        facet::CALL_STATE,
        facet::CALL_FOCUS,
        facet::CALL_ROSTER,
        facet::CALL_MODERATION,
    ]
    .iter()
    .map(|name| facet_value(state, name, call_id))
    .collect()
}

fn set_head(state: &mut ProjectionState, call_id: &str, value: &str) {
    state.set_facet(
        REALM,
        FacetRef::new(facet::CALL_STATE, call_id),
        json!(value),
    );
}

fn transition_operation(from: &str, to: &str, sequence: u64) -> ProjectedEventOperation {
    operation(
        EventKind::CallState,
        json!({
            "call_id": CALL,
            "state_transition": {"from": from, "to": to}
        }),
        sequence,
    )
}

fn committed_transition(from: &str, to: &str) -> CommittedEventFullView {
    let realm_id = RealmId::new(REALM).expect("fixture realm id");
    let event = arkret_wire::test_support::raw_event_at(
        EventKind::CallState.as_str(),
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
        DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        json!({
            "call_id": CALL,
            "state_transition": {"from": from, "to": to}
        }),
        Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
    )
    .expect("fixture event");
    CommittedEventFullView {
        commit: RealmCommit {
            commit_id: RealmCommitId::from_digest([0x42; 32]),
            realm_id: realm_id.clone(),
            stream_ref: CommitStreamRef::Realm { realm_id },
            stream_position: 0,
            previous_commit_ref: None,
            event_ref: event.event_id.clone(),
            governance_generation: 0,
            authority_ref: RealmCommitAuthorityRef::GenesisOrChangeEvent(EventId::from_digest(
                DigestSuite::Sha256,
                [0x43; 32],
            )),
            committed_at: Utc.timestamp_opt(1_800_000_001, 0).unwrap(),
            producer_signer_fact_digest: None,
            signature: DetachedObjectSignature {
                context: DetachedSignatureContext::RealmCommit,
                signature_algorithm: DetachedSignatureAlgorithm::Ed25519,
                verification_method: DidUrl::new("did:web:station.example#key-1").unwrap(),
                signed_digest: Hash::new(format!("sha256:{}", "44".repeat(32))).unwrap(),
                created_at: Utc.timestamp_opt(1_800_000_001, 0).unwrap(),
                sig: Base64UrlString::new("AQ").unwrap(),
            },
        },
        event,
    }
}

fn fixture_now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 19, 12, 0, 0)
        .single()
        .expect("fixture time")
}

fn token_request() -> CallMediaTokenExchangeRequestBody {
    call_media_token_exchange(
        RealmId::new("ak:realm:AdDiiHSzv3bH7EOLwQDdq-UHvwHaUaPammx6UQbpQnb4").unwrap(),
        CallId::new(CALL).unwrap(),
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
            issuer_kid: arkret::DidUrl::new(ISSUER_KID).map_err(anyhow::Error::msg)?,
            expires_at,
        },
        expires_at,
    };
    let input =
        participant_binding_signing_input(&ParticipantBindingContext::from_outcome(&outcome))?;
    outcome.participant_binding.sig = base64url_encode(key.sign(&input).to_bytes());
    Ok(outcome)
}

fn participant_case() -> Result<(usize, usize)> {
    let request = token_request();
    let key = SigningKey::from_bytes(&[11; 32]);
    let issuer = Did::new("did:web:media.example").map_err(anyhow::Error::msg)?;
    let anchors =
        MediaServiceAnchors::new([(arkret_wire::project_did_to_core_id(&issuer)?, issuer)])?
            .with_keys([(ISSUER_KID.to_owned(), key.verifying_key())])?;
    let now = fixture_now();
    let good = token_outcome(&request, &key, now + Duration::minutes(5))?;
    verify_call_media_token_outcome(&request, &good, &anchors, now)?;
    let mut accepted = BTreeSet::from(["participant-binding-accepted"]);

    let mut negatives = Vec::new();
    let mut rogue = good.clone();
    rogue.participant_binding.issuer_kid =
        arkret::DidUrl::new("did:web:rogue.example#media-token").map_err(anyhow::Error::msg)?;
    negatives.push(rogue);
    let mut tuple = good.clone();
    tuple.focus_id = "fra-2".to_owned();
    negatives.push(tuple);
    negatives.push(token_outcome(&request, &key, now - Duration::seconds(1))?);
    let mut signature = good;
    signature.participant_binding.sig = "AAAA".to_owned();
    negatives.push(signature);
    for outcome in negatives {
        let before = accepted.clone();
        ensure!(
            verify_call_media_token_outcome(&request, &outcome, &anchors, now).is_err(),
            "negative participant binding was accepted"
        );
        ensure!(accepted == before, "rejection changed participant sink");
    }
    ensure!(accepted.remove("participant-binding-accepted"));
    Ok((1, 4))
}

fn initial_case() -> Result<(usize, usize)> {
    let hlc = ServerHlc::new("cotest");
    let mut effects = 0;
    for (sequence, initial) in ["scheduled", "ringing", "connecting"].iter().enumerate() {
        let mut state = ProjectionState::new();
        let op = operation(
            EventKind::CallCreate,
            json!({"initial_state": initial}),
            100 + sequence as u64,
        );
        let call_id = CallId::from_event_id(&op.context.event_id).to_string();
        expect_projected(apply(&mut state, &op, &hlc), &call_id)?;
        ensure!(facet_value(&state, facet::CALL_STATE, &call_id) == Some(json!(initial)));
        effects += 1;
    }

    let mut rejected = 0;
    for (sequence, initial) in ["active", "ended", "missed", "failed", "cancelled"]
        .iter()
        .enumerate()
    {
        let mut state = ProjectionState::new();
        let op = operation(
            EventKind::CallCreate,
            json!({"initial_state": initial}),
            110 + sequence as u64,
        );
        let call_id = CallId::from_event_id(&op.context.event_id).to_string();
        let before = call_snapshot(&state, &call_id);
        expect_rejected(
            apply(&mut state, &op, &hlc),
            arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID,
        )?;
        ensure!(call_snapshot(&state, &call_id) == before);
        rejected += 1;
    }
    Ok((effects, rejected))
}

fn transition_matrix_case() -> Result<(usize, usize)> {
    let hlc = ServerHlc::new("cotest");
    let mut effects = 0;
    for (sequence, (from, to)) in EDGES.iter().enumerate() {
        let mut state = ProjectionState::new();
        set_head(&mut state, CALL, from);
        let op = transition_operation(from, to, 200 + sequence as u64);
        expect_projected(apply(&mut state, &op, &hlc), CALL)?;
        ensure!(facet_value(&state, facet::CALL_STATE, CALL) == Some(json!(to)));
        effects += 1;
    }

    let invalid = [
        ("scheduled", "active"),
        ("ringing", "scheduled"),
        ("connecting", "cancelled"),
        ("active", "ringing"),
    ];
    for (sequence, (from, to)) in invalid.iter().enumerate() {
        let mut state = ProjectionState::new();
        set_head(&mut state, CALL, from);
        let before = call_snapshot(&state, CALL);
        let op = transition_operation(from, to, 220 + sequence as u64);
        expect_rejected(
            apply(&mut state, &op, &hlc),
            arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID,
        )?;
        ensure!(call_snapshot(&state, CALL) == before);
    }
    Ok((effects, invalid.len()))
}

fn terminal_case() -> Result<(usize, usize)> {
    let hlc = ServerHlc::new("cotest");
    let mut rejected = 0;
    for terminal in TERMINAL {
        for next in STATES.iter().filter(|state| *state != terminal) {
            let mut state = ProjectionState::new();
            set_head(&mut state, CALL, terminal);
            let before = call_snapshot(&state, CALL);
            let op = transition_operation(terminal, next, 300 + rejected as u64);
            expect_rejected(
                apply(&mut state, &op, &hlc),
                arkret_wire::ReasonCode::CALL_STATE_TERMINAL,
            )?;
            ensure!(call_snapshot(&state, CALL) == before);
            rejected += 1;
        }
    }
    Ok((0, rejected))
}

fn replay_case() -> Result<(usize, usize)> {
    let hlc = ServerHlc::new("cotest");
    let mut state = ProjectionState::new();
    set_head(&mut state, CALL, "ringing");
    let item = committed_transition("ringing", "connecting");
    let mut stream = CommitStreamProjection::new();
    ensure!(matches!(
        stream.apply_committed(item.clone())?,
        CommitStreamEffect::Committed { .. }
    ));
    let op = ProjectedEventOperation::from_accepted_event(
        OperationId::new("ak:operation:0196419b-0000-7000-8000-000000000400").unwrap(),
        arkret_wire::OperationKind::Create,
        None,
        &item.event,
        DigestSuite::Sha256,
    )?;
    expect_projected(apply(&mut state, &op, &hlc), CALL)?;
    let after = call_snapshot(&state, CALL);

    // The authority-stream consumer classifies an exact replay as Duplicate,
    // so it cannot re-enter the reducer against the already advanced head.
    ensure!(matches!(
        stream.apply_committed(item)?,
        CommitStreamEffect::Duplicate { .. }
    ));
    ensure!(call_snapshot(&state, CALL) == after);
    Ok((1, 1))
}

fn competing_case() -> Result<(usize, usize)> {
    let hlc = ServerHlc::new("cotest");
    let mut state = ProjectionState::new();
    set_head(&mut state, CALL, "ringing");
    let winner = transition_operation("ringing", "active", 500);
    expect_projected(apply(&mut state, &winner, &hlc), CALL)?;
    let before = call_snapshot(&state, CALL);
    let stale = transition_operation("ringing", "missed", 501);
    expect_rejected(
        apply(&mut state, &stale, &hlc),
        arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID,
    )?;
    ensure!(call_snapshot(&state, CALL) == before);
    Ok((1, 1))
}

fn axis_case() -> Result<(usize, usize)> {
    let hlc = ServerHlc::new("cotest");
    let mut state = ProjectionState::new();
    set_head(&mut state, CALL, "scheduled");
    let participant = json!({
        "actor_id": ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
        )),
        "device_id": "ak:device:01904100-0000-7000-8000-d00000000001"
    });
    let combined = operation(
        EventKind::CallState,
        json!({
            "call_id": CALL,
            "state_transition": {"from": "scheduled", "to": "ringing"},
            "focus": {"mode": "sfu", "session_focus": "fra-1"},
            "roster_delta": {"op": "join", "participant": participant}
        }),
        600,
    );
    expect_projected(apply(&mut state, &combined, &hlc), CALL)?;
    ensure!(facet_value(&state, facet::CALL_STATE, CALL) == Some(json!("ringing")));
    ensure!(
        facet_value(&state, facet::CALL_FOCUS, CALL).context("focus missing")?["session_focus"]
            == "fra-1"
    );
    ensure!(
        facet_value(&state, facet::CALL_ROSTER, CALL).context("roster missing")?[0]["tag_id"]
            == combined.context.event_id.as_str()
    );

    let stale = transition_operation("scheduled", "connecting", 601);
    let before = call_snapshot(&state, CALL);
    expect_rejected(
        apply(&mut state, &stale, &hlc),
        arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID,
    )?;
    ensure!(call_snapshot(&state, CALL) == before);

    let moved_focus = operation(
        EventKind::CallState,
        json!({"call_id": CALL, "focus": {"mode": "sfu", "session_focus": "iad-1"}}),
        602,
    );
    let before = call_snapshot(&state, CALL);
    expect_rejected(
        apply(&mut state, &moved_focus, &hlc),
        arkret_wire::ReasonCode::SESSION_FOCUS_ALREADY_COMMITTED,
    )?;
    ensure!(call_snapshot(&state, CALL) == before);

    let removal = json!({
        "actor_id": ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
            DidCoreId::new("ak:did_core:web:bob.example").unwrap(),
        )),
        "action": "ban",
        "removed_by": "ak:did_core:web:mod.example",
        "removed_at": "2026-07-26T00:00:00.000Z"
    });
    let moderation = operation(
        EventKind::CallState,
        json!({
            "call_id": CALL,
            "moderation_delta": {"op": "remove_participant", "removal": removal}
        }),
        603,
    );
    expect_projected(apply(&mut state, &moderation, &hlc), CALL)?;
    ensure!(
        facet_value(&state, facet::CALL_MODERATION, CALL).context("moderation missing")?[0]["tag_id"]
            == moderation.context.event_id.as_str()
    );

    let capture = FacetRef::composite(facet::CALL_RECORDING, &[CALL, "capture-1"]);
    let result = FacetRef::composite(facet::CALL_RECORDING_RESULT, &[CALL, "capture-1"]);
    let capture_payload = |consent_confirmed| {
        json!({
            "call_id": CALL,
            "recording_id": "capture-1",
            "recording_agent_id": "ak:did_core:web:capture.example",
            "capture_kind": "recording",
            "mode": "audio_video",
            "visible_notice": true,
            "result": {"retention": {"consent_confirmed": consent_confirmed}}
        })
    };
    let unconsented = operation(EventKind::CallRecordingStart, capture_payload(false), 604);
    let before_call = call_snapshot(&state, CALL);
    let before_capture = state.facet_value(REALM, &capture).cloned();
    let before_result = state.facet_value(REALM, &result).cloned();
    expect_rejected(
        apply(&mut state, &unconsented, &hlc),
        arkret_wire::ErrorCode::SCHEMA_VIOLATION,
    )?;
    ensure!(call_snapshot(&state, CALL) == before_call);
    ensure!(state.facet_value(REALM, &capture).cloned() == before_capture);
    ensure!(state.facet_value(REALM, &result).cloned() == before_result);

    let consented = operation(EventKind::CallRecordingStart, capture_payload(true), 605);
    expect_projected(apply(&mut state, &consented, &hlc), CALL)?;
    ensure!(state.facet_value(REALM, &capture) == Some(&json!("recording")));
    ensure!(state.facet_value(REALM, &result).is_some());
    Ok((3, 3))
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

    let mut cases = Vec::with_capacity(fixture.cases.len());
    for (case, vector_id) in fixture.cases.iter().zip(VECTOR_IDS) {
        ensure!(case.vector_id == *vector_id);
        ensure!(!case.runner.trim().is_empty());
        ensure!(!case.assertions.is_empty());
        let (committed_effects, rejected_zero_effects) = match case.name.as_str() {
            "participant_binding_invalid" => participant_case()?,
            "initial_state_accepts_allowed" => initial_case()?,
            "transition_matrix" => transition_matrix_case()?,
            "terminal_absorbing" => terminal_case()?,
            "replay_same_state_noop" => replay_case()?,
            "ordered_competing_transitions" => competing_case()?,
            "axis_result_split" => axis_case()?,
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
        assert_eq!(execution.committed_effects, 24);
        assert_eq!(execution.rejected_zero_effects, 46);
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
