//! Core call-state conformance vectors.
//!
//! Covers the six `ak.vector.call_state.*` vectors for participant binding
//! admission and the base call lifecycle FSM. The fixture provides registry
//! evidence; this runner exercises SDK signing / verification helpers and the
//! core `Fsm` lattice directly.

use anyhow::{Result, anyhow, bail};
use arkret::{
    MediaServiceAnchors, call_media_token_exchange, participant_binding_signing_input,
    verify_call_media_token_outcome,
};
use arkret_canonical::base64url::base64url_encode;
use arkret_identifiers::{CallId, CellRef, DeviceId, DidCoreId, DidFullId, Hash, RealmId};
use arkret_models_collaboration::events_payloads::call::ParticipantBinding;
use arkret_models_collaboration::objects::media::{
    CallMediaParticipantBinding, CallMediaServiceSignature, CallMediaTokenExchangeOutcome,
    CallMediaTokenExchangeRequestBody,
};
use arkret_state::lattice::{CellState, Fsm, Lattice, SealedOp};
use arkret_wire::{BottomKind, LatticeOp, LatticeOpType, ProfileId};
use chrono::{DateTime, Duration, TimeZone, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};

pub const VECTOR_ID_PARTICIPANT_BINDING_INVALID: &str =
    "ak.vector.call_state.participant_binding_invalid.v1";
pub const VECTOR_ID_INITIAL_STATE_ACCEPTS_ALLOWED: &str =
    "ak.vector.call_state.initial_state_accepts_allowed.v1";
pub const VECTOR_ID_TRANSITION_MATRIX: &str = "ak.vector.call_state.transition_matrix.v1";
pub const VECTOR_ID_TERMINAL_ABSORBING: &str = "ak.vector.call_state.terminal_absorbing.v1";
pub const VECTOR_ID_REPLAY_SAME_STATE_NOOP: &str = "ak.vector.call_state.replay_same_state_noop.v1";
pub const VECTOR_ID_CONCURRENT_SIBLING_BOTTOM: &str =
    "ak.vector.call_state.concurrent_sibling_bottom.v1";

pub const ALL_CALL_STATE_CORE_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_PARTICIPANT_BINDING_INVALID,
    VECTOR_ID_INITIAL_STATE_ACCEPTS_ALLOWED,
    VECTOR_ID_TRANSITION_MATRIX,
    VECTOR_ID_TERMINAL_ABSORBING,
    VECTOR_ID_REPLAY_SAME_STATE_NOOP,
    VECTOR_ID_CONCURRENT_SIBLING_BOTTOM,
];

const CALL_STATE_CORE_FIXTURE_FILE: &str = "call-state-core-fixture.json";

const ISSUER_KID: &str = "did:web:media.example#media-token";
const ROGUE_KID: &str = "did:web:rogue.example#media-token";

const INITIAL_STATES: &[&str] = &["scheduled", "ringing", "connecting"];
const NON_TERMINAL_STATES: &[&str] = &["scheduled", "ringing", "connecting", "active"];
const TERMINAL_STATES: &[&str] = &["ended", "missed", "failed", "cancelled"];
const ALL_STATES: &[&str] = &[
    "scheduled",
    "ringing",
    "connecting",
    "active",
    "ended",
    "missed",
    "failed",
    "cancelled",
];
const ALLOWED_TRANSITIONS: &[(&str, &str)] = &[
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

fn validate_call_state_core_fixture_metadata() -> Result<()> {
    let fixture = super::load_fixture_value(CALL_STATE_CORE_FIXTURE_FILE)?;
    super::validate_profile(&fixture, ProfileId::MEDIA_SERVICE_BINDING_V1)?;
    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("call-state core fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("call-state core fixture missing cases[]"))?;

    for vector_id in ALL_CALL_STATE_CORE_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("call-state core fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("call-state core fixture missing asserted case {vector_id}");
        }
    }

    Ok(())
}

fn fixture_now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 6, 19, 12, 0, 0)
        .single()
        .expect("fixture timestamp should be valid")
}

fn did(label: &str) -> DidCoreId {
    DidCoreId::new(format!("ak:did_core:web:{label}.example"))
        .expect("fixture Core DID should be valid")
}

fn full_did(label: &str) -> DidFullId {
    DidFullId::new(format!("did:web:{label}.example")).expect("fixture DID should be valid")
}

fn issuer_key() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

fn anchors_with_issuer_key(key: &SigningKey) -> MediaServiceAnchors {
    MediaServiceAnchors::new([full_did("media")])
        .with_keys([(ISSUER_KID.to_owned(), key.verifying_key())])
}

fn token_request() -> CallMediaTokenExchangeRequestBody {
    call_media_token_exchange(
        RealmId::new("ak:realm:AdDiiHSzv3bH7EOLwQDdq-UHvwHaUaPammx6UQbpQnb4").unwrap(),
        CallId::new("ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz").unwrap(),
        did("alice"),
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000005").unwrap(),
        "fra-1",
    )
}

fn unsigned_token_outcome(
    request: &CallMediaTokenExchangeRequestBody,
    expires_at: DateTime<Utc>,
) -> CallMediaTokenExchangeOutcome {
    let identity = "ak:rtc_participant:0198c2f4-0000-7000-8000-000000000000".to_owned();
    CallMediaTokenExchangeOutcome {
        focus_id: request.focus_id.clone(),
        backend_kind: "livekit".to_owned(),
        connect_url: "wss://livekit-fra.example.com".to_owned(),
        backend_token: "opaque-backend-token".to_owned(),
        participant_identity: identity.clone(),
        participant_binding: CallMediaParticipantBinding {
            scheme: ParticipantBinding::SCHEMA.to_owned(),
            sig: String::new(),
            issuer_kid: arkret::DidUrl::new(ISSUER_KID).unwrap(),
            realm_id: request.realm_id.clone(),
            call_id: request.call_id.clone(),
            focus_id: request.focus_id.clone(),
            actor_id: request.actor_id.clone(),
            device_id: request.device_id.clone(),
            participant_identity: identity,
            issued_at: expires_at - Duration::minutes(5),
            expires_at,
        },
        expires_at,
        service_signature: CallMediaServiceSignature {
            kid: arkret::DidUrl::new(ISSUER_KID).unwrap(),
            sig: String::new(),
        },
    }
}

fn sign_outcome(outcome: &mut CallMediaTokenExchangeOutcome, key: &SigningKey) -> Result<()> {
    let input = participant_binding_signing_input(&outcome.participant_binding)?;
    let sig = base64url_encode(key.sign(&input).to_bytes());
    outcome.participant_binding.sig = sig.clone();
    outcome.service_signature.sig = sig;
    Ok(())
}

fn signed_token_outcome(
    request: &CallMediaTokenExchangeRequestBody,
    key: &SigningKey,
    expires_at: DateTime<Utc>,
) -> Result<CallMediaTokenExchangeOutcome> {
    let mut outcome = unsigned_token_outcome(request, expires_at);
    sign_outcome(&mut outcome, key)?;
    Ok(outcome)
}

fn reducer_participant_binding_admission(
    request: &CallMediaTokenExchangeRequestBody,
    outcome: &CallMediaTokenExchangeOutcome,
    anchors: &MediaServiceAnchors,
    now: DateTime<Utc>,
) -> std::result::Result<(), &'static str> {
    match verify_call_media_token_outcome(request, outcome, anchors, now) {
        Ok(_) => Ok(()),
        Err(_) => Err(arkret_wire::ReasonCode::PARTICIPANT_BINDING_INVALID),
    }
}

fn assert_participant_binding_invalid(
    label: &str,
    request: &CallMediaTokenExchangeRequestBody,
    outcome: &CallMediaTokenExchangeOutcome,
    anchors: &MediaServiceAnchors,
    now: DateTime<Utc>,
) -> Result<()> {
    match reducer_participant_binding_admission(request, outcome, anchors, now) {
        Err(code) if code == arkret_wire::ReasonCode::PARTICIPANT_BINDING_INVALID => Ok(()),
        other => bail!("{label} must map to participant_binding_invalid, got {other:?}"),
    }
}

pub fn run_participant_binding_invalid_vector() -> Result<()> {
    if arkret_wire::ReasonCode::PARTICIPANT_BINDING_INVALID != "participant_binding_invalid" {
        bail!(
            "arkret_wire::ReasonCode::PARTICIPANT_BINDING_INVALID spelling drifted: participant_binding_invalid"
        );
    }

    let request = token_request();
    let key = issuer_key();
    let anchors = anchors_with_issuer_key(&key);
    let now = fixture_now();
    let expires_at = now + Duration::minutes(5);

    let mut rogue_issuer = unsigned_token_outcome(&request, expires_at);
    rogue_issuer.participant_binding.issuer_kid = arkret::DidUrl::new(ROGUE_KID).unwrap();
    rogue_issuer.service_signature.kid = arkret::DidUrl::new(ROGUE_KID).unwrap();
    sign_outcome(&mut rogue_issuer, &key)?;
    assert_participant_binding_invalid(
        "unanchored issuer",
        &request,
        &rogue_issuer,
        &anchors,
        now,
    )?;

    let mut tuple_mismatch = unsigned_token_outcome(&request, expires_at);
    tuple_mismatch.participant_binding.focus_id = "fra-2".to_owned();
    sign_outcome(&mut tuple_mismatch, &key)?;
    assert_participant_binding_invalid(
        "binding tuple mismatch",
        &request,
        &tuple_mismatch,
        &anchors,
        now,
    )?;

    let mut expired = unsigned_token_outcome(&request, expires_at);
    expired.participant_binding.issued_at = now - Duration::minutes(10);
    expired.participant_binding.expires_at = now - Duration::seconds(1);
    sign_outcome(&mut expired, &key)?;
    assert_participant_binding_invalid("expired binding", &request, &expired, &anchors, now)?;

    let mut bad_signature = signed_token_outcome(&request, &key, expires_at)?;
    bad_signature.participant_binding.sig = "AAAA".to_owned();
    assert_participant_binding_invalid(
        "participant binding bad signature",
        &request,
        &bad_signature,
        &anchors,
        now,
    )?;

    let good = signed_token_outcome(&request, &key, expires_at)?;
    reducer_participant_binding_admission(&request, &good, &anchors, now)
        .map_err(|code| anyhow!("valid participant_binding control rejected: {code}"))?;
    Ok(())
}

fn cell() -> CellRef {
    CellRef::new(
        "ak:cell:ak.component.call.state.v1:ak.call.0196441c-0000-7000-8000-000000000000"
            .to_owned(),
    )
    .expect("fixture cell id should be valid")
}

fn issuer_digest(suffix: &str) -> Hash {
    let suffix = suffix.to_ascii_lowercase();
    assert!(
        suffix
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()),
        "fixture digest suffix must be lowercase hex"
    );
    let padding = 64usize.saturating_sub(suffix.len());
    let id = format!("sha256:{suffix}{}", "0".repeat(padding));
    Hash::new(id).expect("fixture digest should be valid")
}

fn op_transition(from: &str, to: &str) -> LatticeOp {
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

fn call_state_fsm(initial: &str) -> Fsm {
    Fsm::new(
        ALLOWED_TRANSITIONS
            .iter()
            .map(|(from, to)| (json!(from), json!(to)))
            .collect(),
    )
    .with_initial(json!(initial))
}

fn transition_allowed(from: &str, to: &str) -> bool {
    ALLOWED_TRANSITIONS
        .iter()
        .any(|(candidate_from, candidate_to)| candidate_from == &from && candidate_to == &to)
}

fn classify_call_state_transition(from: &str, to: &str) -> std::result::Result<(), &'static str> {
    if TERMINAL_STATES.contains(&from) {
        return Err(arkret_wire::ReasonCode::CALL_STATE_TERMINAL);
    }
    if transition_allowed(from, to) {
        Ok(())
    } else {
        Err(arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID)
    }
}

fn assert_fsm_transition_value(from: &str, to: &str, suffix: &str) -> Result<()> {
    let fsm = call_state_fsm(from);
    let resolved = fsm.join(
        &cell(),
        &[SealedOp::new(
            issuer_digest(suffix),
            op_transition(from, to),
        )],
    );
    if resolved != CellState::Value(json!(to)) {
        bail!("expected call-state transition {from}->{to} to resolve to {to}, got {resolved:?}");
    }
    Ok(())
}

pub fn run_initial_state_accepts_allowed_vector() -> Result<()> {
    for state in INITIAL_STATES {
        if !INITIAL_STATES.contains(state) {
            bail!("initial state {state} should be accepted");
        }
        let resolved = call_state_fsm(state).join(&cell(), &[]);
        if resolved != CellState::Value(json!(state)) {
            bail!("initial call-state head {state} did not resolve cleanly: {resolved:?}");
        }
    }

    for state in ["active", "ended", "missed", "failed", "cancelled"] {
        match initial_state_admission(state) {
            Err(code) if code == arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID => {}
            other => bail!(
                "initial state {state} must fail call_state_transition_invalid, got {other:?}"
            ),
        }
    }
    Ok(())
}

fn initial_state_admission(state: &str) -> std::result::Result<(), &'static str> {
    if INITIAL_STATES.contains(&state) {
        Ok(())
    } else {
        Err(arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID)
    }
}

pub fn run_transition_matrix_vector() -> Result<()> {
    if NON_TERMINAL_STATES.len() != 4 {
        bail!("call-state non-terminal set drifted");
    }

    for (idx, (from, to)) in ALLOWED_TRANSITIONS.iter().enumerate() {
        classify_call_state_transition(from, to)
            .map_err(|code| anyhow!("legal edge {from}->{to} rejected with {code}"))?;
        assert_fsm_transition_value(from, to, &format!("{:02x}", idx + 1))?;
    }

    for (from, to) in [
        ("scheduled", "active"),
        ("ringing", "scheduled"),
        ("connecting", "cancelled"),
        ("active", "ringing"),
    ] {
        match classify_call_state_transition(from, to) {
            Err(code) if code == arkret_wire::ReasonCode::CALL_STATE_TRANSITION_INVALID => {}
            other => bail!(
                "illegal non-terminal edge {from}->{to} must be call_state_transition_invalid, got {other:?}"
            ),
        }
        let resolved = call_state_fsm(from).join(
            &cell(),
            &[SealedOp::new(
                issuer_digest(
                    &format!("f{from}{to}")
                        .bytes()
                        .fold(String::new(), |mut acc, b| {
                            use std::fmt::Write as _;
                            let _ = write!(&mut acc, "{:02x}", b);
                            acc
                        }),
                ),
                op_transition(from, to),
            )],
        );
        match resolved {
            CellState::Bottom(bottom) if bottom.kind == BottomKind::InvalidTransition => {}
            other => bail!(
                "illegal non-terminal edge {from}->{to} must Bottom invalid_transition, got {other:?}"
            ),
        }
    }

    Ok(())
}

pub fn run_terminal_absorbing_vector() -> Result<()> {
    for terminal in TERMINAL_STATES {
        let head_before = *terminal;
        for next in ALL_STATES {
            if next == terminal {
                continue;
            }
            match classify_call_state_transition(terminal, next) {
                Err(code) if code == arkret_wire::ReasonCode::CALL_STATE_TERMINAL => {}
                other => bail!(
                    "terminal edge {terminal}->{next} must be call_state_terminal, got {other:?}"
                ),
            }
            if head_before != *terminal {
                bail!("terminal head changed while rejecting outgoing transition");
            }
        }
    }
    Ok(())
}

pub fn run_replay_same_state_noop_vector() -> Result<()> {
    let resolved = call_state_fsm("ringing").join(
        &cell(),
        &[
            SealedOp::new(issuer_digest("aa"), op_transition("ringing", "connecting")),
            SealedOp::new(issuer_digest("ab"), op_transition("ringing", "connecting")),
        ],
    );
    if resolved != CellState::Value(json!("connecting")) {
        bail!("same transition replay must remain connecting, got {resolved:?}");
    }
    classify_call_state_transition("ringing", "connecting")
        .map_err(|code| anyhow!("same transition replay classified as invalid: {code}"))?;
    Ok(())
}

pub fn run_concurrent_sibling_bottom_vector() -> Result<()> {
    let resolved = call_state_fsm("ringing").join(
        &cell(),
        &[
            SealedOp::new(issuer_digest("ba"), op_transition("ringing", "active")),
            SealedOp::new(issuer_digest("bb"), op_transition("ringing", "missed")),
        ],
    );
    match resolved {
        CellState::Bottom(bottom) if bottom.kind == BottomKind::Conflict => Ok(()),
        other => bail!("ringing sibling transitions must produce conflict Bottom, got {other:?}"),
    }
}

pub fn run_call_state_core_fixture_suite() -> Result<()> {
    validate_call_state_core_fixture_metadata()?;
    if ALL_CALL_STATE_CORE_VECTOR_IDS.len() != 6 {
        bail!(
            "expected 6 call_state core vector ids, got {}",
            ALL_CALL_STATE_CORE_VECTOR_IDS.len()
        );
    }
    run_participant_binding_invalid_vector()?;
    run_initial_state_accepts_allowed_vector()?;
    run_transition_matrix_vector()?;
    run_terminal_absorbing_vector()?;
    run_replay_same_state_noop_vector()?;
    run_concurrent_sibling_bottom_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_six_call_state_core_vectors_run_clean() {
        run_call_state_core_fixture_suite().unwrap();
    }
}
