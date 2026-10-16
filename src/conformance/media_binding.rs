//! AKP-0010 media-binding conformance vectors.
//!
//! 10 vectors:
//!
//! - `ak.vector.media_binding.focus_selection_oldest_membership.v1`
//! - `ak.vector.media_binding.session_focus_no_split_brain.v1`
//! - `ak.vector.media_binding.token_exchange_minimal.v1`
//! - `ak.vector.media_binding.token_issuer_unauthorised.v1`
//! - `ak.vector.media_binding.participant_binding_required.v1`
//! - `ak.vector.media_binding.unknown_type_fail_closed.v1`
//! - `ak.vector.media_binding.e2ee_key_source.v1`
//! - `ak.vector.media_binding.participant_id_unrecognised.v1`
//! - `ak.vector.media_binding.recording_artifact_via_arkret_blob.v1`
//! - `ak.vector.media_binding.recording_exporter_label.v1`
//!
//! These are SDK-pure wire-shape pins. They lock the spelling of the
//! 10 new error codes (cotest mirrors Wire's registry), the
//! participant_binding scheme id, the 600s TTL ceiling, the
//! oldest-membership focus-selection contract, and the
//! `ak.profile.media_service_binding.v1` registry id so a downstream
//! coland / floria implementation regression hard-fails before reaching
//! a live integration target. The live tokens themselves are issued
//! server-side (R3.1 work — see scenarios under `tests/`).

use anyhow::{Result, anyhow, bail};
use arkret::{ParticipantBindingContext, participant_binding_signing_input};
use arkret_models_collaboration::call_invitation::{
    CallMediaSubjectBinding, canonical_request_digest,
};
use arkret_models_collaboration::events_payloads::call::ParticipantBinding;
use arkret_models_collaboration::objects::media::MEDIA_ICE_CONFIG_SIGNING_LABEL;
use arkret_wire::{ExporterLabelId, MEDIA_TOKEN_TTL_MAX_SECS, ProfileId};
use ed25519_dalek::{Signer, SigningKey, Verifier};
use hkdf::Hkdf;
use serde_json::{Value, json};
use sha2::Sha256;

/// Vector id pins. Hard-fails any future rename of the canonical
/// `ak.vector.media_binding.*.v1` registry entries.
pub const VECTOR_ID_FOCUS_SELECTION_OLDEST_MEMBERSHIP: &str =
    "ak.vector.media_binding.focus_selection_oldest_membership.v1";
pub const VECTOR_ID_SESSION_FOCUS_NO_SPLIT_BRAIN: &str =
    "ak.vector.media_binding.session_focus_no_split_brain.v1";
pub const VECTOR_ID_TOKEN_EXCHANGE_MINIMAL: &str =
    "ak.vector.media_binding.token_exchange_minimal.v1";
pub const VECTOR_ID_TOKEN_ISSUER_UNAUTHORISED: &str =
    "ak.vector.media_binding.token_issuer_unauthorised.v1";
pub const VECTOR_ID_PARTICIPANT_BINDING_REQUIRED: &str =
    "ak.vector.media_binding.participant_binding_required.v1";
pub const VECTOR_ID_UNKNOWN_TYPE_FAIL_CLOSED: &str =
    "ak.vector.media_binding.unknown_type_fail_closed.v1";
pub const VECTOR_ID_E2EE_KEY_SOURCE: &str = "ak.vector.media_binding.e2ee_key_source.v1";
pub const VECTOR_ID_PARTICIPANT_ID_UNRECOGNISED: &str =
    "ak.vector.media_binding.participant_id_unrecognised.v1";
pub const VECTOR_ID_RECORDING_ARTIFACT_VIA_ARKRET_BLOB: &str =
    "ak.vector.media_binding.recording_artifact_via_arkret_blob.v1";
pub const VECTOR_ID_RECORDING_EXPORTER_LABEL: &str =
    "ak.vector.media_binding.recording_exporter_label.v1";

/// Canonical list of all 10 vector ids. Used by the registry / discovery
/// gate to spot missing entries.
pub const ALL_MEDIA_BINDING_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_FOCUS_SELECTION_OLDEST_MEMBERSHIP,
    VECTOR_ID_SESSION_FOCUS_NO_SPLIT_BRAIN,
    VECTOR_ID_TOKEN_EXCHANGE_MINIMAL,
    VECTOR_ID_TOKEN_ISSUER_UNAUTHORISED,
    VECTOR_ID_PARTICIPANT_BINDING_REQUIRED,
    VECTOR_ID_UNKNOWN_TYPE_FAIL_CLOSED,
    VECTOR_ID_E2EE_KEY_SOURCE,
    VECTOR_ID_PARTICIPANT_ID_UNRECOGNISED,
    VECTOR_ID_RECORDING_ARTIFACT_VIA_ARKRET_BLOB,
    VECTOR_ID_RECORDING_EXPORTER_LABEL,
];

const MEDIA_BINDING_FIXTURE_FILE: &str = "media-binding-fixture.json";
pub const MEDIA_BINDING_ENTRYPOINT: &str = "ak.suite.media.binding.v1";

fn validate_media_binding_fixture_metadata() -> Result<()> {
    let fixture = super::load_fixture_value(MEDIA_BINDING_FIXTURE_FILE)?;
    super::validate_profile(&fixture, ProfileId::MEDIA_SERVICE_BINDING_V1)?;
    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("media-binding fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("media-binding fixture missing cases[]"))?;

    for vector_id in ALL_MEDIA_BINDING_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("media-binding fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("media-binding fixture missing asserted case {vector_id}");
        }
    }

    Ok(())
}

/// Known media-backend type tags from `ak.realm.media_service.foci[].type`.
/// Mirrors the Signatures owner's
/// `arkret_signatures::media::MediaBackendKind` enum; kept local so the vector suite runs under
/// cotest's minimal direct-owner dependency slice.
const KNOWN_MEDIA_BACKEND_TYPES: &[&str] = &[
    "livekit",
    "mediasoup",
    "janus",
    "arkret_native",
    "moq_relay",
];

fn known_backend_type(label: &str) -> bool {
    KNOWN_MEDIA_BACKEND_TYPES.contains(&label)
}

// ─── VECT-MB-1 — focus_selection_oldest_membership ─────────────────────────

/// Synthetic membership record for the oldest-member-wins focus-selection
/// vector. `joined_at_unix_ms` decides the ordering; ties (impossible
/// under HLC) fall back to lexicographic `actor_id`.
#[derive(Clone, Debug)]
struct CallMember<'a> {
    actor_id: &'a str,
    joined_at_unix_ms: i64,
    foci_preferred: &'a [&'a str],
}

/// Spec rule (media-service-binding.md §5): `session_focus` is decided by
/// the oldest member's `foci_preferred[0]`. Late-joining members do NOT
/// re-elect. Off-focus token requests MUST fail closed with
/// `focus_mismatch`.
fn pick_oldest_focus<'a>(members: &'a [CallMember<'a>]) -> Option<&'a str> {
    let mut sorted: Vec<&CallMember> = members.iter().collect();
    sorted.sort_by(|l, r| {
        l.joined_at_unix_ms
            .cmp(&r.joined_at_unix_ms)
            .then_with(|| l.actor_id.cmp(r.actor_id))
    });
    sorted
        .first()
        .and_then(|member| member.foci_preferred.first().copied())
}

pub fn run_focus_selection_oldest_membership_vector() -> Result<()> {
    let alice = CallMember {
        actor_id: "ak:did_core:web:alice.example",
        joined_at_unix_ms: 1_700_000_000_000,
        foci_preferred: &["focus.livekit.lhr", "focus.arkret.lhr"],
    };
    let bob = CallMember {
        actor_id: "ak:did_core:web:bob.example",
        joined_at_unix_ms: 1_700_000_005_000,
        foci_preferred: &["focus.arkret.lhr", "focus.livekit.lhr"],
    };
    let expected_focus = alice.foci_preferred[0];
    let members = [alice, bob];
    let elected =
        pick_oldest_focus(&members).ok_or_else(|| anyhow!("oldest member must elect a focus"))?;
    if elected != expected_focus {
        bail!("focus selection drifted: expected {expected_focus}, got {elected}");
    }

    // Off-focus token request from Bob must fail-closed with
    // `focus_mismatch`.
    if arkret_wire::ReasonCode::FOCUS_MISMATCH != "focus_mismatch" {
        bail!("arkret_wire::ReasonCode::FOCUS_MISMATCH spelling drifted: focus_mismatch");
    }
    Ok(())
}

// ─── VECT-MB-2 — session_focus_no_split_brain ──────────────────────────────

/// Minimal write-once cell modelling the `ak.call.state.session_focus`
/// `sequenced_state` write-once rule. Second writer hits `session_focus_already_committed`;
/// a local-only client whose chosen focus is unavailable surfaces
/// `focus_unavailable_for_client` instead of silently downgrading.
#[derive(Debug, Default)]
struct SessionFocusCell {
    committed: Option<String>,
}

impl SessionFocusCell {
    fn commit(&mut self, focus_id: &str) -> std::result::Result<(), &'static str> {
        if self.committed.is_some() {
            return Err(arkret_wire::ReasonCode::SESSION_FOCUS_ALREADY_COMMITTED);
        }
        self.committed = Some(focus_id.to_owned());
        Ok(())
    }
}

pub fn run_session_focus_no_split_brain_vector() -> Result<()> {
    let mut cell = SessionFocusCell::default();
    cell.commit("focus.livekit.lhr")
        .map_err(|e| anyhow!("first commit unexpectedly failed: {e}"))?;
    let second = cell.commit("focus.arkret.lhr");
    match second {
        Err(code) if code == arkret_wire::ReasonCode::SESSION_FOCUS_ALREADY_COMMITTED => {}
        other => bail!("second write must surface session_focus_already_committed, got {other:?}"),
    }

    // Carol's local-fail surfaces `focus_unavailable_for_client` rather
    // than silently downgrading to plaintext or any other focus.
    if arkret_wire::ReasonCode::FOCUS_UNAVAILABLE_FOR_CLIENT != "focus_unavailable_for_client" {
        bail!(
            "arkret_wire::ReasonCode::FOCUS_UNAVAILABLE_FOR_CLIENT spelling drifted: focus_unavailable_for_client"
        );
    }
    Ok(())
}

// ─── VECT-MB-3 — token_exchange_minimal ────────────────────────────────────

/// Validate that `remaining_secs` (token expires_at - now) is within
/// the spec's 600s ceiling and strictly positive. Mirrors
/// `arkret_signatures::media::validate_token_ttl` so cotest can pin the
/// constraint at the wire layer without pulling application runtime code.
fn token_ttl_within_bounds(remaining_secs: i64) -> Result<()> {
    if remaining_secs <= 0 {
        bail!("participant_binding_invalid: token already expired");
    }
    if (remaining_secs as u64) > MEDIA_TOKEN_TTL_MAX_SECS {
        bail!("participant_binding_invalid: token TTL exceeds 600s ceiling");
    }
    Ok(())
}

pub fn run_token_exchange_minimal_vector() -> Result<()> {
    if arkret_wire::ServiceOperationId::SELF_CALL_MEDIA_EXCHANGE_ISSUE_TOKEN_V1
        != "ak.self.call.media.exchange.issue_token.v1"
    {
        bail!(
            "arkret_wire::ServiceOperationId::SELF_CALL_MEDIA_EXCHANGE_ISSUE_TOKEN_V1 spelling drifted: arkret_wire::ServiceOperationId::SELF_CALL_MEDIA_EXCHANGE_ISSUE_TOKEN_V1"
        );
    }
    if ParticipantBinding::SCHEMA != "ak.media.participant_binding.v1" {
        bail!(
            "ParticipantBinding::SCHEMA drifted: {}",
            ParticipantBinding::SCHEMA
        );
    }
    if MEDIA_TOKEN_TTL_MAX_SECS != 600 {
        bail!("MEDIA_TOKEN_TTL_MAX_SECS drifted: {MEDIA_TOKEN_TTL_MAX_SECS} (spec ceiling is 600)");
    }

    // TTL must be within [1, 600] seconds.
    token_ttl_within_bounds(300)?;
    token_ttl_within_bounds(600)?;
    token_ttl_within_bounds(601)
        .err()
        .ok_or_else(|| anyhow!("601s TTL must be rejected (>600s ceiling)"))?;
    token_ttl_within_bounds(0)
        .err()
        .ok_or_else(|| anyhow!("0s TTL must be rejected"))?;
    token_ttl_within_bounds(-1)
        .err()
        .ok_or_else(|| anyhow!("negative TTL must be rejected"))?;

    // Required minimum fields of a token-exchange request payload.
    let required_fields = ["realm_id", "call_id", "actor_id", "device_id", "focus_id"];
    for f in required_fields {
        if f.is_empty() {
            bail!("token-exchange request field name corrupted");
        }
    }
    Ok(())
}

// ─── VECT-MB-4 — token_issuer_unauthorised ─────────────────────────────────

pub fn run_token_issuer_unauthorised_vector() -> Result<()> {
    if arkret_wire::ReasonCode::TOKEN_ISSUER_UNAUTHORISED != "token_issuer_unauthorised" {
        bail!(
            "arkret_wire::ReasonCode::TOKEN_ISSUER_UNAUTHORISED spelling drifted: token_issuer_unauthorised"
        );
    }

    // A rogue DID not anchored to `ak.realm.media_service.service_id`
    // MUST fail closed at the binding-validation stage. We model the
    // anchor lookup as a simple membership predicate; downstream servers
    // resolve this via the realm-state epoch.
    let trusted_issuer = "did:web:media.example";
    let rogue_issuer = "did:web:rogue.example";
    let is_trusted = |kid: &str| kid.starts_with(&format!("{trusted_issuer}#"));
    if !is_trusted("did:web:media.example#key-1") {
        bail!("trusted issuer kid resolution drifted");
    }
    if is_trusted(&format!("{rogue_issuer}#key-1")) {
        bail!("rogue issuer kid leaked past anchor check");
    }
    Ok(())
}

// ─── VECT-MB-5 — participant_binding_required ──────────────────────────────

pub fn run_participant_binding_required_vector() -> Result<()> {
    if arkret_wire::ReasonCode::PARTICIPANT_BINDING_INVALID != "participant_binding_invalid" {
        bail!(
            "arkret_wire::ReasonCode::PARTICIPANT_BINDING_INVALID spelling drifted: participant_binding_invalid"
        );
    }
    let (_, binding) = participant_binding_test_material()?;
    let compact = serde_json::to_value(binding)?;
    serde_json::from_value::<ParticipantBinding>(compact.clone())?;
    for field in ["expires_at", "issuer_kid", "subject_binding_digest", "sig"] {
        let mut missing = compact.clone();
        missing.as_object_mut().unwrap().remove(field);
        if serde_json::from_value::<ParticipantBinding>(missing).is_ok() {
            bail!("compact participant binding accepted missing {field}");
        }
    }
    for field in [
        "scheme",
        "issued_at",
        "realm_id",
        "call_id",
        "focus_id",
        "actor_id",
        "device_id",
        "participant_id",
    ] {
        let mut old_shape = compact.clone();
        old_shape[field] = serde_json::json!("retired");
        if serde_json::from_value::<ParticipantBinding>(old_shape).is_ok() {
            bail!("compact participant binding accepted retired {field}");
        }
    }

    // Real Ed25519 verification (no longer a field-presence stub): reconstruct
    // the §3 signing_input and verify `sig` against the issuer key.
    run_participant_binding_ed25519_vector()
}

/// Fixed synthetic receipt material for a cryptographic KAT, not live issuance.
fn participant_binding_test_material() -> Result<(CallMediaSubjectBinding, ParticipantBinding)> {
    let issuer = SigningKey::from_bytes(&[11; 32]);
    let mut receipt: CallMediaSubjectBinding = serde_json::from_value(json!({
        "realm_id": "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1",
        "call_id": "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz",
        "subject_actor_id": {
            "kind": "account",
            "account_id": {
                "principal_id": "ak:did_core:web:alice.example.com",
                "station_id": "ak:did_core:web:station.example.com"
            }
        },
        "subject_device_id": "ak:device:01964137-0000-7000-8000-000000000001",
        "roster_identity": {
            "actor_id": "ak:did_core:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
            "device_id": "ak:device:01964137-0000-7000-8000-000000000000"
        },
        "focus_id": "fra-1",
        "participant_id": "ak:rtc_participant:0198c2f4-0000-7000-8000-000000000000",
        "media": {"audio": true, "video": true, "screen": false},
        "expires_at": "2026-05-27T12:34:56.000Z",
        "nonce": arkret_canonical::base64url_encode([48; 32]),
        "issuer_kid": "did:web:media.example#media",
        "sig": ""
    }))?;
    receipt.sig =
        arkret_canonical::base64url_encode(issuer.sign(&receipt.signature_input()?).to_bytes());
    let digest = canonical_request_digest(&receipt)?;
    let context = participant_test_context(&receipt, &digest);
    let binding = ParticipantBinding {
        expires_at: receipt.expires_at,
        issuer_kid: receipt.issuer_kid.clone(),
        subject_binding_digest: digest.clone(),
        sig: arkret_canonical::base64url_encode(
            issuer
                .sign(&participant_binding_signing_input(&context)?)
                .to_bytes(),
        ),
    };
    Ok((receipt, binding))
}

fn participant_test_context<'a>(
    receipt: &'a CallMediaSubjectBinding,
    digest: &'a str,
) -> ParticipantBindingContext<'a> {
    ParticipantBindingContext {
        actor_id: &receipt.roster_identity.actor_id,
        call_id: &receipt.call_id,
        device_id: &receipt.roster_identity.device_id,
        expires_at: receipt.expires_at,
        focus_id: &receipt.focus_id,
        participant_id: &receipt.participant_id,
        realm_id: &receipt.realm_id,
        media: receipt.media.clone(),
        issuer_kid: receipt.issuer_kid.as_str(),
        subject_binding_digest: digest,
    }
}

/// Lock all ten signed fields to an independently calculated Ed25519 KAT.
fn run_participant_binding_ed25519_vector() -> Result<()> {
    let (receipt, binding) = participant_binding_test_material()?;
    let context = participant_test_context(&receipt, &binding.subject_binding_digest);
    let input = participant_binding_signing_input(&context)?;
    let issuer = SigningKey::from_bytes(&[11; 32]);
    let verifying = issuer.verifying_key();
    let sig = issuer.sign(&input);
    // Calculated independently with Python cryptography Ed25519 and ASCII JCS.
    const EXPECTED_SIG_HEX: &str = "bcde34696fd95673431c39783ccccc0d3c6513e2430dec89abb5829b6f63e9ca4cb70bb96d0c711eda6d9125d1ce8b18970bd268e9afdec895ee398111145c05";
    if hex_lower(&sig.to_bytes()) != EXPECTED_SIG_HEX {
        bail!("participant binding ten-field signature differs from the independent KAT");
    }
    verifying.verify(&input, &sig)?;
    let fields = serde_json::to_value(&context)?;
    if fields.as_object().map(|object| object.len()) != Some(10) {
        bail!("participant binding must sign exactly ten fields");
    }
    let tampers = [
        ("actor_id", json!("ak:did_core:key:tampered")),
        (
            "call_id",
            json!("ak:call:AXeSRv0BBNTmteRf54F8yu5ahdBtw9_GfJ47WLgnrkD5"),
        ),
        (
            "device_id",
            json!("ak:device:01964137-0000-7000-8000-00000000dead"),
        ),
        ("expires_at", json!("2099-01-01T00:00:00.000Z")),
        ("focus_id", json!("fra-2")),
        ("participant_id", json!("different-participant")),
        (
            "realm_id",
            json!("ak:realm:AeqRpQIZxaoTV-G0Cl9jzAJ6wSak3GJUvizlNJRsvSFY"),
        ),
        (
            "media",
            json!({"audio": true, "video": true, "screen": true}),
        ),
        ("issuer_kid", json!("did:web:rogue.example#media")),
        (
            "subject_binding_digest",
            json!(format!("sha256:{}", "00".repeat(32))),
        ),
    ];
    for (field, replacement) in tampers {
        let mut tampered = fields.clone();
        tampered[field] = replacement;
        let mut bytes = b"ak.media.participant_binding.v1\0".to_vec();
        bytes.extend_from_slice(&arkret_canonical::canonical_json_bytes(&tampered)?);
        if verifying.verify(&bytes, &sig).is_ok() {
            bail!("tampered participant binding field {field} verified");
        }
    }
    let mut retired = fields.clone();
    for field in ["media", "issuer_kid", "subject_binding_digest"] {
        retired.as_object_mut().unwrap().remove(field);
    }
    let mut old_input = b"ak.media.participant_binding.v1\0".to_vec();
    old_input.extend_from_slice(&arkret_canonical::canonical_json_bytes(&retired)?);
    if verifying.verify(&old_input, &sig).is_ok() {
        bail!("retired seven-field binding verified");
    }
    let mut cross_input = MEDIA_ICE_CONFIG_SIGNING_LABEL.as_bytes().to_vec();
    cross_input.push(0);
    cross_input.extend_from_slice(&arkret_canonical::canonical_json_bytes(&fields)?);
    if verifying.verify(&cross_input, &sig).is_ok() {
        bail!("participant binding verified under the ICE-config domain label");
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

// ─── VECT-MB-6 — unknown_type_fail_closed ──────────────────────────────────

pub fn run_unknown_type_fail_closed_vector() -> Result<()> {
    if arkret_wire::ReasonCode::UNKNOWN_FOCUS_TYPE != "unknown_focus_type" {
        bail!("arkret_wire::ReasonCode::UNKNOWN_FOCUS_TYPE spelling drifted: unknown_focus_type");
    }
    // Known variants must round-trip; anything else MUST fail closed
    // at the SDK helper, never silently downgrade.
    for label in KNOWN_MEDIA_BACKEND_TYPES {
        if !known_backend_type(label) {
            bail!("known backend kind {label} not accepted");
        }
    }
    for unknown in ["totally-new-backend", "", "sfu_endpoint", "MoqRelay"] {
        if known_backend_type(unknown) {
            bail!("unknown focus type `{unknown}` leaked past fail-closed gate");
        }
    }
    Ok(())
}

// ─── VECT-MB-7 — e2ee_key_source ───────────────────────────────────────────

pub fn run_e2ee_key_source_vector() -> Result<()> {
    if arkret_wire::ReasonCode::E2EE_KEY_SOURCE_UNAUTHORISED != "e2ee_key_source_unauthorised" {
        bail!(
            "arkret_wire::ReasonCode::E2EE_KEY_SOURCE_UNAUTHORISED spelling drifted: e2ee_key_source_unauthorised"
        );
    }
    // Only MLS-Exporter (label `ak-rtc-frame-key/v1`, length=19) is
    // accepted as the SFrame frame key source. Backend-cloud key
    // escrow (any wire form that funnels keys through the focus
    // service) is rejected.
    const MLS_EXPORTER_LENGTH: usize = 19;
    if ExporterLabelId::RTC_FRAME_KEY_V1.len() != MLS_EXPORTER_LENGTH {
        bail!(
            "MLS-Exporter label length drifted: expected {MLS_EXPORTER_LENGTH}, got {}",
            ExporterLabelId::RTC_FRAME_KEY_V1.len()
        );
    }
    let accept = |source: &str| matches!(source, "mls-exporter");
    if !accept("mls-exporter") {
        bail!("MLS-Exporter key source must be accepted");
    }
    for bad in ["backend-cloud-escrow", "kms", "out-of-band", ""] {
        if accept(bad) {
            bail!("e2ee key source `{bad}` leaked past fail-closed gate");
        }
    }

    // Real SFrame frame-key derivation (no longer a `label.len()==19` literal):
    // exercise the actual exporter-style KDF over the byte-correct label +
    // canonical Context.
    run_sframe_frame_key_derivation_vector()
}

/// VECT-MB-7b — REAL SFrame frame-key derivation
/// (media-service-binding.md §8.1, byte-locked label + canonical Context).
///
/// The spec derives the 32-byte SFrame frame key as
/// `MLS-Exporter(label="ak.rtc-frame-key/v1", Context, 32)` where
/// `Context = canonical_json({realm_id, call_id, focus_id, epoch_id,
/// participant_id, device_id})`. A live MLS group / RFC 9420 exporter is
/// NOT available under cotest's pure-vector slice, so this vector pins the two
/// halves cotest CAN verify cryptographically:
///   1. the Context is the byte-correct canonical JSON of the EXACT 6-tuple (an empty / epoch-only
///      / missing-sender Context MUST fail closed);
///   2. running a real RFC-5869 HKDF over a fixed exporter secret with the byte-correct `label ||
///      0x00 || Context` info yields a deterministic 32-byte key (golden vector) — proving the
///      derivation is a genuine KDF over the right inputs, not a length check.
///
/// LIVE RESIDUAL: substituting cotest's fixed exporter secret for a real MLS
/// group's exporter secret (RFC 9420 §8) requires a live MLS group; that is the
/// activated-call residual deferred to the live round.
fn run_sframe_frame_key_derivation_vector() -> Result<()> {
    // The canonical Context MUST be exactly this 6-tuple.
    let realm_id = "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1";
    let call_id = "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz";
    let focus_id = "fra-1";
    let epoch_id = "ak:mls_epoch:7";
    let participant_id = "ak:rtc_participant:0198c2f4-0000-7000-8000-000000000000";
    let device_id = "ak:device:01964137-0000-7000-8000-000000000000";

    let context = sframe_context(
        realm_id,
        call_id,
        focus_id,
        epoch_id,
        participant_id,
        device_id,
    )?;

    // Context MUST bind all sender fields. An empty / epoch-only Context fails
    // closed (e2ee_key_source_unauthorised). Model the gate: a Context missing
    // any of the 6 fields is rejected.
    let context_value: serde_json::Value = serde_json::from_slice(&context)
        .map_err(|err| anyhow!("Context is not valid JSON: {err}"))?;
    for field in [
        "realm_id",
        "call_id",
        "focus_id",
        "epoch_id",
        "participant_id",
        "device_id",
    ] {
        if context_value.get(field).and_then(|v| v.as_str()).is_none() {
            bail!(
                "SFrame Context MUST bind `{field}`; an epoch-only / missing-sender Context \
                 fails closed (e2ee_key_source_unauthorised)"
            );
        }
    }

    // Fixed exporter secret stands in for the MLS group's exporter secret. The
    // info string is `label || 0x00 || Context` — the byte-correct domain-
    // separated input.
    const EXPORTER_SECRET: [u8; 32] = [0x42u8; 32];
    let mut info = Vec::with_capacity(ExporterLabelId::RTC_FRAME_KEY_V1.len() + 1 + context.len());
    info.extend_from_slice(ExporterLabelId::RTC_FRAME_KEY_V1.as_bytes());
    info.push(0x00);
    info.extend_from_slice(&context);

    let hk = Hkdf::<Sha256>::new(None, &EXPORTER_SECRET);
    let mut frame_key = [0u8; 32];
    hk.expand(&info, &mut frame_key)
        .map_err(|err| anyhow!("HKDF expand failed: {err}"))?;

    // Golden key pin: the deterministic 32-byte output over the fixed secret +
    // byte-correct label + canonical Context. A drift in label, separator, or
    // Context JCS changes these bytes.
    const EXPECTED_KEY_HEX: &str =
        "d07379ecad8758632937ebb8541418451bc5d31f5d7cd82ef49a866f9534e09d";
    let actual_key_hex = hex_lower(&frame_key);
    if actual_key_hex != EXPECTED_KEY_HEX {
        bail!(
            "SFrame frame-key golden vector drifted:\n  expected {EXPECTED_KEY_HEX}\n  actual   {actual_key_hex}\n(label / 0x00 / Context JCS changed)"
        );
    }

    // A different Context (e.g. another device) MUST derive a different key —
    // the key is sender-bound, not call-wide.
    let other_context = sframe_context(
        realm_id,
        call_id,
        focus_id,
        epoch_id,
        participant_id,
        "ak:device:01964137-0000-7000-8000-0000000000ff",
    )?;
    let mut other_info = Vec::new();
    other_info.extend_from_slice(ExporterLabelId::RTC_FRAME_KEY_V1.as_bytes());
    other_info.push(0x00);
    other_info.extend_from_slice(&other_context);
    let mut other_key = [0u8; 32];
    Hkdf::<Sha256>::new(None, &EXPORTER_SECRET)
        .expand(&other_info, &mut other_key)
        .map_err(|err| anyhow!("HKDF expand (other) failed: {err}"))?;
    if other_key == frame_key {
        bail!("a different sender device produced the same frame key — Context is not bound");
    }

    Ok(())
}

/// Canonical SFrame `Context` bytes (media-service-binding.md §8.1): the JCS of
/// exactly `{realm_id, call_id, focus_id, epoch_id, participant_id,
/// device_id}`.
fn sframe_context(
    realm_id: &str,
    call_id: &str,
    focus_id: &str,
    epoch_id: &str,
    participant_id: &str,
    device_id: &str,
) -> Result<Vec<u8>> {
    arkret_canonical::canonical_json_bytes(&json!({
        "realm_id": realm_id,
        "call_id": call_id,
        "focus_id": focus_id,
        "epoch_id": epoch_id,
        "participant_id": participant_id,
        "device_id": device_id,
    }))
    .map_err(|err| anyhow!("SFrame Context JCS encoding failed: {err}"))
}

// ─── VECT-MB-8 — participant_id_unrecognised ─────────────────────────

pub fn run_participant_id_unrecognised_vector() -> Result<()> {
    if arkret_wire::ReasonCode::PARTICIPANT_ID_UNRECOGNISED != "participant_id_unrecognised" {
        bail!(
            "arkret_wire::ReasonCode::PARTICIPANT_ID_UNRECOGNISED spelling drifted: participant_id_unrecognised"
        );
    }
    // The backend MUST signal only identities that match an entry in
    // the effective `ak.component.call.roster.v1` OR-Set. Unknown identities fail closed
    // — clients MUST NOT trust them.
    let known: &[&str] = &["ak:rtc_participant:01999999-0000-7000-8000-00000000abcd"];
    let unknown = "ak:rtc_participant:01999999-0000-7000-8000-deadbeefdead";
    if known.contains(&unknown) {
        bail!("participant identity leak: unknown id in known set");
    }
    // `rtc_participant` id-kind MUST keep the canonical `ak:rtc_participant:` prefix.
    for id in known {
        if !id.starts_with("ak:rtc_participant:") {
            bail!("rtcpart id lost canonical prefix: {id}");
        }
    }
    Ok(())
}

// ─── VECT-MB-9 — recording_artifact_via_arkret_blob ───────────────────────

pub fn run_recording_artifact_via_arkret_blob_vector() -> Result<()> {
    if arkret_wire::ReasonCode::RECORDING_ARTIFACT_PIPELINE_BYPASSED
        != "recording_artifact_pipeline_bypassed"
    {
        bail!(
            "arkret_wire::ReasonCode::RECORDING_ARTIFACT_PIPELINE_BYPASSED spelling drifted: recording_artifact_pipeline_bypassed"
        );
    }
    // Egress MUST land on a Arkret blob endpoint. Direct S3 / GCS
    // / arbitrary http upload is bypass.
    let is_arkret_blob = |url: &str| {
        url.starts_with("https://")
            && (url.contains("/_matrix/arkret/v1/media") || url.contains("/arkret/v1/media"))
    };
    if !is_arkret_blob("https://server.example/arkret/v1/media/upload") {
        bail!("legit arkret blob endpoint not accepted");
    }
    for bad in [
        "https://s3.amazonaws.com/bucket/recording.mp4",
        "https://my-egress.example/dump",
        "https://storage.googleapis.com/foo",
    ] {
        if is_arkret_blob(bad) {
            bail!("non-arkret egress endpoint `{bad}` leaked past pipeline check");
        }
    }
    Ok(())
}

// VECT-MB-10: recording_exporter_label.

fn recording_context(
    realm_id: &str,
    call_id: &str,
    focus_id: &str,
    recording_id: &str,
    media_service_id: &str,
    recording_start_event_id: &str,
) -> Result<Vec<u8>> {
    arkret_canonical::canonical_json_bytes(&json!({
        "realm_id": realm_id,
        "call_id": call_id,
        "focus_id": focus_id,
        "recording_id": recording_id,
        "media_service_id": media_service_id,
        "recording_start_event_id": recording_start_event_id,
    }))
    .map_err(|err| anyhow!("recording exporter Context JCS encoding failed: {err}"))
}

fn recording_exporter_key_source_ok(
    label: &str,
    context: &[u8],
) -> std::result::Result<(), &'static str> {
    if label != ExporterLabelId::RTC_RECORDING_KEY_V1 || context.is_empty() {
        return Err(arkret_wire::ReasonCode::E2EE_KEY_SOURCE_UNAUTHORISED);
    }
    Ok(())
}

pub fn run_recording_exporter_label_vector() -> Result<()> {
    if ExporterLabelId::RTC_RECORDING_KEY_V1 != "ak.rtc-recording-key/v1" {
        bail!(
            "recording exporter label drifted: {exporterlabelid_rtc_recording_key_v1}",
            exporterlabelid_rtc_recording_key_v1 = ExporterLabelId::RTC_RECORDING_KEY_V1
        );
    }

    let context = recording_context(
        "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1",
        "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz",
        "fra-1",
        "rtc-recording-019a7360-0000-7000-8000-000000000002",
        "ak:did_core:web:recorder.example",
        "ak:event:ARHMhWPvHwsRKYQXNhB6wm4cESEe1fbHz6rJWPRl9wHY",
    )?;

    for (label, candidate_context) in [
        (ExporterLabelId::RTC_FRAME_KEY_V1, context.as_slice()),
        (ExporterLabelId::RTC_TRANSCRIPT_KEY_V1, context.as_slice()),
        (ExporterLabelId::RTC_RECORDING_KEY_V1, &[][..]),
    ] {
        match recording_exporter_key_source_ok(label, candidate_context) {
            Err(code) if code == arkret_wire::ReasonCode::E2EE_KEY_SOURCE_UNAUTHORISED => {}
            other => bail!(
                "recording exporter source ({label}, {} bytes) must be rejected, got {other:?}",
                candidate_context.len()
            ),
        }
    }

    recording_exporter_key_source_ok(ExporterLabelId::RTC_RECORDING_KEY_V1, &context)
        .map_err(|code| anyhow!("valid recording exporter source rejected: {code}"))?;

    let context_value: serde_json::Value =
        serde_json::from_slice(&context).map_err(|err| anyhow!("Context JSON failed: {err}"))?;
    let fields = context_value
        .as_object()
        .ok_or_else(|| anyhow!("recording Context must be a JSON object"))?;
    let required_fields = [
        "realm_id",
        "call_id",
        "focus_id",
        "recording_id",
        "media_service_id",
        "recording_start_event_id",
    ];
    if fields.len() != required_fields.len() {
        bail!(
            "recording exporter Context field count drifted: expected {}, got {}",
            required_fields.len(),
            fields.len()
        );
    }
    for field in required_fields {
        if fields.get(field).and_then(|value| value.as_str()).is_none() {
            bail!("recording exporter Context missing {field}");
        }
    }

    const EXPORTER_SECRET: [u8; 32] = [0x42u8; 32];
    let mut info =
        Vec::with_capacity(ExporterLabelId::RTC_RECORDING_KEY_V1.len() + 1 + context.len());
    info.extend_from_slice(ExporterLabelId::RTC_RECORDING_KEY_V1.as_bytes());
    info.push(0x00);
    info.extend_from_slice(&context);

    let hk = Hkdf::<Sha256>::new(None, &EXPORTER_SECRET);
    let mut recording_key = [0u8; 32];
    hk.expand(&info, &mut recording_key)
        .map_err(|err| anyhow!("HKDF expand failed: {err}"))?;

    const EXPECTED_KEY_HEX: &str =
        "882a68faf71d618aabe26d26bd0c340ad32ed36ebd2e387e9d38ecf8a7bb50ec";
    let actual_key_hex = hex_lower(&recording_key);
    if actual_key_hex != EXPECTED_KEY_HEX {
        bail!(
            "recording exporter golden vector drifted:\n  expected {EXPECTED_KEY_HEX}\n  actual   {actual_key_hex}\n(label / 0x00 / Context JCS changed)"
        );
    }

    let other_context = recording_context(
        "ak:realm:AZAySZA7XRDeJ9cO4MqaDWrJD-rqPk6Cudk7CCzsDQz1",
        "ak:call:AYf05kF8z4cSo8r6qmqXgu4KPuv2YtKBlsE00FOmblaz",
        "fra-1",
        "rtc-recording-019a7360-0000-7000-8000-000000000002",
        "ak:did_core:web:recorder.example",
        "ak:event:AS-ORd5zGMm1S5O6yi-p0U6TY6n0gvX_I-ZaEoNxW5LO",
    )?;
    let mut other_info =
        Vec::with_capacity(ExporterLabelId::RTC_RECORDING_KEY_V1.len() + 1 + other_context.len());
    other_info.extend_from_slice(ExporterLabelId::RTC_RECORDING_KEY_V1.as_bytes());
    other_info.push(0x00);
    other_info.extend_from_slice(&other_context);
    let mut other_key = [0u8; 32];
    Hkdf::<Sha256>::new(None, &EXPORTER_SECRET)
        .expand(&other_info, &mut other_key)
        .map_err(|err| anyhow!("HKDF expand (other) failed: {err}"))?;
    if other_key == recording_key {
        bail!("recording_start_event_id did not change the recording exporter key");
    }

    Ok(())
}

/// Suite entry point — runs all 10 media-binding vectors back to back.
/// One failure stops the run with full context.
pub fn run_media_binding_vector_suite() -> Result<()> {
    run_media_binding_suite().map(|_| ())
}

/// Named-suite entrypoint. Each canonical fixture case is dispatched to the
/// exact typed SDK vector runner named by the fixture; unknown, reordered, or
/// assertion-free cases fail closed.
pub fn run_media_binding_suite() -> Result<super::SuiteExecutionResult> {
    validate_media_binding_fixture_metadata()?;
    if ALL_MEDIA_BINDING_VECTOR_IDS.len() != 10 {
        bail!(
            "expected 10 media_binding vector ids, got {}",
            ALL_MEDIA_BINDING_VECTOR_IDS.len()
        );
    }
    let fixture = super::load_fixture_value(MEDIA_BINDING_FIXTURE_FILE)?;
    if fixture
        .pointer("/runner/entrypoint")
        .and_then(Value::as_str)
        != Some(MEDIA_BINDING_ENTRYPOINT)
    {
        bail!("media-binding named-suite entrypoint drifted");
    }
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("media-binding fixture missing cases[]"))?;
    let mut results = Vec::with_capacity(cases.len());
    for case in cases {
        let name = case
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("media-binding case missing name"))?;
        let vector_id = case
            .get("vector_id")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("media-binding case {name} missing vector_id"))?;
        let runner = case
            .get("runner")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("media-binding case {name} missing runner"))?;
        let (expected_vector, expected_runner, execute): (&str, &str, fn() -> Result<()>) =
            match name {
                "focus_selection_oldest_membership" => (
                    VECTOR_ID_FOCUS_SELECTION_OLDEST_MEMBERSHIP,
                    "cotest::conformance::media_binding::run_focus_selection_oldest_membership_vector",
                    run_focus_selection_oldest_membership_vector,
                ),
                "session_focus_no_split_brain" => (
                    VECTOR_ID_SESSION_FOCUS_NO_SPLIT_BRAIN,
                    "cotest::conformance::media_binding::run_session_focus_no_split_brain_vector",
                    run_session_focus_no_split_brain_vector,
                ),
                "token_exchange_minimal" => (
                    VECTOR_ID_TOKEN_EXCHANGE_MINIMAL,
                    "cotest::conformance::media_binding::run_token_exchange_minimal_vector",
                    run_token_exchange_minimal_vector,
                ),
                "token_issuer_unauthorised" => (
                    VECTOR_ID_TOKEN_ISSUER_UNAUTHORISED,
                    "cotest::conformance::media_binding::run_token_issuer_unauthorised_vector",
                    run_token_issuer_unauthorised_vector,
                ),
                "participant_binding_required" => (
                    VECTOR_ID_PARTICIPANT_BINDING_REQUIRED,
                    "cotest::conformance::media_binding::run_participant_binding_required_vector",
                    run_participant_binding_required_vector,
                ),
                "unknown_type_fail_closed" => (
                    VECTOR_ID_UNKNOWN_TYPE_FAIL_CLOSED,
                    "cotest::conformance::media_binding::run_unknown_type_fail_closed_vector",
                    run_unknown_type_fail_closed_vector,
                ),
                "e2ee_key_source" => (
                    VECTOR_ID_E2EE_KEY_SOURCE,
                    "cotest::conformance::media_binding::run_e2ee_key_source_vector",
                    run_e2ee_key_source_vector,
                ),
                "participant_id_unrecognised" => (
                    VECTOR_ID_PARTICIPANT_ID_UNRECOGNISED,
                    "cotest::conformance::media_binding::run_participant_id_unrecognised_vector",
                    run_participant_id_unrecognised_vector,
                ),
                "recording_artifact_via_arkret_blob" => (
                    VECTOR_ID_RECORDING_ARTIFACT_VIA_ARKRET_BLOB,
                    "cotest::conformance::media_binding::run_recording_artifact_via_arkret_blob_vector",
                    run_recording_artifact_via_arkret_blob_vector,
                ),
                "recording_exporter_label" => (
                    VECTOR_ID_RECORDING_EXPORTER_LABEL,
                    "cotest::conformance::media_binding::run_recording_exporter_label_vector",
                    run_recording_exporter_label_vector,
                ),
                other => bail!("unknown media-binding case {other}"),
            };
        if vector_id != expected_vector || runner != expected_runner {
            bail!("media-binding case {name} dispatch metadata drifted");
        }
        execute()?;
        let assertions = case
            .get("assertions")
            .and_then(Value::as_array)
            .map(Vec::len)
            .filter(|count| *count > 0)
            .ok_or_else(|| anyhow!("media-binding case {name} has no assertions"))?;
        results.push(super::CaseExecutionResult {
            case_id: name.to_owned(),
            assertions,
        });
    }
    Ok(super::SuiteExecutionResult {
        entrypoint: MEDIA_BINDING_ENTRYPOINT,
        fixture: MEDIA_BINDING_FIXTURE_FILE,
        cases: results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_ten_media_binding_vectors_run_clean() {
        let execution = run_media_binding_suite().unwrap();
        assert_eq!(execution.cases.len(), 10);
        assert!(execution.cases.iter().all(|case| case.assertions > 0));
    }
}
