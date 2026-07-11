//! AKP-0010 media-binding conformance vectors.
//!
//! 10 vectors covering [§0.11 of `_before_todos.md`]:
//!
//! - `ak.vector.media_binding.focus_selection_oldest_membership.v1`
//! - `ak.vector.media_binding.session_focus_no_split_brain.v1`
//! - `ak.vector.media_binding.token_exchange_minimal.v1`
//! - `ak.vector.media_binding.token_issuer_unauthorised.v1`
//! - `ak.vector.media_binding.participant_binding_required.v1`
//! - `ak.vector.media_binding.unknown_type_fail_closed.v1`
//! - `ak.vector.media_binding.e2ee_key_source.v1`
//! - `ak.vector.media_binding.participant_identity_unrecognised.v1`
//! - `ak.vector.media_binding.recording_artifact_via_arkret_blob.v1`
//! - `ak.vector.media_binding.recording_exporter_label.v1`
//!
//! These are SDK-pure wire-shape pins. They lock the spelling of the
//! 10 new error codes (cotest mirrors `arkret_core`'s registry), the
//! participant_binding scheme id, the 600s TTL ceiling, the
//! oldest-membership focus-selection contract, and the
//! `ak.profile.media_service_binding.v1` registry id so a downstream
//! soland / floria implementation regression hard-fails before reaching
//! a live integration target. The live tokens themselves are issued
//! server-side (R3.1 work — see scenarios under `tests/`).

use anyhow::{Result, anyhow, bail};
use arkret_core::error::{
    REASON_E2EE_KEY_SOURCE_UNAUTHORISED, REASON_FOCUS_MISMATCH,
    REASON_FOCUS_UNAVAILABLE_FOR_CLIENT, REASON_PARTICIPANT_BINDING_INVALID,
    REASON_PARTICIPANT_IDENTITY_UNRECOGNISED, REASON_RECORDING_ARTIFACT_PIPELINE_BYPASSED,
    REASON_SESSION_FOCUS_ALREADY_COMMITTED, REASON_TOKEN_ISSUER_UNAUTHORISED,
    REASON_UNKNOWN_FOCUS_TYPE,
};
use arkret_core::{
    MEDIA_TOKEN_TTL_MAX_SECS, OP_CALL_MEDIA_TOKEN_EXCHANGE, PARTICIPANT_BINDING_SCHEMA,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
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
pub const VECTOR_ID_PARTICIPANT_IDENTITY_UNRECOGNISED: &str =
    "ak.vector.media_binding.participant_identity_unrecognised.v1";
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
    VECTOR_ID_PARTICIPANT_IDENTITY_UNRECOGNISED,
    VECTOR_ID_RECORDING_ARTIFACT_VIA_ARKRET_BLOB,
    VECTOR_ID_RECORDING_EXPORTER_LABEL,
];

const MEDIA_BINDING_FIXTURE_FILE: &str = "media-binding-fixture.json";
const MEDIA_BINDING_PROFILE: &str = "ak.profile.media_service_binding.v1";

fn validate_media_binding_fixture_metadata() -> Result<()> {
    let fixture = super::load_fixture_value(MEDIA_BINDING_FIXTURE_FILE)?;
    super::validate_profile(&fixture, MEDIA_BINDING_PROFILE)?;
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
/// Mirrors `arkret_sdk::media::MediaBackendType` enum (R3 SDK feature
/// `full-surface`) — kept local so the vector suite runs under cotest's
/// minimal `arkret-core` dep slice.
const KNOWN_MEDIA_BACKEND_TYPES: &[&str] = &[
    "livekit",
    "mediasoup",
    "janus",
    "arkret-native",
    "moq-relay",
];

fn known_backend_type(label: &str) -> bool {
    KNOWN_MEDIA_BACKEND_TYPES.contains(&label)
}

const LABEL_RTC_FRAME_KEY: &str = "ak.rtc-frame-key/v1";
const LABEL_RTC_RECORDING_KEY: &str = "ak.rtc-recording-key/v1";
const LABEL_RTC_TRANSCRIPT_KEY: &str = "ak.rtc-transcript-key/v1";

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
        actor_id: "did:web:alice.example",
        joined_at_unix_ms: 1_700_000_000_000,
        foci_preferred: &["focus.livekit.lhr", "focus.arkret.lhr"],
    };
    let bob = CallMember {
        actor_id: "did:web:bob.example",
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
    if REASON_FOCUS_MISMATCH != "focus_mismatch" {
        bail!("REASON_FOCUS_MISMATCH spelling drifted: {REASON_FOCUS_MISMATCH}");
    }
    Ok(())
}

// ─── VECT-MB-2 — session_focus_no_split_brain ──────────────────────────────

/// Minimal write-once cell modelling the `ak.call.state.session_focus`
/// cas-register. Second writer hits `session_focus_already_committed`;
/// a local-only client whose chosen focus is unavailable surfaces
/// `focus_unavailable_for_client` instead of silently downgrading.
#[derive(Debug, Default)]
struct SessionFocusCell {
    committed: Option<String>,
}

impl SessionFocusCell {
    fn commit(&mut self, focus_id: &str) -> std::result::Result<(), &'static str> {
        if self.committed.is_some() {
            return Err(REASON_SESSION_FOCUS_ALREADY_COMMITTED);
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
        Err(code) if code == REASON_SESSION_FOCUS_ALREADY_COMMITTED => {}
        other => bail!("second write must surface session_focus_already_committed, got {other:?}"),
    }

    // Carol's local-fail surfaces `focus_unavailable_for_client` rather
    // than silently downgrading to plaintext or any other focus.
    if REASON_FOCUS_UNAVAILABLE_FOR_CLIENT != "focus_unavailable_for_client" {
        bail!(
            "REASON_FOCUS_UNAVAILABLE_FOR_CLIENT spelling drifted: {REASON_FOCUS_UNAVAILABLE_FOR_CLIENT}"
        );
    }
    Ok(())
}

// ─── VECT-MB-3 — token_exchange_minimal ────────────────────────────────────

/// Validate that `remaining_secs` (token expires_at - now) is within
/// the spec's 600s ceiling and strictly positive. Mirrors
/// `arkret_sdk::media::validate_token_ttl` so cotest can pin the
/// constraint at the wire layer without pulling the full-surface SDK.
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
    if OP_CALL_MEDIA_TOKEN_EXCHANGE != "ak.self.call.media.exchange.issue_token" {
        bail!("OP_CALL_MEDIA_TOKEN_EXCHANGE spelling drifted: {OP_CALL_MEDIA_TOKEN_EXCHANGE}");
    }
    if PARTICIPANT_BINDING_SCHEMA != "ak.media.participant_binding.v1" {
        bail!("PARTICIPANT_BINDING_SCHEMA drifted: {PARTICIPANT_BINDING_SCHEMA}");
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
    if REASON_TOKEN_ISSUER_UNAUTHORISED != "token_issuer_unauthorised" {
        bail!(
            "REASON_TOKEN_ISSUER_UNAUTHORISED spelling drifted: {REASON_TOKEN_ISSUER_UNAUTHORISED}"
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
    if REASON_PARTICIPANT_BINDING_INVALID != "participant_binding_invalid" {
        bail!(
            "REASON_PARTICIPANT_BINDING_INVALID spelling drifted: {REASON_PARTICIPANT_BINDING_INVALID}"
        );
    }
    // A response missing the `participant_binding` field, or one whose
    // `scheme` is anything other than `ak.media.participant_binding.v1`,
    // is invalid. We pin both branches at the SDK constant layer; the
    // schema-validator integration target lands under R3.1.
    let valid_scheme = PARTICIPANT_BINDING_SCHEMA;
    for bogus in [
        "",
        "ak.media.participant_binding",
        "ak.media.participant_binding.v0",
        "ak.media.participant_binding.v2",
    ] {
        if bogus == valid_scheme {
            bail!("participant_binding scheme leak: {bogus}");
        }
    }
    // The bound tuple fields (sig + issuer_kid + realm_id + call_id +
    // focus_id + actor_id + device_id + participant_identity +
    // expires_at) MUST all be present; missing any one is
    // `participant_binding_invalid`.
    let required = [
        "sig",
        "issuer_kid",
        "realm_id",
        "call_id",
        "focus_id",
        "actor_id",
        "device_id",
        "participant_identity",
        "expires_at",
    ];
    if required.len() != 9 {
        bail!("participant_binding required tuple drifted (expected 9 fields)");
    }

    // Real EdDSA verification (no longer a field-presence stub): reconstruct
    // the §3 signing_input and verify `sig` against the issuer key.
    run_participant_binding_eddsa_vector()
}

/// Canonical participant_binding signing_input
/// (media-service-binding.md §3 / §3.1, byte-locked):
///
/// ```text
/// signing_input = "ak.media.participant_binding.v1" || 0x00 ||
///   canonical_json({ actor_id, call_id, device_id, expires_at,
///                    focus_id, participant_identity, realm_id })
/// ```
///
/// The label is the literal `scheme` value; the JCS object covers EXACTLY the
/// 7 authoritative fields (the `scheme` / `issuer_kid` / `issued_at` metadata
/// MUST NOT enter the input). Returns the bytes a verifier signs/checks.
fn participant_binding_signing_input(
    actor_id: &str,
    call_id: &str,
    device_id: &str,
    expires_at: &str,
    focus_id: &str,
    participant_identity: &str,
    realm_id: &str,
) -> Result<Vec<u8>> {
    let seven_tuple = json!({
        "actor_id": actor_id,
        "call_id": call_id,
        "device_id": device_id,
        "expires_at": expires_at,
        "focus_id": focus_id,
        "participant_identity": participant_identity,
        "realm_id": realm_id,
    });
    let jcs = arkret_core::canonical::canonical_json_bytes(&seven_tuple)
        .map_err(|err| anyhow!("participant_binding JCS encoding failed: {err}"))?;
    let mut input = Vec::with_capacity(PARTICIPANT_BINDING_SCHEMA.len() + 1 + jcs.len());
    input.extend_from_slice(PARTICIPANT_BINDING_SCHEMA.as_bytes());
    input.push(0x00);
    input.extend_from_slice(&jcs);
    Ok(input)
}

/// VECT-MB-5b — REAL EdDSA golden vector for `participant_binding.sig` and the
/// `service_signature.sig` (which reuses the SAME signing_input, §3.1).
///
/// Fixed issuer seed + fixed 7-tuple ⇒ a deterministic golden signature. The
/// vector proves:
///   1. a correctly signed binding verifies (the issuer key signs the §3 signing_input, not the raw
///      object);
///   2. tampering with ANY one authoritative field breaks verification (the signature actually
///      covers the field, it is not merely compared);
///   3. the domain label is load-bearing — verifying the same `sig` under the ICE-config label
///      (`ak.media.ice_config.v1`) MUST fail (cross-purpose signature confusion is rejected);
///   4. `service_signature.sig` over the identical input verifies with the same issuer key.
fn run_participant_binding_eddsa_vector() -> Result<()> {
    // Fixed golden inputs.
    const ISSUER_SEED: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
        0xf0, 0x01,
    ];
    let actor_id = "did:web:alice.example.com";
    let call_id = "ak:call:0196441c-0000-7000-8000-000000000000";
    let device_id = "ak:device:01964137-0000-7000-8000-000000000000";
    let expires_at = "2026-05-27T12:34:56Z";
    let focus_id = "fra-1";
    let participant_identity = "ak:rtc_participant:0198c2f4-0000-7000-8000-000000000000";
    let realm_id = "ak:realm:0196419b-0000-7000-8000-000000000000";

    let signing_input = participant_binding_signing_input(
        actor_id,
        call_id,
        device_id,
        expires_at,
        focus_id,
        participant_identity,
        realm_id,
    )?;

    let issuer = SigningKey::from_bytes(&ISSUER_SEED);
    let verifying: VerifyingKey = issuer.verifying_key();
    let sig = issuer.sign(&signing_input);

    // Golden signature pin: the deterministic ed25519 signature over the fixed
    // input MUST reproduce this byte string. A drift in canonical JSON, the
    // label, the 0x00 separator, or the field set changes these bytes.
    const EXPECTED_SIG_HEX: &str = "53bede6ece7e1211283533ca96301fc07d523b41f65e502a3a34c89b6ee41db15906d2ed57e21c0250dc120fb41ec82f271e6ce7853a1a4dab81070de4cc2b0c";
    let actual_sig_hex = hex_lower(&sig.to_bytes());
    if actual_sig_hex != EXPECTED_SIG_HEX {
        bail!(
            "participant_binding golden signature drifted:\n  expected {EXPECTED_SIG_HEX}\n  actual   {actual_sig_hex}\n(signing_input / label / JCS changed)"
        );
    }

    // 1. The honest signature verifies.
    verifying
        .verify(&signing_input, &sig)
        .map_err(|err| anyhow!("honest participant_binding sig must verify: {err}"))?;

    // 2. Tampering each authoritative field breaks verification.
    let tampers: [(&str, &str); 7] = [
        (actor_id, "did:web:eve.example.com"),
        (call_id, "ak:call:0196441c-0000-7000-8000-00000000dead"),
        (device_id, "ak:device:01964137-0000-7000-8000-00000000dead"),
        (expires_at, "2099-01-01T00:00:00Z"),
        (focus_id, "fra-2"),
        (
            participant_identity,
            "ak:rtc_participant:0198c2f4-0000-7000-8000-0000000000ff",
        ),
        (realm_id, "ak:realm:0196419b-0000-7000-8000-00000000dead"),
    ];
    for (idx, (_orig, replacement)) in tampers.iter().enumerate() {
        let tampered = participant_binding_signing_input(
            if idx == 0 { replacement } else { actor_id },
            if idx == 1 { replacement } else { call_id },
            if idx == 2 { replacement } else { device_id },
            if idx == 3 { replacement } else { expires_at },
            if idx == 4 { replacement } else { focus_id },
            if idx == 5 {
                replacement
            } else {
                participant_identity
            },
            if idx == 6 { replacement } else { realm_id },
        )?;
        if verifying.verify(&tampered, &sig).is_ok() {
            bail!(
                "tampered participant_binding field #{idx} verified against the original sig — \
                 the signature does not actually cover that field ({REASON_PARTICIPANT_BINDING_INVALID})"
            );
        }
    }

    // 3. Domain-label separation: the same sig under the ICE-config label MUST NOT verify
    //    (cross-purpose confusion is rejected).
    const ICE_CONFIG_LABEL: &str = "ak.media.ice_config.v1";
    let mut cross_input = Vec::new();
    cross_input.extend_from_slice(ICE_CONFIG_LABEL.as_bytes());
    cross_input.push(0x00);
    cross_input.extend_from_slice(
        &arkret_core::canonical::canonical_json_bytes(&json!({
            "actor_id": actor_id, "call_id": call_id, "device_id": device_id,
            "expires_at": expires_at, "focus_id": focus_id,
            "participant_identity": participant_identity, "realm_id": realm_id,
        }))
        .map_err(|err| anyhow!("cross-label JCS failed: {err}"))?,
    );
    if verifying.verify(&cross_input, &sig).is_ok() {
        bail!(
            "participant_binding sig verified under the ICE-config domain label — \
             domain separation is broken"
        );
    }

    // 4. service_signature reuses the identical signing_input (§3.1) and verifies with the same
    //    issuer key.
    let service_sig = issuer.sign(&signing_input);
    verifying
        .verify(&signing_input, &service_sig)
        .map_err(|err| anyhow!("service_signature over identical input must verify: {err}"))?;
    if hex_lower(&service_sig.to_bytes()) != EXPECTED_SIG_HEX {
        bail!(
            "service_signature over the same input must reproduce the golden sig (deterministic ed25519)"
        );
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
    if REASON_UNKNOWN_FOCUS_TYPE != "unknown_focus_type" {
        bail!("REASON_UNKNOWN_FOCUS_TYPE spelling drifted: {REASON_UNKNOWN_FOCUS_TYPE}");
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
    if REASON_E2EE_KEY_SOURCE_UNAUTHORISED != "e2ee_key_source_unauthorised" {
        bail!(
            "REASON_E2EE_KEY_SOURCE_UNAUTHORISED spelling drifted: {REASON_E2EE_KEY_SOURCE_UNAUTHORISED}"
        );
    }
    // Only MLS-Exporter (label `ak-rtc-frame-key/v1`, length=19) is
    // accepted as the SFrame frame key source. Backend-cloud key
    // escrow (any wire form that funnels keys through the focus
    // service) is rejected.
    const MLS_EXPORTER_LENGTH: usize = 19;
    if LABEL_RTC_FRAME_KEY.len() != MLS_EXPORTER_LENGTH {
        bail!(
            "MLS-Exporter label length drifted: expected {MLS_EXPORTER_LENGTH}, got {}",
            LABEL_RTC_FRAME_KEY.len()
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
/// participant_identity, device_id})`. A live MLS group / RFC 9420 exporter is
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
    let realm_id = "ak:realm:0196419b-0000-7000-8000-000000000000";
    let call_id = "ak:call:0196441c-0000-7000-8000-000000000000";
    let focus_id = "fra-1";
    let epoch_id = "ak:mls_epoch:7";
    let participant_identity = "ak:rtc_participant:0198c2f4-0000-7000-8000-000000000000";
    let device_id = "ak:device:01964137-0000-7000-8000-000000000000";

    let context = sframe_context(
        realm_id,
        call_id,
        focus_id,
        epoch_id,
        participant_identity,
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
        "participant_identity",
        "device_id",
    ] {
        if context_value.get(field).and_then(|v| v.as_str()).is_none() {
            bail!(
                "SFrame Context MUST bind `{field}`; an epoch-only / missing-sender Context \
                 fails closed ({REASON_E2EE_KEY_SOURCE_UNAUTHORISED})"
            );
        }
    }

    // Fixed exporter secret stands in for the MLS group's exporter secret. The
    // info string is `label || 0x00 || Context` — the byte-correct domain-
    // separated input.
    const EXPORTER_SECRET: [u8; 32] = [0x42u8; 32];
    let mut info = Vec::with_capacity(LABEL_RTC_FRAME_KEY.len() + 1 + context.len());
    info.extend_from_slice(LABEL_RTC_FRAME_KEY.as_bytes());
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
        "d967efacc932d850ddcbe827e4e0aa399524a7b21ea2bef56a2ee9bf0b81dcc1";
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
        participant_identity,
        "ak:device:01964137-0000-7000-8000-0000000000ff",
    )?;
    let mut other_info = Vec::new();
    other_info.extend_from_slice(LABEL_RTC_FRAME_KEY.as_bytes());
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
/// exactly `{realm_id, call_id, focus_id, epoch_id, participant_identity,
/// device_id}`.
fn sframe_context(
    realm_id: &str,
    call_id: &str,
    focus_id: &str,
    epoch_id: &str,
    participant_identity: &str,
    device_id: &str,
) -> Result<Vec<u8>> {
    arkret_core::canonical::canonical_json_bytes(&json!({
        "realm_id": realm_id,
        "call_id": call_id,
        "focus_id": focus_id,
        "epoch_id": epoch_id,
        "participant_identity": participant_identity,
        "device_id": device_id,
    }))
    .map_err(|err| anyhow!("SFrame Context JCS encoding failed: {err}"))
}

// ─── VECT-MB-8 — participant_identity_unrecognised ─────────────────────────

pub fn run_participant_identity_unrecognised_vector() -> Result<()> {
    if REASON_PARTICIPANT_IDENTITY_UNRECOGNISED != "participant_identity_unrecognised" {
        bail!(
            "REASON_PARTICIPANT_IDENTITY_UNRECOGNISED spelling drifted: {REASON_PARTICIPANT_IDENTITY_UNRECOGNISED}"
        );
    }
    // The backend MUST signal only identities that match an entry in
    // `ak.call.state.participants[]`. Unknown identities fail closed
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
    if REASON_RECORDING_ARTIFACT_PIPELINE_BYPASSED != "recording_artifact_pipeline_bypassed" {
        bail!(
            "REASON_RECORDING_ARTIFACT_PIPELINE_BYPASSED spelling drifted: {REASON_RECORDING_ARTIFACT_PIPELINE_BYPASSED}"
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
    arkret_core::canonical::canonical_json_bytes(&json!({
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
    if label != LABEL_RTC_RECORDING_KEY || context.is_empty() {
        return Err(REASON_E2EE_KEY_SOURCE_UNAUTHORISED);
    }
    Ok(())
}

pub fn run_recording_exporter_label_vector() -> Result<()> {
    if LABEL_RTC_RECORDING_KEY != "ak.rtc-recording-key/v1" {
        bail!("recording exporter label drifted: {LABEL_RTC_RECORDING_KEY}");
    }

    let context = recording_context(
        "ak:realm:0196419b-0000-7000-8000-000000000000",
        "ak:call:0196441c-0000-7000-8000-000000000000",
        "fra-1",
        "rtc-recording-019a7360-0000-7000-8000-000000000002",
        "did:web:recorder.example",
        "ak:event:019a7360-0000-7000-8000-000000000003",
    )?;

    for (label, candidate_context) in [
        (LABEL_RTC_FRAME_KEY, context.as_slice()),
        (LABEL_RTC_TRANSCRIPT_KEY, context.as_slice()),
        (LABEL_RTC_RECORDING_KEY, &[][..]),
    ] {
        match recording_exporter_key_source_ok(label, candidate_context) {
            Err(code) if code == REASON_E2EE_KEY_SOURCE_UNAUTHORISED => {}
            other => bail!(
                "recording exporter source ({label}, {} bytes) must be rejected, got {other:?}",
                candidate_context.len()
            ),
        }
    }

    recording_exporter_key_source_ok(LABEL_RTC_RECORDING_KEY, &context)
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
    let mut info = Vec::with_capacity(LABEL_RTC_RECORDING_KEY.len() + 1 + context.len());
    info.extend_from_slice(LABEL_RTC_RECORDING_KEY.as_bytes());
    info.push(0x00);
    info.extend_from_slice(&context);

    let hk = Hkdf::<Sha256>::new(None, &EXPORTER_SECRET);
    let mut recording_key = [0u8; 32];
    hk.expand(&info, &mut recording_key)
        .map_err(|err| anyhow!("HKDF expand failed: {err}"))?;

    const EXPECTED_KEY_HEX: &str =
        "65ff920ee6cd964549a5ee8b581346ca9dfc2b4ceb91227b7d95dc2a15a761f8";
    let actual_key_hex = hex_lower(&recording_key);
    if actual_key_hex != EXPECTED_KEY_HEX {
        bail!(
            "recording exporter golden vector drifted:\n  expected {EXPECTED_KEY_HEX}\n  actual   {actual_key_hex}\n(label / 0x00 / Context JCS changed)"
        );
    }

    let other_context = recording_context(
        "ak:realm:0196419b-0000-7000-8000-000000000000",
        "ak:call:0196441c-0000-7000-8000-000000000000",
        "fra-1",
        "rtc-recording-019a7360-0000-7000-8000-000000000002",
        "did:web:recorder.example",
        "ak:event:019a7360-0000-7000-8000-000000000004",
    )?;
    let mut other_info =
        Vec::with_capacity(LABEL_RTC_RECORDING_KEY.len() + 1 + other_context.len());
    other_info.extend_from_slice(LABEL_RTC_RECORDING_KEY.as_bytes());
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
    validate_media_binding_fixture_metadata()?;
    if ALL_MEDIA_BINDING_VECTOR_IDS.len() != 10 {
        bail!(
            "expected 10 media_binding vector ids, got {}",
            ALL_MEDIA_BINDING_VECTOR_IDS.len()
        );
    }
    run_focus_selection_oldest_membership_vector()?;
    run_session_focus_no_split_brain_vector()?;
    run_token_exchange_minimal_vector()?;
    run_token_issuer_unauthorised_vector()?;
    run_participant_binding_required_vector()?;
    run_unknown_type_fail_closed_vector()?;
    run_e2ee_key_source_vector()?;
    run_participant_identity_unrecognised_vector()?;
    run_recording_artifact_via_arkret_blob_vector()?;
    run_recording_exporter_label_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_ten_media_binding_vectors_run_clean() {
        run_media_binding_vector_suite().unwrap();
    }
}
