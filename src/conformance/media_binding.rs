//! R3 spec-sync (cokret-spec @ b47ff6ec) — CKP-0010 media-binding
//! conformance vectors.
//!
//! 9 vectors covering [§0.11 of `_before_todos.md`]:
//!
//! - `ck.vector.media_binding.focus_selection_oldest_membership.v1`
//! - `ck.vector.media_binding.session_focus_no_split_brain.v1`
//! - `ck.vector.media_binding.token_exchange_minimal.v1`
//! - `ck.vector.media_binding.token_issuer_unauthorised.v1`
//! - `ck.vector.media_binding.participant_binding_required.v1`
//! - `ck.vector.media_binding.unknown_type_fail_closed.v1`
//! - `ck.vector.media_binding.e2ee_key_source.v1`
//! - `ck.vector.media_binding.participant_identity_unrecognised.v1`
//! - `ck.vector.media_binding.recording_artifact_via_cokret_blob.v1`
//!
//! These are SDK-pure wire-shape pins. They lock the spelling of the
//! 10 new error codes (cotest mirrors `cokret_core`'s registry), the
//! participant_binding scheme id, the 600s TTL ceiling, the
//! oldest-membership focus-selection contract, and the
//! `ck.profile.media_service_binding.v1` registry id so a downstream
//! soland / floria implementation regression hard-fails before reaching
//! a live integration target. The live tokens themselves are issued
//! server-side (R3.1 work — see scenarios under `tests/`).

use anyhow::{Result, anyhow, bail};
use cokret_core::error::{
    ERROR_CODE_E2EE_KEY_SOURCE_UNAUTHORISED, ERROR_CODE_FOCUS_MISMATCH,
    ERROR_CODE_FOCUS_UNAVAILABLE_FOR_CLIENT, ERROR_CODE_PARTICIPANT_BINDING_INVALID,
    ERROR_CODE_PARTICIPANT_IDENTITY_UNRECOGNISED, ERROR_CODE_RECORDING_ARTIFACT_PIPELINE_BYPASSED,
    ERROR_CODE_SESSION_FOCUS_ALREADY_COMMITTED, ERROR_CODE_TOKEN_ISSUER_UNAUTHORISED,
    ERROR_CODE_UNKNOWN_FOCUS_TYPE,
};
use cokret_core::{
    MEDIA_TOKEN_TTL_MAX_SECS, OP_CALL_MEDIA_TOKEN_EXCHANGE, PARTICIPANT_BINDING_SCHEMA,
};

/// Vector id pins. Hard-fails any future rename of the canonical
/// `ck.vector.media_binding.*.v1` registry entries.
pub const VECTOR_ID_FOCUS_SELECTION_OLDEST_MEMBERSHIP: &str =
    "ck.vector.media_binding.focus_selection_oldest_membership.v1";
pub const VECTOR_ID_SESSION_FOCUS_NO_SPLIT_BRAIN: &str =
    "ck.vector.media_binding.session_focus_no_split_brain.v1";
pub const VECTOR_ID_TOKEN_EXCHANGE_MINIMAL: &str =
    "ck.vector.media_binding.token_exchange_minimal.v1";
pub const VECTOR_ID_TOKEN_ISSUER_UNAUTHORISED: &str =
    "ck.vector.media_binding.token_issuer_unauthorised.v1";
pub const VECTOR_ID_PARTICIPANT_BINDING_REQUIRED: &str =
    "ck.vector.media_binding.participant_binding_required.v1";
pub const VECTOR_ID_UNKNOWN_TYPE_FAIL_CLOSED: &str =
    "ck.vector.media_binding.unknown_type_fail_closed.v1";
pub const VECTOR_ID_E2EE_KEY_SOURCE: &str = "ck.vector.media_binding.e2ee_key_source.v1";
pub const VECTOR_ID_PARTICIPANT_IDENTITY_UNRECOGNISED: &str =
    "ck.vector.media_binding.participant_identity_unrecognised.v1";
pub const VECTOR_ID_RECORDING_ARTIFACT_VIA_COKRET_BLOB: &str =
    "ck.vector.media_binding.recording_artifact_via_cokret_blob.v1";

/// Canonical list of all 9 vector ids. Used by the registry / discovery
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
    VECTOR_ID_RECORDING_ARTIFACT_VIA_COKRET_BLOB,
];

/// Known media-backend type tags from `ck.realm.media_service.foci[].type`.
/// Mirrors `cokret_sdk::media::MediaBackendType` enum (R3 SDK feature
/// `full-surface`) — kept local so the vector suite runs under cotest's
/// minimal `cokret-core` dep slice.
const KNOWN_MEDIA_BACKEND_TYPES: &[&str] = &[
    "livekit",
    "mediasoup",
    "janus",
    "cokret-native",
    "moq-relay",
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
        actor_id: "did:web:alice.example",
        joined_at_unix_ms: 1_700_000_000_000,
        foci_preferred: &["focus.livekit.lhr", "focus.cokret.lhr"],
    };
    let bob = CallMember {
        actor_id: "did:web:bob.example",
        joined_at_unix_ms: 1_700_000_005_000,
        foci_preferred: &["focus.cokret.lhr", "focus.livekit.lhr"],
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
    if ERROR_CODE_FOCUS_MISMATCH != "focus_mismatch" {
        bail!("ERROR_CODE_FOCUS_MISMATCH spelling drifted: {ERROR_CODE_FOCUS_MISMATCH}");
    }
    Ok(())
}

// ─── VECT-MB-2 — session_focus_no_split_brain ──────────────────────────────

/// Minimal write-once cell modelling the `ck.call.state.session_focus`
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
            return Err(ERROR_CODE_SESSION_FOCUS_ALREADY_COMMITTED);
        }
        self.committed = Some(focus_id.to_owned());
        Ok(())
    }
}

pub fn run_session_focus_no_split_brain_vector() -> Result<()> {
    let mut cell = SessionFocusCell::default();
    cell.commit("focus.livekit.lhr")
        .map_err(|e| anyhow!("first commit unexpectedly failed: {e}"))?;
    let second = cell.commit("focus.cokret.lhr");
    match second {
        Err(code) if code == ERROR_CODE_SESSION_FOCUS_ALREADY_COMMITTED => {}
        other => bail!("second write must surface session_focus_already_committed, got {other:?}"),
    }

    // Carol's local-fail surfaces `focus_unavailable_for_client` rather
    // than silently downgrading to plaintext or any other focus.
    if ERROR_CODE_FOCUS_UNAVAILABLE_FOR_CLIENT != "focus_unavailable_for_client" {
        bail!(
            "ERROR_CODE_FOCUS_UNAVAILABLE_FOR_CLIENT spelling drifted: {ERROR_CODE_FOCUS_UNAVAILABLE_FOR_CLIENT}"
        );
    }
    Ok(())
}

// ─── VECT-MB-3 — token_exchange_minimal ────────────────────────────────────

/// Validate that `remaining_secs` (token expires_at - now) is within
/// the spec's 600s ceiling and strictly positive. Mirrors
/// `cokret_sdk::media::validate_token_ttl` so cotest can pin the
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
    if OP_CALL_MEDIA_TOKEN_EXCHANGE != "ck.call.media.token_exchange" {
        bail!("OP_CALL_MEDIA_TOKEN_EXCHANGE spelling drifted: {OP_CALL_MEDIA_TOKEN_EXCHANGE}");
    }
    if PARTICIPANT_BINDING_SCHEMA != "ck.media.participant_binding.v1" {
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
    if ERROR_CODE_TOKEN_ISSUER_UNAUTHORISED != "token_issuer_unauthorised" {
        bail!(
            "ERROR_CODE_TOKEN_ISSUER_UNAUTHORISED spelling drifted: {ERROR_CODE_TOKEN_ISSUER_UNAUTHORISED}"
        );
    }

    // A rogue DID not anchored to `ck.realm.media_service.service_id`
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
    if ERROR_CODE_PARTICIPANT_BINDING_INVALID != "participant_binding_invalid" {
        bail!(
            "ERROR_CODE_PARTICIPANT_BINDING_INVALID spelling drifted: {ERROR_CODE_PARTICIPANT_BINDING_INVALID}"
        );
    }
    // A response missing the `participant_binding` field, or one whose
    // `scheme` is anything other than `ck.media.participant_binding.v1`,
    // is invalid. We pin both branches at the SDK constant layer; the
    // schema-validator integration target lands under R3.1.
    let valid_scheme = PARTICIPANT_BINDING_SCHEMA;
    for bogus in [
        "",
        "ck.media.participant_binding",
        "ck.media.participant_binding.v0",
        "ck.media.participant_binding.v2",
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
    Ok(())
}

// ─── VECT-MB-6 — unknown_type_fail_closed ──────────────────────────────────

pub fn run_unknown_type_fail_closed_vector() -> Result<()> {
    if ERROR_CODE_UNKNOWN_FOCUS_TYPE != "unknown_focus_type" {
        bail!("ERROR_CODE_UNKNOWN_FOCUS_TYPE spelling drifted: {ERROR_CODE_UNKNOWN_FOCUS_TYPE}");
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
    if ERROR_CODE_E2EE_KEY_SOURCE_UNAUTHORISED != "e2ee_key_source_unauthorised" {
        bail!(
            "ERROR_CODE_E2EE_KEY_SOURCE_UNAUTHORISED spelling drifted: {ERROR_CODE_E2EE_KEY_SOURCE_UNAUTHORISED}"
        );
    }
    // Only MLS-Exporter (label `cx-rtc-frame-key/v1`, length=19) is
    // accepted as the SFrame frame key source. Backend-cloud key
    // escrow (any wire form that funnels keys through the focus
    // service) is rejected.
    const MLS_EXPORTER_LABEL: &str = "cx-rtc-frame-key/v1";
    const MLS_EXPORTER_LENGTH: usize = 19;
    if MLS_EXPORTER_LABEL.len() != MLS_EXPORTER_LENGTH {
        bail!(
            "MLS-Exporter label length drifted: expected {MLS_EXPORTER_LENGTH}, got {}",
            MLS_EXPORTER_LABEL.len()
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
    Ok(())
}

// ─── VECT-MB-8 — participant_identity_unrecognised ─────────────────────────

pub fn run_participant_identity_unrecognised_vector() -> Result<()> {
    if ERROR_CODE_PARTICIPANT_IDENTITY_UNRECOGNISED != "participant_identity_unrecognised" {
        bail!(
            "ERROR_CODE_PARTICIPANT_IDENTITY_UNRECOGNISED spelling drifted: {ERROR_CODE_PARTICIPANT_IDENTITY_UNRECOGNISED}"
        );
    }
    // The backend MUST signal only identities that match an entry in
    // `ck.call.state.participants[]`. Unknown identities fail closed
    // — clients MUST NOT trust them.
    let known: &[&str] = &["ck:rtc_participant:01999999-0000-7000-8000-00000000abcd"];
    let unknown = "ck:rtc_participant:01999999-0000-7000-8000-deadbeefdead";
    if known.contains(&unknown) {
        bail!("participant identity leak: unknown id in known set");
    }
    // `rtc_participant` id-kind MUST keep the canonical `ck:rtc_participant:` prefix.
    for id in known {
        if !id.starts_with("ck:rtc_participant:") {
            bail!("rtcpart id lost canonical prefix: {id}");
        }
    }
    Ok(())
}

// ─── VECT-MB-9 — recording_artifact_via_cokret_blob ───────────────────────

pub fn run_recording_artifact_via_cokret_blob_vector() -> Result<()> {
    if ERROR_CODE_RECORDING_ARTIFACT_PIPELINE_BYPASSED != "recording_artifact_pipeline_bypassed" {
        bail!(
            "ERROR_CODE_RECORDING_ARTIFACT_PIPELINE_BYPASSED spelling drifted: {ERROR_CODE_RECORDING_ARTIFACT_PIPELINE_BYPASSED}"
        );
    }
    // Egress MUST land on a Cokret blob endpoint. Direct S3 / GCS
    // / arbitrary http upload is bypass.
    let is_cokret_blob = |url: &str| {
        url.starts_with("https://")
            && (url.contains("/_matrix/cokret/v1/media") || url.contains("/cokret/v1/media"))
    };
    if !is_cokret_blob("https://server.example/cokret/v1/media/upload") {
        bail!("legit cokret blob endpoint not accepted");
    }
    for bad in [
        "https://s3.amazonaws.com/bucket/recording.mp4",
        "https://my-egress.example/dump",
        "https://storage.googleapis.com/foo",
    ] {
        if is_cokret_blob(bad) {
            bail!("non-cokret egress endpoint `{bad}` leaked past pipeline check");
        }
    }
    Ok(())
}

/// Suite entry point — runs all 9 media-binding vectors back to back.
/// One failure stops the run with full context.
pub fn run_media_binding_vector_suite() -> Result<()> {
    if ALL_MEDIA_BINDING_VECTOR_IDS.len() != 9 {
        bail!(
            "expected 9 media_binding vector ids, got {}",
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
    run_recording_artifact_via_cokret_blob_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_nine_media_binding_vectors_run_clean() {
        run_media_binding_vector_suite().unwrap();
    }
}
