//! Call-state media lifecycle conformance vectors (§12.16–§12.19).
//!
//! 5 vectors covering the recording-retention / recording-result artifact /
//! transcribe / moderation /
//! P2P→SFU-upgrade additions to `ak.call.state` and `ak.call.summary`:
//!
//! - `ak.vector.call_state.recording_retention_lock.v1`
//! - `ak.vector.call_state.recording_result_artifact_shape.v1`
//! - `ak.vector.call_state.transcribe_lifecycle.v1`
//! - `ak.vector.call_state.moderator_kick_ban.v1`
//! - `ak.vector.call_state.p2p_to_sfu_upgrade.v1`
//!
//! These are SDK-pure wire-shape pins. They lock the spelling of the new
//! reason codes (cotest mirrors the spec `error-code-registry.json`), the
//! transcript / recording MLS-Exporter labels and their distinct Context
//! field shapes (`exporter-label-registry.json`), the audit-lock-over-TTL
//! deletion gate, the moderation OR-Set token-reissue gate,
//! and the oldest-membership P2P→SFU upgrade / summary terminal-state gate, so
//! a downstream soland reducer regression hard-fails before reaching a live
//! integration target (see the `#[ignore]` live legs under `tests/`).
//!
//! `legal_hold_active` is the one reason code already minted in
//! `arkret_wire::error_codes`; the rest are pinned as local consts until the SDK
//! error enum grows them.

use anyhow::{Result, bail};
use arkret_identifiers::{BlobRef, CallId, Did, EventId, GrantId, Hash, PolicyId, RealmId};
use arkret_models_collaboration::events_payloads::call::{
    CallRecordingArtifact, CallRecordingArtifactKind, CallRecordingDeletionAudit,
    CallRecordingDeletionOutcome, CallRecordingDeletionTrigger, CallRecordingEncryption,
    CallRecordingEncryptionAlg, CallRecordingEncryptionContext, CallRecordingId,
    CallRecordingRetention, CallRecordingState, CallRecordingTransition, CallStatePayload,
    CallStatePayloadRecordingResult, CallStatePayloadTranscriptResult, CallTranscriptState,
    CallTranscriptTransition, RecordingStartPayload,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

// ── Canonical vector ids (registered in vector-registry.json) ───────────────

pub const VECTOR_ID_RECORDING_RETENTION_LOCK: &str =
    "ak.vector.call_state.recording_retention_lock.v1";
pub const VECTOR_ID_RECORDING_RESULT_ARTIFACT_SHAPE: &str =
    "ak.vector.call_state.recording_result_artifact_shape.v1";
pub const VECTOR_ID_TRANSCRIBE_LIFECYCLE: &str = "ak.vector.call_state.transcribe_lifecycle.v1";
pub const VECTOR_ID_MODERATOR_KICK_BAN: &str = "ak.vector.call_state.moderator_kick_ban.v1";
pub const VECTOR_ID_P2P_TO_SFU_UPGRADE: &str = "ak.vector.call_state.p2p_to_sfu_upgrade.v1";

/// Canonical list of the 5 call-state media-lifecycle vector ids.
pub const ALL_CALL_STATE_MEDIA_LIFECYCLE_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_RECORDING_RETENTION_LOCK,
    VECTOR_ID_RECORDING_RESULT_ARTIFACT_SHAPE,
    VECTOR_ID_TRANSCRIBE_LIFECYCLE,
    VECTOR_ID_MODERATOR_KICK_BAN,
    VECTOR_ID_P2P_TO_SFU_UPGRADE,
];

const CALL_STATE_MEDIA_LIFECYCLE_FIXTURE_FILE: &str = "call-state-media-lifecycle-fixture.json";
const CALL_STATE_MEDIA_LIFECYCLE_PROFILE: &str = "ak.profile.media_service_binding.v1";

fn validate_call_state_media_lifecycle_fixture_metadata() -> Result<()> {
    let fixture = super::load_fixture_value(CALL_STATE_MEDIA_LIFECYCLE_FIXTURE_FILE)?;
    super::validate_profile(&fixture, CALL_STATE_MEDIA_LIFECYCLE_PROFILE)?;
    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow::anyhow!("call-state media-lifecycle fixture missing covers_vectors[]")
        })?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("call-state media-lifecycle fixture missing cases[]"))?;

    for vector_id in ALL_CALL_STATE_MEDIA_LIFECYCLE_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("call-state media-lifecycle fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("call-state media-lifecycle fixture missing asserted case {vector_id}");
        }
    }

    Ok(())
}

// ── Reason-code spelling pins (error-code-registry.json) ────────────────────
//
// Mirrors the canonical spelling. Remaining local pins cover codes not yet
// surfaced as SDK constants.

// `arkret_wire::ReasonCode::TRANSCRIPTION_DENIED` /
// `arkret_wire::ReasonCode::TRANSCRIPTION_ARTIFACT_PIPELINE_BYPASSED` now come from
// `arkret_wire::error_codes` (imported above) instead of local pins.

// ── Exporter-label pins (exporter-label-registry.json) ──────────────────────

const LABEL_RTC_FRAME_KEY: &str = "ak.rtc-frame-key/v1";
const LABEL_RTC_RECORDING_KEY: &str = "ak.rtc-recording-key/v1";
const LABEL_RTC_TRANSCRIPT_KEY: &str = "ak.rtc-transcript-key/v1";

/// Terminal call states (`call-state.md` §4.2). `ak.call.summary` is gated on
/// the call head being one of these.
const TERMINAL_CALL_STATES: &[&str] = &["ended", "missed", "failed", "cancelled"];

// ─── §12.16 — recording_retention_lock ─────────────────────────────────────

/// Minimal retention descriptor mirroring `recording_result.retention`.
#[derive(Clone, Debug)]
struct RetentionState {
    audit_lock: bool,
    retention_expired: bool,
    deletion_trigger: &'static str,
}

/// Audit-lock precedence: a delete is permitted only when the audit lock is
/// clear AND the retention TTL has elapsed under a `retention_expiry` trigger.
/// An active audit lock blocks deletion regardless of TTL → `legal_hold_active`.
fn try_delete_recording(state: &RetentionState) -> std::result::Result<(), &'static str> {
    if state.audit_lock {
        return Err(arkret_wire::ReasonCode::LEGAL_HOLD_ACTIVE);
    }
    if !state.retention_expired || state.deletion_trigger != "retention_expiry" {
        return Err("retention_active");
    }
    Ok(())
}

/// Entering capture requires the recording-start result to confirm consent.
fn capture_consent_ok(consent_confirmed: bool) -> std::result::Result<(), &'static str> {
    if consent_confirmed {
        Ok(())
    } else {
        Err(arkret_wire::ReasonCode::RECORDING_CONSENT_REQUIRED)
    }
}

pub fn run_recording_retention_lock_vector() -> Result<()> {
    if arkret_wire::ReasonCode::LEGAL_HOLD_ACTIVE != "legal_hold_active" {
        bail!("arkret_wire::ReasonCode::LEGAL_HOLD_ACTIVE spelling drifted: legal_hold_active");
    }

    // Step 2 — delete before TTL with audit_lock set → legal_hold_active.
    let locked_before = RetentionState {
        audit_lock: true,
        retention_expired: false,
        deletion_trigger: "retention_expiry",
    };
    match try_delete_recording(&locked_before) {
        Err(code) if code == arkret_wire::ReasonCode::LEGAL_HOLD_ACTIVE => {}
        other => {
            bail!("delete before TTL under audit_lock must be legal_hold_active, got {other:?}")
        }
    }

    // Step 3 — delete after TTL but audit_lock still set → legal_hold_active
    // (audit_lock takes precedence over TTL and capability).
    let locked_after = RetentionState {
        audit_lock: true,
        retention_expired: true,
        deletion_trigger: "retention_expiry",
    };
    match try_delete_recording(&locked_after) {
        Err(code) if code == arkret_wire::ReasonCode::LEGAL_HOLD_ACTIVE => {}
        other => {
            bail!("delete after TTL under audit_lock must be legal_hold_active, got {other:?}")
        }
    }

    // Step 4 — capture start without consent_confirmed.
    match capture_consent_ok(false) {
        Err(code) if code == arkret_wire::ReasonCode::RECORDING_CONSENT_REQUIRED => {}
        other => bail!("capture without consent must be recording_consent_required, got {other:?}"),
    }

    // Controls — audit_lock clear + TTL elapsed deletes; consent set captures.
    let unlocked = RetentionState {
        audit_lock: false,
        retention_expired: true,
        deletion_trigger: "retention_expiry",
    };
    try_delete_recording(&unlocked)
        .map_err(|code| anyhow::anyhow!("control delete unexpectedly rejected: {code}"))?;
    capture_consent_ok(true)
        .map_err(|code| anyhow::anyhow!("control capture unexpectedly rejected: {code}"))?;
    Ok(())
}

// ─── §12.16.1 — recording_result_artifact_shape ────────────────────────────

fn ts(value: &str) -> DateTime<Utc> {
    arkret_canonical::parse_timestamp_canonical(value).unwrap()
}

fn realm_id() -> RealmId {
    RealmId::new("ak:realm:019a7360-0000-7000-8000-000000000000").unwrap()
}

fn call_id() -> CallId {
    CallId::new("ak:call:019a7360-0000-7000-8000-000000000001").unwrap()
}

fn start_event_id() -> EventId {
    EventId::new("ak:event:019a7360-0000-7000-8000-000000000003").unwrap()
}

fn hash(ch: char) -> Hash {
    Hash::new(format!("sha256:{}", ch.to_string().repeat(64))).unwrap()
}

fn valid_recording_artifact() -> CallRecordingArtifact {
    let recording_id =
        CallRecordingId::new("rtc-recording-019a7360-0000-7000-8000-000000000002").unwrap();
    CallRecordingArtifact {
        schema: CallRecordingArtifact::SCHEMA.to_owned(),
        realm_id: realm_id(),
        call_id: call_id(),
        recording_id: recording_id.clone(),
        recording_start_event_id: start_event_id(),
        artifact_kind: CallRecordingArtifactKind::Recording,
        blob_ref: BlobRef::new("ak:blob:019a7360-0000-7000-8000-000000000004").unwrap(),
        content_digest: hash('a'),
        ciphertext_digest: hash('b'),
        size_bytes: 1_048_576,
        duration_ms: 42_000,
        media_type: "video/mp4".to_owned(),
        encryption: CallRecordingEncryption {
            alg: CallRecordingEncryptionAlg::MlsExporterAeadXchacha20poly1305Stream,
            exporter_label: LABEL_RTC_RECORDING_KEY.to_owned(),
            context: CallRecordingEncryptionContext {
                realm_id: realm_id(),
                call_id: call_id(),
                focus_id: "fra-1".to_owned(),
                recording_id,
                media_service_id: Did::new("did:web:recorder.example").unwrap(),
                recording_start_event_id: start_event_id(),
            },
            ciphertext_digest: hash('b'),
        },
        retention_policy_id: Some(
            PolicyId::new("ak:policy:019a7360-0000-7000-8000-000000000005").unwrap(),
        ),
        retention: CallRecordingRetention {
            retention_expires_at: Some(ts("2026-06-20T00:00:00.000Z")),
            deletion_trigger: Some(CallRecordingDeletionTrigger::RetentionExpiry),
            audit_lock: Some(false),
            consent_confirmed: Some(true),
        },
        produced_by: Did::new("did:web:recorder.example").unwrap(),
        recording_initiator_capability_ref: GrantId::new(
            "ak:grant:019a7360-0000-7000-8000-000000000006",
        )
        .unwrap(),
        created_at: ts("2026-06-19T00:00:00.000Z"),
        deletion_audit: Some(CallRecordingDeletionAudit {
            trigger: CallRecordingDeletionTrigger::RetentionExpiry,
            outcome: CallRecordingDeletionOutcome::Completed,
            requested_by: None,
            trigger_event_id: None,
            requested_at: ts("2026-06-20T00:00:00.000Z"),
            completed_at: Some(ts("2026-06-20T00:00:01.000Z")),
            erasure_receipt_ref: Some("ak:receipt:019a7360-0000-7000-8000-000000000007".to_owned()),
            legal_hold_ref: None,
            failure_reason_code: None,
        }),
    }
}

fn ready_call_state_payload(artifact: Option<CallRecordingArtifact>) -> CallStatePayload {
    let artifact_ref = artifact.as_ref();
    CallStatePayload {
        call_id: call_id(),
        state_transition: None,
        focus: None,
        recording_transition: Some(CallRecordingTransition {
            recording_id: CallRecordingId::new(
                "rtc-recording-019a7360-0000-7000-8000-000000000002",
            )
            .unwrap(),
            from: CallRecordingState::Stopped,
            to: CallRecordingState::Ready,
            result: Some(CallStatePayloadRecordingResult {
                content_digest: artifact_ref.map(|artifact| artifact.content_digest.clone()),
                duration_ms: artifact_ref.map(|artifact| artifact.duration_ms),
                media_type: artifact_ref.map(|artifact| artifact.media_type.clone()),
                retention_policy_id: artifact_ref
                    .and_then(|artifact| artifact.retention_policy_id.clone()),
                retention: artifact_ref.map(|artifact| artifact.retention.clone()),
                recording_start_event_id: artifact_ref
                    .map(|artifact| artifact.recording_start_event_id.clone()),
                artifact,
                failure_reason_code: None,
                failure_message: None,
            }),
        }),
        transcript_transition: None,
        roster_delta: None,
        moderation_delta: None,
        mute_override: None,
    }
}

fn value_has_backend_direct_ref(value: &Value) -> bool {
    match value {
        Value::String(value) => {
            let lower = value.to_ascii_lowercase();
            lower.contains("http://")
                || lower.contains("https://")
                || lower.contains("s3://")
                || lower.contains("gs://")
                || lower.contains("s3.amazonaws.com")
                || lower.contains("storage.googleapis.com")
                || lower.contains("livekit")
        }
        Value::Array(values) => values.iter().any(value_has_backend_direct_ref),
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "url" | "download_url" | "recording_url" | "destination" | "external_url"
            ) || value_has_backend_direct_ref(value)
        }),
        _ => false,
    }
}

fn evaluate_recording_result_artifact_shape(
    value: Value,
    deletion_completed: bool,
) -> std::result::Result<(), &'static str> {
    if value_has_backend_direct_ref(&value) {
        return Err(arkret_wire::ReasonCode::RECORDING_ARTIFACT_PIPELINE_BYPASSED);
    }
    let payload: CallStatePayload =
        serde_json::from_value(value).map_err(|_| arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
    payload.validate_recording_result_artifact()?;
    let artifact = payload
        .recording_transition
        .as_ref()
        .and_then(|transition| transition.result.as_ref())
        .and_then(|result| result.artifact.as_ref())
        .ok_or(arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
    if deletion_completed {
        let audit = artifact
            .deletion_audit
            .as_ref()
            .ok_or(arkret_wire::ErrorCode::SCHEMA_VIOLATION)?;
        if audit.outcome != CallRecordingDeletionOutcome::Completed
            || audit
                .erasure_receipt_ref
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return Err(arkret_wire::ErrorCode::SCHEMA_VIOLATION);
        }
    }
    Ok(())
}

pub fn run_recording_result_artifact_shape_vector() -> Result<()> {
    if CallRecordingArtifact::SCHEMA != "ak.schema.call_recording_artifact.v1" {
        bail!(
            "CallRecordingArtifact schema spelling drifted: {}",
            CallRecordingArtifact::SCHEMA
        );
    }
    if arkret_wire::ReasonCode::RECORDING_ARTIFACT_PIPELINE_BYPASSED
        != "recording_artifact_pipeline_bypassed"
    {
        bail!(
            "arkret_wire::ReasonCode::RECORDING_ARTIFACT_PIPELINE_BYPASSED spelling drifted: recording_artifact_pipeline_bypassed"
        );
    }

    match evaluate_recording_result_artifact_shape(
        serde_json::to_value(ready_call_state_payload(None)).unwrap(),
        false,
    ) {
        Err(code) if code == arkret_wire::ErrorCode::SCHEMA_VIOLATION => {}
        other => bail!("ready recording without artifact must be schema_violation, got {other:?}"),
    }

    let mut direct_result =
        serde_json::to_value(ready_call_state_payload(Some(valid_recording_artifact()))).unwrap();
    direct_result["recording_transition"]["result"]["recording_url"] =
        json!("https://s3.amazonaws.com/bucket/recording.mp4");
    match evaluate_recording_result_artifact_shape(direct_result, false) {
        Err(code) if code == arkret_wire::ReasonCode::RECORDING_ARTIFACT_PIPELINE_BYPASSED => {}
        other => bail!("backend direct result URL must be pipeline bypass, got {other:?}"),
    }

    let mut direct_artifact =
        serde_json::to_value(ready_call_state_payload(Some(valid_recording_artifact()))).unwrap();
    direct_artifact["recording_transition"]["result"]["artifact"]["destination"] =
        json!("livekit://egress/recording-1");
    match evaluate_recording_result_artifact_shape(direct_artifact, false) {
        Err(code) if code == arkret_wire::ReasonCode::RECORDING_ARTIFACT_PIPELINE_BYPASSED => {}
        other => {
            bail!("backend direct artifact destination must be pipeline bypass, got {other:?}")
        }
    }

    let mut missing_audit = valid_recording_artifact();
    missing_audit.deletion_audit = None;
    match evaluate_recording_result_artifact_shape(
        serde_json::to_value(ready_call_state_payload(Some(missing_audit))).unwrap(),
        true,
    ) {
        Err(code) if code == arkret_wire::ErrorCode::SCHEMA_VIOLATION => {}
        other => bail!("completed deletion without deletion_audit must fail closed, got {other:?}"),
    }

    let mut missing_receipt = valid_recording_artifact();
    missing_receipt
        .deletion_audit
        .as_mut()
        .unwrap()
        .erasure_receipt_ref = None;
    match evaluate_recording_result_artifact_shape(
        serde_json::to_value(ready_call_state_payload(Some(missing_receipt))).unwrap(),
        true,
    ) {
        Err(code) if code == arkret_wire::ErrorCode::SCHEMA_VIOLATION => {}
        other => {
            bail!("completed deletion without erasure_receipt_ref must fail closed, got {other:?}")
        }
    }

    evaluate_recording_result_artifact_shape(
        serde_json::to_value(ready_call_state_payload(Some(valid_recording_artifact()))).unwrap(),
        true,
    )
    .map_err(|code| anyhow::anyhow!("valid recording artifact unexpectedly rejected: {code}"))?;
    Ok(())
}

// ─── §12.17 — transcribe_lifecycle ─────────────────────────────────────────

/// Transcription requires the `ak.call.transcribe` capability.
fn transcribe_authorised(has_transcribe_cap: bool) -> std::result::Result<(), &'static str> {
    if has_transcribe_cap {
        Ok(())
    } else {
        Err(arkret_wire::ReasonCode::TRANSCRIPTION_DENIED)
    }
}

/// Transcript artifacts MUST use the dedicated `ak-rtc-transcript-key/v1`
/// label with a non-empty Context; reusing the SFrame / recording label or an
/// empty Context fails closed with `transcription_artifact_pipeline_bypassed`.
fn transcript_key_source_ok(
    label: &str,
    context_fields: &[&str],
) -> std::result::Result<(), &'static str> {
    if label != LABEL_RTC_TRANSCRIPT_KEY {
        return Err(arkret_wire::ReasonCode::TRANSCRIPTION_ARTIFACT_PIPELINE_BYPASSED);
    }
    if context_fields.is_empty() {
        return Err(arkret_wire::ReasonCode::TRANSCRIPTION_ARTIFACT_PIPELINE_BYPASSED);
    }
    Ok(())
}

pub fn run_transcribe_lifecycle_vector() -> Result<()> {
    let start_value = json!({
        "call_id": call_id().to_string(),
        "recording_id": "transcript-019a7360-0000-7000-8000-000000000002",
        "recording_agent": "did:web:recorder.example",
        "capture_kind": "transcript",
        "mode": "audio",
        "visible_notice": true,
        "result": {
            "transcript_start_event_id": start_event_id(),
            "retention": {
                "consent_confirmed": true
            }
        }
    });
    let start_payload = serde_json::from_value::<RecordingStartPayload>(start_value.clone())
        .map_err(|error| anyhow::anyhow!("valid transcript start rejected: {error}"))?;
    start_payload
        .validate(&start_event_id())
        .map_err(|error| anyhow::anyhow!("valid transcript start rejected: {error}"))?;
    let mut missing_mode = start_value.clone();
    missing_mode.as_object_mut().unwrap().remove("mode");
    if serde_json::from_value::<RecordingStartPayload>(missing_mode).is_ok() {
        bail!("recording start without mode must be schema_violation");
    }
    let mut noncanonical_recording_id = start_value;
    noncanonical_recording_id["recording_id"] = json!("transcript id");
    if serde_json::from_value::<RecordingStartPayload>(noncanonical_recording_id).is_ok() {
        bail!("recording start with noncanonical recording_id must be schema_violation");
    }

    // Step 1 — transcribe without capability is denied.
    match transcribe_authorised(false) {
        Err(code) if code == arkret_wire::ReasonCode::TRANSCRIPTION_DENIED => {}
        other => bail!("transcribe without cap must be transcription_denied, got {other:?}"),
    }
    transcribe_authorised(true)
        .map_err(|code| anyhow::anyhow!("authorised transcribe unexpectedly denied: {code}"))?;

    // Step 2 — reusing the SFrame label or empty Context is bypass.
    for (label, context) in [
        (LABEL_RTC_FRAME_KEY, &["realm_id"][..]),
        (LABEL_RTC_RECORDING_KEY, &["realm_id"][..]),
        (LABEL_RTC_TRANSCRIPT_KEY, &[][..]),
    ] {
        match transcript_key_source_ok(label, context) {
            Err(code)
                if code == arkret_wire::ReasonCode::TRANSCRIPTION_ARTIFACT_PIPELINE_BYPASSED => {}
            other => bail!(
                "transcript key reuse ({label}, {context:?}) must be \
                 transcription_artifact_pipeline_bypassed, got {other:?}"
            ),
        }
    }

    // Step 3 — dedicated label + full Context is accepted.
    let transcript_context = [
        "realm_id",
        "call_id",
        "focus_id",
        "recording_id",
        "media_service_id",
        "transcript_start_event_id",
    ];
    transcript_key_source_ok(LABEL_RTC_TRANSCRIPT_KEY, &transcript_context)
        .map_err(|code| anyhow::anyhow!("control transcript key unexpectedly rejected: {code}"))?;

    let ready = CallStatePayload {
        call_id: call_id(),
        state_transition: None,
        focus: None,
        recording_transition: None,
        transcript_transition: Some(CallTranscriptTransition {
            recording_id: CallRecordingId::new("transcript-019a7360-0000-7000-8000-000000000002")
                .unwrap(),
            from: CallTranscriptState::Stopped,
            to: CallTranscriptState::Ready,
            result: Some(CallStatePayloadTranscriptResult {
                content_digest: Some(hash('c')),
                media_type: Some("text/vtt".to_owned()),
                language: Some("en-US".to_owned()),
                retention_policy_id: Some(
                    PolicyId::new("ak:policy:019a7360-0000-7000-8000-000000000005").unwrap(),
                ),
                retention: Some(CallRecordingRetention {
                    retention_expires_at: Some(ts("2026-06-20T00:00:00.000Z")),
                    deletion_trigger: Some(CallRecordingDeletionTrigger::RetentionExpiry),
                    audit_lock: Some(false),
                    consent_confirmed: Some(true),
                }),
                transcript_start_event_id: Some(start_event_id()),
                failure_reason_code: None,
            }),
        }),
        roster_delta: None,
        moderation_delta: None,
        mute_override: None,
    };
    ready
        .validate_transcript_result_storage()
        .map_err(|code| anyhow::anyhow!("typed transcript result unexpectedly rejected: {code}"))?;

    let bypass = json!({
        "call_id": call_id().to_string(),
        "transcript_transition": {
            "recording_id": "transcript-019a7360-0000-7000-8000-000000000002",
            "from": "stopped",
            "to": "ready",
            "result": {
                "transcript_artifact_url": "https://backend.example/transcript.vtt"
            }
        }
    });
    if serde_json::from_value::<CallStatePayload>(bypass).is_ok() {
        bail!("transcript_result must reject backend-hosted artifact URLs");
    }

    let failed = json!({
        "call_id": call_id().to_string(),
        "transcript_transition": {
            "recording_id": "transcript-019a7360-0000-7000-8000-000000000002",
            "from": "transcribing",
            "to": "failed",
            "result": {
                "transcript_start_event_id": start_event_id().to_string(),
                "failure_reason_code": "storage_failed"
            }
        }
    });
    let failed_payload: CallStatePayload = serde_json::from_value(failed.clone())
        .map_err(|error| anyhow::anyhow!("registered transcript failure rejected: {error}"))?;
    failed_payload
        .validate_transcript_result_storage()
        .map_err(|code| anyhow::anyhow!("registered transcript failure invalid: {code}"))?;
    let mut unknown_failure = failed;
    unknown_failure["transcript_transition"]["result"]["failure_reason_code"] =
        json!("vendor_timeout");
    if serde_json::from_value::<CallStatePayload>(unknown_failure).is_ok() {
        bail!("unregistered transcript failure reason must be schema_violation");
    }

    // The three labels are mutually distinct (no cross-label reuse).
    if LABEL_RTC_FRAME_KEY == LABEL_RTC_RECORDING_KEY
        || LABEL_RTC_FRAME_KEY == LABEL_RTC_TRANSCRIPT_KEY
        || LABEL_RTC_RECORDING_KEY == LABEL_RTC_TRANSCRIPT_KEY
    {
        bail!("exporter labels must be mutually distinct");
    }
    Ok(())
}

// ─── §12.18 — moderator_kick_ban ───────────────────────────────────────────

/// An effective moderation OR-Set value. A missing `device_id` encodes an
/// actor-wide ban.
#[derive(Clone, Debug)]
struct RemovedParticipant {
    actor_id: &'static str,
    device_id: Option<&'static str>,
}

/// A moderator action requires `ak.call.moderate`.
fn moderation_authorised(has_moderate_cap: bool) -> std::result::Result<(), &'static str> {
    if has_moderate_cap {
        Ok(())
    } else {
        Err(arkret_wire::ReasonCode::CALL_MODERATION_UNAUTHORISED)
    }
}

/// Token re-issue is gated on the effective moderation OR-Set: a kicked device
/// `(actor, device)` is refused, and a banned actor (device_id omitted) is
/// refused for any device. A non-removed device of an un-banned actor passes.
fn token_reissue_allowed(
    removed: &[RemovedParticipant],
    actor_id: &str,
    device_id: &str,
) -> std::result::Result<(), &'static str> {
    for entry in removed {
        if entry.actor_id != actor_id {
            continue;
        }
        match entry.device_id {
            // Actor-wide ban: every device of this actor is refused.
            None => return Err(arkret_wire::ReasonCode::CALL_PARTICIPANT_REMOVED),
            // Device-scoped kick: only the named device is refused.
            Some(removed_device) if removed_device == device_id => {
                return Err(arkret_wire::ReasonCode::CALL_PARTICIPANT_REMOVED);
            }
            Some(_) => {}
        }
    }
    Ok(())
}

pub fn run_moderator_kick_ban_vector() -> Result<()> {
    // Step 1 — moderation without ak.call.moderate is unauthorised.
    match moderation_authorised(false) {
        Err(code) if code == arkret_wire::ReasonCode::CALL_MODERATION_UNAUTHORISED => {}
        other => {
            bail!("moderation without cap must be call_moderation_unauthorised, got {other:?}")
        }
    }
    moderation_authorised(true)
        .map_err(|code| anyhow::anyhow!("authorised moderation unexpectedly denied: {code}"))?;

    // Step 2 — kicked device is refused on re-issue, but a fresh join from the
    // same actor on a different device is NOT blocked by a device-scoped kick.
    let kicked = [RemovedParticipant {
        actor_id: "did:web:bob.example",
        device_id: Some("ak:device:bob-1"),
    }];
    match token_reissue_allowed(&kicked, "did:web:bob.example", "ak:device:bob-1") {
        Err(code) if code == arkret_wire::ReasonCode::CALL_PARTICIPANT_REMOVED => {}
        other => bail!("kicked device re-issue must be call_participant_removed, got {other:?}"),
    }
    token_reissue_allowed(&kicked, "did:web:bob.example", "ak:device:bob-2")
        .map_err(|code| anyhow::anyhow!("same-actor new device must rejoin after kick: {code}"))?;

    // Step 3/4 — a banned actor (device_id omitted) is refused for any device.
    let banned = [RemovedParticipant {
        actor_id: "did:web:bob.example",
        device_id: None,
    }];
    for device in ["ak:device:bob-1", "ak:device:bob-2"] {
        match token_reissue_allowed(&banned, "did:web:bob.example", device) {
            Err(code) if code == arkret_wire::ReasonCode::CALL_PARTICIPANT_REMOVED => {}
            other => bail!(
                "banned actor re-issue ({device}) must be call_participant_removed, got {other:?}"
            ),
        }
    }

    // Control — an unrelated actor is not gated.
    token_reissue_allowed(&banned, "did:web:carol.example", "ak:device:carol-1")
        .map_err(|code| anyhow::anyhow!("unrelated actor unexpectedly gated: {code}"))?;
    Ok(())
}

// ─── §12.19 — p2p_to_sfu_upgrade & summary gate ────────────────────────────

/// P2P calls MUST converge to SFU once the active leg exceeds two; mode MUST
/// NOT auto-downgrade back to p2p within the same lifecycle.
fn resolve_mode(initial_mode: &str, active_participants: usize) -> &'static str {
    if initial_mode == "p2p" && active_participants > 2 {
        "sfu"
    } else if initial_mode == "p2p" {
        "p2p"
    } else {
        "sfu"
    }
}

fn is_terminal_call_state(state: &str) -> bool {
    TERMINAL_CALL_STATES.contains(&state)
}

/// `ak.call.summary` is accepted only when its `final_state` is terminal and
/// matches the call head; otherwise `call_summary_invalid`.
fn summary_accepted(final_state: &str) -> std::result::Result<(), &'static str> {
    if is_terminal_call_state(final_state) {
        Ok(())
    } else {
        Err(arkret_wire::ReasonCode::CALL_SUMMARY_INVALID)
    }
}

pub fn run_p2p_to_sfu_upgrade_vector() -> Result<()> {
    // Step 1 — third active participant forces SFU; 3 participants MUST NOT be
    // carried over P2P / mesh.
    if resolve_mode("p2p", 3) != "sfu" {
        bail!("p2p with 3 active participants must upgrade to sfu");
    }
    // Step 3 — falling back to 2 does NOT auto-downgrade an already-sfu call.
    if resolve_mode("sfu", 2) != "sfu" {
        bail!("sfu must not auto-downgrade to p2p when participants fall to 2");
    }
    // Two-party p2p stays p2p.
    if resolve_mode("p2p", 2) != "p2p" {
        bail!("two-party p2p must stay p2p");
    }

    // Step 4 — summary on a terminal call is accepted; on an active call it is
    // call_summary_invalid.
    for terminal in TERMINAL_CALL_STATES {
        summary_accepted(terminal)
            .map_err(|code| anyhow::anyhow!("summary on terminal {terminal} rejected: {code}"))?;
    }
    for non_terminal in ["scheduled", "ringing", "connecting", "active"] {
        match summary_accepted(non_terminal) {
            Err(code) if code == arkret_wire::ReasonCode::CALL_SUMMARY_INVALID => {}
            other => bail!("summary on {non_terminal} must be call_summary_invalid, got {other:?}"),
        }
    }
    Ok(())
}

/// Suite entry point — runs all 5 call-state media-lifecycle vectors back to
/// back. One failure stops the run with full context.
pub fn run_call_state_media_lifecycle_vector_suite() -> Result<()> {
    validate_call_state_media_lifecycle_fixture_metadata()?;
    if ALL_CALL_STATE_MEDIA_LIFECYCLE_VECTOR_IDS.len() != 5 {
        bail!(
            "expected 5 call_state media-lifecycle vector ids, got {}",
            ALL_CALL_STATE_MEDIA_LIFECYCLE_VECTOR_IDS.len()
        );
    }
    run_recording_retention_lock_vector()?;
    run_recording_result_artifact_shape_vector()?;
    run_transcribe_lifecycle_vector()?;
    run_moderator_kick_ban_vector()?;
    run_p2p_to_sfu_upgrade_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_five_call_state_media_lifecycle_vectors_run_clean() {
        run_call_state_media_lifecycle_vector_suite().unwrap();
    }
}
