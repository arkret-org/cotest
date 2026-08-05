use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use arkret_models_collaboration::http_bodies::{EventsSubscribeFrame, EventsSubscribeFrameKind};
use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeFrame, AccountSubscribeFrameKind,
};
use arkret_models_collaboration::sync_frames::stream_trace::{
    StreamTraceError, StreamTraceFrame, StreamTraceFrameKind, StreamTraceValidator,
};
use arkret_state::snapshot::{EventSetCommitmentAlgorithm, EventSetLeaf, event_set_root};
use arkret_wire::ErrorCode;
use serde_json::{Value, json};

use super::{
    load_fixture_value, looks_like_sha256_digest, required_field, validate_profile, value_array,
    value_field_str, value_field_u64,
};
use crate::transcripts::record_vector_event;

pub fn run_sync_fixture_suite() -> Result<()> {
    let value = load_fixture_value("sync-fixture.json")?;
    validate_profile(&value, "ak.vector_group.sync.v1")?;
    validate_collection_projection(&value)?;
    validate_strand_discussion_timeline(&value)?;
    validate_snapshot_frontier_recovery(&value)?;
    validate_snapshot_inclusion_challenge(&value)?;
    validate_e2ee_pending(&value)?;
    validate_realm_actor_frontier_vectors(&value)?;
    run_stream_frame_sequence_vector()?;
    Ok(())
}

fn validate_realm_actor_frontier_vectors(value: &Value) -> Result<()> {
    let cases = value_array(
        required_field(value, "schema_validation_cases")?,
        "sync schema_validation_cases",
    )?;
    for case in cases.iter().filter(|case| {
        case.get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| name.starts_with("realm_actor_frontier_"))
    }) {
        let expect_valid = case
            .get("expect_valid")
            .and_then(Value::as_bool)
            .ok_or_else(|| anyhow!("frontier schema case lacks expect_valid"))?;
        let decoded = serde_json::from_value::<
            arkret_models_collaboration::event_sync::RealmActorFrontierView,
        >(required_field(case, "instance")?.clone());
        let valid = decoded
            .as_ref()
            .is_ok_and(|frontier| frontier.validate().is_ok());
        if expect_valid != valid {
            bail!(
                "frontier case {} validity mismatch",
                value_field_str(case, "name")?
            );
        }
    }

    let vector = required_field(value, "actor_frontier_digest")?;
    let realm_id = arkret_identifiers::RealmId::new(
        "ak:realm:01904100-0000-8000-8000-000000000001".to_owned(),
    )?;
    let actor_id = arkret_identifiers::Did::new("did:web:alice.example".to_owned())?;
    let event_ids = vec![
        arkret_identifiers::EventId::new(
            "ak:event:01904100-0000-8000-8000-000000000001".to_owned(),
        )?,
        arkret_identifiers::EventId::new(
            "ak:event:01904100-0000-8000-8000-000000000002".to_owned(),
        )?,
    ];
    let digest = arkret_models_collaboration::event_sync::RealmActorFrontierView::compute_digest(
        &realm_id,
        &actor_id,
        43,
        &event_ids,
        arkret_canonical::DigestSuite::Sha256,
    )?;
    if digest.as_str() != value_field_str(vector, "expected_digest")? {
        bail!("Realm actor frontier digest golden mismatch");
    }
    Ok(())
}

const STREAM_FRAME_SEQUENCE_VECTOR_ID: &str = "ak.vector.sync.stream_frame_sequence.v1";

#[derive(Clone, Copy, Debug)]
enum StreamSurface {
    Account,
    Events,
}

impl StreamSurface {
    const fn operation_id(self) -> &'static str {
        match self {
            Self::Account => arkret_wire::ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE,
            Self::Events => arkret_wire::ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE,
        }
    }
}

enum EmittedStreamFrame {
    Account(Box<AccountSubscribeFrame>),
    Events(EventsSubscribeFrame),
}

impl StreamTraceFrame for EmittedStreamFrame {
    fn trace_kind(&self) -> StreamTraceFrameKind {
        match self {
            Self::Account(frame) => frame.trace_kind(),
            Self::Events(frame) => frame.trace_kind(),
        }
    }

    fn trace_cursor(&self) -> Option<&str> {
        match self {
            Self::Account(frame) => frame.trace_cursor(),
            Self::Events(frame) => frame.trace_cursor(),
        }
    }
}

fn exact_object_keys(value: &Value, expected: &[&str], context: &str) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("{context} must be an object"))?;
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        bail!("{context} fields must be exactly {expected:?}, got {actual:?}");
    }
    Ok(())
}

fn validate_stream_frame_shape(frame: &Value) -> Result<&str> {
    let kind = value_field_str(frame, "kind")?;
    let fields: &[&str] = match kind {
        "delta" => &["cursor", "kind", "partial"],
        "frontier" | "catchup_complete" => &["cursor", "kind"],
        "heartbeat" | "unauthorized" => &["kind"],
        "dropped" => &["cursor", "kind", "reconnect_after_ms"],
        "resync_required" => &["kind", "reconnect_after_ms"],
        other => bail!("unsupported stream trace frame kind {other}"),
    };
    exact_object_keys(frame, fields, "stream trace frame")?;
    if kind == "delta" && frame.get("partial").and_then(Value::as_bool) != Some(false) {
        bail!("stream trace baseline delta must set partial=false");
    }
    if matches!(kind, "delta" | "frontier" | "catchup_complete" | "dropped")
        && frame
            .get("cursor")
            .and_then(Value::as_str)
            .is_some_and(|cursor| cursor.trim().is_empty())
    {
        bail!("stream trace cursor must be non-empty when present");
    }
    Ok(kind)
}

fn emit_stream_frame(surface: StreamSurface, frame: &Value) -> Result<EmittedStreamFrame> {
    let kind = validate_stream_frame_shape(frame)?;
    let cursor = frame.get("cursor").and_then(Value::as_str);
    let reconnect_after_ms = frame.get("reconnect_after_ms").and_then(Value::as_u64);
    Ok(match surface {
        StreamSurface::Account => EmittedStreamFrame::Account(Box::new(AccountSubscribeFrame {
            kind: match kind {
                "delta" => AccountSubscribeFrameKind::Delta,
                "frontier" => AccountSubscribeFrameKind::Frontier,
                "heartbeat" => AccountSubscribeFrameKind::Heartbeat,
                "catchup_complete" => AccountSubscribeFrameKind::CatchupComplete,
                "dropped" => AccountSubscribeFrameKind::Dropped,
                "resync_required" => AccountSubscribeFrameKind::ResyncRequired,
                "unauthorized" => AccountSubscribeFrameKind::Unauthorized,
                _ => unreachable!("validated stream trace frame kind"),
            },
            cursor: cursor.map(ToOwned::to_owned),
            realms: None,
            to_device: None,
            device_lists: None,
            account_data: None,
            notifications: None,
            agent_signer_evidence_bundle: None,
            partial: frame.get("partial").and_then(Value::as_bool),
            priority: None,
            reconnect_after_ms,
        })),
        StreamSurface::Events => EmittedStreamFrame::Events(EventsSubscribeFrame {
            kind: match kind {
                "delta" => EventsSubscribeFrameKind::Event,
                "frontier" => EventsSubscribeFrameKind::Frontier,
                "heartbeat" => EventsSubscribeFrameKind::Heartbeat,
                "catchup_complete" => EventsSubscribeFrameKind::CatchupComplete,
                "dropped" => EventsSubscribeFrameKind::Dropped,
                "resync_required" => EventsSubscribeFrameKind::ResyncRequired,
                "unauthorized" => EventsSubscribeFrameKind::Unauthorized,
                _ => unreachable!("validated stream trace frame kind"),
            },
            realm_id: None,
            cursor: cursor
                .map(|cursor| arkret_identifiers::Cursor::new(cursor.to_owned()))
                .transpose()?,
            payload: None,
            reconnect_after_ms,
        }),
    })
}

fn emit_forbidden_cursorless_dropped(surface: StreamSurface) -> EmittedStreamFrame {
    match surface {
        StreamSurface::Account => EmittedStreamFrame::Account(Box::new(AccountSubscribeFrame {
            kind: AccountSubscribeFrameKind::Dropped,
            cursor: None,
            realms: None,
            to_device: None,
            device_lists: None,
            account_data: None,
            notifications: None,
            agent_signer_evidence_bundle: None,
            partial: None,
            priority: None,
            reconnect_after_ms: None,
        })),
        StreamSurface::Events => EmittedStreamFrame::Events(EventsSubscribeFrame {
            kind: EventsSubscribeFrameKind::Dropped,
            realm_id: None,
            cursor: None,
            payload: None,
            reconnect_after_ms: None,
        }),
    }
}

fn rejected_trace_observation(error: &StreamTraceError) -> Value {
    json!({
        "result": "reject",
        "reason": error.error_code().as_str(),
        "trace_violation": error.violation(),
    })
}

fn run_stream_frame_case(surface: StreamSurface, case: &Value) -> Result<Value> {
    exact_object_keys(
        case,
        &[
            "expected",
            "forbidden_frame",
            "frames",
            "initial_reconnect_cursor",
            "name",
            "request",
            "required_frame",
            "server_has_resume_cursor",
        ]
        .into_iter()
        .filter(|field| case.get(*field).is_some())
        .collect::<Vec<_>>(),
        "stream frame sequence case",
    )?;
    let name = value_field_str(case, "name")?;
    let request = required_field(case, "request")?;
    exact_object_keys(request, &["catchup"], "stream frame sequence request")?;
    let catchup = request
        .get("catchup")
        .and_then(Value::as_bool)
        .ok_or_else(|| anyhow!("stream frame sequence request catchup must be boolean"))?;
    let initial_cursor = case
        .get("initial_reconnect_cursor")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let expected = required_field(case, "expected")?;
    let expected_fields = [
        "catchup_complete_seen",
        "reason",
        "reconnect_after",
        "reconnect_cursor_advanced",
        "result",
        "trace_violation",
    ]
    .into_iter()
    .filter(|field| expected.get(*field).is_some())
    .collect::<Vec<_>>();
    exact_object_keys(expected, &expected_fields, "stream frame sequence expected")?;

    if name == "missing_drop_cursor_uses_resync_required" {
        if case
            .get("server_has_resume_cursor")
            .and_then(Value::as_bool)
            != Some(false)
        {
            bail!("missing-drop-cursor case must model a server without a resume cursor");
        }
        let forbidden = required_field(case, "forbidden_frame")?;
        exact_object_keys(forbidden, &["kind"], "forbidden cursorless dropped frame")?;
        if value_field_str(forbidden, "kind")? != "dropped" {
            bail!("forbidden frame must be cursorless dropped");
        }
        let mut forbidden_validator = StreamTraceValidator::new(catchup, initial_cursor.clone());
        let error = forbidden_validator
            .push(&emit_forbidden_cursorless_dropped(surface))
            .expect_err("cursorless dropped must be rejected");
        if error.error_code() != ErrorCode::SchemaViolation
            || error.violation() != "dropped_missing_cursor"
        {
            bail!("cursorless dropped returned the wrong trace violation");
        }

        let required = required_field(case, "required_frame")?;
        let mut validator = StreamTraceValidator::new(catchup, initial_cursor);
        let update = validator.push(&emit_stream_frame(surface, required)?)?;
        if !update.terminal || update.cursor_advanced || validator.reconnect_cursor().is_some() {
            bail!("resync_required did not clear reconnect state without advancing a cursor");
        }
        validator.finish()?;
        return Ok(json!({
            "result": "resync",
            "reconnect_cursor_advanced": update.cursor_advanced,
        }));
    }

    let frames = value_array(
        required_field(case, "frames")?,
        "stream frame sequence frames",
    )?;
    let mut validator = StreamTraceValidator::new(catchup, initial_cursor);
    let mut last_kind = None;
    for frame in frames {
        let emitted = emit_stream_frame(surface, frame)?;
        let kind = emitted.trace_kind();
        match validator.push(&emitted) {
            Ok(update) => {
                if matches!(
                    kind,
                    StreamTraceFrameKind::Heartbeat
                        | StreamTraceFrameKind::ResyncRequired
                        | StreamTraceFrameKind::Unauthorized
                ) && update.cursor_advanced
                {
                    bail!("cursorless control frame advanced the reconnect cursor");
                }
                last_kind = Some(kind);
            }
            Err(error) => {
                if error.error_code() != ErrorCode::SchemaViolation {
                    bail!("stream trace rejection did not map to schema_violation");
                }
                let heartbeat = emit_stream_frame(surface, &json!({"kind": "heartbeat"}))?;
                if validator.push(&heartbeat) != Err(StreamTraceError::TraceAlreadyRejected) {
                    bail!("rejected stream trace accepted a subsequent frame");
                }
                return Ok(rejected_trace_observation(&error));
            }
        }
    }
    validator.finish()?;

    let result = match last_kind {
        Some(StreamTraceFrameKind::Dropped) => "reconnect",
        Some(StreamTraceFrameKind::ResyncRequired) => "resync",
        Some(StreamTraceFrameKind::Unauthorized) => "closed",
        _ => "accept",
    };
    let mut observed = serde_json::Map::from_iter([("result".to_owned(), json!(result))]);
    if expected.get("reconnect_after").is_some() {
        observed.insert(
            "reconnect_after".to_owned(),
            validator
                .reconnect_cursor()
                .map_or(Value::Null, |cursor| json!(cursor)),
        );
    }
    if expected.get("catchup_complete_seen").is_some() {
        observed.insert(
            "catchup_complete_seen".to_owned(),
            json!(validator.catchup_complete_seen()),
        );
    }
    Ok(Value::Object(observed))
}

pub fn run_stream_frame_sequence_vector() -> Result<()> {
    let fixture = load_fixture_value("sync-fixture.json")?;
    let vector = required_field(&fixture, "stream_frame_sequence")?;
    exact_object_keys(
        vector,
        &["assertions", "cases", "operations", "runner", "vector_id"],
        "stream frame sequence vector",
    )?;
    if value_field_str(vector, "vector_id")? != STREAM_FRAME_SEQUENCE_VECTOR_ID
        || value_field_str(vector, "runner")?
            != "cotest::conformance::sync::run_stream_frame_sequence_vector"
    {
        bail!("stream frame sequence vector registration drifted");
    }
    let operations = value_array(
        required_field(vector, "operations")?,
        "stream frame sequence operations",
    )?;
    let expected_operations = [
        arkret_wire::ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE,
        arkret_wire::ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE,
    ];
    if operations.len() != expected_operations.len()
        || !expected_operations.iter().all(|operation| {
            operations
                .iter()
                .any(|entry| entry.as_str() == Some(*operation))
        })
    {
        bail!("stream frame sequence vector must cover account and events subscribe operations");
    }
    let cases = value_array(
        required_field(vector, "cases")?,
        "stream frame sequence cases",
    )?;
    if cases.len() != 7 {
        bail!("stream frame sequence vector must contain exactly 7 cases");
    }

    let mut executions = 0usize;
    for surface in [StreamSurface::Account, StreamSurface::Events] {
        for case in cases {
            let name = value_field_str(case, "name")?;
            let expected = required_field(case, "expected")?;
            let observed = run_stream_frame_case(surface, case)?;
            assert_expected_subset(name, expected, &observed)?;
            record_vector_event(
                &format!(
                    "sync.stream_frame_sequence.{}.{}",
                    surface.operation_id(),
                    name
                ),
                &json!({
                    "vector_id": STREAM_FRAME_SEQUENCE_VECTOR_ID,
                    "operation_id": surface.operation_id(),
                    "case": case,
                }),
                expected,
                &observed,
            );
            executions += 1;
        }
    }
    if executions != 14 {
        bail!("stream frame sequence runner did not execute 7 cases on both operations");
    }
    Ok(())
}

fn validate_collection_projection(value: &Value) -> Result<()> {
    let projection = required_field(value, "collection_projection")?;
    if value_field_str(projection, "projection")? != "collection"
        || value_field_str(projection, "renderer")? != "board"
    {
        bail!("sync artifact collection projection discriminator drifted");
    }
    let state_digest = projection
        .pointer("/frontier/state_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("sync artifact collection projection missing state_digest"))?;
    if !looks_like_sha256_digest(state_digest) {
        bail!("sync artifact collection projection state_digest was invalid");
    }
    let groups = value_array(
        required_field(projection, "groups")?,
        "collection_projection.groups",
    )?;
    if groups.is_empty() {
        bail!("sync artifact collection projection has no groups");
    }
    for group in groups {
        let items = value_array(required_field(group, "items")?, "group.items")?;
        for item in items {
            let object = required_field(item, "object")?;
            if !value_field_str(object, "id")?.starts_with("ak:strand:") {
                bail!("sync artifact collection item object id was not a strand");
            }
            let position = required_field(item, "position")?;
            let model = value_field_str(position, "model")?;
            if model != "relation" && model != "relation_container" {
                bail!("sync artifact collection item position model was invalid");
            }
            if !value_field_str(position, "relation_id")?.starts_with("ak:relation:") {
                bail!("sync artifact collection item relation id was invalid");
            }
        }
    }
    Ok(())
}

fn validate_strand_discussion_timeline(value: &Value) -> Result<()> {
    let timeline = required_field(value, "strand_discussion_timeline")?;
    if !value_field_str(timeline, "strand_id")?.starts_with("ak:strand:") {
        bail!("sync artifact strand discussion timeline strand id was invalid");
    }
    if !value_field_str(timeline, "next_cursor")?.starts_with("ak:cursor:") {
        bail!("sync artifact strand discussion timeline cursor was invalid");
    }
    for entry in value_array(
        required_field(timeline, "entries")?,
        "strand_discussion_timeline.entries",
    )? {
        if !value_field_str(entry, "event_id")?.starts_with("ak:event:") {
            bail!("sync artifact strand discussion timeline event id was invalid");
        }
        if !value_field_str(entry, "message_id")?.starts_with("ak:message:") {
            bail!("sync artifact strand discussion timeline message id was invalid");
        }
    }
    Ok(())
}

fn validate_snapshot_frontier_recovery(value: &Value) -> Result<()> {
    let snapshot = required_field(value, "snapshot_frontier_recovery")?;
    let state_digest = value_field_str(snapshot, "state_digest")?;
    if !looks_like_sha256_digest(state_digest) {
        bail!("sync artifact snapshot state_digest was invalid");
    }
    let root = snapshot
        .pointer("/event_set_commitment/root")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("sync artifact snapshot commitment missing digest root"))?;
    if !looks_like_sha256_digest(root) {
        bail!("sync artifact snapshot commitment root was invalid");
    }
    Ok(())
}

fn validate_snapshot_inclusion_challenge(value: &Value) -> Result<()> {
    let vector = required_field(value, "snapshot_inclusion_challenge")?;
    let vector_id = value_field_str(vector, "vector_id")?;
    if vector_id != "ak.vector.snapshot.inclusion_challenge.v1" {
        bail!("sync artifact snapshot inclusion challenge vector id drifted");
    }

    let manifest = required_field(vector, "manifest")?;
    if value_field_str(manifest, "security_class")? != "high_assurance" {
        bail!("snapshot inclusion challenge must pin high_assurance security_class");
    }
    let commitment = required_field(manifest, "event_set_commitment")?;
    if value_field_str(commitment, "algorithm")? != "merkle_event_set_v1" {
        bail!("snapshot inclusion challenge must exercise merkle_event_set_v1");
    }
    let entries = value_array(
        required_field(vector, "event_set_entries")?,
        "snapshot_inclusion_challenge.event_set_entries",
    )?;
    let computed_root = merkle_event_set_root(entries)?;
    let manifest_root = value_field_str(commitment, "root")?;
    if computed_root != manifest_root {
        bail!("snapshot inclusion challenge manifest root does not match event_set_entries");
    }
    if value_field_u64(commitment, "covered_event_count")? as usize != entries.len() {
        bail!("snapshot inclusion challenge covered_event_count drifted");
    }
    let actor_ranges = value_array(
        required_field(commitment, "actor_seq_ranges")?,
        "event_set_commitment.actor_seq_ranges",
    )?;
    for range in actor_ranges {
        let actor_id = value_field_str(range, "actor_id")?;
        let from_seq = value_field_u64(range, "from_seq")?;
        let to_seq = value_field_u64(range, "to_seq")?;
        let actor_entries = entries
            .iter()
            .filter(|entry| {
                entry.get("actor_id").and_then(Value::as_str) == Some(actor_id)
                    && entry
                        .get("actor_seq")
                        .and_then(Value::as_u64)
                        .is_some_and(|seq| (from_seq..=to_seq).contains(&seq))
            })
            .cloned()
            .collect::<Vec<_>>();
        if actor_entries.is_empty()
            || merkle_event_set_root(&actor_entries)? != value_field_str(range, "root")?
        {
            bail!("actor range {actor_id}:{from_seq}:{to_seq} Merkle root does not match entries");
        }
    }

    let base_challenge = required_field(vector, "base_challenge")?;
    let base_response = required_field(vector, "base_response")?;
    let cases = value_array(
        required_field(vector, "cases")?,
        "snapshot_inclusion_challenge.cases",
    )?;
    let mut seen = BTreeSet::new();
    for case in cases {
        let name = value_field_str(case, "name")?;
        seen.insert(name.to_owned());
        let mut challenge = base_challenge.clone();
        let mut response = base_response.clone();
        apply_snapshot_inclusion_mutation(case, &mut challenge, &mut response)?;
        let observed = evaluate_snapshot_inclusion_case(manifest, entries, &challenge, &response)?;
        assert_expected_subset(name, required_field(case, "expected")?, &observed)?;
        record_vector_event(
            &format!("sync.snapshot_inclusion_challenge.{name}"),
            &json!({"vector_id": vector_id, "case": case}),
            required_field(case, "expected")?,
            &observed,
        );
    }

    for required in [
        "valid_high_assurance_challenge",
        "insufficient_event_id_samples",
        "commitment_root_mismatch",
        "legacy_unprefixed_commitment_root",
        "silent_actor_seq_gap",
    ] {
        if !seen.contains(required) {
            bail!("snapshot inclusion challenge fixture missing case {required}");
        }
    }
    Ok(())
}

fn evaluate_snapshot_inclusion_case(
    manifest: &Value,
    entries: &[Value],
    challenge: &Value,
    response: &Value,
) -> Result<Value> {
    let commitment = required_field(manifest, "event_set_commitment")?;
    let covered_event_count = value_field_u64(commitment, "covered_event_count")?;
    let minimum_event_samples = std::cmp::max(20, ceil_log2(covered_event_count));
    let samples = value_array(required_field(challenge, "samples")?, "challenge.samples")?;
    let mut sampled_event_ids = BTreeSet::new();
    let mut sampled_range_keys = BTreeSet::new();
    for sample in samples {
        match value_field_str(sample, "kind")? {
            "event_id" => {
                for event_id in value_array(required_field(sample, "event_ids")?, "event_ids")? {
                    sampled_event_ids.insert(
                        event_id
                            .as_str()
                            .ok_or_else(|| anyhow!("event_ids entry must be string"))?
                            .to_owned(),
                    );
                }
            }
            "actor_seq_range" => {
                sampled_range_keys.insert(range_key(sample)?);
            }
            other => bail!("snapshot inclusion challenge sample kind {other} is unsupported"),
        }
    }
    if sampled_event_ids.len() < minimum_event_samples as usize || sampled_range_keys.len() < 3 {
        return Ok(json!({
            "decision": "reject",
            "reason": "insufficient_challenge_samples",
        }));
    }

    let manifest_root = value_field_str(commitment, "root")?;
    let computed_root = merkle_event_set_root(entries)?;
    if value_field_str(response, "commitment_algorithm")?
        != value_field_str(commitment, "algorithm")?
        || value_field_str(response, "commitment_root")? != manifest_root
        || computed_root != manifest_root
    {
        return Ok(json!({"decision": "reject", "reason": "inclusion_proof_failed"}));
    }
    let signature = required_field(response, "issuer_signature")?;
    if signature.get("signature_valid").and_then(Value::as_bool) != Some(true)
        || signature
            .get("verification_authorized_at_created_at")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Ok(json!({"decision": "reject", "reason": "inclusion_proof_failed"}));
    }

    let entry_ids = entries
        .iter()
        .map(|entry| value_field_str(entry, "event_id").map(str::to_owned))
        .collect::<Result<BTreeSet<_>>>()?;
    let proofs = value_array(required_field(response, "proofs")?, "response.proofs")?;
    let mut event_proofs = BTreeSet::new();
    let mut range_proofs = BTreeMap::new();
    for proof in proofs {
        match value_field_str(proof, "kind")? {
            "event_id" => {
                event_proofs.insert(value_field_str(proof, "event_id")?.to_owned());
            }
            "actor_seq_range" => {
                range_proofs.insert(range_key(proof)?, proof);
            }
            other => bail!("snapshot inclusion proof kind {other} is unsupported"),
        }
    }
    for event_id in &sampled_event_ids {
        if !entry_ids.contains(event_id) || !event_proofs.contains(event_id) {
            return Ok(json!({"decision": "reject", "reason": "inclusion_proof_failed"}));
        }
    }
    for key in &sampled_range_keys {
        let Some(proof) = range_proofs.get(key) else {
            return Ok(json!({"decision": "reject", "reason": "inclusion_proof_failed"}));
        };
        let gap_attribution = value_array(
            required_field(proof, "gap_attribution")?,
            "proof.gap_attribution",
        )?;
        if gap_attribution.is_empty() {
            return Ok(json!({"decision": "reject", "reason": "inclusion_proof_failed"}));
        }
        for gap in gap_attribution {
            match value_field_str(gap, "category")? {
                "soft_failed" | "quarantined" | "conflict_records" => {}
                other => bail!("snapshot inclusion gap category {other} is unsupported"),
            }
        }
    }

    Ok(json!({"decision": "accept"}))
}

fn apply_snapshot_inclusion_mutation(
    case: &Value,
    challenge: &mut Value,
    response: &mut Value,
) -> Result<()> {
    let mutation = value_field_str(case, "mutation")?;
    match mutation {
        "none" => {}
        "drop_one_event_id_sample" => {
            let samples = challenge
                .get_mut("samples")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| anyhow!("challenge samples must be mutable array"))?;
            let Some(index) = samples
                .iter()
                .position(|sample| sample.get("kind").and_then(Value::as_str) == Some("event_id"))
            else {
                bail!("cannot drop event_id sample from challenge");
            };
            samples.remove(index);
        }
        "commitment_root_mismatch" => {
            response["commitment_root"] = Value::String(format!("sha256:{}", "0".repeat(64)));
        }
        "replace_commitment_root" => {
            response["commitment_root"] = Value::String(
                value_field_str(case, "replacement_root")
                    .map_err(|_| anyhow!("replace_commitment_root case lacks replacement_root"))?
                    .to_owned(),
            );
        }
        "drop_gap_attribution" => {
            let proofs = response
                .get_mut("proofs")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| anyhow!("response proofs must be mutable array"))?;
            let Some(proof) = proofs
                .iter_mut()
                .find(|proof| proof.get("kind").and_then(Value::as_str) == Some("actor_seq_range"))
            else {
                bail!("cannot drop gap attribution from actor_seq_range proof");
            };
            proof["gap_attribution"] = Value::Array(Vec::new());
        }
        other => bail!("unknown snapshot inclusion mutation {other}"),
    }
    Ok(())
}

fn merkle_event_set_root(entries: &[Value]) -> Result<String> {
    let entries = entries
        .iter()
        .cloned()
        .map(serde_json::from_value::<EventSetLeaf>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| anyhow!("invalid event-set leaf: {error}"))?;
    Ok(event_set_root(&EventSetCommitmentAlgorithm::MerkleEventSetV1, &entries)?.into_string())
}

fn range_key(value: &Value) -> Result<String> {
    Ok(format!(
        "{}:{}:{}",
        value_field_str(value, "actor_id")?,
        value_field_u64(value, "from_seq")?,
        value_field_u64(value, "to_seq")?
    ))
}

fn ceil_log2(value: u64) -> u64 {
    if value <= 1 {
        0
    } else {
        u64::BITS as u64 - (value - 1).leading_zeros() as u64
    }
}

fn assert_expected_subset(name: &str, expected: &Value, observed: &Value) -> Result<()> {
    let expected = expected
        .as_object()
        .ok_or_else(|| anyhow!("{name} expected value must be an object"))?;
    let observed = observed
        .as_object()
        .ok_or_else(|| anyhow!("{name} observed value must be an object"))?;
    for (key, expected_value) in expected {
        match observed.get(key) {
            Some(observed_value) if observed_value == expected_value => {}
            Some(observed_value) => {
                bail!("{name} expected {key}={expected_value}, got {observed_value}");
            }
            None => bail!("{name} observed result missing expected key {key}"),
        }
    }
    Ok(())
}

fn validate_e2ee_pending(value: &Value) -> Result<()> {
    let pending = required_field(value, "e2ee_decryption_pending")?;
    if pending
        .get("must_not_drop_timeline_entry")
        .and_then(Value::as_bool)
        != Some(true)
    {
        bail!("sync artifact no longer requires keeping pending E2EE entries");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_frame_sequence_runs_all_cases_on_both_operations() {
        run_stream_frame_sequence_vector().unwrap();
    }

    #[test]
    fn removed_stream_request_fields_are_rejected() {
        let fixture = load_fixture_value("sync-fixture.json").unwrap();
        let baseline = fixture.pointer("/stream_frame_sequence/cases/0").unwrap();
        for field in ["include_history", "max_duration_ms", "heartbeat_ms"] {
            let mut case = baseline.clone();
            case["request"][field] = json!(1);
            assert!(run_stream_frame_case(StreamSurface::Account, &case).is_err());
            assert!(run_stream_frame_case(StreamSurface::Events, &case).is_err());
        }
    }
}
