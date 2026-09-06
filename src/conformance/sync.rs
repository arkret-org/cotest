use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Result, anyhow, bail};
use arkret_models_collaboration::http_bodies::EventsSubscribeFrameKind;
use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeFrame, AccountSubscribeFrameKind,
};
use arkret_models_collaboration::sync_frames::stream_trace::{
    StreamTraceError, StreamTraceFrame, StreamTraceFrameKind, StreamTraceValidator,
};
use arkret_state::realm_state_snapshot::{
    CoveredEventMembership, CoveredEventSet, EventSetCommitmentAlgorithm, EventSetLeaf,
    RealmStateSnapshotChunkPayload, RealmStateSnapshotMaterializedItem,
    RealmStateSnapshotMerkleTree, event_set_merkle_tree, event_set_root,
    realm_state_snapshot_conflict_records_digest, realm_state_snapshot_erasure_stubs_digest,
    realm_state_snapshot_state_leaf_hash, state_digest_from_chunk_payloads,
    state_digest_from_items,
};
use arkret_wire::{ErrorCode, EventId, Hash};
use serde_json::{Value, json};

use super::helpers::assert_expected_subset;
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
    validate_realm_state_snapshot_frontier_recovery(&value)?;
    validate_realm_state_snapshot_inclusion_challenge(&value)?;
    validate_snapshot_state_digest(&value)?;
    validate_realm_state_snapshot_restore_covered_membership(&value)?;
    super::realm_state_snapshot_witness_quorum::run_realm_state_snapshot_witness_quorum_attestation_vector()?;
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
        let validation: Result<()> = match decoded {
            Ok(frontier) => frontier.validate().map_err(Into::into),
            Err(error) => Err(error.into()),
        };
        let valid = validation.is_ok();
        if expect_valid != valid {
            bail!(
                "frontier case {} validity mismatch: {}",
                value_field_str(case, "name")?,
                validation.expect_err("validity mismatch must carry a decode or validation error")
            );
        }
    }

    let vector = required_field(value, "actor_frontier_digest")?;
    let valid_case = cases
        .iter()
        .find(|case| {
            case.get("name").and_then(Value::as_str)
                == Some("realm_actor_frontier_sibling_set_valid")
        })
        .ok_or_else(|| anyhow!("sync fixture lacks the valid sibling frontier case"))?;
    let frontier = serde_json::from_value::<
        arkret_models_collaboration::event_sync::RealmActorFrontierView,
    >(required_field(valid_case, "instance")?.clone())?;
    let suite = arkret_canonical::digest_suite(value_field_str(vector, "digest_algorithm")?)?;
    let digest = arkret_models_collaboration::event_sync::RealmActorFrontierView::compute_digest(
        &frontier.realm_id,
        &frontier.actor_id,
        frontier.next_actor_seq,
        &frontier.frontier_event_ids,
        suite,
    )?;
    if digest != frontier.frontier_digest
        || digest.as_str() != value_field_str(vector, "expected_digest")?
    {
        bail!("Realm actor frontier digest golden mismatch");
    }
    let canonical = String::from_utf8(arkret_canonical::canonical_json_bytes(&json!({
        "kind": "realm_actor",
        "realm_id": frontier.realm_id,
        "actor_id": frontier.actor_id,
        "next_actor_seq": frontier.next_actor_seq,
        "frontier_event_ids": frontier.frontier_event_ids,
    }))?)?;
    if canonical != value_field_str(vector, "canonical_json")? {
        bail!("Realm actor frontier canonical transcript golden mismatch");
    }
    if value_field_str(vector, "transcript_label_utf8_nul")?.as_bytes()
        != arkret_models_collaboration::event_sync::REALM_ACTOR_FRONTIER_DIGEST_DOMAIN
    {
        bail!("Realm actor frontier digest domain label drifted");
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
            Self::Account => arkret_wire::ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE_V1,
            Self::Events => arkret_wire::ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE_V1,
        }
    }
}

enum EmittedStreamFrame {
    Account(Box<AccountSubscribeFrame>),
    Events(SyntheticEventsTraceFrame),
}

struct SyntheticEventsTraceFrame {
    kind: EventsSubscribeFrameKind,
    cursor: Option<String>,
}

impl StreamTraceFrame for EmittedStreamFrame {
    fn trace_kind(&self) -> StreamTraceFrameKind {
        match self {
            Self::Account(frame) => frame.trace_kind(),
            Self::Events(frame) => match frame.kind {
                EventsSubscribeFrameKind::Event => StreamTraceFrameKind::Data,
                EventsSubscribeFrameKind::Frontier => StreamTraceFrameKind::Frontier,
                EventsSubscribeFrameKind::Heartbeat => StreamTraceFrameKind::Heartbeat,
                EventsSubscribeFrameKind::CatchupComplete => StreamTraceFrameKind::CatchupComplete,
                EventsSubscribeFrameKind::EpochRotation => StreamTraceFrameKind::EpochRotation,
                EventsSubscribeFrameKind::Dropped => StreamTraceFrameKind::Dropped,
                EventsSubscribeFrameKind::ResyncRequired => StreamTraceFrameKind::ResyncRequired,
                EventsSubscribeFrameKind::Unauthorized => StreamTraceFrameKind::Unauthorized,
                _ => panic!("unregistered events frame kind"),
            },
        }
    }

    fn trace_cursor(&self) -> Option<&str> {
        match self {
            Self::Account(frame) => frame.trace_cursor(),
            Self::Events(frame) => frame.cursor.as_deref(),
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
        StreamSurface::Events => EmittedStreamFrame::Events(SyntheticEventsTraceFrame {
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
            cursor: cursor.map(ToOwned::to_owned),
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
        StreamSurface::Events => EmittedStreamFrame::Events(SyntheticEventsTraceFrame {
            kind: EventsSubscribeFrameKind::Dropped,
            cursor: None,
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
        arkret_wire::ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE_V1,
        arkret_wire::ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE_V1,
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

fn validate_realm_state_snapshot_frontier_recovery(value: &Value) -> Result<()> {
    let snapshot = required_field(value, "realm_state_snapshot_frontier_recovery")?;
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

fn validate_realm_state_snapshot_inclusion_challenge(value: &Value) -> Result<()> {
    let vector = required_field(value, "snapshot_inclusion_challenge")?;
    let vector_id = value_field_str(vector, "vector_id")?;
    if vector_id != "ak.vector.realm_state_snapshot.inclusion_challenge.v1" {
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
        let actor_id = super::value_field_actor(range, "actor_id")?;
        let from_seq = value_field_u64(range, "from_seq")?;
        let to_seq = value_field_u64(range, "to_seq")?;
        let actor_entries = entries
            .iter()
            .filter(|entry| {
                super::value_field_actor(entry, "actor_id").is_ok_and(|actor| actor == actor_id)
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
        apply_realm_state_snapshot_inclusion_mutation(case, &mut challenge, &mut response)?;
        let observed =
            evaluate_realm_state_snapshot_inclusion_case(manifest, entries, &challenge, &response)?;
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
        "silent_actor_seq_gap",
        "entire_unknown_actor_omitted_without_independent_witness",
    ] {
        if !seen.contains(required) {
            bail!("snapshot inclusion challenge fixture missing case {required}");
        }
    }
    Ok(())
}

/// `ak.vector.realm_state_snapshot.state_digest_recompute.v1` (`sync-fixture.json` block
/// `snapshot_state_digest`, `realm-state-snapshot-schema.md` §3 / §4).
///
/// The SDK is the implementation under test: every chunk is parsed through its
/// closed `ak.schema.realm_state_snapshot_chunk.v1` types and `state_digest` is recomputed
/// with its consumer-side verifier, so a reject case that the SDK would accept
/// — or an accept case whose bytes it hashes differently — fails here, not in
/// a Station months later.
fn validate_snapshot_state_digest(value: &Value) -> Result<()> {
    let vector = required_field(value, "snapshot_state_digest")?;
    let vector_id = value_field_str(vector, "vector_id")?;
    if vector_id != "ak.vector.realm_state_snapshot.state_digest_recompute.v1" {
        bail!("sync artifact snapshot state digest vector id drifted");
    }
    let reducer_profile = value_field_str(required_field(vector, "manifest")?, "reducer_profile")?;
    let cases = value_array(
        required_field(vector, "cases")?,
        "snapshot_state_digest.cases",
    )?;

    // The published leaves are reproduced item by item: the leaf preimage is
    // the §6.2.1 `{"cell","state"}` canonical JSON and the leaf is
    // H(0x00 || preimage) under the vector's SHA-256 baseline.
    let canonical_items = cases
        .first()
        .and_then(|case| case.pointer("/chunks/0/items"))
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("snapshot state digest fixture has no canonical chunk"))?
        .iter()
        .map(|item| {
            serde_json::from_value::<RealmStateSnapshotMaterializedItem>(item.clone())
                .map_err(|error| anyhow!("canonical snapshot item did not parse: {error}"))
        })
        .collect::<Result<Vec<_>>>()?;
    for row in value_array(
        required_field(vector, "leaves")?,
        "snapshot_state_digest.leaves",
    )? {
        let id = value_field_str(row, "id")?;
        let item = canonical_items
            .iter()
            .find(|item| item.id() == id)
            .ok_or_else(|| anyhow!("leaf row {id} names no canonical snapshot item"))?;
        let preimage = super::canonical_json(&item.leaf_preimage())?;
        if preimage != value_field_str(row, "leaf_preimage")? {
            bail!("snapshot leaf preimage of {id} does not match the SDK canonical form");
        }
        if realm_state_snapshot_state_leaf_hash(item)?.as_str() != value_field_str(row, "leaf")? {
            bail!("snapshot leaf of {id} does not match the SDK leaf hash");
        }
    }
    if state_digest_from_items(&canonical_items)?.as_str()
        != value_field_str(vector, "state_digest")?
    {
        bail!(
            "snapshot state_digest does not match the SDK recomputation over the canonical items"
        );
    }

    let mut seen = BTreeSet::new();
    for case in cases {
        let name = value_field_str(case, "name")?;
        seen.insert(name.to_owned());
        let suite = arkret_canonical::digest_suite(value_field_str(case, "digest_algorithm")?)?;
        let declared = value_field_str(case, "declared_state_digest")?;
        let mut expected = json!({ "outcome": value_field_str(case, "expected")? });
        for key in [
            "expected_conflict_records_digest",
            "expected_erasure_stubs_digest",
        ] {
            if let Some(digest) = case.get(key) {
                expected[key.trim_start_matches("expected_")] = digest.clone();
            }
        }

        let parsed = value_array(required_field(case, "chunks")?, "case.chunks")?
            .iter()
            .map(|chunk| serde_json::from_value::<RealmStateSnapshotChunkPayload>(chunk.clone()))
            .collect::<std::result::Result<Vec<_>, _>>();
        let observed = match parsed {
            Err(error) => json!({ "outcome": "reject", "reason": error.to_string() }),
            Ok(chunks) => match state_digest_from_chunk_payloads(&chunks, reducer_profile, suite) {
                Err(error) => json!({ "outcome": "reject", "reason": error.to_string() }),
                Ok(root) if root.as_str() != declared => json!({
                    "outcome": "reject",
                    "reason": format!("recomputed {root} but the manifest declares {declared}"),
                }),
                Ok(_) => json!({
                    "outcome": "accept",
                    "conflict_records_digest": realm_state_snapshot_conflict_records_digest(&chunks, suite)?,
                    "erasure_stubs_digest": realm_state_snapshot_erasure_stubs_digest(&chunks, suite)?,
                }),
            },
        };
        assert_expected_subset(name, &expected, &observed)?;
        record_vector_event(
            &format!("sync.snapshot_state_digest.{name}"),
            &json!({ "vector_id": vector_id, "case": name }),
            &expected,
            &observed,
        );
    }

    for required in [
        "canonical_chunk_recomputes_state_digest",
        "chunk_boundaries_do_not_change_state_digest",
        "state_digest_follows_the_realm_digest_suite",
        "empty_reducer_output_is_the_empty_tree_root",
        "bottom_cell_is_a_conflict_record_not_a_leaf",
        "erasure_stub_is_committed_by_its_own_digest_not_a_leaf",
        "declared_state_digest_mismatch_is_rejected",
        "materialized_object_branch_is_rejected",
        "cas_cell_literal_is_rejected",
        "cas_register_cell_with_value_state_is_rejected",
        "non_cas_register_cell_with_heads_state_is_rejected",
        "empty_head_set_is_rejected",
        "unsorted_heads_are_rejected",
        "unsorted_items_are_rejected",
        "duplicate_cell_across_chunks_is_rejected",
        "actor_private_family_is_rejected",
        "reducer_profile_drift_between_chunk_and_manifest_is_rejected",
    ] {
        if !seen.contains(required) {
            bail!("snapshot state digest fixture missing case {required}");
        }
    }
    Ok(())
}

fn evaluate_realm_state_snapshot_inclusion_case(
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
    if response
        .get("entire_actor_omitted")
        .and_then(Value::as_bool)
        == Some(true)
        && response
            .get("independent_actor_set_witness")
            .is_none_or(Value::is_null)
        && response
            .get("raw_replay_completed")
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Ok(json!({
            "decision": "reject_high_assurance_snapshot",
            "completeness_state": "unverified",
            "reason": "inclusion_proof_failed",
        }));
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

fn apply_realm_state_snapshot_inclusion_mutation(
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
        "omit_actor_and_all_of_its_events_then_recompute_issuer_signature_root_count_and_actor_seq_ranges" =>
        {
            response["entire_actor_omitted"] = Value::Bool(true);
            response["independent_actor_set_witness"] = Value::Null;
            response["raw_replay_completed"] = Value::Bool(false);
        }
        other => bail!("unknown snapshot inclusion mutation {other}"),
    }
    Ok(())
}

/// `ak.vector.realm_state_snapshot.restore_covered_membership.v1`
/// (`sync-fixture.json` block `snapshot_restore_covered_membership`,
/// `realm-state-snapshot-schema.md` §3).
///
/// The SDK's [`CoveredEventSet`] is the implementation under test. The point of
/// the vector is the answer it must *refuse* to give: an Event it has no
/// evidence about is `Unknown`, never `NotCovered`, because §9.3.1.4 reads
/// `NotCovered` as "the peer never saw it" and resurrects the writes that
/// Event superseded.
fn validate_realm_state_snapshot_restore_covered_membership(value: &Value) -> Result<()> {
    let vector = required_field(value, "snapshot_restore_covered_membership")?;
    let vector_id = value_field_str(vector, "vector_id")?;
    if vector_id != "ak.vector.realm_state_snapshot.restore_covered_membership.v1" {
        bail!("sync artifact snapshot restore membership vector id drifted");
    }

    // The committed set is not duplicated here: it is the inclusion-challenge
    // block's, so the §6 challenge and this §3 membership rule cannot drift
    // onto two different event sets.
    let source = value_field_str(vector, "event_set_source")?;
    let entries = value_array(
        required_field(required_field(value, source)?, "event_set_entries")?,
        "snapshot_restore_covered_membership.event_set_entries",
    )?
    .iter()
    .cloned()
    .map(serde_json::from_value::<EventSetLeaf>)
    .collect::<std::result::Result<Vec<_>, _>>()
    .map_err(|error| anyhow!("invalid event-set leaf: {error}"))?;

    let commitment = required_field(vector, "event_set_commitment")?;
    let declared_root = value_field_str(commitment, "root")?;
    let covered_event_count = value_field_u64(commitment, "covered_event_count")?;
    if covered_event_count as usize != entries.len() {
        bail!("snapshot restore membership covered_event_count drifted from the source entries");
    }
    if event_set_root(&EventSetCommitmentAlgorithm::MerkleEventSetV1, &entries)?.as_str()
        != declared_root
    {
        bail!("snapshot restore membership root does not match the source entries");
    }

    let frontier = value_array(
        required_field(required_field(vector, "frontier")?, "event_ids")?,
        "snapshot_restore_covered_membership.frontier.event_ids",
    )?
    .iter()
    .map(|id| {
        EventId::new(
            id.as_str()
                .ok_or_else(|| anyhow!("frontier event id was not a string"))?
                .to_owned(),
        )
        .map_err(|error| anyhow!("frontier event id is invalid: {error}"))
    })
    .collect::<Result<Vec<_>>>()?;

    let (sorted, tree) = event_set_merkle_tree(&entries)?;
    let mut seen = BTreeSet::new();
    for case in value_array(
        required_field(vector, "cases")?,
        "snapshot_restore_covered_membership.cases",
    )? {
        let name = value_field_str(case, "name")?;
        seen.insert(name.to_owned());
        let observed = evaluate_restore_covered_membership_case(
            case,
            &entries,
            &sorted,
            &tree,
            declared_root,
            covered_event_count,
            &frontier,
        )?;
        assert_expected_subset(name, required_field(case, "expected")?, &observed)?;
        record_vector_event(
            &format!("sync.snapshot_restore_covered_membership.{name}"),
            &json!({"vector_id": vector_id, "case": case}),
            required_field(case, "expected")?,
            &observed,
        );
    }

    for required in [
        "absent_event_without_evidence_holds_rather_than_answering_not_covered",
        "committed_index_admits_and_absence_becomes_provable",
        "committed_index_prefix_is_rejected",
        "inclusion_proof_admits_one_entry_under_the_manifest_root",
        "branch_verified_at_the_wrong_leaf_index_is_rejected",
        "ordered_event_id_sha256_v1_has_no_per_entry_branch",
    ] {
        if !seen.contains(required) {
            bail!("snapshot restore membership fixture missing case {required}");
        }
    }
    Ok(())
}

fn evaluate_restore_covered_membership_case(
    case: &Value,
    entries: &[EventSetLeaf],
    sorted: &[EventSetLeaf],
    tree: &RealmStateSnapshotMerkleTree,
    declared_root: &str,
    covered_event_count: u64,
    frontier: &[EventId],
) -> Result<Value> {
    let evidence = required_field(case, "evidence")?;
    let kind = value_field_str(evidence, "kind")?;
    let algorithm = match evidence.get("algorithm").and_then(Value::as_str) {
        Some("ordered_event_id_sha256_v1") => EventSetCommitmentAlgorithm::OrderedEventIdSha256V1,
        Some(other) => bail!("unknown event-set commitment algorithm {other}"),
        None => EventSetCommitmentAlgorithm::MerkleEventSetV1,
    };
    // A case that swaps the algorithm commits to that algorithm's own root:
    // the point is that no per-entry branch exists under it, not that the root
    // stopped matching.
    let root = match algorithm {
        EventSetCommitmentAlgorithm::MerkleEventSetV1 => Hash::new(declared_root.to_owned())
            .map_err(|error| anyhow!("declared root is not a digest: {error}"))?,
        EventSetCommitmentAlgorithm::OrderedEventIdSha256V1 => event_set_root(&algorithm, entries)?,
    };

    let mut set = CoveredEventSet::new(
        algorithm,
        root,
        covered_event_count,
        frontier.iter().cloned(),
    );

    let admitted = match kind {
        "none" => Ok(()),
        "committed_index" => {
            let mut index = match value_field_str(evidence, "entries")? {
                "all" => sorted.to_vec(),
                "prefix" => {
                    let count = value_field_u64(evidence, "count")? as usize;
                    sorted.iter().take(count).cloned().collect()
                }
                other => bail!("unknown committed index selector {other}"),
            };
            if let Some(mutate) = evidence.get("mutate") {
                let position = value_field_u64(mutate, "index")? as usize;
                let target = index
                    .get_mut(position)
                    .ok_or_else(|| anyhow!("mutation index {position} is past the index"))?;
                match value_field_str(mutate, "field")? {
                    "actor_seq" => target.actor_seq = value_field_u64(mutate, "value")?,
                    other => bail!("unknown committed index mutation field {other}"),
                }
            }
            set.admit_committed_index(index)
        }
        "inclusion_proof" => {
            let leaf_index = value_field_u64(evidence, "leaf_index")? as usize;
            let verify_at = evidence
                .get("verify_at_leaf_index")
                .and_then(Value::as_u64)
                .map_or(leaf_index, |index| index as usize);
            let entry = sorted
                .get(leaf_index)
                .ok_or_else(|| anyhow!("leaf index {leaf_index} is past the committed set"))?
                .clone();
            let audit_path = tree
                .audit_path(leaf_index)
                .ok_or_else(|| anyhow!("no audit path for leaf {leaf_index}"))?;
            set.admit_inclusion_proof(entry, verify_at, &audit_path)
        }
        other => bail!("unknown covered-membership evidence kind {other}"),
    };

    if let Err(error) = admitted {
        return Ok(json!({
            "outcome": "reject",
            "error_code": error.code.as_str(),
            "complete": set.is_complete(),
        }));
    }

    let query = EventId::new(value_field_str(case, "query_event_id")?.to_owned())
        .map_err(|error| anyhow!("query event id is invalid: {error}"))?;
    let outcome = match set.membership(&query) {
        CoveredEventMembership::Covered => "covered",
        CoveredEventMembership::NotCovered => "not_covered",
        CoveredEventMembership::Unknown => "unknown",
    };
    Ok(json!({"outcome": outcome, "complete": set.is_complete()}))
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
        super::value_field_actor(value, "actor_id")?,
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
}
