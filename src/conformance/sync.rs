use std::collections::{BTreeSet, HashSet};

use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{
    SyncCase, SyncFixture, canonical_json, load_fixture_value, looks_like_sha256_digest,
    parse_fixture_value, required_field, sha256_prefixed, validate_profile, value_array,
    value_field_bool, value_field_str, value_field_u64,
};

use super::encoding::{
    validate_entity, validate_projection_position, validate_query_renderer,
    validate_response_entities_against_request_facets,
};

pub fn run_sync_fixture_suite() -> Result<()> {
    let value = load_fixture_value("sync-fixture.json")?;
    if value.get("suite").is_none() {
        return run_sync_artifact_suite(&value);
    }
    let fixture: SyncFixture = parse_fixture_value("sync-fixture.json", value)?;
    if fixture.suite != "sync" {
        bail!("unexpected fixture suite {}", fixture.suite);
    }
    let mut service = ReferenceSyncService::sample();

    for case in fixture.cases {
        match case.name.as_str() {
            "initial_sync" => {
                let response = service.initial_sync(10)?;
                if response.events.len() != 3 || response.next_cursor.is_none() {
                    bail!(
                        "sync fixture {} did not return full visible state",
                        case.name
                    );
                }
            }
            "incremental_sync" => {
                let initial = service.initial_sync(10)?;
                let response = service.incremental_sync(initial.next_cursor.as_deref(), 10)?;
                if response.events.len() != 1 || response.events[0].event_id != "evt_4" {
                    bail!("sync fixture {} did not return only delta", case.name);
                }
            }
            "state_after" => {
                let response = service.initial_sync(10)?;
                if !response.state_after.starts_with("sha256:") {
                    bail!("sync fixture {} missing post-reducer frontier", case.name);
                }
            }
            "limited_timeline_backfill" => {
                let response = service.backfill(2)?;
                if !response.limited || response.prev_batch.is_none() {
                    bail!("sync fixture {} missing limited/prev_batch", case.name);
                }
            }
            "expired_cursor" => {
                let result = service.incremental_sync(Some("cx:cursor:expired"), 10);
                match result {
                    Err(error) if error.to_string().contains("snapshot_bootstrap") => {}
                    _ => bail!("sync fixture {} did not signal expiry recovery", case.name),
                }
            }
            "filter_mismatch" => {
                let result = service.validate_filter("unsupported-profile");
                match result {
                    Err(error) if error.to_string().contains("describe_guidance") => {}
                    _ => bail!(
                        "sync fixture {} did not reject mismatched filter",
                        case.name
                    ),
                }
            }
            "to_device_ack" => {
                service.queue_to_device("msg-1");
                let first = service.pull_to_device();
                if first != vec!["msg-1".to_owned()] {
                    bail!("sync fixture {} failed first delivery", case.name);
                }
                service.ack_to_device("msg-1");
                if !service.pull_to_device().is_empty() {
                    bail!("sync fixture {} redelivered acked message", case.name);
                }
            }
            "snapshot_manifest_chunk_frontier" => {
                let snapshot = ReferenceSnapshot::sample()?;
                if !snapshot.verify()? {
                    bail!("sync fixture {} snapshot verification failed", case.name);
                }
            }
            "kanban_projection_column_pagination" | "board_projection_group_pagination" => {
                validate_kanban_column_pagination(&case)?
            }
            "kanban_projection_hidden_counts" | "board_projection_hidden_counts" => {
                validate_kanban_hidden_counts(&case)?
            }
            "row_projection_contract" => {
                validate_projection_contract(&case, "collection", "table")?
            }
            "timeline_projection_contract" => {
                validate_projection_contract(&case, "timeline", "chat")?
            }
            "graph_projection_contract" => validate_projection_contract(&case, "graph", "graph")?,
            "document_projection_contract" => {
                validate_projection_contract(&case, "document", "document")?
            }
            "composite_projection_contract" => {
                validate_projection_contract(&case, "composite", "dashboard")?
            }
            _ => bail!("unknown sync fixture case {}", case.name),
        }
    }

    Ok(())
}

fn run_sync_artifact_suite(value: &Value) -> Result<()> {
    validate_profile(value, "cx.profile.sync_vectors.v1")?;
    if value
        .pointer("/collection_projection/frontier/state_hash")
        .and_then(Value::as_str)
        .is_none_or(|hash| !looks_like_sha256_digest(hash))
    {
        bail!("sync artifact collection projection missing state_hash");
    }
    if value
        .pointer("/room_timeline/next_cursor")
        .and_then(Value::as_str)
        .is_none_or(|cursor| !cursor.starts_with("cx:cursor:"))
    {
        bail!("sync artifact room timeline missing cursor");
    }
    if value
        .pointer("/snapshot_frontier_recovery/event_set_commitment/root")
        .and_then(Value::as_str)
        .is_none_or(|root| !looks_like_sha256_digest(root))
    {
        bail!("sync artifact snapshot commitment missing digest root");
    }
    if value
        .pointer("/e2ee_decryption_pending/must_not_drop_timeline_entry")
        .and_then(Value::as_bool)
        != Some(true)
    {
        bail!("sync artifact no longer requires keeping pending E2EE entries");
    }
    Ok(())
}

// ── Reference sync service ──────────────────────────────────────────────────

#[derive(Clone)]
struct SyncEvent {
    cursor: String,
    event_id: String,
}

struct SyncResponse {
    events: Vec<SyncEvent>,
    next_cursor: Option<String>,
    state_after: String,
    limited: bool,
    prev_batch: Option<String>,
}

struct ReferenceSyncService {
    events: Vec<SyncEvent>,
    visible_cursor: Option<String>,
    pending_to_device: Vec<String>,
    acked_to_device: HashSet<String>,
}

impl ReferenceSyncService {
    fn sample() -> Self {
        Self {
            events: vec![
                SyncEvent {
                    cursor: "cx:cursor:001".to_owned(),
                    event_id: "evt_1".to_owned(),
                },
                SyncEvent {
                    cursor: "cx:cursor:002".to_owned(),
                    event_id: "evt_2".to_owned(),
                },
                SyncEvent {
                    cursor: "cx:cursor:003".to_owned(),
                    event_id: "evt_3".to_owned(),
                },
                SyncEvent {
                    cursor: "cx:cursor:004".to_owned(),
                    event_id: "evt_4".to_owned(),
                },
            ],
            visible_cursor: Some("cx:cursor:003".to_owned()),
            pending_to_device: Vec::new(),
            acked_to_device: HashSet::new(),
        }
    }

    fn initial_sync(&self, limit: usize) -> Result<SyncResponse> {
        let events = self
            .events
            .iter()
            .take(limit.min(3))
            .cloned()
            .collect::<Vec<_>>();
        let next_cursor = events.last().map(|event| event.cursor.clone());
        Ok(SyncResponse {
            state_after: sha256_prefixed(b"state-after-initial"),
            events,
            next_cursor,
            limited: false,
            prev_batch: None,
        })
    }

    fn incremental_sync(&self, since: Option<&str>, limit: usize) -> Result<SyncResponse> {
        if let Some(cursor) = since {
            if !self.events.iter().any(|event| event.cursor == cursor) {
                bail!("sync_token_expired_or_snapshot_bootstrap");
            }
        }
        let since = since.unwrap_or(self.visible_cursor.as_deref().unwrap_or(""));
        let start_index = self
            .events
            .iter()
            .position(|event| event.cursor == since)
            .map(|index| index + 1)
            .unwrap_or(0);
        let events = self.events[start_index..]
            .iter()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let next_cursor = events.last().map(|event| event.cursor.clone());
        Ok(SyncResponse {
            state_after: sha256_prefixed(b"state-after-incremental"),
            events,
            next_cursor,
            limited: false,
            prev_batch: None,
        })
    }

    fn backfill(&self, limit: usize) -> Result<SyncResponse> {
        let events = self
            .events
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        Ok(SyncResponse {
            state_after: sha256_prefixed(b"state-after-backfill"),
            limited: self.events.len() > limit,
            prev_batch: Some("cx:cursor:prev-batch".to_owned()),
            next_cursor: events.last().map(|event| event.cursor.clone()),
            events,
        })
    }

    fn validate_filter(&self, profile: &str) -> Result<()> {
        if profile == "default" {
            return Ok(());
        }
        bail!("invalid_param_or_describe_guidance");
    }

    fn queue_to_device(&mut self, message_id: &str) {
        self.pending_to_device.push(message_id.to_owned());
    }

    fn pull_to_device(&self) -> Vec<String> {
        self.pending_to_device
            .iter()
            .filter(|message| !self.acked_to_device.contains(*message))
            .cloned()
            .collect()
    }

    fn ack_to_device(&mut self, message_id: &str) {
        self.acked_to_device.insert(message_id.to_owned());
    }
}

// ── Reference snapshot ──────────────────────────────────────────────────────

struct ReferenceSnapshot {
    manifest: Value,
    chunks: Vec<Value>,
}

impl ReferenceSnapshot {
    fn sample() -> Result<Self> {
        let chunk_1 = json!({"chunk_id": "chunk-1", "events": ["evt_1", "evt_2"]});
        let chunk_2 = json!({"chunk_id": "chunk-2", "events": ["evt_3", "evt_4"]});
        let chunk_digests = vec![
            sha256_prefixed(canonical_json(&chunk_1)?.as_bytes()),
            sha256_prefixed(canonical_json(&chunk_2)?.as_bytes()),
        ];
        let manifest = json!({
            "snapshot_ref": "cx:snapshot:01JS0SN000000000000000000",
            "space_id": "cx:space:fixture",
            "state_hash": sha256_prefixed("evt_1evt_2evt_3evt_4".as_bytes()),
            "frontier": ["evt_4"],
            "chunks": [
                {"chunk_id": "chunk-1", "digest": chunk_digests[0]},
                {"chunk_id": "chunk-2", "digest": chunk_digests[1]}
            ],
            "signature": {"alg": "none", "sig": "fixture"}
        });
        Ok(Self {
            manifest,
            chunks: vec![chunk_1, chunk_2],
        })
    }

    fn verify(&self) -> Result<bool> {
        let manifest_chunks = self.manifest["chunks"]
            .as_array()
            .ok_or_else(|| anyhow!("snapshot manifest missing chunks"))?;
        for (entry, chunk) in manifest_chunks.iter().zip(self.chunks.iter()) {
            let expected = entry["digest"]
                .as_str()
                .ok_or_else(|| anyhow!("snapshot digest missing"))?;
            let actual = sha256_prefixed(canonical_json(chunk)?.as_bytes());
            if actual != expected {
                return Ok(false);
            }
        }
        let state_hash = self.manifest["state_hash"]
            .as_str()
            .ok_or_else(|| anyhow!("snapshot state_hash missing"))?;
        Ok(state_hash == sha256_prefixed("evt_1evt_2evt_3evt_4".as_bytes()))
    }
}

// ── Sync validation helpers ─────────────────────────────────────────────────

fn validate_kanban_column_pagination(case: &SyncCase) -> Result<()> {
    let initial_request = required_sync_field(case, "initial_request")?;
    let initial_response = required_sync_field(case, "initial_response")?;
    validate_projection_pair(
        case,
        initial_request,
        initial_response,
        "collection",
        "kanban",
    )?;

    let groups = value_array(
        required_field(initial_response, "groups")?,
        "initial_response.groups",
    )?;
    let todo = find_group(groups, "todo")?;
    let done = find_group(groups, "done")?;
    if !value_field_bool(todo, "limited")? || required_field(todo, "next_cursor")?.is_null() {
        bail!(
            "sync fixture {} todo column was not limited with cursor",
            case.name
        );
    }
    if value_field_bool(done, "limited")? || !required_field(done, "next_cursor")?.is_null() {
        bail!(
            "sync fixture {} done column pagination leaked cursor",
            case.name
        );
    }
    validate_kanban_group_positions(todo, &case.name)?;
    validate_kanban_group_positions(done, &case.name)?;

    let followup_request = required_sync_field(case, "followup_request")?;
    let expected_followup = required_sync_field(case, "expected_followup_response")?;
    let followup_cursor = value_field_str(followup_request, "cursor")?;
    if followup_cursor != value_field_str(todo, "next_cursor")? {
        bail!(
            "sync fixture {} followup cursor did not resume todo column",
            case.name
        );
    }
    validate_projection_pair(
        case,
        followup_request,
        expected_followup,
        "collection",
        "kanban",
    )?;
    let followup_groups = value_array(
        required_field(expected_followup, "groups")?,
        "expected_followup_response.groups",
    )?;
    if followup_groups.len() != 1 || value_field_str(&followup_groups[0], "key")? != "todo" {
        bail!(
            "sync fixture {} followup did not isolate todo column",
            case.name
        );
    }
    validate_kanban_group_positions(&followup_groups[0], &case.name)
}

fn validate_kanban_hidden_counts(case: &SyncCase) -> Result<()> {
    let input = required_sync_field(case, "input")?;
    let visible_entities = value_array(
        required_field(
            required_field(input, "actor_visibility")?,
            "visible_entities",
        )?,
        "input.actor_visibility.visible_entities",
    )?
    .iter()
    .map(|value| {
        value
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| anyhow!("sync fixture {} visible entity must be string", case.name))
    })
    .collect::<Result<BTreeSet<_>>>()?;

    let policy_cases = value_array(required_sync_field(case, "policy_cases")?, "policy_cases")?;
    for policy_case in policy_cases {
        let policy_name = value_field_str(policy_case, "name")?;
        let allowed = required_field(policy_case, "allowed_response")?;
        validate_projection_response(allowed, "collection", "kanban", &case.name)?;
        let groups = value_array(
            required_field(allowed, "groups")?,
            "allowed_response.groups",
        )?;
        for group in groups {
            let visible_count = assert_group_items_visible(group, &visible_entities, &case.name)?;
            match policy_name {
                "omit" if group.get("total_estimate").is_some() => {
                    bail!(
                        "sync fixture {} omit policy exposed total_estimate",
                        case.name
                    );
                }
                "authorized_estimate" | "authorized_exact" => {
                    if value_field_u64(group, "total_estimate")? != visible_count as u64 {
                        bail!(
                            "sync fixture {} count policy was not visibility-trimmed",
                            case.name
                        );
                    }
                }
                "omit" => {}
                other => bail!(
                    "sync fixture {} unknown hidden count policy {other}",
                    case.name
                ),
            }
        }
    }
    Ok(())
}

fn validate_projection_contract(case: &SyncCase, projection: &str, preset: &str) -> Result<()> {
    let request = required_sync_field(case, "request")?;
    let response = required_sync_field(case, "response")?;
    validate_projection_pair(case, request, response, projection, preset)?;
    validate_projection_shape(response, projection, &case.name)
}

fn validate_projection_pair(
    case: &SyncCase,
    request: &Value,
    response: &Value,
    projection: &str,
    preset: &str,
) -> Result<()> {
    if value_field_str(request, "projection")? != projection
        || value_field_str(response, "projection")? != projection
    {
        bail!(
            "sync fixture {} projection discriminator mismatch",
            case.name
        );
    }
    if let Some(request_preset) = request.get("preset").and_then(Value::as_str) {
        if request_preset != preset {
            bail!("sync fixture {} request preset mismatch", case.name);
        }
    }
    if let Some(response_preset) = response.get("preset").and_then(Value::as_str) {
        if response_preset != preset {
            bail!("sync fixture {} response preset mismatch", case.name);
        }
    }
    if let Some(request_view_id) = request.get("view_id").and_then(Value::as_str) {
        if value_field_str(response, "view_id")? != request_view_id {
            bail!("sync fixture {} response view_id drifted", case.name);
        }
    }
    if request.get("renderer").is_some() {
        validate_query_renderer(request)?;
    }
    validate_projection_response(response, projection, preset, &case.name)?;
    validate_response_entities_against_request_facets(response, request, &case.name)
}

fn validate_projection_response(
    response: &Value,
    projection: &str,
    preset: &str,
    case_name: &str,
) -> Result<()> {
    if value_field_str(response, "projection")? != projection {
        bail!("sync fixture {case_name} response discriminator mismatch");
    }
    if let Some(response_preset) = response.get("preset").and_then(Value::as_str) {
        if response_preset != preset {
            bail!("sync fixture {case_name} response preset mismatch");
        }
    }
    let frontier = required_field(response, "frontier")?;
    let state_hash = value_field_str(frontier, "state_hash")?;
    if !looks_like_sha256_digest(state_hash) {
        bail!("sync fixture {case_name} response frontier hash was invalid");
    }
    validate_optional_cursor(response.get("next_cursor"), case_name)?;
    Ok(())
}

fn validate_projection_shape(response: &Value, projection: &str, case_name: &str) -> Result<()> {
    match projection {
        "collection" => {
            let items = required_field(response, "items")?;
            if value_array(items, "response.items")?.is_empty() {
                bail!("sync fixture {case_name} collection projection had no items");
            }
            for item in value_array(items, "response.items")? {
                validate_entity(required_field(item, "entity")?, &BTreeSet::new(), case_name)?;
                if required_field(item, "position")?
                    .as_object()
                    .map_or(true, serde_json::Map::is_empty)
                {
                    bail!(
                        "sync fixture {case_name} collection item missing position discriminator"
                    );
                }
            }
        }
        "timeline" => {
            let entries = value_array(required_field(response, "entries")?, "response.entries")?;
            for entry in entries {
                if !value_field_str(entry, "sort_key")?.contains('|') {
                    bail!("sync fixture {case_name} timeline entry missing stable sort key");
                }
                validate_entity(
                    required_field(entry, "entity")?,
                    &BTreeSet::new(),
                    case_name,
                )?;
            }
        }
        "graph" => {
            if value_array(required_field(response, "nodes")?, "response.nodes")?.is_empty() {
                bail!("sync fixture {case_name} graph projection had no nodes");
            }
            for node in value_array(required_field(response, "nodes")?, "response.nodes")? {
                validate_entity(required_field(node, "entity")?, &BTreeSet::new(), case_name)?;
            }
            for edge in value_array(required_field(response, "edges")?, "response.edges")? {
                if !value_field_str(edge, "relation_id")?.starts_with("cx:relation:") {
                    bail!("sync fixture {case_name} graph edge relation id was invalid");
                }
            }
        }
        "document" => {
            for section in value_array(required_field(response, "sections")?, "response.sections")?
            {
                if value_field_str(section, "sort_key")?.is_empty() {
                    bail!("sync fixture {case_name} document section missing sort key");
                }
                validate_entity(
                    required_field(section, "entity")?,
                    &BTreeSet::new(),
                    case_name,
                )?;
            }
        }
        "composite" => {
            for widget in value_array(required_field(response, "widgets")?, "response.widgets")? {
                if widget.get("frontier").is_none() || widget.get("projection").is_none() {
                    bail!("sync fixture {case_name} composite widget missing projection frontier");
                }
            }
        }
        other => bail!("sync fixture {case_name} unsupported projection {other}"),
    }
    Ok(())
}

fn validate_kanban_group_positions(group: &Value, case_name: &str) -> Result<()> {
    let source = required_field(group, "source")?;
    if value_field_str(source, "model")? != "field_value" {
        bail!("sync fixture {case_name} kanban group was not field-value sourced");
    }
    for item in value_array(required_field(group, "items")?, "group.items")? {
        let position = required_field(item, "position")?;
        validate_projection_position(position)?;
        if value_field_str(position, "model")? != "field_value" {
            bail!("sync fixture {case_name} kanban item position discriminator mismatch");
        }
    }
    Ok(())
}

fn assert_group_items_visible(
    group: &Value,
    visible_entities: &BTreeSet<String>,
    case_name: &str,
) -> Result<usize> {
    let mut visible_count = 0;
    for item in value_array(required_field(group, "items")?, "group.items")? {
        let entity_id = value_field_str(required_field(item, "entity")?, "id")?;
        if !visible_entities.contains(entity_id) {
            bail!("sync fixture {case_name} leaked hidden entity in group response");
        }
        visible_count += 1;
    }
    Ok(visible_count)
}

fn find_group<'a>(groups: &'a [Value], key: &str) -> Result<&'a Value> {
    groups
        .iter()
        .find(|group| group.get("key").and_then(Value::as_str) == Some(key))
        .ok_or_else(|| anyhow!("missing projection group {key}"))
}

fn validate_optional_cursor(value: Option<&Value>, case_name: &str) -> Result<()> {
    match value {
        Some(Value::Null) | None => Ok(()),
        Some(Value::String(cursor)) if cursor.starts_with("cx:cursor:") => Ok(()),
        _ => bail!("sync fixture {case_name} invalid cursor shape"),
    }
}

fn required_sync_field<'a>(case: &'a SyncCase, key: &str) -> Result<&'a Value> {
    case.fields
        .get(key)
        .ok_or_else(|| anyhow!("sync fixture {} missing {key}", case.name))
}
