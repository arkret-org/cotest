use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};

use super::{
    EncodingFixture, RANK_MAX_LENGTH, canonical_json, decode_cursor_shape, encode_cursor_shape,
    load_fixture_value, looks_like_sha256_digest, parse_fixture_value, rank_between,
    rebalance_assignments, sha256_prefixed, validate_profile, validate_rank,
    validate_rebalance_assignment_count, value_field_str,
};

pub fn run_encoding_fixture_suite() -> Result<()> {
    let value = load_fixture_value("encoding-fixture.json")?;
    if value.get("suite").is_none() {
        return run_encoding_artifact_suite(&value);
    }
    let fixture: EncodingFixture = parse_fixture_value("encoding-fixture.json", value)?;
    if fixture.suite != "encoding" {
        bail!("unexpected fixture suite {}", fixture.suite);
    }

    for case in fixture.cases.canonical_json {
        let canonical = canonical_json(&case.input)?;
        if canonical != case.canonical {
            bail!(
                "encoding fixture {} expected canonical {}, got {}",
                case.name,
                case.canonical,
                canonical
            );
        }
    }

    for case in fixture.cases.hash_digest {
        let digest = sha256_prefixed(case.input_ref.as_bytes());
        if case.expected_pattern != "^sha256:[0-9a-f]{64}$" {
            bail!(
                "encoding fixture {} pattern drifted to {}",
                case.name,
                case.expected_pattern
            );
        }
        if !looks_like_sha256_digest(&digest) {
            bail!(
                "encoding fixture {} produced invalid digest {}",
                case.name,
                digest
            );
        }
        if digest == sha256_prefixed(b"") {
            bail!(
                "encoding fixture {} digest collapsed to empty input",
                case.name
            );
        }
    }

    for case in fixture.cases.proof_payload {
        let event = json!({
            "event_id": "cx:event:01970e58-0003-7000-8000-000000000010",
            "kind": "cx.message.create",
            "space_id": "cx:space:01970e58-0003-7000-8000-000000000011",
            "content": {"body": "covered"},
            "proofs": [{"alg": "none"}],
            "unsigned": {"hint": "not covered"}
        });
        let payload = super::canonical_proof_payload(&event)?;
        for field in case.covered_fields {
            if payload.get(&field).is_none() {
                bail!(
                    "encoding fixture {} missing covered field {}",
                    case.name,
                    field
                );
            }
        }
        for field in case.excluded_fields {
            if payload.get(&field).is_some() {
                bail!(
                    "encoding fixture {} leaked excluded field {}",
                    case.name,
                    field
                );
            }
        }
    }

    for case in fixture.cases.hlc {
        for pair in case.values.windows(2) {
            if pair[0] >= pair[1] {
                bail!(
                    "encoding fixture {} is not lexicographically increasing",
                    case.name
                );
            }
        }
    }

    for case in fixture.cases.cursor {
        let encoded = encode_cursor_shape(&case.shape)?;
        if !encoded.starts_with("cx:cursor:") {
            bail!(
                "encoding fixture {} did not produce cx:cursor prefix",
                case.name
            );
        }
        let decoded = decode_cursor_shape(&encoded)?;
        if decoded != case.shape {
            bail!(
                "encoding fixture {} roundtrip mismatch: expected {:?}, got {:?}",
                case.name,
                case.shape,
                decoded
            );
        }
    }

    for case in fixture.cases.fractional_rank {
        match case.name.as_str() {
            "rank_between"
            | "rank_between_start"
            | "rank_between_end"
            | "rank_dense_insert_extends" => {
                let expected = case.expected.as_deref().ok_or_else(|| {
                    anyhow!("encoding fixture {} missing expected rank", case.name)
                })?;
                let actual = rank_between(case.left.as_deref(), case.right.as_deref())?;
                if actual != expected {
                    bail!(
                        "encoding fixture {} expected rank {}, got {}",
                        case.name,
                        expected,
                        actual
                    );
                }
            }
            "rebalance_assignments_three_items" => {
                let edges = case.ordered_edges.as_deref().ok_or_else(|| {
                    anyhow!("encoding fixture {} missing ordered_edges", case.name)
                })?;
                let expected = case.expected_assignments.as_deref().ok_or_else(|| {
                    anyhow!(
                        "encoding fixture {} missing expected_assignments",
                        case.name
                    )
                })?;
                let actual = rebalance_assignments(edges)?;
                if actual != expected {
                    bail!(
                        "encoding fixture {} rank rebalance assignments differed",
                        case.name
                    );
                }
            }
            "rebalance_reject_partial_assignment" => {
                let active = case.active_edge_count.ok_or_else(|| {
                    anyhow!("encoding fixture {} missing active_edge_count", case.name)
                })?;
                let assignments = case.assignment_count.ok_or_else(|| {
                    anyhow!("encoding fixture {} missing assignment_count", case.name)
                })?;
                if validate_rebalance_assignment_count(active, assignments).is_ok() {
                    bail!(
                        "encoding fixture {} accepted partial rebalance assignment",
                        case.name
                    );
                }
            }
            "rank_reject_invalid_character" => {
                let input = case
                    .input
                    .as_deref()
                    .ok_or_else(|| anyhow!("encoding fixture {} missing input", case.name))?;
                if validate_rank(input, RANK_MAX_LENGTH).is_ok() {
                    bail!(
                        "encoding fixture {} accepted invalid rank character",
                        case.name
                    );
                }
            }
            "rank_reject_too_long" => {
                let max_length = case
                    .max_length
                    .ok_or_else(|| anyhow!("encoding fixture {} missing max_length", case.name))?;
                let too_long = "0".repeat(max_length + 1);
                if validate_rank(&too_long, max_length).is_ok() {
                    bail!("encoding fixture {} accepted overlong rank", case.name);
                }
            }
            _ => bail!("unknown fractional rank fixture case {}", case.name),
        }
    }

    Ok(())
}

fn run_encoding_artifact_suite(value: &Value) -> Result<()> {
    validate_profile(value, "cx.profile.encoding_vectors.v1")?;
    let rank_order = value
        .get("rank_order")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("encoding artifact missing rank_order"))?;
    let expected = value
        .get("expected_order")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("encoding artifact missing expected_order"))?;
    let mut sorted = rank_order.clone();
    sorted.sort_by(|left, right| {
        left.get("rank")
            .and_then(Value::as_str)
            .cmp(&right.get("rank").and_then(Value::as_str))
    });
    let actual = sorted
        .iter()
        .map(rank_order_entry_id)
        .collect::<Result<Vec<_>>>()?;
    let expected = expected
        .iter()
        .map(|entry| entry.as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    if actual != expected {
        bail!("encoding rank_order did not match expected_order");
    }
    Ok(())
}

fn rank_order_entry_id(entry: &Value) -> Result<String> {
    if let Some(value) = entry.get("flow_id").and_then(Value::as_str) {
        return Ok(value.to_owned());
    }
    bail!("encoding rank_order entry missing flow_id");
}

// ── Facet renderer query fixture suite ──────────────────────────────────────

pub fn run_facet_renderer_query_fixture_suite() -> Result<()> {
    let request = json!({
        "projection": "collection",
        "preset": "kanban",
        "renderer": "board",
        "view_id": "cx:view:019641be-0000-7000-8000-000000000000",
        "facets": ["stateful", "rankable"],
        "limit": 50
    });
    validate_query_renderer(&request)?;
    let required_facets = request_facets(&request)?;
    let entities = vec![
        json!({
            "id": "cx:entity:019641a5-0000-7000-8000-000000000000",
            "entity_type": "task",
            "facets": ["stateful", "rankable", "renderable"],
            "title": "Rankable task"
        }),
        json!({
            "id": "cx:entity:01964155-0000-7000-8000-000000000000",
            "entity_type": "note",
            "facets": ["stateful", "renderable"],
            "title": "State-only note"
        }),
    ];
    let visible = filter_entities_by_facets(&entities, &required_facets)?;
    if visible.len() != 1
        || value_field_str(&visible[0], "id")? != "cx:entity:019641a5-0000-7000-8000-000000000000"
    {
        bail!("facet renderer query suite did not filter by requested facets");
    }

    let response = json!({
        "projection": "collection",
        "preset": "kanban",
        "view_id": "cx:view:019641be-0000-7000-8000-000000000000",
        "frontier": {"state_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        "groups": [{
            "key": "todo",
            "title": "Todo",
            "source": {"model": "field_value", "field": "fields.status", "value": "todo"},
            "items": [{
                "entity": visible[0].clone(),
                "position": {"model": "field_value", "container_id": "todo", "rank": "F"}
            }],
            "next_cursor": null,
            "limited": false
        }]
    });
    validate_response_entities_against_request_facets(&response, &request, "facet_renderer_query")?;

    let invalid_renderer = json!({
        "projection": "collection",
        "preset": "kanban",
        "renderer": "table",
        "view_id": "cx:view:019641be-0000-7000-8000-000000000000",
        "facets": ["stateful", "rankable"]
    });
    if validate_query_renderer(&invalid_renderer).is_ok() {
        bail!("facet renderer query suite accepted mismatched renderer");
    }

    Ok(())
}

// ── Projection position discriminator fixture suite ─────────────────────────

pub fn run_projection_position_discriminator_fixture_suite() -> Result<()> {
    let positions = [
        json!({
            "model": "field_value",
            "container_id": "todo",
            "rank": "F"
        }),
        json!({
            "model": "relation_container",
            "scope_container_id": "cx:entity:019640b6-8000-7000-8000-000000000000",
            "container_id": "cx:entity:019640c0-8000-7000-8000-000000000000",
            "relation_kind": "contains",
            "relation_id": "cx:relation:01970e58-0002-7000-8000-000000000001",
            "rank": "V"
        }),
        json!({
            "model": "time_bucket",
            "start_field": "fields.starts_at",
            "bucket": "week",
            "timezone": "UTC",
            "bucket_start": "2026-04-27T00:00:00Z",
            "rank": "k"
        }),
        json!({
            "model": "matrix_cell",
            "rows_by": "fields.assignee",
            "columns_by": "fields.status",
            "row_key": "did:web:alice.example",
            "column_key": "todo",
            "rank": "F"
        }),
    ];
    for position in positions {
        validate_projection_position(&position)?;
    }

    let invalid = json!({
        "model": "relation_container",
        "container_id": "cx:entity:019640c0-8000-7000-8000-000000000000",
        "relation_kind": "contains",
        "rank": "F"
    });
    if validate_projection_position(&invalid).is_ok() {
        bail!("projection position suite accepted incomplete relation_container position");
    }

    Ok(())
}

// ── Shared validation helpers (encoding/projection) ─────────────────────────

pub(crate) fn validate_query_renderer(request: &Value) -> Result<()> {
    let projection = value_field_str(request, "projection")?;
    let renderer = value_field_str(request, "renderer")?;
    let preset = request
        .get("preset")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| infer_preset_from_renderer(projection, renderer).map(ToOwned::to_owned))
        .ok_or_else(|| {
            anyhow!("unsupported projection/renderer mapping {projection}/{renderer}")
        })?;
    let expected = expected_renderer(projection, &preset).ok_or_else(|| {
        anyhow!("unsupported projection/preset renderer mapping {projection}/{preset}")
    })?;
    if renderer != expected {
        bail!("renderer {renderer} does not match {projection}/{preset}; expected {expected}");
    }
    Ok(())
}

fn infer_preset_from_renderer(projection: &str, renderer: &str) -> Option<&'static str> {
    match (projection, renderer) {
        ("collection", "board") => Some("kanban"),
        ("collection", "table") => Some("table"),
        ("collection", "calendar") => Some("calendar"),
        ("collection", "gantt") => Some("gantt"),
        ("timeline", "chat") => Some("chat"),
        ("timeline", "timeline") => Some("timeline"),
        ("graph", "graph") => Some("graph"),
        ("graph", "tree") => Some("tree"),
        ("document", "document") => Some("document"),
        ("composite", "dashboard") => Some("dashboard"),
        _ => None,
    }
}

pub(crate) fn expected_renderer(projection: &str, preset: &str) -> Option<&'static str> {
    match (projection, preset) {
        ("collection", "kanban") => Some("board"),
        ("collection", "table") => Some("table"),
        ("collection", "calendar") => Some("calendar"),
        ("collection", "gantt") => Some("gantt"),
        ("collection", "matrix") => Some("table"),
        ("timeline", "chat") => Some("chat"),
        ("timeline", "timeline") => Some("timeline"),
        ("graph", "graph") => Some("graph"),
        ("graph", "tree") => Some("tree"),
        ("document", "document") => Some("document"),
        ("composite", "dashboard") => Some("dashboard"),
        _ => None,
    }
}

pub(crate) fn validate_projection_position(position: &Value) -> Result<()> {
    match value_field_str(position, "model")? {
        "field_value" => {
            require_position_field(position, "container_id")?;
            require_rank(position)?;
        }
        "relation_container" => {
            require_position_field(position, "scope_container_id")?;
            require_position_field(position, "container_id")?;
            require_position_field(position, "relation_kind")?;
            let relation_id = require_position_field(position, "relation_id")?;
            if !relation_id.starts_with("cx:relation:") {
                bail!("relation_container position relation_id was invalid");
            }
            require_rank(position)?;
        }
        "time_bucket" => {
            require_position_field(position, "start_field")?;
            require_position_field(position, "bucket")?;
            require_position_field(position, "timezone")?;
            let bucket_start = require_position_field(position, "bucket_start")?;
            if !bucket_start.ends_with('Z') {
                bail!("time_bucket position bucket_start must be UTC timestamp");
            }
            require_rank(position)?;
        }
        "matrix_cell" => {
            require_position_field(position, "rows_by")?;
            require_position_field(position, "columns_by")?;
            require_position_field(position, "row_key")?;
            require_position_field(position, "column_key")?;
            require_rank(position)?;
        }
        other => bail!("unknown projection position model {other}"),
    }
    Ok(())
}

fn require_position_field<'a>(position: &'a Value, field: &str) -> Result<&'a str> {
    let value = value_field_str(position, field)?;
    if value.is_empty() {
        bail!("projection position field {field} must not be empty");
    }
    Ok(value)
}

fn require_rank(position: &Value) -> Result<()> {
    super::validate_rank(require_position_field(position, "rank")?, RANK_MAX_LENGTH)
}

pub(crate) fn validate_response_entities_against_request_facets(
    response: &Value,
    request: &Value,
    case_name: &str,
) -> Result<()> {
    let required_facets = request_facets(request)?;
    validate_nested_entities(response, &required_facets, case_name)
}

pub(crate) fn request_facets(request: &Value) -> Result<std::collections::BTreeSet<String>> {
    use std::collections::BTreeSet;
    request
        .get("facets")
        .and_then(Value::as_array)
        .map(|facets| {
            facets
                .iter()
                .map(|facet| {
                    facet
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| anyhow!("query facet must be a string"))
                })
                .collect::<Result<BTreeSet<_>>>()
        })
        .unwrap_or_else(|| Ok(BTreeSet::new()))
}

fn filter_entities_by_facets(
    entities: &[Value],
    required_facets: &std::collections::BTreeSet<String>,
) -> Result<Vec<Value>> {
    let mut filtered = Vec::new();
    for entity in entities {
        let facets = entity_facets(entity)?;
        if required_facets.is_subset(&facets) {
            filtered.push(entity.clone());
        }
    }
    Ok(filtered)
}

pub(crate) fn validate_nested_entities(
    value: &Value,
    required_facets: &std::collections::BTreeSet<String>,
    case_name: &str,
) -> Result<()> {
    match value {
        Value::Object(object) => {
            if object.contains_key("entity_type") && object.contains_key("facets") {
                validate_entity(value, required_facets, case_name)?;
            }
            for child in object.values() {
                validate_nested_entities(child, required_facets, case_name)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                validate_nested_entities(item, required_facets, case_name)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn validate_entity(
    entity: &Value,
    required_facets: &std::collections::BTreeSet<String>,
    case_name: &str,
) -> Result<()> {
    if !value_field_str(entity, "id")?.starts_with("cx:entity:") {
        bail!("sync fixture {case_name} entity id was invalid");
    }
    let facets = entity_facets(entity)?;
    if !required_facets.is_subset(&facets) {
        bail!("sync fixture {case_name} entity did not satisfy requested facets");
    }
    Ok(())
}

fn entity_facets(entity: &Value) -> Result<std::collections::BTreeSet<String>> {
    super::value_array(super::required_field(entity, "facets")?, "entity.facets")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| anyhow!("entity facet was not string"))
        })
        .collect()
}
