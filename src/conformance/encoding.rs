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
            "event_id": "ak:event:01970e58-0003-7000-8000-000000000010",
            "kind": "ck.message.create",
            "realm_id": "ak:realm:01970e58-0003-7000-8000-000000000011",
            "content": {"kind": "ck.content.text", "body": "covered"},
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
        if !encoded.starts_with("ak:cursor:") {
            bail!(
                "encoding fixture {} did not produce ck:cursor prefix",
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
    validate_profile(value, "ck.vector_group.encoding.v1")?;
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
    if let Some(value) = entry.get("strand_id").and_then(Value::as_str) {
        return Ok(value.to_owned());
    }
    bail!("encoding rank_order entry missing strand_id");
}

// ── Projection position discriminator fixture suite ─────────────────────────

pub fn run_projection_position_discriminator_fixture_suite() -> Result<()> {
    // Mirrors `models/views.md §3.3 CollectionGrouping`: discriminator field is
    // `mode`, enumerated `none | field | relation_container | time_bucket |
    // matrix`. `relation_container` binds a board Space via `board_space_id`
    // (`ak:space:` typed-id) plus `container_relation_kind` / `item_relation_kind`.
    let positions = [
        json!({
            "mode": "none",
            "rank": "F"
        }),
        json!({
            "mode": "field",
            "field": "fields.status",
            "lanes": [
                { "key": "todo" },
                { "key": "in_progress" }
            ],
            "rank": "F"
        }),
        json!({
            "mode": "relation_container",
            "board_space_id": "ak:space:019640b6-8000-7000-8000-000000000000",
            "container_relation_kind": "contains",
            "item_relation_kind": "contains",
            "rank": "V"
        }),
        json!({
            "mode": "time_bucket",
            "start_field": "fields.starts_at",
            "rank": "k"
        }),
        json!({
            "mode": "matrix",
            "rows_by": "fields.priority",
            "columns_by": "fields.status",
            "rank": "F"
        }),
    ];
    for position in positions {
        validate_projection_position(&position)?;
    }

    let invalid = json!({
        "mode": "relation_container",
        "container_relation_kind": "contains",
        "rank": "F"
    });
    if validate_projection_position(&invalid).is_ok() {
        bail!("projection position suite accepted incomplete relation_container grouping");
    }

    Ok(())
}

// ── Shared validation helpers (encoding/projection) ─────────────────────────

pub(crate) fn validate_projection_position(position: &Value) -> Result<()> {
    // `CollectionGrouping` per `models/views.md §3.3`. The discriminator is
    // `mode`; per-mode conditional fields follow the spec table.
    match value_field_str(position, "mode")? {
        "none" => {
            require_rank(position)?;
        }
        "field" => {
            require_position_field(position, "field")?;
            if !position.get("lanes").map(Value::is_array).unwrap_or(false) {
                bail!("field grouping requires a `lanes` array");
            }
            require_rank(position)?;
        }
        "relation_container" => {
            let board_space_id = require_position_field(position, "board_space_id")?;
            if !board_space_id.starts_with("ak:space:") {
                bail!("relation_container grouping board_space_id must be a ak:space: id");
            }
            // `container_relation_kind` is optional (defaults to `contains`);
            // `item_relation_kind` is mandatory and MUST NOT be inferred.
            require_position_field(position, "item_relation_kind")?;
            require_rank(position)?;
        }
        "time_bucket" => {
            require_position_field(position, "start_field")?;
            require_rank(position)?;
        }
        "matrix" => {
            require_position_field(position, "rows_by")?;
            require_position_field(position, "columns_by")?;
            require_rank(position)?;
        }
        other => bail!("unknown projection grouping mode {other}"),
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
