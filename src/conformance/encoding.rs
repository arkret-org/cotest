use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Value, json};

use super::{RANK_MAX_LENGTH, load_fixture_value, value_field_str};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodingArtifactFixture {
    runner: Value,
    profile: String,
    version: String,
    description: String,
    generator_semantics: String,
    vectors: Vec<Value>,
    rank_order: Vec<Value>,
    expected_order: Vec<String>,
}

pub fn run_encoding_fixture_suite() -> Result<()> {
    let value = load_fixture_value("encoding-fixture.json")?;
    let fixture: EncodingArtifactFixture = serde_json::from_value(value)?;
    run_encoding_artifact_suite(&fixture)
}

fn run_encoding_artifact_suite(fixture: &EncodingArtifactFixture) -> Result<()> {
    if fixture.profile != "ak.vector_group.encoding.v1"
        || fixture.version.trim().is_empty()
        || fixture.description.trim().is_empty()
        || fixture.generator_semantics.trim().is_empty()
        || fixture.runner.is_null()
    {
        bail!("encoding artifact metadata drifted");
    }
    let mut sorted = fixture.rank_order.clone();
    sorted.sort_by(|left, right| {
        left.get("rank")
            .and_then(Value::as_str)
            .cmp(&right.get("rank").and_then(Value::as_str))
    });
    let actual = sorted
        .iter()
        .map(rank_order_entry_id)
        .collect::<Result<Vec<_>>>()?;
    if actual != fixture.expected_order {
        bail!("encoding rank_order did not match expected_order");
    }
    run_encrypted_envelope_digest_vector(fixture)?;
    Ok(())
}

fn run_encrypted_envelope_digest_vector(fixture: &EncodingArtifactFixture) -> Result<()> {
    const VECTOR_ID: &str = "ak.vector.encoding.encrypted_envelope_digest.v1";
    let vector = fixture
        .vectors
        .iter()
        .find(|vector| vector.get("vector_id").and_then(Value::as_str) == Some(VECTOR_ID))
        .ok_or_else(|| anyhow!("encoding fixture missing {VECTOR_ID}"))?;
    let metadata = vector
        .get("payload_metadata")
        .cloned()
        .ok_or_else(|| anyhow!("{VECTOR_ID} missing payload_metadata"))?;
    let canonical = arkret_canonical::canonical_json_string(&metadata)?;
    if canonical != value_field_str(vector, "expected_metadata_canonical_bytes_utf8")? {
        bail!("{VECTOR_ID} minimal envelope metadata canonical bytes drifted");
    }
    let ciphertext = value_field_str(vector, "ciphertext_base64url")?;
    let mut envelope = metadata;
    envelope
        .as_object_mut()
        .ok_or_else(|| anyhow!("{VECTOR_ID} payload_metadata must be an object"))?
        .insert(
            "ciphertext".to_owned(),
            Value::String(ciphertext.to_owned()),
        );
    let envelope = serde_json::from_value::<arkret_models_crypto::EncryptedEnvelope>(envelope)?;
    envelope.validate()?;
    if envelope.payload_digest()?.as_str() != value_field_str(vector, "expected_digest")? {
        bail!("{VECTOR_ID} minimal envelope digest known-answer mismatch");
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
            "board_space_id": "ak:space:AdouNWm0_Osk7GwYrppoMcCJUjPlKufC8wapFR7Bj4eN",
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
