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
    run_accountability_scope_set_subject_vector(fixture)?;
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

fn run_accountability_scope_set_subject_vector(fixture: &EncodingArtifactFixture) -> Result<()> {
    use arkret_models_collaboration::governance::accountability::AccountabilityScope;

    const VECTOR_ID: &str = "ak.vector.identity.accountability_scope_set_subject.v1";
    let vector = fixture
        .vectors
        .iter()
        .find(|vector| vector.get("vector_id").and_then(Value::as_str) == Some(VECTOR_ID))
        .ok_or_else(|| anyhow!("encoding fixture missing {VECTOR_ID}"))?;
    let issuer = value_field_str(vector, "issuer_id")?;
    let station_id = value_field_str(vector, "station_id")?;
    let subject = value_field_str(vector, "subject_id")?;
    let descriptor = arkret_wire::EventKind::from("ak.identity.accountability_grant")
        .descriptor()
        .ok_or_else(|| anyhow!("accountability grant descriptor is missing"))?;
    let write = descriptor
        .cell_writes
        .iter()
        .find(|write| {
            write.cell_family.map(|family| family.as_str())
                == Some(arkret_wire::CellFamilyId::IDENTITY_ACCOUNTABILITY_V1)
        })
        .ok_or_else(|| anyhow!("accountability grant SDK cell write is missing"))?;
    let actual_descriptor = write
        .cell_subject_rule
        .ok_or_else(|| anyhow!("accountability grant subject rule is missing"))?
        .to_json_value();
    if actual_descriptor
        != vector
            .get("source_descriptor")
            .and_then(|source| source.get("components"))
            .map(|components| json!({"kind": "composite", "components": components}))
            .ok_or_else(|| anyhow!("{VECTOR_ID} source descriptor is malformed"))?
    {
        bail!("{VECTOR_ID} source descriptor drifted from the generated registry");
    }

    let positive_cases = vector
        .get("positive_cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("{VECTOR_ID} missing positive_cases"))?;
    for case in positive_cases {
        let scope: AccountabilityScope = serde_json::from_value(
            case.get("input")
                .cloned()
                .ok_or_else(|| anyhow!("{VECTOR_ID} positive case missing input"))?,
        )?;
        scope.validate()?;
        let component = scope.scope_set_component()?;
        if component != value_field_str(case, "scope_set_component")? {
            bail!("{VECTOR_ID} scope-set component KAT mismatch");
        }
        let cell_subject = arkret_wire::composite_subject(&[issuer, subject, component.as_str()])?;
        if cell_subject != value_field_str(case, "cell_subject")? {
            bail!("{VECTOR_ID} outer cell-subject KAT mismatch");
        }
    }

    for case in vector
        .get("negative_cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("{VECTOR_ID} missing negative_cases"))?
    {
        let Some(input) = case.get("input") else {
            continue;
        };
        let accepted = serde_json::from_value::<AccountabilityScope>(input.clone())
            .ok()
            .and_then(|scope| scope.scope_set_component().ok())
            .is_some();
        if accepted {
            bail!(
                "{VECTOR_ID} accepted negative case {}",
                value_field_str(case, "name")?
            );
        }
    }

    let string: AccountabilityScope = serde_json::from_value(json!("employment"))?;
    let singleton: AccountabilityScope = serde_json::from_value(json!(["employment"]))?;
    if string != singleton {
        bail!("{VECTOR_ID} string and singleton-array domain equality diverged");
    }
    let authoring = serde_json::to_value(singleton.canonicalized_for_authoring()?)?;
    if authoring != json!("employment") {
        bail!("{VECTOR_ID} canonical authoring did not emit singleton as a string");
    }
    let reordered: AccountabilityScope =
        serde_json::from_value(json!(["employment", "agent_operator"]))?;
    let authoring = serde_json::to_value(reordered.canonicalized_for_authoring()?)?;
    if authoring != json!(["agent_operator", "employment"]) {
        bail!("{VECTOR_ID} canonical authoring did not bytewise-sort a multi-value set");
    }

    let event_for = |scope: Value, status: &str| -> Result<arkret_wire::Event> {
        Ok(serde_json::from_value(json!({
            "event_id": "ak:event:AdUJkfoC4GBgYoPW4M0pjanZUQUGUONyXm711OvGtCga",
            "kind": "ak.identity.accountability_grant",
            "realm_id": "ak:realm:AUhhceSJLo6_BscKp90reATdtKd6Wu5jC9lZdYyfXDjN",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AUhhceSJLo6_BscKp90reATdtKd6Wu5jC9lZdYyfXDjN"},
            "actor_id": {"kind":"account", "account_id":{"principal_id":issuer, "station_id":station_id}},
            "actor_seq": 7,
            "created_at": "2026-07-26T01:00:00.000Z",
            "hlc": "019f9e500000-0000-aabbccdd",
            "prev_refs": [],
            "seal_basis": {
                "leaves": ["ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
            },
            "payload": {
                "issuer_id": issuer,
                "subject_id": subject,
                "accountability_scope": scope,
                // The registered cell contract projects `not_before` out of the
                // grant's own signed payload (the Agent-provision writer reads
                // it off the envelope instead). It is a required member of both
                // `accountability-grant.schema.json` and the projected record,
                // so a payload without it addresses no cell at all.
                "not_before": "2026-07-26T01:00:00.000Z",
                "grant_status": status
            },
            "producer_proof": null
        }))?)
    };
    // The cell an accountability grant addresses is derived from `kind +
    // payload` through the contract registry, not declared by the producer: v1
    // deleted the Event `effects[]` array. So the vector projects each Event
    // and compares the *derived* cell, which is a strictly stronger assertion
    // than comparing two producer-authored cell refs — a registry that
    // addressed the exact-set subject wrongly now fails here.
    let projected_cell = |event: &arkret_wire::Event| -> Result<arkret_wire::CellRef> {
        let writes = crate::publication::project_cells(event)
            .map_err(|error| anyhow!("{VECTOR_ID} projection failed: {error}"))?;
        let [write] = writes.as_slice() else {
            bail!(
                "{VECTOR_ID} expected exactly one derived cell write, got {}",
                writes.len()
            );
        };
        Ok(write.cell_id.clone())
    };
    // The subject is the canonical exact-set component, so a reordered set
    // addresses the same cell.
    let active = event_for(json!(["employment", "agent_operator"]), "active")?;
    let revoked = event_for(json!(["agent_operator", "employment"]), "revoked")?;
    if projected_cell(&active)? != projected_cell(&revoked)? {
        bail!("{VECTOR_ID} reordered exact-set revoke addressed a different cell");
    }
    arkret_schema::validate_registered_cell_writes(&active, arkret_canonical::DigestSuite::Sha256)?;
    arkret_schema::validate_registered_cell_writes(
        &revoked,
        arkret_canonical::DigestSuite::Sha256,
    )?;

    // A subset is a different exact set and therefore a different cell: a
    // partial revoke must not collide with the superset grant.
    let subset = event_for(json!("employment"), "revoked")?;
    if projected_cell(&subset)? == projected_cell(&active)? {
        bail!("{VECTOR_ID} subset revoke collided with the superset cell");
    }

    // The pre-composite-subject addressing (the scope value used directly as
    // the cell subject) must not be reachable: it is exactly the collision the
    // composite subject exists to prevent.
    let collision_subject = arkret_wire::CellRef::new(
        "ak:cell:ak.component.identity.accountability.v1:q76kFdC2LNwLBlUed_ICSOysggmqrOXJbAtWHO49Woc",
    )?;
    if projected_cell(&event_for(json!("employment"), "active")?)? == collision_subject {
        bail!("{VECTOR_ID} projection addresses the direct-scalar subject");
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
