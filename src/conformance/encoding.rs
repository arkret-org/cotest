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
            "event_id": "ak:event:AffYvO1bZNivtZWJPL_VcWqpd_MP-_igXCfxL5lhBbXu",
            "kind": "ak.message.create",
            "realm_id": "ak:realm:AWjfZKM-MUJ5ix2n8mCPUPOIgAUAF68FMFxNS0MIgSSv",
            "content": {"kind": "ak.content.text", "body": "covered"},
            "proofs": [{"fixture_marker": "not_covered"}],
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
                "encoding fixture {} did not produce ak:cursor prefix",
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
    validate_profile(value, "ak.vector_group.encoding.v1")?;
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
    run_accountability_scope_set_subject_vector(value)?;
    Ok(())
}

fn run_accountability_scope_set_subject_vector(fixture: &Value) -> Result<()> {
    use arkret_models_collaboration::governance::accountability::AccountabilityScope;

    const VECTOR_ID: &str = "ak.vector.identity.accountability_scope_set_subject.v1";
    let vector = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .and_then(|vectors| {
            vectors
                .iter()
                .find(|vector| vector.get("vector_id").and_then(Value::as_str) == Some(VECTOR_ID))
        })
        .ok_or_else(|| anyhow!("encoding fixture missing {VECTOR_ID}"))?;
    let issuer = value_field_str(vector, "issuer")?;
    let subject = value_field_str(vector, "subject")?;
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
            "actor_id": issuer,
            "actor_seq": 7,
            "created_at": "2026-07-26T01:00:00.000Z",
            "hlc": "019f9e500000-0000-aabbccdd",
            "prev_refs": [],
            "seal_basis": {
                "leaves": ["ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
            },
            "payload": {
                "issuer": issuer,
                "subject": subject,
                "accountability_scope": scope,
                "grant_status": status
            },
            "proofs": []
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
        Ok(write.cell.clone())
    };
    // The subject is the canonical exact-set component, so a reordered set
    // addresses the same cell.
    let active = event_for(json!(["employment", "agent_operator"]), "active")?;
    let revoked = event_for(json!(["agent_operator", "employment"]), "revoked")?;
    if projected_cell(&active)? != projected_cell(&revoked)? {
        bail!("{VECTOR_ID} reordered exact-set revoke addressed a different cell");
    }
    arkret_schema::validate_registered_cell_writes(&active)?;
    arkret_schema::validate_registered_cell_writes(&revoked)?;

    // A subset is a different exact set and therefore a different cell: a
    // partial revoke must not collide with the superset grant.
    let subset = event_for(json!("employment"), "revoked")?;
    if projected_cell(&subset)? == projected_cell(&active)? {
        bail!("{VECTOR_ID} subset revoke collided with the superset cell");
    }

    // The pre-composite-subject addressing (the scope value used directly as
    // the cell subject) must not be reachable: it is exactly the collision the
    // composite subject exists to prevent.
    let legacy_subject = arkret_wire::CellRef::new(
        "ak:cell:ak.component.identity.accountability.v1:q76kFdC2LNwLBlUed_ICSOysggmqrOXJbAtWHO49Woc",
    )?;
    if projected_cell(&event_for(json!("employment"), "active")?)? == legacy_subject {
        bail!("{VECTOR_ID} projection still addresses the legacy direct-scalar subject");
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
            "board_space_id": "ak:space:019640b6-8000-8000-8000-000000000000",
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
