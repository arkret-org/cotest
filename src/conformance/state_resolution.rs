use anyhow::{Result, anyhow, bail};
use serde_json::Value;

use super::{
    RankEdge, StateResolutionCase, StateResolutionFixture, assert_json_eq, load_fixture_value,
    parse_fixture_value, rebalance_assignments, required_field, required_str, validate_profile,
    value_array, value_field_str, value_field_u64, value_object,
};

pub fn run_state_resolution_fixture_suite() -> Result<()> {
    let value = load_fixture_value("state-resolution-fixture.json")?;
    if value.get("suite").is_none() {
        return run_state_resolution_artifact_suite(&value);
    }
    let fixture: StateResolutionFixture =
        parse_fixture_value("state-resolution-fixture.json", value)?;
    if fixture.suite != "state_resolution" {
        bail!("unexpected fixture suite {}", fixture.suite);
    }

    for case in fixture.cases {
        match case.name.as_str() {
            "membership_concurrency" => {
                let join = StateEvent {
                    kind: "join".to_owned(),
                    auth_weight: 10,
                    hlc: "01970e589d21-0004-a13f9c2e".to_owned(),
                    actor_seq: 1,
                    event_id: "cx:event:join".to_owned(),
                };
                let ban = StateEvent {
                    kind: "ban".to_owned(),
                    auth_weight: 20,
                    hlc: "01970e589d21-0005-a13f9c2e".to_owned(),
                    actor_seq: 1,
                    event_id: "cx:event:ban".to_owned(),
                };
                let resolved = resolve_state_events(&[join, ban])?;
                if resolved.kind != "ban" {
                    bail!("state resolution fixture {} did not pick ban", case.name);
                }
            }
            "capability_delegate_revoke_race" => {
                let delegate = StateEvent {
                    kind: "delegate".to_owned(),
                    auth_weight: 15,
                    hlc: "01970e589d21-0005-a13f9c2e".to_owned(),
                    actor_seq: 1,
                    event_id: "cx:event:delegate".to_owned(),
                };
                let revoke = StateEvent {
                    kind: "revoke".to_owned(),
                    auth_weight: 15,
                    hlc: "01970e589d21-0005-a13f9c2e".to_owned(),
                    actor_seq: 1,
                    event_id: "cx:event:revoke".to_owned(),
                };
                let resolved = resolve_state_events(&[delegate, revoke])?;
                if resolved.kind != "revoke" {
                    bail!(
                        "state resolution fixture {} did not fail closed on revoke",
                        case.name
                    );
                }
            }
            "schema_policy_update_race" => {
                let policy_state = PolicyState {
                    decision: "deny".to_owned(),
                };
                let write = PendingWrite {
                    event_id: "cx:event:write".to_owned(),
                    required_decision: "allow".to_owned(),
                };
                if write_is_valid_against_policy(&write, &policy_state) {
                    bail!(
                        "state resolution fixture {} accepted stale policy",
                        case.name
                    );
                }
            }
            "deterministic_tie_breaker" => {
                let first = StateEvent {
                    kind: "join".to_owned(),
                    auth_weight: 10,
                    hlc: "01970e589d21-0005-a13f9c2e".to_owned(),
                    actor_seq: 1,
                    event_id: "cx:event:a".to_owned(),
                };
                let second = StateEvent {
                    kind: "join".to_owned(),
                    auth_weight: 10,
                    hlc: "01970e589d21-0005-a13f9c2e".to_owned(),
                    actor_seq: 2,
                    event_id: "cx:event:b".to_owned(),
                };
                let resolved = resolve_state_events(&[second, first.clone()])?;
                if resolved.event_id != first.event_id {
                    bail!(
                        "state resolution fixture {} was not deterministic",
                        case.name
                    );
                }
            }
            "kanban_concurrent_card_move" | "board_concurrent_item_move" => {
                validate_container_move_resolution(&case)?
            }
            "kanban_atomic_task_move" | "board_atomic_field_position_move" => {
                validate_field_position_resolution(&case)?
            }
            "relation_rebalance_assignment" | "container_rebalance_assignment" => {
                validate_state_rebalance_assignment(&case)?
            }
            "relation_rebalance_cas_conflict" | "container_rebalance_cas_conflict" => {
                validate_state_rebalance_cas_conflict(&case)?
            }
            _ => bail!("unknown state resolution fixture case {}", case.name),
        }
    }

    Ok(())
}

fn run_state_resolution_artifact_suite(value: &Value) -> Result<()> {
    validate_profile(value, "cx.profile.state_resolution_vectors.v1")?;
    let vectors = value
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("state resolution artifact missing vectors"))?;
    for vector in vectors {
        let name = required_str(vector, "name")?;
        if let Some(candidates) = vector.get("candidates").and_then(Value::as_array) {
            let expected = vector
                .pointer("/expected/winner_event_id")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("state vector {name} missing winner_event_id"))?;
            let actual = select_state_resolution_candidate(candidates)
                .ok_or_else(|| anyhow!("state vector {name} has no selectable candidate"))?;
            if actual != expected {
                bail!("state vector {name} winner drifted: expected {expected}, got {actual}");
            }
        }
        if name == "offline_write_concurrent_with_revoke_soft_fails_when_order_unknown"
            && vector.pointer("/expected/decision").and_then(Value::as_str) != Some("soft_fail")
        {
            bail!("state vector {name} no longer soft-fails unknown revoke ordering");
        }
    }
    Ok(())
}

fn select_state_resolution_candidate(candidates: &[Value]) -> Option<&str> {
    candidates
        .iter()
        .filter(|candidate| {
            candidate.get("policy_result").and_then(Value::as_str) != Some("hard_deny")
        })
        .max_by(|left, right| compare_state_candidates(left, right))
        .and_then(|candidate| candidate.get("event_id").and_then(Value::as_str))
}

fn compare_state_candidates(left: &Value, right: &Value) -> std::cmp::Ordering {
    let left_weight = left
        .get("auth_weight")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    let right_weight = right
        .get("auth_weight")
        .and_then(Value::as_i64)
        .unwrap_or_default();
    left_weight
        .cmp(&right_weight)
        .then_with(|| {
            left.get("hlc")
                .and_then(Value::as_str)
                .cmp(&right.get("hlc").and_then(Value::as_str))
        })
        .then_with(|| {
            left.get("event_id")
                .and_then(Value::as_str)
                .cmp(&right.get("event_id").and_then(Value::as_str))
        })
}

// ── Internal types ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct StateEvent {
    kind: String,
    auth_weight: u64,
    hlc: String,
    actor_seq: u64,
    event_id: String,
}

fn resolve_state_events(events: &[StateEvent]) -> Result<StateEvent> {
    let mut sorted = events.to_vec();
    sorted.sort_by(|left, right| {
        right
            .auth_weight
            .cmp(&left.auth_weight)
            .then_with(|| precedence_of(&right.kind).cmp(&precedence_of(&left.kind)))
            .then_with(|| left.hlc.cmp(&right.hlc))
            .then_with(|| left.actor_seq.cmp(&right.actor_seq))
            .then_with(|| left.event_id.cmp(&right.event_id))
    });
    sorted
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("cannot resolve empty state set"))
}

fn precedence_of(kind: &str) -> u8 {
    match kind {
        "ban" => 3,
        "revoke" => 2,
        "delegate" => 1,
        _ => 0,
    }
}

struct PolicyState {
    decision: String,
}

struct PendingWrite {
    event_id: String,
    required_decision: String,
}

fn write_is_valid_against_policy(write: &PendingWrite, policy: &PolicyState) -> bool {
    let _ = &write.event_id;
    write.required_decision == policy.decision
}

fn validate_container_move_resolution(case: &StateResolutionCase) -> Result<()> {
    let input = required_case_input(case)?;
    let base_state = value_object(required_field(input, "base_state")?, "input.base_state")?;
    let candidates = value_array(required_field(input, "candidates")?, "input.candidates")?;
    let expected = required_case_expected(case)?;
    let winner = choose_operation_winner(candidates)?;
    let winner_id = value_field_str(winner, "operation_id")?;
    let content = required_field(winner, "content")?;
    if value_field_str(winner, "kind")? != "cx.container.move_item" {
        bail!(
            "state fixture {} winner was not canonical container move",
            case.name
        );
    }

    let resolved_position = Value::Object({
        let mut map = serde_json::Map::new();
        map.insert(
            "scope_container_id".to_owned(),
            required_field(content, "scope_container_id")?.clone(),
        );
        map.insert(
            "relation_kind".to_owned(),
            required_field(content, "relation_kind")?.clone(),
        );
        map.insert(
            "entity_id".to_owned(),
            required_field(content, "entity_id")?.clone(),
        );
        map.insert(
            "container_id".to_owned(),
            required_field(content, "to_container_id")?.clone(),
        );
        map.insert("rank".to_owned(), required_field(content, "rank")?.clone());
        map.insert(
            "source_operation_id".to_owned(),
            Value::String(winner_id.to_owned()),
        );
        map
    });
    assert_json_eq(
        &resolved_position,
        required_field(expected, "resolved_position")?,
        &case.name,
        "resolved_position",
    )?;

    let state_key = format!(
        "{}|{}|{}",
        value_field_str(content, "scope_container_id")?,
        value_field_str(content, "relation_kind")?,
        value_field_str(content, "entity_id")?
    );
    let active_registers = serde_json::json!([{
        "state_key": state_key,
        "container_id": required_field(content, "to_container_id")?.clone(),
        "rank": required_field(content, "rank")?.clone(),
        "source_operation_id": winner_id
    }]);
    assert_json_eq(
        &active_registers,
        required_field(expected, "active_position_registers")?,
        &case.name,
        "active_position_registers",
    )?;

    let loser_ids = operation_ids_except(candidates, winner_id)?;
    let mut inactive_ids = Vec::with_capacity(loser_ids.len() + 1);
    inactive_ids.push(
        base_state
            .get("source_operation_id")
            .cloned()
            .ok_or_else(|| anyhow!("state fixture {} missing base source operation", case.name))?,
    );
    inactive_ids.extend(
        loser_ids
            .iter()
            .map(|operation_id| serde_json::json!(operation_id)),
    );
    assert_json_eq(
        &serde_json::json!(inactive_ids),
        required_field(expected, "inactive_source_operation_ids")?,
        &case.name,
        "inactive_source_operation_ids",
    )?;

    let expected_conflicts = required_field(expected, "conflict_records")?;
    let conflict = serde_json::json!([{
        "conflict_type": "exclusive_position",
        "state_key": active_registers[0]["state_key"].clone(),
        "winner": winner_id,
        "losers": loser_ids,
        "reason": expected_conflicts[0]["reason"].clone()
    }]);
    assert_json_eq(
        &conflict,
        expected_conflicts,
        &case.name,
        "conflict_records",
    )
}

fn validate_field_position_resolution(case: &StateResolutionCase) -> Result<()> {
    let input = required_case_input(case)?;
    let candidates = value_array(required_field(input, "candidates")?, "input.candidates")?;
    let expected = required_case_expected(case)?;
    let winner = choose_operation_winner(candidates)?;
    let winner_id = value_field_str(winner, "operation_id")?;
    let content = required_field(winner, "content")?;
    if value_field_str(winner, "kind")? != "cx.field_position.move" {
        bail!(
            "state fixture {} winner was not canonical field-position move",
            case.name
        );
    }

    let resolved_position = serde_json::json!({
        "view_id": required_field(content, "view_id")?.clone(),
        "entity_id": required_field(content, "entity_id")?.clone(),
        "group_by": required_field(content, "group_by")?.clone(),
        "value": required_field(content, "to_value")?.clone(),
        "rank": required_field(content, "rank")?.clone(),
        "source_operation_id": winner_id
    });
    assert_json_eq(
        &resolved_position,
        required_field(expected, "resolved_position")?,
        &case.name,
        "resolved_position",
    )?;

    let loser_ids = operation_ids_except(candidates, winner_id)?;
    let expected_conflicts = required_field(expected, "conflict_records")?;
    let conflict = serde_json::json!([{
        "conflict_type": "atomic_position_register",
        "state_key": format!(
            "{}|{}|{}",
            value_field_str(content, "view_id")?,
            value_field_str(content, "entity_id")?,
            value_field_str(content, "group_by")?
        ),
        "winner": winner_id,
        "losers": loser_ids,
        "reason": expected_conflicts[0]["reason"].clone()
    }]);
    assert_json_eq(
        &conflict,
        expected_conflicts,
        &case.name,
        "conflict_records",
    )
}

fn validate_state_rebalance_assignment(case: &StateResolutionCase) -> Result<()> {
    let input = required_case_input(case)?;
    let active_edges =
        serde_json::from_value::<Vec<RankEdge>>(required_field(input, "active_edges")?.clone())?;
    let state_hash = value_field_str(input, "state_hash")?;
    let expected_state_hash = value_field_str(input, "expected_state_hash")?;
    if state_hash != expected_state_hash {
        bail!(
            "state fixture {} attempted rebalance from stale state hash",
            case.name
        );
    }
    let actual = rebalance_assignments(&active_edges)?;
    let expected = case
        .expected_assignments
        .as_deref()
        .ok_or_else(|| anyhow!("state fixture {} missing expected_assignments", case.name))?;
    if actual != expected {
        bail!("state fixture {} rebalance assignments differed", case.name);
    }
    Ok(())
}

fn validate_state_rebalance_cas_conflict(case: &StateResolutionCase) -> Result<()> {
    let input = required_case_input(case)?;
    let state_hash = value_field_str(input, "state_hash")?;
    let expected_state_hash = value_field_str(input, "expected_state_hash")?;
    let expected = case
        .expected
        .as_ref()
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("state fixture {} missing string expected", case.name))?;
    if expected != "reject_without_partial_assignment" {
        bail!(
            "state fixture {} expected CAS rejection semantics drifted",
            case.name
        );
    }
    if state_hash == expected_state_hash {
        bail!(
            "state fixture {} did not model a stale state hash",
            case.name
        );
    }
    Ok(())
}

fn choose_operation_winner(candidates: &[Value]) -> Result<&Value> {
    let mut winner = candidates
        .first()
        .ok_or_else(|| anyhow!("cannot resolve empty operation candidate set"))?;
    for candidate in &candidates[1..] {
        if operation_order(candidate, winner)? == std::cmp::Ordering::Greater {
            winner = candidate;
        }
    }
    Ok(winner)
}

fn operation_order(left: &Value, right: &Value) -> Result<std::cmp::Ordering> {
    let left_weight = value_field_u64(left, "auth_weight")?;
    let right_weight = value_field_u64(right, "auth_weight")?;
    let left_hlc = value_field_str(left, "hlc")?;
    let right_hlc = value_field_str(right, "hlc")?;
    let left_operation_id = value_field_str(left, "operation_id")?;
    let right_operation_id = value_field_str(right, "operation_id")?;
    Ok(left_weight
        .cmp(&right_weight)
        .then_with(|| left_hlc.cmp(right_hlc))
        .then_with(|| left_operation_id.cmp(right_operation_id)))
}

fn operation_ids_except(candidates: &[Value], winner_id: &str) -> Result<Vec<String>> {
    let mut operation_ids = Vec::new();
    for candidate in candidates {
        let operation_id = value_field_str(candidate, "operation_id")?;
        if operation_id != winner_id {
            operation_ids.push(operation_id.to_owned());
        }
    }
    Ok(operation_ids)
}

fn required_case_input(case: &StateResolutionCase) -> Result<&Value> {
    case.input
        .as_ref()
        .ok_or_else(|| anyhow!("state fixture {} missing input", case.name))
}

fn required_case_expected(case: &StateResolutionCase) -> Result<&Value> {
    case.expected
        .as_ref()
        .ok_or_else(|| anyhow!("state fixture {} missing expected object", case.name))
}
