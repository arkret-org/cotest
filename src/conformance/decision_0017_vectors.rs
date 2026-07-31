use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail, ensure};
use arkret_models_collaboration::objects::read_receipts::{
    ReadCursor, ReadCursorCausalRelation, merge_read_cursors,
};
use serde::Deserialize;
use serde_json::{Map, Value};

use super::load_fixture_value;

const READ_CURSOR_FIXTURE: &str = "read-cursor-multi-device-merge-fixture.json";
const READ_CURSOR_SUITE: &str = "ak.suite.read_cursor.multi_device_merge.v1";
const READ_CURSOR_VECTOR: &str = "ak.vector.read_cursor.multi_device_merge.v1";
const ACCOUNT_DATA_FIXTURE: &str = "account-data-cas-convergence-fixture.json";
const ACCOUNT_DATA_SUITE: &str = "ak.suite.account_data.cas_convergence.v1";
const ACCOUNT_DATA_VECTOR: &str = "ak.vector.account_data.cas_convergence.v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Runner {
    kind: String,
    entrypoint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadCursorFixture {
    profile: String,
    version: String,
    suite: String,
    runner: Runner,
    covers_vectors: Vec<String>,
    shared: Map<String, Value>,
    cases: Vec<ReadCursorCase>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadCursorCase {
    name: String,
    a: CursorPosition,
    b: CursorPosition,
    causal_relation: String,
    expected_winner: String,
    expected_provisional: bool,
    verify_both_delivery_orders: bool,
    verify_idempotent: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorPosition {
    id: String,
    device_id: String,
    event_id: String,
    hlc: String,
}

pub fn run_read_cursor_multi_device_merge_vector_suite() -> Result<()> {
    let fixture: ReadCursorFixture =
        serde_json::from_value(load_fixture_value(READ_CURSOR_FIXTURE)?)?;
    validate_fixture_header(
        &fixture.profile,
        &fixture.version,
        &fixture.suite,
        &fixture.runner,
        &fixture.covers_vectors,
        "read_cursor_multi_device_merge",
        READ_CURSOR_SUITE,
        READ_CURSOR_VECTOR,
    )?;
    ensure!(
        !fixture.cases.is_empty(),
        "read cursor fixture has no cases"
    );

    let mut names = BTreeSet::new();
    for case in &fixture.cases {
        ensure!(
            names.insert(case.name.as_str()),
            "duplicate case {}",
            case.name
        );
        let a = make_cursor(&fixture.shared, &case.a)?;
        let b = make_cursor(&fixture.shared, &case.b)?;
        let relation = relation_for_order(&case.causal_relation, false)?;
        let merged = merge_read_cursors(&a, &b, relation)
            .with_context(|| format!("merge forward case {}", case.name))?;
        let expected_forward = expected_cursor(&case.expected_winner, &a, &b, &a)?;
        ensure!(
            merged.winner.position.event_id == expected_forward.position.event_id,
            "{} forward winner drifted",
            case.name
        );
        ensure!(
            merged.provisional == case.expected_provisional,
            "{} provisional flag drifted",
            case.name
        );

        if case.verify_both_delivery_orders {
            let reverse =
                merge_read_cursors(&b, &a, relation_for_order(&case.causal_relation, true)?)
                    .with_context(|| format!("merge reverse case {}", case.name))?;
            let expected_reverse = expected_cursor(&case.expected_winner, &a, &b, &b)?;
            ensure!(
                reverse.winner.position.event_id == expected_reverse.position.event_id,
                "{} reverse winner drifted",
                case.name
            );
            ensure!(
                reverse.winner.position.event_id == merged.winner.position.event_id,
                "{} is not commutative",
                case.name
            );
            ensure!(
                reverse.provisional == case.expected_provisional,
                "{} reverse provisional flag drifted",
                case.name
            );
        }

        if case.verify_idempotent {
            let idempotent = merge_read_cursors(
                merged.winner,
                merged.winner,
                ReadCursorCausalRelation::Concurrent,
            )?;
            ensure!(
                idempotent.winner.position.event_id == merged.winner.position.event_id
                    && !idempotent.provisional,
                "{} is not idempotent",
                case.name
            );
        }
    }
    Ok(())
}

fn make_cursor(shared: &Map<String, Value>, position: &CursorPosition) -> Result<ReadCursor> {
    let mut value = shared.clone();
    value.insert("id".to_owned(), Value::String(position.id.clone()));
    value.insert(
        "device_id".to_owned(),
        Value::String(position.device_id.clone()),
    );
    value.insert(
        "position".to_owned(),
        serde_json::json!({
            "event_id": position.event_id,
            "hlc": position.hlc,
        }),
    );
    serde_json::from_value(Value::Object(value)).context("parse fixture read cursor")
}

fn relation_for_order(relation: &str, reverse: bool) -> Result<ReadCursorCausalRelation> {
    let relation = match (relation, reverse) {
        ("a_dominates_b", false) | ("b_dominates_a", true) => {
            ReadCursorCausalRelation::CurrentDominatesCandidate
        }
        ("a_dominates_b", true) | ("b_dominates_a", false) => {
            ReadCursorCausalRelation::CandidateDominatesCurrent
        }
        ("concurrent", _) => ReadCursorCausalRelation::Concurrent,
        ("undecidable", _) => ReadCursorCausalRelation::Undecidable,
        (unknown, _) => bail!("unknown causal_relation {unknown}"),
    };
    Ok(relation)
}

fn expected_cursor<'a>(
    expected: &str,
    a: &'a ReadCursor,
    b: &'a ReadCursor,
    current: &'a ReadCursor,
) -> Result<&'a ReadCursor> {
    match expected {
        "a" => Ok(a),
        "b" => Ok(b),
        "current" => Ok(current),
        unknown => bail!("unknown expected_winner {unknown}"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountDataFixture {
    profile: String,
    version: String,
    suite: String,
    runner: Runner,
    covers_vectors: Vec<String>,
    account_data_key: String,
    cases: Vec<Value>,
    minimum_independent_runners: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Register {
    revision: u64,
    content: Option<String>,
    tombstone: bool,
    deletion_mode: DeletionMode,
    fanout_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeletionMode {
    PhysicalDelete,
    ValueTombstone,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: String,
    #[serde(default)]
    surface: Option<String>,
    operation: String,
    #[serde(default)]
    expected_revision: Option<u64>,
    #[serde(default)]
    content: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ApplyOutcome {
    Accepted {
        revision: u64,
    },
    Conflict {
        current_revision: u64,
        current_entry: Option<String>,
    },
    Rejected,
    SchemaViolation,
}

pub fn run_account_data_cas_convergence_vector_suite() -> Result<()> {
    let fixture: AccountDataFixture =
        serde_json::from_value(load_fixture_value(ACCOUNT_DATA_FIXTURE)?)?;
    validate_fixture_header(
        &fixture.profile,
        &fixture.version,
        &fixture.suite,
        &fixture.runner,
        &fixture.covers_vectors,
        "account_data_cas_convergence",
        ACCOUNT_DATA_SUITE,
        ACCOUNT_DATA_VECTOR,
    )?;
    ensure!(
        !fixture.account_data_key.is_empty(),
        "account_data_key must not be empty"
    );
    ensure!(
        fixture.minimum_independent_runners >= 2,
        "account data convergence requires at least two independent runners"
    );

    let mut names = BTreeSet::new();
    for case in &fixture.cases {
        let name = string_field(case, "name")?;
        ensure!(names.insert(name), "duplicate account data case {name}");
        match name {
            "old_retry_after_new_write" => run_simple_cas_case(case, true)?,
            "conflict_details_enable_one_merge_retry" => run_simple_cas_case(case, false)?,
            "concurrent_delete_update_converges_after_one_merge_retry"
            | "opposite_write_arrival_orders_converge" => run_delivery_matrix_case(case)?,
            "tombstone_gc_retains_revision_high_water" => run_tombstone_gc_case(case)?,
            "create_repeat_and_recreate" => run_create_recreate_case(case)?,
            "value_tombstone_rejects_physical_delete_and_cannot_revive" => {
                run_value_tombstone_case(case)?
            }
            "missing_expected_revision_rejected_before_handler" => run_missing_revision_case(case)?,
            unknown => bail!("unmapped account data fixture case {unknown}"),
        }
    }
    ensure!(
        names.len() == 8,
        "account data fixture must execute all eight cases"
    );
    Ok(())
}

// Each parameter is one independently-asserted fixture header field;
// grouping them would let a vector pass with the wrong suite name.
#[allow(clippy::too_many_arguments)]
fn validate_fixture_header(
    profile: &str,
    version: &str,
    suite: &str,
    runner: &Runner,
    vectors: &[String],
    expected_suite_name: &str,
    expected_entrypoint: &str,
    expected_vector: &str,
) -> Result<()> {
    ensure!(profile == "ak.profile.full_client.v1", "profile drifted");
    ensure!(!version.is_empty(), "fixture version must not be empty");
    ensure!(suite == expected_suite_name, "suite name drifted");
    ensure!(runner.kind == "named_suite", "runner kind drifted");
    ensure!(
        runner.entrypoint == expected_entrypoint,
        "runner entrypoint drifted"
    );
    ensure!(
        vectors == [expected_vector],
        "fixture vector coverage drifted"
    );
    Ok(())
}

fn register_from(value: &Value, deletion_mode: DeletionMode) -> Result<Register> {
    let revision = u64_field(value, "revision")?;
    let content = value
        .get("content")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let tombstone = value
        .get("tombstone")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    ensure!(
        !(tombstone && content.is_some()),
        "tombstone cannot contain live content"
    );
    Ok(Register {
        revision,
        content,
        tombstone,
        deletion_mode,
        fanout_count: 0,
    })
}

fn apply(register: &mut Register, request: &Request) -> ApplyOutcome {
    let Some(expected_revision) = request.expected_revision else {
        return ApplyOutcome::SchemaViolation;
    };
    match request.operation.as_str() {
        "replace" if request.content.is_none() => return ApplyOutcome::SchemaViolation,
        "replace" | "delete" => {}
        _ => return ApplyOutcome::SchemaViolation,
    }
    if request.operation == "delete" && register.deletion_mode == DeletionMode::ValueTombstone {
        return ApplyOutcome::Rejected;
    }
    if expected_revision != register.revision {
        return ApplyOutcome::Conflict {
            current_revision: register.revision,
            current_entry: (!register.tombstone)
                .then(|| register.content.clone())
                .flatten(),
        };
    }
    register.revision += 1;
    register.fanout_count += 1;
    match request.operation.as_str() {
        "replace" => {
            register.content = request.content.clone();
            register.tombstone = false;
        }
        "delete" => {
            register.content = None;
            register.tombstone = true;
        }
        _ => unreachable!("operation was validated before mutation"),
    }
    ApplyOutcome::Accepted {
        revision: register.revision,
    }
}

fn run_simple_cas_case(case: &Value, require_conflict_details: bool) -> Result<()> {
    let mut register = register_from(object_field(case, "initial")?, DeletionMode::PhysicalDelete)?;
    let requests = requests_by_id(case)?;
    let order = string_array(case, "delivery_order")?;
    let outcomes = apply_order(&mut register, &requests, &order)?;
    let expected = object_field(case, "expected")?;
    assert_outcome_ids(&outcomes, expected)?;
    assert_final_register(&register, expected)?;
    if require_conflict_details {
        let conflict = outcomes
            .values()
            .find_map(|outcome| match outcome {
                ApplyOutcome::Conflict {
                    current_revision,
                    current_entry,
                } => Some((*current_revision, current_entry.as_deref())),
                _ => None,
            })
            .context("expected a CAS conflict")?;
        ensure!(
            conflict.0 == u64_field(expected, "conflict_current_revision")?,
            "conflict current_revision drifted"
        );
        ensure!(
            conflict.1
                == expected
                    .get("conflict_current_entry")
                    .and_then(Value::as_str),
            "conflict current_entry drifted"
        );
        ensure!(register.fanout_count == 1, "rejected write advanced fanout");
    }
    Ok(())
}

fn run_delivery_matrix_case(case: &Value) -> Result<()> {
    let initial = object_field(case, "initial")?;
    let requests = requests_by_id(case)?;
    let expected = object_field(case, "expected")?;
    let deliveries = array_field(case, "deliveries")?;
    let mut final_states = Vec::new();
    for delivery in deliveries {
        let mut register = register_from(initial, DeletionMode::PhysicalDelete)?;
        let order = string_array(delivery, "order")?;
        let outcomes = apply_order(&mut register, &requests, &order)?;
        let success_count = outcomes
            .values()
            .filter(|outcome| matches!(outcome, ApplyOutcome::Accepted { .. }))
            .count() as u64;
        let conflict_count = outcomes
            .values()
            .filter(|outcome| matches!(outcome, ApplyOutcome::Conflict { .. }))
            .count() as u64;
        if let Some(count) = expected
            .get("initial_success_count")
            .and_then(Value::as_u64)
        {
            ensure!(success_count == count, "initial success count drifted");
        }
        if let Some(count) = expected
            .get("initial_conflict_count")
            .and_then(Value::as_u64)
        {
            ensure!(conflict_count == count, "initial conflict count drifted");
        }
        let retry: Request = serde_json::from_value(
            delivery
                .get("merged_retry")
                .cloned()
                .context("delivery missing merged_retry")?,
        )?;
        ensure!(
            matches!(apply(&mut register, &retry), ApplyOutcome::Accepted { .. }),
            "merged retry was not accepted"
        );
        assert_final_register(&register, expected)?;
        final_states.push(register);
    }
    ensure!(
        final_states.windows(2).all(|pair| pair[0] == pair[1]),
        "opposite delivery orders did not converge"
    );
    Ok(())
}

fn run_tombstone_gc_case(case: &Value) -> Result<()> {
    let mut register = register_from(object_field(case, "initial")?, DeletionMode::PhysicalDelete)?;
    ensure!(register.tombstone, "GC case must start tombstoned");
    let requests = requests_by_id(case)?;
    let order = string_array(case, "delivery_order")?;
    let outcomes = apply_order(&mut register, &requests, &order)?;
    let expected = object_field(case, "expected")?;
    assert_outcome_ids(&outcomes, expected)?;
    assert_final_register(&register, expected)?;
    ensure!(
        string_field(expected, "resource_get")? == "not_found",
        "GC case must return not_found"
    );
    ensure!(
        u64_field(expected, "not_found_current_revision")? == register.revision,
        "not_found current_revision drifted"
    );
    let conflict = outcomes.values().next().context("missing GC outcome")?;
    ensure!(
        matches!(
            conflict,
            ApplyOutcome::Conflict {
                current_entry: None,
                ..
            }
        ),
        "tombstoned conflict leaked current_entry"
    );
    Ok(())
}

fn run_create_recreate_case(case: &Value) -> Result<()> {
    for scenario in array_field(case, "scenarios")? {
        let mut register = register_from(
            object_field(scenario, "initial")?,
            DeletionMode::PhysicalDelete,
        )?;
        let requests = requests_by_id(scenario)?;
        let order = requests.keys().map(String::as_str).collect::<Vec<_>>();
        let outcomes = apply_order(&mut register, &requests, &order)?;
        let expected = object_field(scenario, "expected")?;
        assert_outcome_ids(&outcomes, expected)?;
        assert_final_register(&register, expected)?;
    }
    Ok(())
}

fn run_value_tombstone_case(case: &Value) -> Result<()> {
    ensure!(
        string_field(case, "deletion_mode")? == "value_tombstone",
        "value tombstone deletion_mode drifted"
    );
    let mut register = register_from(object_field(case, "initial")?, DeletionMode::ValueTombstone)?;
    let requests = requests_by_id(case)?;
    let physical_delete = requests
        .get("physical_delete")
        .context("missing physical_delete")?;
    let before = register.clone();
    ensure!(
        apply(&mut register, physical_delete) == ApplyOutcome::Rejected,
        "value_tombstone physical delete was not rejected"
    );
    ensure!(register == before, "rejected physical delete mutated state");
    ensure!(
        matches!(
            apply(
                &mut register,
                requests
                    .get("terminal_value")
                    .context("missing terminal_value")?
            ),
            ApplyOutcome::Accepted { revision: 4 }
        ),
        "terminal value was not accepted"
    );
    ensure!(
        matches!(
            apply(
                &mut register,
                requests
                    .get("stale_live_value")
                    .context("missing stale_live_value")?
            ),
            ApplyOutcome::Conflict { .. }
        ),
        "stale live value revived terminal state"
    );
    let expected = object_field(case, "expected")?;
    ensure!(
        register.content.as_deref() == expected.get("final_content").and_then(Value::as_str),
        "value tombstone final content drifted"
    );
    ensure!(
        expected.get("revival_allowed").and_then(Value::as_bool) == Some(false),
        "fixture must forbid revival"
    );
    Ok(())
}

fn run_missing_revision_case(case: &Value) -> Result<()> {
    let requests = request_list(case)?;
    let mut register = Register {
        revision: 0,
        content: None,
        tombstone: false,
        deletion_mode: DeletionMode::PhysicalDelete,
        fanout_count: 0,
    };
    for request in &requests {
        ensure!(
            request.surface.is_some(),
            "{} missing protocol surface",
            request.id
        );
        ensure!(
            apply(&mut register, request) == ApplyOutcome::SchemaViolation,
            "{} reached handler without expected_revision",
            request.id
        );
    }
    ensure!(
        register.revision == 0 && register.fanout_count == 0,
        "schema violations mutated register"
    );
    let expected = object_field(case, "expected")?;
    ensure!(
        expected
            .get("all_rejected_before_handler")
            .and_then(Value::as_bool)
            == Some(true)
            && string_field(expected, "error")? == "schema_violation",
        "missing revision expectation drifted"
    );
    Ok(())
}

fn request_list(value: &Value) -> Result<Vec<Request>> {
    array_field(value, "requests")?
        .iter()
        .cloned()
        .map(serde_json::from_value)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn requests_by_id(value: &Value) -> Result<BTreeMap<String, Request>> {
    let mut requests = BTreeMap::new();
    for request in request_list(value)? {
        let id = request.id.clone();
        ensure!(
            requests.insert(id.clone(), request).is_none(),
            "duplicate request {id}"
        );
    }
    Ok(requests)
}

fn apply_order(
    register: &mut Register,
    requests: &BTreeMap<String, Request>,
    order: &[&str],
) -> Result<BTreeMap<String, ApplyOutcome>> {
    let mut outcomes = BTreeMap::new();
    for id in order {
        let request = requests
            .get(*id)
            .with_context(|| format!("delivery references unknown request {id}"))?;
        outcomes.insert((*id).to_owned(), apply(register, request));
    }
    ensure!(
        outcomes.len() == requests.len(),
        "delivery order did not execute every request"
    );
    Ok(outcomes)
}

fn assert_outcome_ids(outcomes: &BTreeMap<String, ApplyOutcome>, expected: &Value) -> Result<()> {
    let accepted = outcomes
        .iter()
        .filter_map(|(id, outcome)| {
            matches!(outcome, ApplyOutcome::Accepted { .. }).then_some(id.as_str())
        })
        .collect::<BTreeSet<_>>();
    let conflicts = outcomes
        .iter()
        .filter_map(|(id, outcome)| {
            matches!(outcome, ApplyOutcome::Conflict { .. }).then_some(id.as_str())
        })
        .collect::<BTreeSet<_>>();
    ensure!(
        accepted == string_array(expected, "accepted")?.into_iter().collect(),
        "accepted request set drifted"
    );
    ensure!(
        conflicts == string_array(expected, "conflicts")?.into_iter().collect(),
        "conflict request set drifted"
    );
    Ok(())
}

fn assert_final_register(register: &Register, expected: &Value) -> Result<()> {
    ensure!(
        register.revision == u64_field(expected, "final_revision")?,
        "final revision drifted"
    );
    if let Some(content) = expected.get("final_content").and_then(Value::as_str) {
        ensure!(
            register.content.as_deref() == Some(content) && !register.tombstone,
            "final content drifted"
        );
    }
    if let Some(tombstone) = expected.get("final_tombstone").and_then(Value::as_bool) {
        ensure!(register.tombstone == tombstone, "final tombstone drifted");
    }
    Ok(())
}

fn object_field<'a>(value: &'a Value, field: &str) -> Result<&'a Value> {
    value
        .get(field)
        .filter(|value| value.is_object())
        .with_context(|| format!("missing object field {field}"))
}

fn array_field<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .with_context(|| format!("missing array field {field}"))
}

fn string_field<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string field {field}"))
}

fn u64_field(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .with_context(|| format!("missing unsigned integer field {field}"))
}

fn string_array<'a>(value: &'a Value, field: &str) -> Result<Vec<&'a str>> {
    array_field(value, field)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .with_context(|| format!("{field} entries must be strings"))
        })
        .collect()
}
