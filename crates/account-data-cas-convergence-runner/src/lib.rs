//! Executable Account Data compare-and-set convergence conformance runner.
//!
//! The state model executes every delivery order and merge retry from the
//! canonical fixture. Its request parser uses the current
//! `expected_server_revision` name, and the schema-validation cases are also
//! deserialized through the production `AccountDataSetPayload` carrier.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use arkret_models_collaboration::events_payloads::AccountDataSetPayload;
use serde::Deserialize;
use serde_json::Value;

pub const ACCOUNT_DATA_CAS_CONVERGENCE_ENTRYPOINT: &str =
    "ak.suite.account_data.cas_convergence.v1";
pub const FIXTURE: &str = "account-data-cas-convergence-fixture.json";

const VECTOR_ID: &str = "ak.vector.account_data.cas_convergence.v1";
const PAYLOAD_SCHEMA_REF: &str =
    "schemas/event-payload.schema.json#/$defs/account_data_set_payload";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRoot {
    profile: String,
    version: String,
    suite: String,
    runner: Runner,
    covers_vectors: Vec<String>,
    account_data_key: String,
    cases: Vec<Value>,
    schema_validation_cases: Vec<SchemaValidationCase>,
    minimum_independent_runners: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Runner {
    kind: String,
    entrypoint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchemaValidationCase {
    name: String,
    schema_ref: String,
    expect_valid: bool,
    instance: Value,
    #[serde(default)]
    first_expected_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Register {
    revision: u64,
    content: Option<String>,
    tombstone: bool,
    deletion_mode: DeletionMode,
    fanout_count: usize,
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
    expected_server_revision: Option<u64>,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
    pub accepted_writes: usize,
    pub conflicts: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountDataCasExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
    pub schema_cases: usize,
    pub schema_rejections: usize,
}

fn spec_artifacts_root() -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT") {
        return PathBuf::from(root);
    }
    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        let root = PathBuf::from(root);
        for candidate in [root.clone(), root.join("spec").join("v1").join("artifacts")] {
            if candidate.join("fixtures").is_dir() {
                return candidate;
            }
        }
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
}

fn load_fixture() -> Result<FixtureRoot> {
    let path = spec_artifacts_root().join("fixtures").join(FIXTURE);
    serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("parse fixture {}", path.display()))
}

fn required<'a>(value: &'a Value, field: &str) -> Result<&'a Value> {
    value
        .get(field)
        .with_context(|| format!("missing field {field}"))
}

fn object_field<'a>(value: &'a Value, field: &str) -> Result<&'a Value> {
    required(value, field)?
        .as_object()
        .map(|_| required(value, field))
        .transpose()?
        .context("object field unexpectedly missing")
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    required(value, field)?
        .as_str()
        .with_context(|| format!("{field} is not a string"))
}

fn required_u64(value: &Value, field: &str) -> Result<u64> {
    required(value, field)?
        .as_u64()
        .with_context(|| format!("{field} is not an unsigned integer"))
}

fn required_array<'a>(value: &'a Value, field: &str) -> Result<&'a [Value]> {
    required(value, field)?
        .as_array()
        .map(Vec::as_slice)
        .with_context(|| format!("{field} is not an array"))
}

fn string_array<'a>(value: &'a Value, field: &str) -> Result<Vec<&'a str>> {
    required_array(value, field)?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .with_context(|| format!("{field} entries must be strings"))
        })
        .collect()
}

fn register_from(value: &Value, deletion_mode: DeletionMode) -> Result<Register> {
    let revision = required_u64(value, "revision")?;
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
    let Some(expected_revision) = request.expected_server_revision else {
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
    if request.operation == "replace" {
        register.content.clone_from(&request.content);
        register.tombstone = false;
    } else {
        register.content = None;
        register.tombstone = true;
    }
    ApplyOutcome::Accepted {
        revision: register.revision,
    }
}

fn request_list(value: &Value) -> Result<Vec<Request>> {
    required_array(value, "requests")?
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

fn outcome_counts(outcomes: &BTreeMap<String, ApplyOutcome>) -> (usize, usize) {
    (
        outcomes
            .values()
            .filter(|outcome| matches!(outcome, ApplyOutcome::Accepted { .. }))
            .count(),
        outcomes
            .values()
            .filter(|outcome| matches!(outcome, ApplyOutcome::Conflict { .. }))
            .count(),
    )
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
        register.revision == required_u64(expected, "final_revision")?,
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

fn run_simple_case(case: &Value, require_conflict_details: bool) -> Result<CaseExecutionResult> {
    let mut register = register_from(object_field(case, "initial")?, DeletionMode::PhysicalDelete)?;
    let requests = requests_by_id(case)?;
    let order = string_array(case, "delivery_order")?;
    let outcomes = apply_order(&mut register, &requests, &order)?;
    let expected = object_field(case, "expected")?;
    assert_outcome_ids(&outcomes, expected)?;
    assert_final_register(&register, expected)?;
    let mut assertions = 3;
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
        ensure!(conflict.0 == required_u64(expected, "conflict_current_revision")?);
        ensure!(
            conflict.1
                == expected
                    .get("conflict_current_entry")
                    .and_then(Value::as_str)
        );
        ensure!(register.fanout_count == 1);
        ensure!(expected["rejected_write_fanout"] == Value::Bool(false));
        assertions += 4;
    }
    let (accepted_writes, conflicts) = outcome_counts(&outcomes);
    Ok(CaseExecutionResult {
        case_id: required_str(case, "name")?.to_owned(),
        assertions,
        accepted_writes,
        conflicts,
    })
}

fn run_delivery_matrix(case: &Value) -> Result<CaseExecutionResult> {
    let initial = object_field(case, "initial")?;
    let requests = requests_by_id(case)?;
    let expected = object_field(case, "expected")?;
    let mut final_states = Vec::new();
    let mut accepted_writes = 0;
    let mut conflicts = 0;
    for delivery in required_array(case, "deliveries")? {
        let mut register = register_from(initial, DeletionMode::PhysicalDelete)?;
        let outcomes = apply_order(&mut register, &requests, &string_array(delivery, "order")?)?;
        let (success_count, conflict_count) = outcome_counts(&outcomes);
        if let Some(count) = expected
            .get("initial_success_count")
            .and_then(Value::as_u64)
        {
            ensure!(success_count == count as usize);
        }
        if let Some(count) = expected
            .get("initial_conflict_count")
            .and_then(Value::as_u64)
        {
            ensure!(conflict_count == count as usize);
        }
        let retry: Request = serde_json::from_value(required(delivery, "merged_retry")?.clone())?;
        ensure!(matches!(
            apply(&mut register, &retry),
            ApplyOutcome::Accepted { .. }
        ));
        assert_final_register(&register, expected)?;
        accepted_writes += success_count + 1;
        conflicts += conflict_count;
        final_states.push(register);
    }
    ensure!(final_states.windows(2).all(|pair| pair[0] == pair[1]));
    ensure!(expected["all_delivery_orders_equal"] == Value::Bool(true));
    Ok(CaseExecutionResult {
        case_id: required_str(case, "name")?.to_owned(),
        assertions: 6,
        accepted_writes,
        conflicts,
    })
}

fn run_tombstone_gc(case: &Value) -> Result<CaseExecutionResult> {
    let mut register = register_from(object_field(case, "initial")?, DeletionMode::PhysicalDelete)?;
    ensure!(register.tombstone);
    let requests = requests_by_id(case)?;
    let outcomes = apply_order(
        &mut register,
        &requests,
        &string_array(case, "delivery_order")?,
    )?;
    let expected = object_field(case, "expected")?;
    assert_outcome_ids(&outcomes, expected)?;
    assert_final_register(&register, expected)?;
    ensure!(required_str(expected, "resource_get")? == "not_found");
    ensure!(required_u64(expected, "not_found_current_revision")? == register.revision);
    ensure!(expected["current_entry_omitted"] == Value::Bool(true));
    ensure!(matches!(
        outcomes.values().next(),
        Some(ApplyOutcome::Conflict {
            current_entry: None,
            ..
        })
    ));
    let (accepted_writes, conflicts) = outcome_counts(&outcomes);
    Ok(CaseExecutionResult {
        case_id: required_str(case, "name")?.to_owned(),
        assertions: 7,
        accepted_writes,
        conflicts,
    })
}

fn run_create_recreate(case: &Value) -> Result<CaseExecutionResult> {
    let mut accepted_writes = 0;
    let mut conflicts = 0;
    for scenario in required_array(case, "scenarios")? {
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
        let counts = outcome_counts(&outcomes);
        accepted_writes += counts.0;
        conflicts += counts.1;
    }
    Ok(CaseExecutionResult {
        case_id: required_str(case, "name")?.to_owned(),
        assertions: 4,
        accepted_writes,
        conflicts,
    })
}

fn run_value_tombstone(case: &Value) -> Result<CaseExecutionResult> {
    ensure!(required_str(case, "deletion_mode")? == "value_tombstone");
    let mut register = register_from(object_field(case, "initial")?, DeletionMode::ValueTombstone)?;
    let requests = requests_by_id(case)?;
    let before = register.clone();
    ensure!(
        apply(
            &mut register,
            requests
                .get("physical_delete")
                .context("missing physical_delete")?
        ) == ApplyOutcome::Rejected
    );
    ensure!(register == before);
    ensure!(matches!(
        apply(
            &mut register,
            requests
                .get("terminal_value")
                .context("missing terminal_value")?
        ),
        ApplyOutcome::Accepted { revision: 4 }
    ));
    ensure!(matches!(
        apply(
            &mut register,
            requests
                .get("stale_live_value")
                .context("missing stale_live_value")?
        ),
        ApplyOutcome::Conflict { .. }
    ));
    let expected = object_field(case, "expected")?;
    ensure!(expected["physical_delete"] == Value::String("rejected".to_owned()));
    ensure!(expected["physical_delete_revision_advanced"] == Value::Bool(false));
    ensure!(register.revision == required_u64(expected, "terminal_value_revision")?);
    ensure!(expected["stale_live_value"] == Value::String("cas_conflict".to_owned()));
    ensure!(register.content.as_deref() == expected["final_content"].as_str());
    ensure!(expected["revival_allowed"] == Value::Bool(false));
    Ok(CaseExecutionResult {
        case_id: required_str(case, "name")?.to_owned(),
        assertions: 10,
        accepted_writes: 1,
        conflicts: 1,
    })
}

fn run_missing_revision(case: &Value) -> Result<CaseExecutionResult> {
    let requests = request_list(case)?;
    let mut register = Register {
        revision: 0,
        content: None,
        tombstone: false,
        deletion_mode: DeletionMode::PhysicalDelete,
        fanout_count: 0,
    };
    for request in &requests {
        ensure!(request.surface.is_some());
        ensure!(apply(&mut register, request) == ApplyOutcome::SchemaViolation);
    }
    ensure!(register.revision == 0 && register.fanout_count == 0);
    let expected = object_field(case, "expected")?;
    ensure!(expected["all_rejected_before_handler"] == Value::Bool(true));
    ensure!(required_str(expected, "error")? == "schema_violation");
    Ok(CaseExecutionResult {
        case_id: required_str(case, "name")?.to_owned(),
        assertions: requests.len() * 2 + 3,
        accepted_writes: 0,
        conflicts: 0,
    })
}

fn run_case(case: &Value) -> Result<CaseExecutionResult> {
    match required_str(case, "name")? {
        "old_retry_after_new_write" => run_simple_case(case, true),
        "conflict_details_enable_one_merge_retry" => run_simple_case(case, false),
        "concurrent_delete_update_converges_after_one_merge_retry"
        | "opposite_write_arrival_orders_converge" => run_delivery_matrix(case),
        "tombstone_gc_retains_revision_high_water" => run_tombstone_gc(case),
        "create_repeat_and_recreate" => run_create_recreate(case),
        "value_tombstone_rejects_physical_delete_and_cannot_revive" => run_value_tombstone(case),
        "missing_expected_server_revision_rejected_before_handler" => run_missing_revision(case),
        other => bail!("unknown Account Data CAS case {other}"),
    }
}

fn run_schema_cases(cases: &[SchemaValidationCase]) -> Result<usize> {
    let mut rejected = 0;
    let mut names = BTreeSet::new();
    for case in cases {
        ensure!(
            names.insert(case.name.as_str()),
            "duplicate schema case {}",
            case.name
        );
        ensure!(case.schema_ref == PAYLOAD_SCHEMA_REF, "schema ref drifted");
        let result = serde_json::from_value::<AccountDataSetPayload>(case.instance.clone());
        ensure!(
            result.is_ok() == case.expect_valid,
            "{} validity drifted",
            case.name
        );
        if !case.expect_valid {
            ensure!(
                case.first_expected_error
                    .as_deref()
                    .is_some_and(|error| !error.is_empty())
            );
            rejected += 1;
        }
    }
    ensure!(cases.len() == 4, "expected all four schema cases");
    Ok(rejected)
}

pub fn run_account_data_cas_convergence_suite() -> Result<AccountDataCasExecution> {
    let fixture = load_fixture()?;
    ensure!(
        fixture.profile == "ak.profile.full_client.v1",
        "fixture profile drifted"
    );
    ensure!(
        !fixture.version.trim().is_empty(),
        "fixture version is empty"
    );
    ensure!(
        fixture.suite == "account_data_cas_convergence",
        "fixture suite drifted"
    );
    ensure!(fixture.runner.kind == "named_suite", "runner kind drifted");
    ensure!(
        fixture.runner.entrypoint == ACCOUNT_DATA_CAS_CONVERGENCE_ENTRYPOINT,
        "runner entrypoint drifted"
    );
    ensure!(
        fixture
            .covers_vectors
            .iter()
            .map(String::as_str)
            .eq([VECTOR_ID]),
        "fixture vector closure drifted"
    );
    ensure!(
        !fixture.account_data_key.is_empty(),
        "account data key is empty"
    );
    ensure!(
        fixture.minimum_independent_runners == 2,
        "independent-runner requirement drifted"
    );

    let mut names = BTreeSet::new();
    let mut cases = Vec::with_capacity(fixture.cases.len());
    for case in &fixture.cases {
        let result = run_case(case)?;
        ensure!(
            names.insert(result.case_id.clone()),
            "duplicate case {}",
            result.case_id
        );
        cases.push(result);
    }
    ensure!(cases.len() == 8, "expected all eight CAS cases");
    let schema_rejections = run_schema_cases(&fixture.schema_validation_cases)?;
    Ok(AccountDataCasExecution {
        entrypoint: ACCOUNT_DATA_CAS_CONVERGENCE_ENTRYPOINT,
        fixture: FIXTURE,
        cases,
        schema_cases: fixture.schema_validation_cases.len(),
        schema_rejections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_all_cas_delivery_and_schema_cases() {
        let execution = run_account_data_cas_convergence_suite().unwrap();
        assert_eq!(
            execution.entrypoint,
            ACCOUNT_DATA_CAS_CONVERGENCE_ENTRYPOINT
        );
        assert_eq!(execution.cases.len(), 8);
        assert_eq!(execution.schema_cases, 4);
        assert_eq!(execution.schema_rejections, 3);
        assert!(execution.cases.iter().all(|case| case.assertions > 0));
    }

    #[test]
    fn stale_write_neither_mutates_nor_fans_out() {
        let mut register = Register {
            revision: 8,
            content: Some("ciphertext:b".to_owned()),
            tombstone: false,
            deletion_mode: DeletionMode::PhysicalDelete,
            fanout_count: 0,
        };
        let before = register.clone();
        let request = Request {
            id: "stale".to_owned(),
            surface: None,
            operation: "replace".to_owned(),
            expected_server_revision: Some(7),
            content: Some("ciphertext:a".to_owned()),
        };
        assert!(matches!(
            apply(&mut register, &request),
            ApplyOutcome::Conflict {
                current_revision: 8,
                ..
            }
        ));
        assert_eq!(register, before);
    }

    #[test]
    fn legacy_revision_alias_is_rejected_by_the_production_payload() {
        let legacy = serde_json::json!({
            "key": "ak.preferences.v1",
            "expected_revision": 0,
            "body": "ciphertext:value"
        });
        assert!(serde_json::from_value::<AccountDataSetPayload>(legacy).is_err());
    }
}
