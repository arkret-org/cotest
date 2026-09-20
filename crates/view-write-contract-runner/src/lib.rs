//! Executable View write-contract schema admission suite.
//!
//! A Station must validate author-supplied View create/update/reconcile
//! payloads and materialized values before a reducer result can be published.
//! This runner drives the SDK's production Draft 2020-12 registry built from
//! the formal artifacts. Only a successful validation reaches the accepted
//! write sink; every structured validation rejection must leave it unchanged.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use arkret_schema::{ProtocolSchemaRegistry, SchemaError, SchemaValidationReason};
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde::Deserialize;
use serde_json::Value;

pub const VIEW_WRITE_CONTRACT_ENTRYPOINT: &str = "ak.suite.view.write_contract.v1";
pub const FIXTURE: &str = "view-write-contract-fixture.json";

const VECTOR_ID: &str = "ak.vector.view.terminal_state_patch.v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRoot {
    profile: String,
    version: String,
    suite: String,
    runner: FixtureRunner,
    covers_vectors: Vec<String>,
    description: String,
    author_writable_partition: Value,
    cases: Vec<FixtureCase>,
    admission_cases: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRunner {
    kind: String,
    entrypoint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCase {
    name: String,
    schema_ref: String,
    valid: bool,
    instance: Value,
    why: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
    pub accepted_effects: usize,
    pub rejected_zero_effects: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ViewWriteContractExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
    pub accepted_effects: usize,
    pub rejected_zero_effects: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct AcceptedWriteSink {
    case_ids: Vec<String>,
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

fn load_fixture(artifacts: &Path) -> Result<FixtureRoot> {
    let path = artifacts.join("fixtures").join(FIXTURE);
    serde_json::from_slice(&std::fs::read(&path)?)
        .with_context(|| format!("parse fixture {}", path.display()))
}

fn register_fixture_fragments(
    registry: &mut ProtocolSchemaRegistry,
    artifacts: &Path,
    cases: &[FixtureCase],
) -> Result<()> {
    let mut registered = BTreeSet::new();
    for case in cases {
        let (relative, fragment) = case
            .schema_ref
            .split_once('#')
            .with_context(|| format!("{} has no schema fragment", case.schema_ref))?;
        ensure!(relative.starts_with("schemas/"));
        ensure!(!fragment.is_empty());
        if !registered.insert(relative.to_owned()) {
            continue;
        }
        let path = artifacts.join(relative);
        let schema: Value = serde_json::from_slice(&std::fs::read(&path)?)
            .with_context(|| format!("parse schema {}", path.display()))?;
        // Keep the formal relative document name as the registry key. The
        // production registry resolves the `#/$defs/...` suffix supplied to
        // `validate_value`, so every case exercises the exact fixture ref.
        registry.register(relative, schema);
    }
    Ok(())
}

fn expected_rejection(case_id: &str) -> Option<(&'static str, &'static str)> {
    match case_id {
        "terminal_state_patch_is_accepted"
        | "terminal_state_patch_in_explicit_op_form_is_accepted"
        | "terminal_state_patch_with_prestate_guard_is_accepted"
        | "create_payload_accepts_the_author_definition"
        | "reconcile_payload_accepts_the_author_definition"
        | "materialized_active_view_validates"
        | "materialized_terminal_view_validates" => None,
        "update_payload_refuses_a_reducer_derived_member" | "create_payload_refuses_a_patch" => {
            Some(("additionalProperties", ""))
        }
        "update_payload_refuses_an_object_snapshot" | "update_payload_requires_the_subject" => {
            Some(("required", ""))
        }
        "create_payload_refuses_a_self_reported_creator"
        | "create_payload_refuses_a_self_reported_realm"
        | "create_payload_refuses_a_self_reported_state"
        | "create_payload_refuses_the_derived_id" => Some(("additionalProperties", "/object")),
        "reconcile_definition_cannot_resurrect_or_tombstone" => {
            Some(("additionalProperties", "/definition"))
        }
        "materialized_value_refuses_the_self_reportable_id" => Some(("not", "")),
        _ => Some(("unknown_fixture_case", "")),
    }
}

fn validate_and_accept(
    registry: &ProtocolSchemaRegistry,
    case: &FixtureCase,
    sink: &mut AcceptedWriteSink,
) -> std::result::Result<(), SchemaError> {
    registry.validate_value(&case.schema_ref, &case.instance)?;
    sink.case_ids.push(case.name.clone());
    Ok(())
}

pub fn run_view_write_contract_suite() -> Result<ViewWriteContractExecution> {
    let artifacts = spec_artifacts_root();
    let fixture = load_fixture(&artifacts)?;
    ensure!(fixture.profile == "ak.profile.core_event_store.v1");
    ensure!(!fixture.version.trim().is_empty());
    ensure!(fixture.suite == "view_write_contract");
    ensure!(fixture.runner.kind == "named_suite");
    ensure!(fixture.runner.entrypoint == VIEW_WRITE_CONTRACT_ENTRYPOINT);
    ensure!(fixture.covers_vectors == [VECTOR_ID]);
    ensure!(!fixture.description.trim().is_empty());
    ensure!(fixture.author_writable_partition.is_object());
    ensure!(!fixture.admission_cases.is_empty());
    ensure!(fixture.cases.len() == 17);

    let mut registry = schema_registry_from_spec_artifacts(&artifacts)
        .context("load production schema registry from formal artifacts")?;
    register_fixture_fragments(&mut registry, &artifacts, &fixture.cases)?;
    let mut sink = AcceptedWriteSink::default();
    let mut results = Vec::with_capacity(fixture.cases.len());

    for case in &fixture.cases {
        ensure!(
            !case.why.trim().is_empty(),
            "{} has no rationale",
            case.name
        );
        let before = sink.clone();
        let outcome = validate_and_accept(&registry, case, &mut sink);
        let expected_rejection = expected_rejection(&case.name);
        ensure!(
            expected_rejection != Some(("unknown_fixture_case", "")),
            "unmapped fixture case {}",
            case.name
        );
        if case.valid {
            ensure!(
                expected_rejection.is_none(),
                "{} is misclassified",
                case.name
            );
            outcome.with_context(|| format!("{} failed production validation", case.name))?;
            ensure!(sink.case_ids.len() == before.case_ids.len() + 1);
            ensure!(sink.case_ids.last() == Some(&case.name));
        } else {
            let error =
                outcome.expect_err("invalid View write case passed production schema validation");
            let SchemaError::Validation(issue) = error else {
                bail!("{} failed outside schema admission: {error}", case.name);
            };
            ensure!(
                issue.schema_id == case.schema_ref,
                "{} schema id drifted",
                case.name
            );
            ensure!(issue.reason == SchemaValidationReason::InstanceInvalid);
            let (expected_keyword, expected_instance_pointer) =
                expected_rejection.expect("invalid case needs an expected rejection");
            ensure!(
                issue.keyword == expected_keyword,
                "{} hit keyword {}, expected {expected_keyword} at {}",
                case.name,
                issue.keyword,
                issue.schema_pointer
            );
            ensure!(
                issue.instance_pointer == expected_instance_pointer,
                "{} failed at {}, expected {expected_instance_pointer}",
                case.name,
                issue.instance_pointer
            );
            ensure!(
                sink == before,
                "{} changed the accepted write sink",
                case.name
            );
        }
        results.push(CaseExecutionResult {
            case_id: case.name.clone(),
            assertions: 6,
            accepted_effects: usize::from(case.valid),
            rejected_zero_effects: usize::from(!case.valid),
        });
    }

    ensure!(sink.case_ids.len() == 7);
    let rejected_zero_effects = results.iter().map(|case| case.rejected_zero_effects).sum();
    ensure!(rejected_zero_effects == 10);
    Ok(ViewWriteContractExecution {
        entrypoint: VIEW_WRITE_CONTRACT_ENTRYPOINT,
        fixture: FIXTURE,
        cases: results,
        accepted_effects: sink.case_ids.len(),
        rejected_zero_effects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_all_schema_cases_through_production_registry() -> Result<()> {
        let execution = run_view_write_contract_suite()?;
        assert_eq!(execution.cases.len(), 17);
        assert_eq!(execution.accepted_effects, 7);
        assert_eq!(execution.rejected_zero_effects, 10);
        assert!(execution.cases.iter().all(|case| case.assertions > 0));
        Ok(())
    }

    #[test]
    fn every_negative_leaves_the_accepted_sink_unchanged() -> Result<()> {
        let artifacts = spec_artifacts_root();
        let fixture = load_fixture(&artifacts)?;
        let mut registry = schema_registry_from_spec_artifacts(&artifacts)?;
        register_fixture_fragments(&mut registry, &artifacts, &fixture.cases)?;
        for case in fixture.cases.iter().filter(|case| !case.valid) {
            let mut sink = AcceptedWriteSink {
                case_ids: vec!["sentinel".to_owned()],
            };
            let before = sink.clone();
            assert!(validate_and_accept(&registry, case, &mut sink).is_err());
            assert_eq!(sink, before, "{}", case.name);
        }
        Ok(())
    }
}
