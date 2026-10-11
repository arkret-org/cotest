//! Executable structural-Relation Realm-boundary conformance runner.
//!
//! Coland's governing-Station reducer and SDK producer precheck call the same
//! production predicate, `validate_structural_relation_same_realm`. This
//! runner drives that predicate for every canonical fixture case and records
//! commit/continuation effects only after admission succeeds.

use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::objects::relation::{
    relation_kind_is_structural, validate_structural_relation_same_realm,
};
use arkret_wire::{ErrorCode, RealmId, ReasonCode};
use serde::Deserialize;

pub const RELATION_STRUCTURAL_REALM_ENTRYPOINT: &str = "ak.suite.relation.structural_realm.v1";
pub const FIXTURE: &str = "relation-structural-realm-fixture.json";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRoot {
    profile: String,
    version: String,
    suite: String,
    runner: Runner,
    covers_vectors: Vec<String>,
    authority: String,
    cases: Vec<FixtureCase>,
    non_authoritative_precheck_rule: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Runner {
    kind: String,
    entrypoint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureCase {
    #[serde(rename = "case")]
    case_id: String,
    relation_kind: String,
    relation_realm: String,
    resolved_from_realm: String,
    resolved_to_realm: String,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    decision: String,
    #[serde(default)]
    error_code: Option<String>,
    #[serde(default)]
    reason_code: Option<String>,
    #[serde(default)]
    commits: Option<usize>,
    #[serde(default)]
    projection_writes: Option<usize>,
    #[serde(default)]
    structural_realm_rejection: Option<bool>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct EffectSink {
    commits: usize,
    projection_writes: usize,
    authorization_continuations: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
    pub committed_effects: usize,
    pub rejected_state_unchanged: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationStructuralRealmExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
    pub committed_effects: usize,
    pub authorization_continuations: usize,
    pub rejected_cases: usize,
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

fn validate_fixture_metadata(fixture: &FixtureRoot) -> Result<()> {
    ensure!(
        fixture.profile == "ak.profile.core_event_store.v1",
        "fixture profile drifted"
    );
    ensure!(
        !fixture.version.trim().is_empty(),
        "fixture version is empty"
    );
    ensure!(
        fixture.suite == "relation_structural_realm",
        "fixture suite drifted"
    );
    ensure!(fixture.runner.kind == "named_suite", "runner kind drifted");
    ensure!(
        fixture.runner.entrypoint == RELATION_STRUCTURAL_REALM_ENTRYPOINT,
        "runner entrypoint drifted"
    );
    ensure!(
        fixture
            .covers_vectors
            .iter()
            .map(String::as_str)
            .eq(["ak.vector.relation.structural_realm.v1"]),
        "fixture vector closure drifted"
    );
    ensure!(
        fixture.authority == "current_governance_station_reducer",
        "fixture authority drifted"
    );
    ensure!(
        !fixture.non_authoritative_precheck_rule.trim().is_empty(),
        "fixture omitted the producer-precheck authority boundary"
    );
    Ok(())
}

fn run_case(case: &FixtureCase, sink: &mut EffectSink) -> Result<CaseExecutionResult> {
    let relation_realm = RealmId::new(case.relation_realm.clone())?;
    let from_realm = RealmId::new(case.resolved_from_realm.clone())?;
    let to_realm = RealmId::new(case.resolved_to_realm.clone())?;
    let before = sink.clone();
    let structural = relation_kind_is_structural(&case.relation_kind);
    let decision = validate_structural_relation_same_realm(
        &case.relation_kind,
        relation_realm.as_str(),
        [from_realm.as_str(), to_realm.as_str()],
    );

    let (assertions, rejected_state_unchanged) = match case.expected.decision.as_str() {
        "accept" => {
            ensure!(structural, "accepted control must be a structural relation");
            decision.map_err(anyhow::Error::msg)?;
            sink.commits += 1;
            sink.projection_writes += 1;
            ensure!(
                case.expected.commits == Some(1),
                "accept commit count drifted"
            );
            (4, false)
        }
        "reject" => {
            let reason = decision.expect_err("rejected case unexpectedly passed admission");
            ensure!(
                structural,
                "cross-Realm rejection must apply only to a structural relation"
            );
            ensure!(
                case.expected.error_code.as_deref() == Some(ErrorCode::FAILED_PRECONDITION),
                "rejection error code drifted"
            );
            ensure!(
                case.expected.reason_code.as_deref() == Some(reason),
                "rejection reason drifted"
            );
            ensure!(
                reason == ReasonCode::CROSS_REALM_STRUCTURAL_RELATION,
                "production predicate returned an unregistered reason"
            );
            ensure!(
                ReasonCode::from_wire(reason).descriptor().is_some(),
                "rejection reason is absent from the generated registry"
            );
            ensure!(
                case.expected.commits == Some(0),
                "reject commit count drifted"
            );
            ensure!(
                case.expected.projection_writes == Some(0),
                "reject projection-write count drifted"
            );
            ensure!(&before == sink, "rejected relation mutated the effect sink");
            (8, true)
        }
        "continue_two_sided_authorization" => {
            ensure!(!structural, "continuation control must be a weak relation");
            decision.map_err(anyhow::Error::msg)?;
            ensure!(
                case.expected.structural_realm_rejection == Some(false),
                "weak relation unexpectedly requested structural rejection"
            );
            sink.authorization_continuations += 1;
            (4, false)
        }
        other => anyhow::bail!("unknown expected decision {other}"),
    };

    Ok(CaseExecutionResult {
        case_id: case.case_id.clone(),
        assertions,
        committed_effects: sink.commits - before.commits,
        rejected_state_unchanged,
    })
}

pub fn run_relation_structural_realm_suite() -> Result<RelationStructuralRealmExecution> {
    let fixture = load_fixture()?;
    validate_fixture_metadata(&fixture)?;
    let mut sink = EffectSink::default();
    let mut cases = Vec::with_capacity(fixture.cases.len());
    for case in &fixture.cases {
        cases.push(run_case(case, &mut sink)?);
    }
    ensure!(
        cases.len() == 3,
        "expected all three structural-Realm cases"
    );
    let rejected_cases = cases
        .iter()
        .filter(|case| case.rejected_state_unchanged)
        .count();
    Ok(RelationStructuralRealmExecution {
        entrypoint: RELATION_STRUCTURAL_REALM_ENTRYPOINT,
        fixture: FIXTURE,
        cases,
        committed_effects: sink.commits,
        authorization_continuations: sink.authorization_continuations,
        rejected_cases,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_all_cases_through_the_production_predicate() {
        let execution = run_relation_structural_realm_suite().unwrap();
        assert_eq!(execution.entrypoint, RELATION_STRUCTURAL_REALM_ENTRYPOINT);
        assert_eq!(execution.cases.len(), 3);
        assert_eq!(execution.committed_effects, 1);
        assert_eq!(execution.authorization_continuations, 1);
        assert_eq!(execution.rejected_cases, 1);
        assert!(execution.cases.iter().all(|case| case.assertions > 0));
        assert!(execution.cases[1].rejected_state_unchanged);
    }

    #[test]
    fn structural_and_weak_kinds_take_distinct_paths() {
        assert!(relation_kind_is_structural("contains"));
        assert!(!relation_kind_is_structural("references"));
    }
}
