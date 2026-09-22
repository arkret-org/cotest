//! Executable capability relinquishment authoring conformance runner.
//!
//! The runner consumes the production `GrantList` active-row carrier and
//! copies its typed `CurrentRevision` into the production relinquish payload.
//! A separate CAS model covers stale and concurrent writes without turning a
//! list digest or historical evaluation into an authoring basis.

use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use arkret_models_collaboration::events_payloads::CapabilityRelinquishPayload;
use arkret_models_collaboration::governance::authorization::GrantList;
use arkret_wire::{CurrentRevision, ErrorCode};
use serde::Deserialize;
use serde_json::{Value, json};

pub const CAPABILITY_RELINQUISH_AUTHORING_ENTRYPOINT: &str =
    "ak.suite.capability.relinquish_authoring.v1";
pub const FIXTURE: &str = "capability-relinquish-authoring-fixture.json";

const VECTOR_ID: &str = "ak.vector.capability.relinquish_authoring_basis.v1";
const COMMIT: &str = "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4";
const NEXT_COMMIT: &str = "ak:realm_commit:AQPhm6Di_JMyu-JM932ww_EvyQU0dIIEO2ykFmYb9nD5";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRoot {
    profile: String,
    version: String,
    suite: String,
    runner: Runner,
    covers_vectors: Vec<String>,
    security_evidence: Vec<Value>,
    cases: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Runner {
    kind: String,
    entrypoint: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Confirmation {
    revision: CurrentRevision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CapabilityCell {
    revision: CurrentRevision,
    projection_writes: usize,
}

impl CapabilityCell {
    fn compare_and_swap(&mut self, expected: &CurrentRevision) -> bool {
        if &self.revision != expected {
            return false;
        }
        self.revision = next_revision();
        self.projection_writes += 1;
        true
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityRelinquishAuthoringExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
    pub typed_payloads: usize,
    pub blocked_authoring_cases: usize,
    pub cas_conflicts: usize,
}

fn active_grant() -> Value {
    json!({
        "id": "ak:grant:AR9qVnHK4a0914zPmH5CRZLTjSSV_8ghJKuGGivDaExf",
        "schema": "ak.schema.capability.v1",
        "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
        "issuer_id": {
            "kind": "account",
            "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkissuer",
                "station_id": "ak:did_core:webvh:z6mkstation"
            }
        },
        "subject": {
            "kind": "account",
            "account_id": {
                "principal_id": "ak:did_core:webvh:z6mksubject",
                "station_id": "ak:did_core:webvh:z6mkstation"
            }
        },
        "actions": ["ak.message.create"],
        "resources": [{
            "kind": "realm",
            "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5"
        }],
        "issuer_authority_refs": [{
            "kind": "grant",
            "grant_id": "ak:grant:AU1_A5a8MMz_OdxEleQlWPFn-ljdJteaJv3ZZ9APkcrZ"
        }],
        "authority_depth": 2,
        "authority_root_refs": [{
            "kind": "realm_root",
            "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
            "authority_event_ref": "ak:event:AR9qVnHK4a0914zPmH5CRZLTjSSV_8ghJKuGGivDaExf",
            "authority_generation": 0
        }],
        "issued_at": "2026-09-21T00:00:00.000Z",
        "status": "active"
    })
}

fn grant_list_wire(revision: Value, state_digest: &str) -> Value {
    json!({
        "grants": [{"grant": active_grant(), "revision": revision}],
        "state_digest": state_digest,
        "evaluated_at": "2026-09-21T00:00:01.000Z"
    })
}

fn revision(position: u64) -> CurrentRevision {
    serde_json::from_value(json!({"commit_id": COMMIT, "stream_position": position}))
        .expect("fixed revision is valid")
}

fn next_revision() -> CurrentRevision {
    serde_json::from_value(json!({"commit_id": NEXT_COMMIT, "stream_position": 42}))
        .expect("fixed successor revision is valid")
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

fn case_name(case: &Value) -> Result<&str> {
    case.get("name")
        .and_then(Value::as_str)
        .context("fixture case has no name")
}

fn at<'a>(case: &'a Value, pointer: &str) -> Result<&'a Value> {
    case.pointer(pointer)
        .with_context(|| format!("{} omits {pointer}", case_name(case).unwrap_or("unnamed")))
}

fn bool_at(case: &Value, pointer: &str) -> Result<bool> {
    at(case, pointer)?
        .as_bool()
        .with_context(|| format!("{pointer} is not boolean"))
}

fn u64_at(case: &Value, pointer: &str) -> Result<u64> {
    at(case, pointer)?
        .as_u64()
        .with_context(|| format!("{pointer} is not an unsigned integer"))
}

fn str_at<'a>(case: &'a Value, pointer: &str) -> Result<&'a str> {
    at(case, pointer)?
        .as_str()
        .with_context(|| format!("{pointer} is not a string"))
}

fn run_case(case: &Value) -> Result<(CaseExecutionResult, usize, usize, usize)> {
    let name = case_name(case)?;
    let (assertions, typed_payloads, blocked_authoring_cases, cas_conflicts) = match name {
        "active_row_supplies_exact_atomic_revision" => {
            ensure!(bool_at(
                case,
                "/list_result/grant_and_revision_same_current_result"
            )?);
            ensure!(bool_at(case, "/authoring/copied_row_revision_verbatim")?);
            ensure!(bool_at(case, "/authoring/user_confirmed")?);
            let list_wire = grant_list_wire(
                at(case, "/list_result/revision")?.clone(),
                str_at(case, "/list_result/state_digest")?,
            );
            let list: GrantList = serde_json::from_value(list_wire)?;
            ensure!(list.grants.len() == 1);
            let row = &list.grants[0];
            let payload = CapabilityRelinquishPayload {
                grant_id: row.grant.id.clone(),
                expected_revision: row.revision.clone(),
                reason: None,
            };
            let payload_wire = serde_json::to_value(payload)?;
            ensure!(
                payload_wire["expected_revision"] == at(case, "/list_result/revision")?.clone()
            );
            ensure!(str_at(case, "/expected/decision")? == "allow_authoring");
            ensure!(bool_at(case, "/expected/basis_is_row_revision")?);
            (8, 1, 0, 0)
        }
        "historical_evaluation_must_refresh_before_authoring" => {
            ensure!(bool_at(case, "/list_result/query_has_at")?);
            ensure!(bool_at(case, "/list_result/row_revision_present")?);
            ensure!(str_at(case, "/expected/decision")? == "block_authoring");
            ensure!(bool_at(
                case,
                "/expected/requires_current_query_without_at"
            )?);
            ensure!(bool_at(case, "/expected/requires_user_reconfirmation")?);
            ensure!(u64_at(case, "/expected/submissions")? == 0);
            (6, 0, 1, 0)
        }
        "list_digest_is_not_revision" => {
            ensure!(!bool_at(case, "/list_result/row_revision_present")?);
            ensure!(str_at(case, "/authoring/attempted_basis")? == "state_digest");
            let wire = grant_list_wire(
                Value::String(str_at(case, "/list_result/state_digest")?.to_owned()),
                str_at(case, "/list_result/state_digest")?,
            );
            ensure!(serde_json::from_value::<GrantList>(wire).is_err());
            ensure!(
                serde_json::from_value::<CurrentRevision>(
                    at(case, "/list_result/state_digest")?.clone()
                )
                .is_err()
            );
            ensure!(str_at(case, "/expected/decision")? == "block_authoring");
            ensure!(u64_at(case, "/expected/submissions")? == 0);
            ensure!(u64_at(case, "/expected/signatures")? == 0);
            (7, 0, 1, 0)
        }
        "stale_revision_conflicts_without_write" => {
            ensure!(!bool_at(case, "/authoring/row_revision_is_current")?);
            ensure!(bool_at(case, "/authoring/user_confirmed")?);
            let stale = revision(41);
            let mut cell = CapabilityCell {
                revision: next_revision(),
                projection_writes: 0,
            };
            ensure!(!cell.compare_and_swap(&stale));
            ensure!(str_at(case, "/expected/decision")? == "reject");
            ensure!(str_at(case, "/expected/error_code")? == ErrorCode::CAS_CONFLICT);
            ensure!(
                cell.projection_writes == u64_at(case, "/expected/projection_writes")? as usize
            );
            ensure!(bool_at(
                case,
                "/expected/requires_refresh_and_user_reconfirmation"
            )?);
            ensure!(!bool_at(case, "/expected/automatic_resign")?);
            (8, 0, 1, 1)
        }
        "concurrent_revoke_and_relinquish_have_one_winner" => {
            let operations = at(case, "/operations")?
                .as_array()
                .context("operations is not an array")?;
            ensure!(operations.len() == 2);
            ensure!(bool_at(case, "/same_expected_revision")?);
            let expected = revision(41);
            let mut cell = CapabilityCell {
                revision: expected.clone(),
                projection_writes: 0,
            };
            let first = cell.compare_and_swap(&expected);
            let second = cell.compare_and_swap(&expected);
            ensure!(
                usize::from(first) + usize::from(second)
                    == u64_at(case, "/expected/successful_operations")? as usize
            );
            ensure!(
                usize::from(!first) + usize::from(!second)
                    == u64_at(case, "/expected/cas_conflicts")? as usize
            );
            ensure!(
                cell.projection_writes == u64_at(case, "/expected/projection_writes")? as usize
            );
            (6, 0, 0, 1)
        }
        "refresh_requires_explicit_reconfirmation" => {
            ensure!(bool_at(case, "/authoring/initial_user_confirmation")?);
            ensure!(bool_at(case, "/authoring/revision_changed_after_refresh")?);
            ensure!(!bool_at(case, "/authoring/second_user_confirmation")?);
            let confirmation = Confirmation {
                revision: revision(41),
            };
            ensure!(confirmation.revision != next_revision());
            ensure!(str_at(case, "/expected/decision")? == "block_authoring");
            ensure!(!bool_at(case, "/expected/automatic_resign")?);
            ensure!(u64_at(case, "/expected/submissions")? == 0);
            (7, 0, 1, 0)
        }
        "unreadable_missing_and_terminal_are_non_enumerating" => {
            let requested = at(case, "/requested_states")?
                .as_array()
                .context("requested_states is not an array")?;
            ensure!(requested.iter().filter_map(Value::as_str).eq([
                "unauthorized",
                "missing",
                "revoked",
                "relinquished"
            ]));
            for terminal in ["revoked", "relinquished"] {
                let mut wire = grant_list_wire(
                    serde_json::to_value(revision(41))?,
                    "sha256:7777777777777777777777777777777777777777777777777777777777777777",
                );
                wire["grants"][0]["grant"]["status"] = Value::String(terminal.to_owned());
                ensure!(serde_json::from_value::<GrantList>(wire).is_err());
            }
            ensure!(u64_at(case, "/expected/rows_returned")? == 0);
            ensure!(u64_at(case, "/expected/distinguishable_outcomes")? == 1);
            ensure!(!bool_at(case, "/expected/authoring_allowed")?);
            (7, 0, 1, 0)
        }
        other => bail!("unknown capability relinquish authoring case {other}"),
    };
    Ok((
        CaseExecutionResult {
            case_id: name.to_owned(),
            assertions,
        },
        typed_payloads,
        blocked_authoring_cases,
        cas_conflicts,
    ))
}

pub fn run_capability_relinquish_authoring_suite() -> Result<CapabilityRelinquishAuthoringExecution>
{
    let fixture = load_fixture()?;
    ensure!(
        fixture.profile == "ak.vector_group.capability.v1",
        "fixture profile drifted"
    );
    ensure!(
        !fixture.version.trim().is_empty(),
        "fixture version is empty"
    );
    ensure!(
        fixture.suite == "capability_relinquish_authoring",
        "fixture suite drifted"
    );
    ensure!(fixture.runner.kind == "named_suite", "runner kind drifted");
    ensure!(
        fixture.runner.entrypoint == CAPABILITY_RELINQUISH_AUTHORING_ENTRYPOINT,
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
        fixture.security_evidence.len() == 1,
        "security evidence closure drifted"
    );

    let mut cases = Vec::with_capacity(fixture.cases.len());
    let mut typed_payloads = 0;
    let mut blocked_authoring_cases = 0;
    let mut cas_conflicts = 0;
    for case in &fixture.cases {
        let (result, typed, blocked, conflicts) = run_case(case)?;
        cases.push(result);
        typed_payloads += typed;
        blocked_authoring_cases += blocked;
        cas_conflicts += conflicts;
    }
    ensure!(
        cases.len() == 7,
        "expected all seven relinquish-authoring cases"
    );
    Ok(CapabilityRelinquishAuthoringExecution {
        entrypoint: CAPABILITY_RELINQUISH_AUTHORING_ENTRYPOINT,
        fixture: FIXTURE,
        cases,
        typed_payloads,
        blocked_authoring_cases,
        cas_conflicts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_atomic_row_authoring_and_all_blocking_cases() {
        let execution = run_capability_relinquish_authoring_suite().unwrap();
        assert_eq!(
            execution.entrypoint,
            CAPABILITY_RELINQUISH_AUTHORING_ENTRYPOINT
        );
        assert_eq!(execution.cases.len(), 7);
        assert_eq!(execution.typed_payloads, 1);
        assert_eq!(execution.blocked_authoring_cases, 5);
        assert_eq!(execution.cas_conflicts, 2);
        assert!(execution.cases.iter().all(|case| case.assertions > 0));
    }

    #[test]
    fn effective_list_rejects_a_terminal_grant() {
        let mut wire = grant_list_wire(
            serde_json::to_value(revision(41)).unwrap(),
            "sha256:7777777777777777777777777777777777777777777777777777777777777777",
        );
        wire["grants"][0]["grant"]["status"] = json!("relinquished");
        assert!(serde_json::from_value::<GrantList>(wire).is_err());
    }

    #[test]
    fn stale_compare_and_swap_has_no_projection_effect() {
        let mut cell = CapabilityCell {
            revision: next_revision(),
            projection_writes: 0,
        };
        assert!(!cell.compare_and_swap(&revision(41)));
        assert_eq!(cell.projection_writes, 0);
    }
}
