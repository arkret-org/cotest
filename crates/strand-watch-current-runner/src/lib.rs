//! Executable exact Strand watch-current read conformance runner.
//!
//! The runner uses the production closed request/outcome types and their
//! `validate_for_request` consumer guard. A small Station read model supplies
//! confirmed-head current rows; a separate client guard prevents stale
//! governance generations or revisions from being reused for authoring.

use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use arkret_models_collaboration::events_payloads::{StrandWatchExpectedValue, StrandWatchLevel};
use arkret_models_collaboration::strand_watch_operations::{
    StrandWatchCurrentOutcome, StrandWatchCurrentRequestBody, StrandWatchCurrentValue,
};
use serde::Deserialize;
use serde_json::{Value, json};

pub const STRAND_WATCH_CURRENT_ENTRYPOINT: &str = "ak.suite.state.strand_watch_current_read.v1";
pub const FIXTURE: &str = "strand-watch-current-read-fixture.json";

const VECTOR_ID: &str = "ak.vector.state.strand_watch_current_read.v1";
const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
const STRAND: &str = "ak:strand:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0";
const COMMIT: &str = "ak:realm_commit:AT33EWBTXdTx5CjY-ogbIIF2T4vh-v7jCMCQ80Fss2Rq";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureRoot {
    profile: String,
    version: String,
    suite: String,
    runner: Runner,
    covers_vectors: Vec<String>,
    cases: Vec<Value>,
    minimum_independent_runners: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Runner {
    kind: String,
    entrypoint: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AcceptedWrite {
    stream_position: u64,
    value: Option<StrandWatchExpectedValue>,
}

#[derive(Clone, Debug, Default)]
struct StationReadModel {
    accepted_writes: Vec<AcceptedWrite>,
}

impl StationReadModel {
    fn append(&mut self, stream_position: u64, value: Option<StrandWatchExpectedValue>) {
        self.accepted_writes.push(AcceptedWrite {
            stream_position,
            value,
        });
        self.accepted_writes
            .sort_unstable_by_key(|write| write.stream_position);
    }

    fn read(&self, request: &StrandWatchCurrentRequestBody) -> Result<StrandWatchCurrentOutcome> {
        let wire = if let Some(write) = self.accepted_writes.last() {
            current_wire(
                write.stream_position,
                write.value.map_or(Value::Null, |value| {
                    serde_json::to_value(value).expect("watch value serializes")
                }),
            )
        } else {
            never_written_wire()
        };
        let outcome: StrandWatchCurrentOutcome = serde_json::from_value(wire)?;
        outcome
            .validate_for_request(request)
            .map_err(anyhow::Error::msg)?;
        Ok(outcome)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadGateResult {
    Allowed,
    NotFound,
}

fn authorize_read(
    variant: &str,
    has_watch_set_others: bool,
    has_notification_audit: bool,
) -> ReadGateResult {
    if variant == "self_visible" || (has_watch_set_others && has_notification_audit) {
        ReadGateResult::Allowed
    } else {
        ReadGateResult::NotFound
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClientConfirmation {
    governance_generation: u64,
    stream_position: u64,
}

fn confirmation_is_current(
    confirmation: ClientConfirmation,
    governance_generation: u64,
    stream_position: u64,
) -> bool {
    confirmation.governance_generation == governance_generation
        && confirmation.stream_position == stream_position
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrandWatchCurrentExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
    pub typed_outcomes: usize,
    pub non_enumerating_rejections: usize,
    pub stale_authoring_blocks: usize,
}

fn actor() -> Value {
    json!({
        "kind": "account",
        "account_id": {
            "principal_id": "ak:did_core:webvh:QmTnpRaadxso9gmuqCaoT54ib4kWKNt1F5UuqXN6i5hwey",
            "station_id": "ak:did_core:web:station.example"
        }
    })
}

fn request_wire() -> Value {
    json!({"realm_id": REALM, "strand_id": STRAND, "watcher_actor_id": actor()})
}

fn selector_wire() -> Value {
    json!({"kind": "strand_watch", "strand_id": STRAND, "watcher_actor_id": actor()})
}

fn head_wire(stream_position: u64) -> Value {
    json!({
        "stream_ref": {"kind": "realm", "realm_id": REALM},
        "stream_position": stream_position,
        "commit_id": COMMIT
    })
}

fn never_written_wire() -> Value {
    json!({
        "status": "never_written",
        "realm_id": REALM,
        "governance_generation": 2,
        "stream_head": head_wire(12),
        "selector": selector_wire()
    })
}

fn current_wire(stream_position: u64, value: Value) -> Value {
    json!({
        "status": "current",
        "realm_id": REALM,
        "governance_generation": 2,
        "stream_head": head_wire(12),
        "result": {
            "selector": selector_wire(),
            "source_stream_ref": {"kind": "realm", "realm_id": REALM},
            "revision": {"commit_id": COMMIT, "stream_position": stream_position},
            "value": value
        }
    })
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

fn run_case(
    case: &Value,
    request: &StrandWatchCurrentRequestBody,
) -> Result<(CaseExecutionResult, usize, usize, usize)> {
    let name = case_name(case)?;
    let (assertions, typed_outcomes, non_enumerating_rejections, stale_authoring_blocks) =
        match name {
            "never_written_is_explicit_at_confirmed_head" => {
                ensure!(bool_at(case, "/same_effective_actor")?);
                ensure!(bool_at(case, "/current_scope_readable")?);
                ensure!(u64_at(case, "/accepted_watch_writes")? == 0);
                let outcome = StationReadModel::default().read(request)?;
                ensure!(matches!(
                    outcome,
                    StrandWatchCurrentOutcome::NeverWritten { .. }
                ));
                let wire = serde_json::to_value(&outcome)?;
                ensure!(wire["status"] == at(case, "/expected/status")?.clone());
                ensure!(wire.get("result").is_none());
                ensure!(!bool_at(case, "/expected/revision_present")?);
                ensure!(!bool_at(case, "/expected/value_present")?);
                ensure!(bool_at(
                    case,
                    "/expected/can_omit_expected_value_for_first_write"
                )?);
                (9, 1, 0, 0)
            }
            "written_clear_is_current_null_not_never_written" => {
                ensure!(u64_at(case, "/accepted_watch_writes")? == 2);
                ensure!(at(case, "/last_write_level")?.is_null());
                let mut station = StationReadModel::default();
                station.append(
                    11,
                    Some(StrandWatchExpectedValue {
                        level: StrandWatchLevel::All,
                        level_public: Some(true),
                    }),
                );
                station.append(12, None);
                let outcome = station.read(request)?;
                let StrandWatchCurrentOutcome::Current { result, .. } = &outcome else {
                    bail!("written clear was downgraded to never_written");
                };
                ensure!(result.value == StrandWatchCurrentValue::Cleared(()));
                ensure!(result.value.as_option().is_none());
                let wire = serde_json::to_value(outcome)?;
                ensure!(wire["status"] == at(case, "/expected/status")?.clone());
                ensure!(wire["result"]["value"].is_null());
                ensure!(bool_at(case, "/expected/revision_present")?);
                ensure!(at(case, "/expected/next_write_expected_value")?.is_null());
                (8, 1, 0, 0)
            }
            "whole_value_public_flag_must_match" => {
                let current: StrandWatchExpectedValue =
                    serde_json::from_value(at(case, "/current_value")?.clone())?;
                let attempted: StrandWatchExpectedValue =
                    serde_json::from_value(at(case, "/attempt_expected_value")?.clone())?;
                ensure!(current != attempted);
                ensure!(str_at(case, "/expected/decision")? == "failed_precondition");
                ensure!(u64_at(case, "/expected/effect_count")? == 0);
                ensure!(current.level == attempted.level);
                ensure!(current.level_public != attempted.level_public);
                (5, 0, 0, 1)
            }
            "reverse_arrival_and_missing_tail_do_not_change_current" => {
                ensure!(
                    at(case, "/local_raw_event_order")?
                        != at(case, "/station_accepted_commit_order")?
                );
                let mut station = StationReadModel::default();
                station.append(
                    11,
                    Some(StrandWatchExpectedValue {
                        level: StrandWatchLevel::MentionsOnly,
                        level_public: None,
                    }),
                );
                station.append(
                    12,
                    Some(StrandWatchExpectedValue {
                        level: StrandWatchLevel::All,
                        level_public: Some(true),
                    }),
                );
                let outcome = station.read(request)?;
                let StrandWatchCurrentOutcome::Current { result, .. } = outcome else {
                    bail!("accepted writes did not produce a current row");
                };
                ensure!(
                    result
                        .value
                        .as_option()
                        .is_some_and(|value| value.level == StrandWatchLevel::All)
                );
                ensure!(
                    str_at(case, "/expected/read_source")?
                        == "durable_typed_current_at_confirmed_head"
                );
                ensure!(!bool_at(case, "/expected/uses_local_raw_event_order")?);
                (5, 1, 0, 0)
            }
            "foreign_or_invisible_selector_is_non_enumerating" => {
                let variants = at(case, "/variants")?
                    .as_array()
                    .context("variants is not an array")?;
                ensure!(variants.len() == 3);
                for variant in variants {
                    let variant = variant.as_str().context("variant is not a string")?;
                    ensure!(authorize_read(variant, false, false) == ReadGateResult::NotFound);
                }
                ensure!(str_at(case, "/expected/same_result")? == "not_found");
                ensure!(!bool_at(case, "/expected/watch_value_disclosed")?);
                (6, 0, variants.len(), 0)
            }
            "others_write_does_not_grant_private_read" => {
                let has_others = bool_at(case, "/has_watch_set_others")?;
                let has_audit = bool_at(case, "/has_notification_audit")?;
                ensure!(has_others && !has_audit);
                ensure!(
                    authorize_read("other_watcher", has_others, has_audit)
                        == ReadGateResult::NotFound
                );
                ensure!(str_at(case, "/expected/read_result")? == "not_found");
                ensure!(!bool_at(case, "/expected/watch_value_disclosed")?);
                (5, 0, 1, 0)
            }
            "handoff_and_cas_conflict_require_re_read" => {
                ensure!(bool_at(case, "/old_governance_generation")?);
                ensure!(bool_at(case, "/concurrent_watch_write")?);
                let old = ClientConfirmation {
                    governance_generation: 1,
                    stream_position: 11,
                };
                ensure!(!confirmation_is_current(old, 2, 12));
                ensure!(!bool_at(case, "/expected/old_read_usable")?);
                ensure!(!bool_at(case, "/expected/automatic_retry_with_old_value")?);
                ensure!(str_at(case, "/expected/action")? == "refresh_current_and_reconfirm");
                (6, 0, 0, 1)
            }
            other => bail!("unknown Strand watch-current case {other}"),
        };
    Ok((
        CaseExecutionResult {
            case_id: name.to_owned(),
            assertions,
        },
        typed_outcomes,
        non_enumerating_rejections,
        stale_authoring_blocks,
    ))
}

pub fn run_strand_watch_current_suite() -> Result<StrandWatchCurrentExecution> {
    let fixture = load_fixture()?;
    ensure!(
        fixture.profile == "ak.vector_group.state.v1",
        "fixture profile drifted"
    );
    ensure!(
        !fixture.version.trim().is_empty(),
        "fixture version is empty"
    );
    ensure!(
        fixture.suite == "strand_watch_current_read",
        "fixture suite drifted"
    );
    ensure!(fixture.runner.kind == "named_suite", "runner kind drifted");
    ensure!(
        fixture.runner.entrypoint == STRAND_WATCH_CURRENT_ENTRYPOINT,
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
        fixture.minimum_independent_runners == 2,
        "independent-runner requirement drifted"
    );

    let request: StrandWatchCurrentRequestBody = serde_json::from_value(request_wire())?;
    let mut cases = Vec::with_capacity(fixture.cases.len());
    let mut typed_outcomes = 0;
    let mut non_enumerating_rejections = 0;
    let mut stale_authoring_blocks = 0;
    for case in &fixture.cases {
        let (result, typed, hidden, stale) = run_case(case, &request)?;
        cases.push(result);
        typed_outcomes += typed;
        non_enumerating_rejections += hidden;
        stale_authoring_blocks += stale;
    }
    ensure!(cases.len() == 7, "expected all seven watch-current cases");
    Ok(StrandWatchCurrentExecution {
        entrypoint: STRAND_WATCH_CURRENT_ENTRYPOINT,
        fixture: FIXTURE,
        cases,
        typed_outcomes,
        non_enumerating_rejections,
        stale_authoring_blocks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executes_every_station_and_client_case() {
        let execution = run_strand_watch_current_suite().unwrap();
        assert_eq!(execution.entrypoint, STRAND_WATCH_CURRENT_ENTRYPOINT);
        assert_eq!(execution.cases.len(), 7);
        assert_eq!(execution.typed_outcomes, 3);
        assert_eq!(execution.non_enumerating_rejections, 4);
        assert_eq!(execution.stale_authoring_blocks, 2);
        assert!(execution.cases.iter().all(|case| case.assertions > 0));
    }

    #[test]
    fn closed_outcome_rejects_an_omitted_written_value() {
        let mut wire = current_wire(12, Value::Null);
        wire["result"].as_object_mut().unwrap().remove("value");
        assert!(serde_json::from_value::<StrandWatchCurrentOutcome>(wire).is_err());
    }

    #[test]
    fn closed_outcome_rejects_an_omitted_source_stream() {
        let mut wire = current_wire(12, Value::Null);
        wire["result"]
            .as_object_mut()
            .unwrap()
            .remove("source_stream_ref");
        assert!(serde_json::from_value::<StrandWatchCurrentOutcome>(wire).is_err());
    }

    #[test]
    fn consumer_guard_rejects_a_row_from_another_stream() {
        let request: StrandWatchCurrentRequestBody =
            serde_json::from_value(request_wire()).unwrap();
        let mut wire = current_wire(12, Value::Null);
        wire["result"]["source_stream_ref"] = json!({
            "kind": "circle",
            "realm_id": REALM,
            "circle_id": "ak:circle:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9"
        });
        let outcome: StrandWatchCurrentOutcome = serde_json::from_value(wire).unwrap();
        assert!(outcome.validate_for_request(&request).is_err());
    }

    #[test]
    fn consumer_guard_rejects_a_revision_ahead_of_the_confirmed_head() {
        let request: StrandWatchCurrentRequestBody =
            serde_json::from_value(request_wire()).unwrap();
        let outcome: StrandWatchCurrentOutcome =
            serde_json::from_value(current_wire(13, Value::Null)).unwrap();
        assert!(outcome.validate_for_request(&request).is_err());
    }
}
