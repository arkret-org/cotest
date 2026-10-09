//! Executable SDK Event precheck vectors.
//!
//! The fixture mutations are submitted to the SDK's production Draft 2020-12
//! [`ProtocolSchemaRegistry`]. The Event schema itself owns the kind-selected
//! payload dispatch; this runner deliberately does not call the payload catalog
//! as a second acceptance gate.

use std::path::PathBuf;

use anyhow::{Context, Result, bail, ensure};
use arkret_schema::{ProtocolSchemaRegistry, SchemaError, SchemaValidationIssue};
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use arkret_wire::SchemaId;
use serde_json::{Map, Value, json};

pub const SDK_PRECHECK_ENTRYPOINT: &str = "ak.suite.sdk.precheck.v1";
const FIXTURE: &str = "sdk-precheck-fixture.json";

const CASE_EVENT_SCHEMA: &str = "an_envelope_that_fails_the_event_schema_never_reaches_the_reducer";
const CASE_PAYLOAD_CLASS: &str = "a_payload_that_fails_its_payload_class_never_reaches_the_reducer";
const CASE_NO_REPAIR: &str = "a_rejected_envelope_is_not_repaired_or_partially_applied";
const CASE_HLC: &str = "hlc_at_the_event_top_level_is_refused";
const CASE_PRODUCER_REVISION: &str = "producer_revision_at_the_event_top_level_is_refused";
const CASE_DOMAIN_REFS: &str = "domain_refs_at_the_event_top_level_is_refused";
const CASE_REQUIREMENTS: &str = "requirements_at_the_event_top_level_is_refused";
const CASE_PRODUCER_PROOF: &str = "producer_proof_cannot_be_omitted_or_defaulted";
const CASE_SCOPE_REF: &str = "scope_ref_cannot_be_omitted_or_defaulted";
const CASE_ACTOR_ID: &str = "actor_id_cannot_be_omitted_or_defaulted";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EffectCounts {
    pub verifier_calls: usize,
    pub reducer_writes: usize,
    pub projection_writes: usize,
    pub cache_writes: usize,
    pub outbound_effects: usize,
}

impl EffectCounts {
    fn consume_once(&mut self) {
        self.verifier_calls += 1;
        self.reducer_writes += 1;
        self.projection_writes += 1;
        self.cache_writes += 1;
        self.outbound_effects += 1;
    }

    fn is_zero(self) -> bool {
        self == Self::default()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdmissionPath {
    Initial,
    Retry,
    Reconnect,
    Backfill,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AdmissionObservation {
    accepted: bool,
    reason: Option<&'static str>,
    effects: EffectCounts,
    issue: Option<SchemaValidationIssue>,
}

/// Thin consumer boundary that guarantees schema validation precedes every
/// downstream effect. The validator is production SDK code; the counters are
/// explicit Cotest ports which make forbidden consumption observable.
struct EventAdmissionConsumer {
    registry: ProtocolSchemaRegistry,
}

impl EventAdmissionConsumer {
    fn from_spec_artifacts() -> Result<Self> {
        Ok(Self {
            registry: schema_registry_from_spec_artifacts(spec_artifacts_root())
                .context("load production protocol schema registry")?,
        })
    }

    fn submit(&self, event: &Value, _path: AdmissionPath) -> Result<AdmissionObservation> {
        let mut effects = EffectCounts::default();
        match self.registry.validate_value(SchemaId::EVENT_V1, event) {
            Ok(()) => {
                effects.consume_once();
                Ok(AdmissionObservation {
                    accepted: true,
                    reason: None,
                    effects,
                    issue: None,
                })
            }
            Err(SchemaError::Validation(issue)) => {
                ensure!(
                    issue.schema_id == SchemaId::EVENT_V1,
                    "Event precheck returned a validation issue for {}",
                    issue.schema_id
                );
                Ok(AdmissionObservation {
                    accepted: false,
                    reason: Some("schema_violation"),
                    effects,
                    issue: Some(issue),
                })
            }
            Err(error) => Err(error).context("Event precheck failed outside schema admission"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
    pub decision: &'static str,
    pub reason: &'static str,
    pub attempts: usize,
    pub instance_pointer: String,
    pub keyword: String,
    pub effects: EffectCounts,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SdkPrecheckExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub positive_control_assertions: usize,
    pub cases: Vec<CaseExecutionResult>,
}

impl SdkPrecheckExecution {
    fn assert_complete_against(&self, fixture: &Value) -> Result<()> {
        let declared = fixture["cases"]
            .as_array()
            .context("SDK precheck fixture has no cases[]")?;
        ensure!(
            declared.len() == self.cases.len(),
            "{} declared {} cases but runner returned {} results",
            self.entrypoint,
            declared.len(),
            self.cases.len()
        );
        for (index, (case, result)) in declared.iter().zip(&self.cases).enumerate() {
            let declared_id = case["name"]
                .as_str()
                .with_context(|| format!("{FIXTURE} cases[{index}] has no name"))?;
            ensure!(
                declared_id == result.case_id,
                "{FIXTURE} cases[{index}] is {declared_id}, runner returned {}",
                result.case_id
            );
            ensure!(
                result.assertions > 0,
                "SDK precheck case {declared_id} returned no executed assertions"
            );
        }
        Ok(())
    }
}

fn spec_artifacts_root() -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT") {
        return PathBuf::from(root);
    }
    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        let root = PathBuf::from(root);
        for candidate in [root.clone(), root.join("spec").join("v1").join("artifacts")] {
            if candidate.join("registry").is_dir() {
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

fn load_artifact_json(relative: &str) -> Result<Value> {
    let path = spec_artifacts_root().join(relative);
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read spec artifact {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse spec artifact {}", path.display()))
}

fn load_fixture_and_base_event() -> Result<(Value, Value)> {
    let fixture = load_artifact_json(&format!("fixtures/{FIXTURE}"))?;
    ensure!(
        fixture
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            == Some(SDK_PRECHECK_ENTRYPOINT),
        "{FIXTURE} runner entrypoint drifted"
    );
    ensure!(
        fixture.pointer("/runner/kind").and_then(Value::as_str) == Some("named_suite"),
        "{FIXTURE} runner kind must be named_suite"
    );
    let contracts = fixture["machine_contracts"]
        .as_array()
        .context("SDK precheck fixture has no machine_contracts")?;
    for required in [
        "schemas/event-envelope.schema.json",
        "schemas/event-payload.schema.json#/$defs/strand_create_payload",
    ] {
        ensure!(
            contracts
                .iter()
                .any(|value| value.as_str() == Some(required)),
            "{FIXTURE} is not bound to {required}"
        );
    }

    let base = &fixture["legal_base_event"];
    let fixture_ref = base["fixture_ref"]
        .as_str()
        .context("legal_base_event.fixture_ref is absent")?;
    let pointer = base["json_pointer"]
        .as_str()
        .context("legal_base_event.json_pointer is absent")?;
    let source = load_artifact_json(fixture_ref)?;
    let event = source
        .pointer(pointer)
        .with_context(|| format!("{fixture_ref}{pointer} does not resolve"))?
        .clone();
    Ok((fixture, event))
}

fn event_object(event: &mut Value) -> Result<&mut Map<String, Value>> {
    event
        .as_object_mut()
        .context("legal base Event must be an object")
}

fn mutation_for(case_id: &str, base_event: &Value) -> Result<Value> {
    let mut event = base_event.clone();
    let object = event_object(&mut event)?;
    match case_id {
        CASE_EVENT_SCHEMA | CASE_NO_REPAIR => {
            object.insert("vendor_top".to_owned(), Value::Bool(true));
        }
        CASE_PAYLOAD_CLASS => {
            object.insert("payload".to_owned(), json!({}));
        }
        CASE_HLC => {
            object.insert(
                "hlc".to_owned(),
                Value::String("2026-09-20T00:00:00.000Z-0001-node".to_owned()),
            );
        }
        CASE_PRODUCER_REVISION => {
            object.insert("producer_revision".to_owned(), json!(1));
        }
        CASE_DOMAIN_REFS => {
            object.insert("domain_refs".to_owned(), json!([]));
        }
        CASE_REQUIREMENTS => {
            object.insert("requirements".to_owned(), json!({}));
        }
        CASE_PRODUCER_PROOF => {
            ensure!(
                object.remove("producer_proof").is_some(),
                "base Event has no producer_proof"
            );
        }
        CASE_SCOPE_REF => {
            ensure!(
                object.remove("scope_ref").is_some(),
                "base Event has no scope_ref"
            );
        }
        CASE_ACTOR_ID => {
            ensure!(
                object.remove("actor_id").is_some(),
                "base Event has no actor_id"
            );
        }
        other => bail!("unexecuted SDK precheck fixture case {other}"),
    }
    Ok(event)
}

fn paths_for(case_id: &str) -> &'static [AdmissionPath] {
    if case_id == CASE_NO_REPAIR {
        &[
            AdmissionPath::Initial,
            AdmissionPath::Retry,
            AdmissionPath::Reconnect,
            AdmissionPath::Backfill,
        ]
    } else {
        &[AdmissionPath::Initial]
    }
}

fn assert_expected_issue(case_id: &str, issue: &SchemaValidationIssue) -> Result<usize> {
    match case_id {
        CASE_PAYLOAD_CLASS => {
            ensure!(
                issue.instance_pointer == "/payload",
                "payload case failed at {}",
                issue.instance_pointer
            );
            ensure!(
                issue.keyword == "required",
                "payload case failed with {}",
                issue.keyword
            );
            Ok(2)
        }
        CASE_PRODUCER_PROOF | CASE_SCOPE_REF | CASE_ACTOR_ID => {
            ensure!(
                issue.instance_pointer.is_empty(),
                "required root member failed below root"
            );
            ensure!(
                issue.keyword == "required",
                "required root member failed with {}",
                issue.keyword
            );
            Ok(2)
        }
        CASE_EVENT_SCHEMA
        | CASE_NO_REPAIR
        | CASE_HLC
        | CASE_PRODUCER_REVISION
        | CASE_DOMAIN_REFS
        | CASE_REQUIREMENTS => {
            ensure!(
                issue.instance_pointer.is_empty(),
                "forbidden root member failed below root"
            );
            ensure!(
                issue.keyword == "additionalProperties",
                "forbidden root member failed with {}",
                issue.keyword
            );
            Ok(2)
        }
        other => bail!("no expected schema issue for {other}"),
    }
}

/// The modeled effect ports do not establish production reducer/storage evidence.
pub fn run_sdk_precheck_suite() -> Result<SdkPrecheckExecution> {
    bail!(
        "SDK precheck production Event consumer is unproved; schema/effect-port execution is diagnostic evidence"
    )
}

/// Execute the production schema validator with isolated, modeled effect ports.
pub fn run_sdk_precheck_suite_diagnostic() -> Result<SdkPrecheckExecution> {
    let (fixture, base_event) = load_fixture_and_base_event()?;
    let consumer = EventAdmissionConsumer::from_spec_artifacts()?;

    let positive = consumer.submit(&base_event, AdmissionPath::Initial)?;
    ensure!(
        positive.accepted,
        "legal base Event did not pass complete Event schema"
    );
    ensure!(
        positive.reason.is_none(),
        "legal base Event returned a rejection reason"
    );
    ensure!(
        positive.issue.is_none(),
        "legal base Event returned a validation issue"
    );
    ensure!(
        positive.effects.verifier_calls == 1,
        "positive control missed verifier port"
    );
    ensure!(
        positive.effects.reducer_writes == 1,
        "positive control missed reducer port"
    );
    ensure!(
        positive.effects.projection_writes == 1,
        "positive control missed projection port"
    );
    ensure!(
        positive.effects.cache_writes == 1,
        "positive control missed cache port"
    );
    ensure!(
        positive.effects.outbound_effects == 1,
        "positive control missed outbound port"
    );

    let mut results = Vec::new();
    for case in fixture["cases"]
        .as_array()
        .context("SDK precheck fixture has no cases[]")?
    {
        let case_id = case["name"].as_str().context("precheck case has no name")?;
        ensure!(
            case["decision"].as_str() == Some("reject"),
            "{case_id} decision drifted"
        );
        ensure!(
            case["reason"].as_str() == Some("schema_violation"),
            "{case_id} reason drifted"
        );
        let event = mutation_for(case_id, &base_event)?;
        let paths = paths_for(case_id);
        let mut first_issue = None;
        let mut combined_effects = EffectCounts::default();
        let mut assertions = 2;
        for path in paths {
            let observation = consumer.submit(&event, *path)?;
            ensure!(!observation.accepted, "{case_id} was accepted on {path:?}");
            ensure!(
                observation.reason == Some("schema_violation"),
                "{case_id} reason drifted on {path:?}"
            );
            ensure!(
                observation.effects.is_zero(),
                "{case_id} reached an effect port on {path:?}: {:?}",
                observation.effects
            );
            let issue = observation
                .issue
                .context("schema rejection has no machine issue")?;
            if let Some(expected) = &first_issue {
                ensure!(
                    expected == &issue,
                    "{case_id} schema issue changed across admission paths"
                );
            } else {
                assertions += assert_expected_issue(case_id, &issue)?;
                first_issue = Some(issue);
            }
            combined_effects.verifier_calls += observation.effects.verifier_calls;
            combined_effects.reducer_writes += observation.effects.reducer_writes;
            combined_effects.projection_writes += observation.effects.projection_writes;
            combined_effects.cache_writes += observation.effects.cache_writes;
            combined_effects.outbound_effects += observation.effects.outbound_effects;
            assertions += 3;
        }
        ensure!(
            combined_effects.verifier_calls == 0,
            "{case_id} reached verifier port"
        );
        ensure!(
            combined_effects.reducer_writes == 0,
            "{case_id} reached reducer port"
        );
        ensure!(
            combined_effects.projection_writes == 0,
            "{case_id} reached projection port"
        );
        ensure!(
            combined_effects.cache_writes == 0,
            "{case_id} reached cache port"
        );
        ensure!(
            combined_effects.outbound_effects == 0,
            "{case_id} reached outbound port"
        );
        assertions += 5;
        let issue = first_issue.context("precheck case executed no admission path")?;
        results.push(CaseExecutionResult {
            case_id: case_id.to_owned(),
            assertions,
            decision: "reject",
            reason: "schema_violation",
            attempts: paths.len(),
            instance_pointer: issue.instance_pointer,
            keyword: issue.keyword,
            effects: combined_effects,
        });
    }

    let execution = SdkPrecheckExecution {
        entrypoint: SDK_PRECHECK_ENTRYPOINT,
        fixture: FIXTURE,
        positive_control_assertions: 8,
        cases: results,
    };
    execution.assert_complete_against(&fixture)?;
    Ok(execution)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modeled_effect_ports_cannot_claim_production_consumption() {
        let error = run_sdk_precheck_suite().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("production Event consumer is unproved")
        );
    }

    #[test]
    fn complete_event_precheck_executes_all_current_cases() -> Result<()> {
        let execution = run_sdk_precheck_suite_diagnostic()?;
        assert_eq!(execution.entrypoint, SDK_PRECHECK_ENTRYPOINT);
        assert_eq!(execution.cases.len(), 10);
        assert!(execution.positive_control_assertions > 0);
        assert!(execution.cases.iter().all(|case| case.assertions > 0));
        assert!(execution.cases.iter().all(|case| case.effects.is_zero()));
        Ok(())
    }

    #[test]
    fn kind_selected_payload_fails_inside_the_complete_event_schema() -> Result<()> {
        let execution = run_sdk_precheck_suite_diagnostic()?;
        let payload = execution
            .cases
            .iter()
            .find(|case| case.case_id == CASE_PAYLOAD_CLASS)
            .context("payload-class case did not execute")?;
        assert_eq!(payload.instance_pointer, "/payload");
        assert_eq!(payload.keyword, "required");
        assert_eq!(payload.attempts, 1);
        assert!(payload.effects.is_zero());
        Ok(())
    }

    #[test]
    fn rejected_event_stays_rejected_on_retry_reconnect_and_backfill() -> Result<()> {
        let execution = run_sdk_precheck_suite_diagnostic()?;
        let replay = execution
            .cases
            .iter()
            .find(|case| case.case_id == CASE_NO_REPAIR)
            .context("no-repair case did not execute")?;
        assert_eq!(replay.attempts, 4);
        assert!(replay.effects.is_zero());
        Ok(())
    }
}
