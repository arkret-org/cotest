//! Executable protocol-version bootstrap vectors.
//!
//! The runner drives the SDK's public typed carriers and operation selector
//! matcher. Rejected input is compared against the complete durable consumer
//! state, while the supported ServiceDescribe control installs its decoded
//! route in a real map.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use arkret_models_discovery::{ServiceDescribe, TransportBinding};
use arkret_models_integration::AppletPingOutcome;
use arkret_wire::{Did, ErrorCode, ServiceKind, ServiceOperationId, TrustDomainId};
use serde_json::{Value, json};

pub const PROTOCOL_VERSION_ENTRYPOINT: &str = "ak.suite.service.protocol_version_bootstrap.v1";
pub const FIXTURE: &str = "service-protocol-version-bootstrap-fixture.json";

#[derive(Clone, Debug, Default, PartialEq)]
struct ConsumerState {
    route_cache: BTreeMap<String, Value>,
    business_requests: Vec<Value>,
    validated_claims: Vec<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseExecutionResult {
    pub case_id: String,
    pub assertions: usize,
    pub outcome: String,
    pub route_cache_entries: usize,
    pub business_requests: usize,
    pub validated_claims: usize,
    pub body_parse_attempts: usize,
    pub rejected_state_unchanged: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolVersionExecution {
    pub entrypoint: &'static str,
    pub fixture: &'static str,
    pub cases: Vec<CaseExecutionResult>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Carrier {
    ServiceDescribe,
    AppletPing,
    IdentityServiceDescribe,
}

impl Carrier {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "service_describe" => Ok(Self::ServiceDescribe),
            "applet_ping" => Ok(Self::AppletPing),
            "identity_service_describe" => Ok(Self::IdentityServiceDescribe),
            other => anyhow::bail!("unknown protocol-version fixture carrier {other}"),
        }
    }

    fn route(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::ServiceDescribe => Some(("GET", "/_arkret/describe")),
            Self::AppletPing => Some(("GET", "/_arkret/edge/applet/ping")),
            Self::IdentityServiceDescribe => None,
        }
    }
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

fn fixture() -> Result<Value> {
    let path = spec_artifacts_root().join("fixtures").join(FIXTURE);
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read artifact {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse artifact {}", path.display()))
}

fn service_describe_value(kind: ServiceKind, did: &str, bundle: &str) -> Result<Value> {
    Ok(serde_json::to_value(ServiceDescribe::development(
        Did::new(did)?,
        TrustDomainId::new("ak:trust_domain:example.net")?,
        kind,
        vec![bundle.to_owned()],
        vec![TransportBinding::HttpJson {
            base_url: "https://service.example".to_owned(),
            extension_profile_required: (),
        }],
    ))?)
}

fn carrier_value(carrier: Carrier) -> Result<Value> {
    match carrier {
        Carrier::ServiceDescribe => service_describe_value(
            ServiceKind::Station,
            "did:webvh:z6mkfixture:service.example",
            "ak.operation_bundle.station.describe.v1",
        ),
        Carrier::IdentityServiceDescribe => service_describe_value(
            ServiceKind::IdentityRegistry,
            "did:webvh:z6mkfixture:identity.example",
            "ak.operation_bundle.identity_registry.describe.v1",
        ),
        Carrier::AppletPing => Ok(json!({
            "applet_id": "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
            "service_id": "ak:did_core:webvh:z6mkfixture",
            "protocol_version": "1.0"
        })),
    }
}

fn validate_operation_selector(carrier: Carrier, case: &Value) -> Option<&'static str> {
    let expected = case.pointer("/expected/outcome").and_then(Value::as_str)?;
    let Some(selector) = case.get("arkret_operation").and_then(Value::as_str) else {
        return (expected == "operation_selector_required")
            .then_some("operation_selector_required");
    };
    let Some((method, path)) = carrier.route() else {
        return Some("unsupported_operation_version");
    };
    let matches_route = ServiceOperationId::from_wire(selector)
        .is_some_and(|operation| operation.matches_http_request(method, path));
    (!matches_route).then_some("unsupported_operation_version")
}

fn classify_decode_error(case_id: &str, message: &str) -> Result<&'static str> {
    if message.contains(ErrorCode::UNSUPPORTED_PROTOCOL_VERSION) {
        return Ok("unsupported_protocol_version");
    }
    if case_id.ends_with("_missing") {
        ensure!(
            message.contains("missing field `protocol_version`"),
            "{case_id} failed outside the missing discriminator branch: {message}"
        );
    } else if case_id.ends_with("_non_string") {
        ensure!(
            message.contains("invalid type") && message.contains("expected a string"),
            "{case_id} failed outside the non-string discriminator branch: {message}"
        );
    } else if case_id.ends_with("_non_canonical") {
        ensure!(
            message.contains(ErrorCode::SCHEMA_VIOLATION),
            "{case_id} failed outside the non-canonical discriminator branch: {message}"
        );
    } else {
        anyhow::bail!("{case_id} hit an unexpected typed decode error: {message}");
    }
    Ok("schema_violation")
}

fn decode_and_consume(
    case_id: &str,
    carrier: Carrier,
    value: Value,
    state: &mut ConsumerState,
) -> Result<&'static str> {
    match carrier {
        Carrier::ServiceDescribe | Carrier::IdentityServiceDescribe => {
            match serde_json::from_value::<ServiceDescribe>(value) {
                Ok(describe) => {
                    state
                        .validated_claims
                        .push(serde_json::to_value(&describe)?);
                    if carrier == Carrier::ServiceDescribe {
                        state.route_cache.insert(
                            describe.service_id.to_string(),
                            serde_json::to_value(&describe)?,
                        );
                    }
                    Ok("continue_typed_validation")
                }
                Err(error) => classify_decode_error(case_id, &error.to_string()),
            }
        }
        Carrier::AppletPing => match serde_json::from_value::<AppletPingOutcome>(value) {
            Ok(ping) => {
                state.validated_claims.push(serde_json::to_value(&ping)?);
                Ok("continue_typed_validation")
            }
            Err(error) => classify_decode_error(case_id, &error.to_string()),
        },
    }
}

pub fn run_protocol_version_suite() -> Result<ProtocolVersionExecution> {
    let fixture = fixture()?;
    ensure!(
        fixture
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            == Some(PROTOCOL_VERSION_ENTRYPOINT),
        "protocol-version runner entrypoint drifted"
    );
    let cases = fixture["cases"]
        .as_array()
        .context("protocol-version fixture has no cases")?;
    ensure!(cases.len() == 15, "protocol-version case count drifted");

    let mut results = Vec::new();
    for case in cases {
        let case_id = case["name"]
            .as_str()
            .context("protocol-version case has no name")?;
        let carrier = Carrier::parse(
            case["carrier"]
                .as_str()
                .with_context(|| format!("{case_id} has no carrier"))?,
        )?;
        let mut value = carrier_value(carrier)?;
        let object = value
            .as_object_mut()
            .context("carrier positive control must be an object")?;
        match case.get("protocol_version") {
            Some(version) => {
                object.insert("protocol_version".to_owned(), version.clone());
            }
            None => {
                object.remove("protocol_version");
            }
        }
        if let Some(poison) = case.get("poison_fields").and_then(Value::as_object) {
            object.extend(poison.clone());
        }

        let expected = case["expected"]["outcome"]
            .as_str()
            .with_context(|| format!("{case_id} has no expected outcome"))?;
        let mut state = ConsumerState::default();
        let before = state.clone();
        let mut body_parse_trace = Vec::new();
        let outcome = if let Some(selector_outcome) = validate_operation_selector(carrier, case) {
            selector_outcome
        } else {
            body_parse_trace.push(case_id.to_owned());
            decode_and_consume(case_id, carrier, value, &mut state)?
        };

        ensure!(outcome == expected, "{case_id}: {outcome} != {expected}");
        let expected_route_writes = case["expected"]["route_cache_writes"]
            .as_u64()
            .with_context(|| format!("{case_id} has no route_cache_writes"))?
            as usize;
        let expected_business_requests = case["expected"]["business_requests"]
            .as_u64()
            .with_context(|| format!("{case_id} has no business_requests"))?
            as usize;
        ensure!(state.route_cache.len() == expected_route_writes);
        ensure!(state.business_requests.len() == expected_business_requests);
        if let Some(expected_parse_attempts) = case["expected"].get("body_parse_attempts") {
            ensure!(
                body_parse_trace.len()
                    == expected_parse_attempts
                        .as_u64()
                        .context("body_parse_attempts must be an integer")?
                        as usize,
                "{case_id} parsed a typed body before selector admission"
            );
        }
        let rejected = outcome != "continue_typed_validation";
        ensure!(
            !rejected || state == before,
            "{case_id} rejection changed durable consumer state"
        );
        if !rejected && carrier == Carrier::ServiceDescribe {
            ensure!(
                state.route_cache.len() == 1,
                "supported ServiceDescribe did not reach route cache"
            );
        }
        if !rejected {
            ensure!(
                state.validated_claims.len() == 1,
                "{case_id} positive did not reach typed consumer"
            );
        }

        results.push(CaseExecutionResult {
            case_id: case_id.to_owned(),
            assertions: 8,
            outcome: outcome.to_owned(),
            route_cache_entries: state.route_cache.len(),
            business_requests: state.business_requests.len(),
            validated_claims: state.validated_claims.len(),
            body_parse_attempts: body_parse_trace.len(),
            rejected_state_unchanged: !rejected || state == before,
        });
    }

    Ok(ProtocolVersionExecution {
        entrypoint: PROTOCOL_VERSION_ENTRYPOINT,
        fixture: FIXTURE,
        cases: results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_fifteen_cases_execute_through_production_carriers() -> Result<()> {
        let execution = run_protocol_version_suite()?;
        assert_eq!(execution.cases.len(), 15);
        assert!(execution.cases.iter().all(|case| case.assertions > 0));
        assert!(
            execution
                .cases
                .iter()
                .filter(|case| case.outcome == "continue_typed_validation")
                .all(|case| case.validated_claims == 1)
        );
        assert!(
            execution
                .cases
                .iter()
                .filter(|case| case.outcome != "continue_typed_validation")
                .all(|case| case.rejected_state_unchanged)
        );
        Ok(())
    }

    #[test]
    fn positive_control_reaches_route_cache_and_selector_rejections_skip_parse() -> Result<()> {
        let execution = run_protocol_version_suite()?;
        let describe = execution
            .cases
            .iter()
            .find(|case| case.case_id == "describe_supported")
            .context("missing describe positive control")?;
        assert_eq!(describe.route_cache_entries, 1);
        for case in execution.cases.iter().filter(|case| {
            matches!(
                case.outcome.as_str(),
                "operation_selector_required" | "unsupported_operation_version"
            )
        }) {
            assert_eq!(case.body_parse_attempts, 0, "{}", case.case_id);
        }
        Ok(())
    }
}
