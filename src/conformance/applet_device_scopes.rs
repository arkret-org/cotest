//! Execute canonical scope vectors through the production SDK matcher.
use anyhow::{Context as _, Result, ensure};
use arkret_models_collaboration::events_payloads::AppletManagedDeviceScopes;
use arkret_wire::{CapabilityActionId, ScopeRef};

use super::{
    CaseExecutionResult, SuiteExecutionResult, fixture_runner_entrypoint, load_fixture_value,
    required_str,
};

const FIXTURE: &str = "applet-device-scope-fixture.json";
pub const APPLET_DEVICE_SCOPES_ENTRYPOINT: &str = "ak.suite.applet.device_scopes.v1";

pub fn run_applet_device_scopes_suite() -> Result<SuiteExecutionResult> {
    let fixture = load_fixture_value(FIXTURE)?;
    ensure!(fixture_runner_entrypoint(&fixture)? == APPLET_DEVICE_SCOPES_ENTRYPOINT);
    let cases = fixture["cases"].as_array().context("scope fixture cases")?;
    ensure!(
        !cases.is_empty(),
        "scope fixture must execute non-empty cases"
    );
    let mut results = Vec::new();
    for case in cases {
        let name = required_str(case, "name")?;
        let parsed = serde_json::from_value::<AppletManagedDeviceScopes>(case["scopes"].clone());
        let valid = parsed.is_ok();
        ensure!(
            valid == case["valid"].as_bool().context("valid")?,
            "{name}: canonical scope acceptance differs"
        );
        let permits = if let Ok(scopes) = parsed {
            let scope: ScopeRef = serde_json::from_value(case["scope"].clone())?;
            let actions: Vec<CapabilityActionId> = serde_json::from_value(case["actions"].clone())?;
            ensure!(
                serde_json::to_value(&scopes)? == case["scopes"],
                "{name}: signed list was normalized"
            );
            ensure!(!scopes.permits(&scope, &[]), "{name}: empty action bypass");
            scopes.permits(&scope, &actions)
        } else {
            false
        };
        ensure!(
            permits == case["permits"].as_bool().context("permits")?,
            "{name}: paired authorization differs"
        );
        crate::transcripts::record_vector_event(
            "applet.device_scopes.case",
            case,
            &serde_json::json!({"valid":case["valid"],"permits":case["permits"]}),
            &serde_json::json!({"valid":valid,"permits":permits}),
        );
        results.push(CaseExecutionResult {
            case_id: name.to_owned(),
            assertions: 2,
        });
    }
    let execution = SuiteExecutionResult {
        entrypoint: APPLET_DEVICE_SCOPES_ENTRYPOINT,
        fixture: FIXTURE,
        cases: results,
    };
    execution.assert_complete_against(&fixture)?;
    Ok(execution)
}
