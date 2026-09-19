//! Executable boundary cases for the protocol time-tolerance registry.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, ensure};
use serde_json::Value;

use super::{
    CaseExecutionResult, SuiteExecutionResult, fixture_runner_entrypoint, load_artifact_json,
    load_fixture_value, required_bool, required_field, required_str, value_array,
};

const FIXTURE: &str = "protocol-time-tolerance-fixture.json";
pub const PROTOCOL_TIME_TOLERANCE_ENTRYPOINT: &str = "ak.suite.protocol.time_tolerance.v1";

pub fn run_protocol_time_tolerance_suite() -> Result<SuiteExecutionResult> {
    let fixture = load_fixture_value(FIXTURE)?;
    ensure!(
        fixture_runner_entrypoint(&fixture)? == PROTOCOL_TIME_TOLERANCE_ENTRYPOINT,
        "protocol time-tolerance runner entrypoint drifted"
    );

    let contracts = load_artifact_json("registry/contract-registry.json")?;
    let registry = required_field(&contracts, "protocol_time_tolerance_registry")?;
    let tolerances = value_array(required_field(registry, "tolerances")?, "tolerances")?
        .iter()
        .map(|row| {
            let id = required_str(row, "tolerance_id")?.to_owned();
            let value = required_field(row, "value")?
                .as_i64()
                .ok_or_else(|| anyhow!("{id} value must be an integer"))?;
            ensure!(
                required_str(row, "unit")? == "milliseconds",
                "{id} is not measured in milliseconds"
            );
            Ok((id, value))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let scenarios = value_array(required_field(registry, "scenarios")?, "scenarios")?
        .iter()
        .map(|row| Ok((required_str(row, "scenario_id")?.to_owned(), row)))
        .collect::<Result<BTreeMap<_, _>>>()?;

    let mut results = Vec::new();
    for case in value_array(required_field(&fixture, "cases")?, "cases")? {
        let case_id = required_str(case, "case_id")?;
        let scenario_id = required_str(case, "scenario_id")?;
        let boundary = required_str(case, "boundary")?;
        let offset_ms = required_field(case, "offset_ms")?
            .as_i64()
            .ok_or_else(|| anyhow!("{case_id}: offset_ms must be an integer"))?;
        let expected = required_bool(required_field(case, "expected")?, "accepted")?;

        let scenario = scenarios
            .get(scenario_id)
            .ok_or_else(|| anyhow!("{case_id}: unknown scenario {scenario_id}"))?;
        let tolerance_id = required_str(scenario, "tolerance_id")?;
        let tolerance = *tolerances
            .get(tolerance_id)
            .ok_or_else(|| anyhow!("{case_id}: unknown tolerance {tolerance_id}"))?;
        let direction = required_str(scenario, "direction")?;

        let observed = accepts(direction, boundary, offset_ms, tolerance).ok_or_else(|| {
            anyhow!("{case_id}: boundary {boundary} is not valid for direction {direction}")
        })?;
        ensure!(
            observed == expected,
            "{case_id}: registry comparison produced accepted={observed}, expected {expected}"
        );

        let boundary_row = value_array(
            required_field(scenario, "boundary_cases")?,
            "scenario.boundary_cases",
        )?
        .iter()
        .find(|row| row.get("case_id").and_then(Value::as_str) == Some(case_id))
        .ok_or_else(|| anyhow!("{case_id}: missing from registry boundary_cases"))?;
        ensure!(
            required_str(boundary_row, "boundary")? == boundary,
            "{case_id}: boundary disagrees with registry"
        );
        ensure!(
            required_bool(boundary_row, "accepted")? == expected,
            "{case_id}: expected result disagrees with registry"
        );
        let beyond = required_field(boundary_row, "beyond_limit_ms")?
            .as_i64()
            .ok_or_else(|| anyhow!("{case_id}: beyond_limit_ms must be an integer"))?;
        ensure!(
            offset_ms.unsigned_abs() == (tolerance + beyond).unsigned_abs(),
            "{case_id}: offset is not tolerance plus its declared boundary delta"
        );
        if direction == "future_only" {
            ensure!(
                accepts(direction, boundary, -86_400_000, tolerance) == Some(true),
                "{case_id}: future_only was silently widened into a symmetric past bound"
            );
        }

        results.push(CaseExecutionResult {
            case_id: case_id.to_owned(),
            assertions: 4,
        });
    }

    let execution = SuiteExecutionResult {
        entrypoint: PROTOCOL_TIME_TOLERANCE_ENTRYPOINT,
        fixture: FIXTURE,
        cases: results,
    };
    execution.assert_complete_against(&fixture)?;
    Ok(execution)
}

fn accepts(direction: &str, boundary: &str, offset_ms: i64, tolerance: i64) -> Option<bool> {
    match (direction, boundary) {
        ("future_only", "future") => Some(offset_ms <= tolerance),
        ("symmetric_not_before_and_expiry", "future_not_before") => Some(offset_ms <= tolerance),
        ("symmetric_not_before_and_expiry", "past_expiry") => Some(offset_ms >= -tolerance),
        _ => None,
    }
}
