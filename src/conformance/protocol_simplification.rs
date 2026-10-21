//! Executable shape coverage for decision 0179.
//!
//! This runner credits only schema cases. The semantic obligations are checked
//! by the separate live scenarios and must never inherit schema-only credit.

use anyhow::{Result, ensure};

use super::schema_validation_fixture::{SchemaValidationFixture, run_cases};
use super::{CaseExecutionResult, SuiteExecutionResult, load_local_fixture_value};

pub const PROTOCOL_SIMPLIFICATION_ENTRYPOINT: &str = "ak.suite.protocol_simplification.v1";

pub fn run_protocol_simplification_shape_suite() -> Result<SuiteExecutionResult> {
    const FIXTURE: &str = "protocol-simplification-fixture.json";
    let value = load_local_fixture_value(FIXTURE)?;
    ensure!(value["runner"]["entrypoint"] == PROTOCOL_SIMPLIFICATION_ENTRYPOINT);
    let fixture: SchemaValidationFixture = serde_json::from_value(value)?;
    ensure!(fixture.suite == "protocol_simplification");
    run_cases(&fixture.schema_validation_cases)?;
    let mut cases = Vec::with_capacity(fixture.schema_validation_cases.len());
    for case in fixture.schema_validation_cases {
        cases.push(CaseExecutionResult {
            case_id: case.name,
            assertions: 1,
        });
    }
    Ok(SuiteExecutionResult {
        entrypoint: PROTOCOL_SIMPLIFICATION_ENTRYPOINT,
        fixture: FIXTURE,
        cases,
    })
}
