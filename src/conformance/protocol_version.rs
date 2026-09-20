//! Root-harness adapter for the standalone protocol-version runner.

use anyhow::Result;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub use cotest_protocol_version_runner::PROTOCOL_VERSION_ENTRYPOINT;

pub fn run_protocol_version_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_protocol_version_runner::run_protocol_version_suite()?;
    Ok(SuiteExecutionResult {
        entrypoint: execution.entrypoint,
        fixture: execution.fixture,
        cases: execution
            .cases
            .into_iter()
            .map(|case| CaseExecutionResult {
                case_id: case.case_id,
                assertions: case.assertions,
            })
            .collect(),
    })
}
