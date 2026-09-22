//! Root-harness adapter for the standalone protocol-version runner.

use anyhow::Result;
pub use cotest_protocol_version_runner::PROTOCOL_VERSION_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};

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
