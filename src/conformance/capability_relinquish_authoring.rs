//! Root-harness adapter for the standalone capability relinquish authoring runner.

use anyhow::Result;
pub use cotest_capability_relinquish_authoring_runner::CAPABILITY_RELINQUISH_AUTHORING_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub fn run_capability_relinquish_authoring_suite() -> Result<SuiteExecutionResult> {
    let execution =
        cotest_capability_relinquish_authoring_runner::run_capability_relinquish_authoring_suite()?;
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
