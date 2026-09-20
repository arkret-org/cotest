//! Root-harness adapter for the standalone call-state core runner.

use anyhow::Result;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub use cotest_call_state_core_runner::CALL_STATE_CORE_ENTRYPOINT;

pub fn run_call_state_core_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_call_state_core_runner::run_call_state_core_suite()?;
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
