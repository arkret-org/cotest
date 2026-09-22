//! Root-suite adapter for the independently buildable cursor negative runner.

use anyhow::Result;
pub use cotest_cursor_negative_runner::CURSOR_NEGATIVE_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub fn run_cursor_negative_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_cursor_negative_runner::run_cursor_negative_suite()?;
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
