//! Root-harness adapter for the standalone Strand watch-current runner.

use anyhow::Result;
pub use cotest_strand_watch_current_runner::STRAND_WATCH_CURRENT_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub fn run_strand_watch_current_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_strand_watch_current_runner::run_strand_watch_current_suite()?;
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
