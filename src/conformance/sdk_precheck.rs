//! Root-suite adapter for the independently buildable SDK precheck runner.

use anyhow::Result;
pub use cotest_sdk_precheck_runner::SDK_PRECHECK_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub fn run_sdk_precheck_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_sdk_precheck_runner::run_sdk_precheck_suite()?;
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
