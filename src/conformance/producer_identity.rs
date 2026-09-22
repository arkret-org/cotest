//! Root-harness adapter for producer-allocated identity collision conformance.

use anyhow::Result;
pub use cotest_producer_identity_runner::PRODUCER_IDENTITY_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub fn run_producer_identity_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_producer_identity_runner::run_producer_identity_suite()?;
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
