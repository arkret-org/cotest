//! Root-harness adapter for the standalone franking-proof runner.

use anyhow::Result;
pub use cotest_franking_proof_runner::FRANKING_PROOF_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub fn run_franking_proof_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_franking_proof_runner::run_franking_proof_suite()?;
    Ok(SuiteExecutionResult {
        entrypoint: execution.entrypoint,
        fixture: execution.fixture,
        cases: execution
            .mutations
            .into_iter()
            .map(|case| CaseExecutionResult {
                case_id: case.field,
                assertions: case.assertions,
            })
            .collect(),
    })
}
