//! Root-harness adapter for the standalone View write-contract runner.

use anyhow::Result;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub use cotest_view_write_contract_runner::VIEW_WRITE_CONTRACT_ENTRYPOINT;

pub fn run_view_write_contract_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_view_write_contract_runner::run_view_write_contract_suite()?;
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
