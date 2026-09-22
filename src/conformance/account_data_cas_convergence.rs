//! Root-harness adapter for the standalone Account Data CAS runner.

use anyhow::Result;
pub use cotest_account_data_cas_convergence_runner::ACCOUNT_DATA_CAS_CONVERGENCE_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub fn run_account_data_cas_convergence_suite() -> Result<SuiteExecutionResult> {
    let execution =
        cotest_account_data_cas_convergence_runner::run_account_data_cas_convergence_suite()?;
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
