//! Root-harness adapter for the standalone MLS governance-binding runner.

use anyhow::Result;
pub use cotest_mls_governance_binding_runner::MLS_GOVERNANCE_BINDING_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub fn run_mls_governance_binding_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_mls_governance_binding_runner::run_mls_governance_binding_suite()?;
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
