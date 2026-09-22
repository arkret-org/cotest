//! Root-harness adapter for the standalone string-profile runner.

use anyhow::Result;
pub use cotest_string_profile_runner::STRING_PROFILE_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub fn run_string_profile_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_string_profile_runner::run_string_profile_suite()?;
    Ok(SuiteExecutionResult {
        entrypoint: execution.entrypoint,
        fixture: execution.fixture,
        cases: execution
            .vectors
            .into_iter()
            .map(|vector| CaseExecutionResult {
                case_id: vector.vector_id,
                assertions: vector.assertions,
            })
            .collect(),
    })
}
