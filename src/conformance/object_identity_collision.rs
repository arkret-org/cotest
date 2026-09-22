//! Root-harness adapter for producer-allocated object identity collision conformance.

use anyhow::Result;
pub use cotest_producer_identity_runner::OBJECT_IDENTITY_COLLISION_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub fn run_object_identity_collision_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_producer_identity_runner::run_object_identity_collision_suite()?;
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
