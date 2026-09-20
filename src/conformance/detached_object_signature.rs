//! Root-harness adapter for the standalone detached-object signature runner.

use anyhow::Result;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub use cotest_detached_object_signature_runner::DETACHED_OBJECT_SIGNATURE_ENTRYPOINT;

pub fn run_detached_object_signature_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_detached_object_signature_runner::run_detached_object_signature_suite()?;
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
