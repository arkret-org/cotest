//! Root-harness adapter for the standalone structural-Relation runner.

use anyhow::Result;
pub use cotest_relation_structural_realm_runner::RELATION_STRUCTURAL_REALM_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub fn run_relation_structural_realm_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_relation_structural_realm_runner::run_relation_structural_realm_suite()?;
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
