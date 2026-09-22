//! Root-harness adapter for the standalone Realm join candidate runner.

use anyhow::Result;
pub use cotest_realm_join_candidate_runner::REALM_JOIN_CANDIDATE_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub fn run_realm_join_candidate_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_realm_join_candidate_runner::run_realm_join_candidate_suite()?;
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
