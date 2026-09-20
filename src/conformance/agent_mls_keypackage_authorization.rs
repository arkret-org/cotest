//! Root-harness adapter for the standalone Agent MLS KeyPackage authorization runner.

use anyhow::Result;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub use cotest_agent_mls_keypackage_authorization_runner::AGENT_MLS_KEYPACKAGE_AUTHORIZATION_ENTRYPOINT;

pub fn run_agent_mls_keypackage_authorization_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_agent_mls_keypackage_authorization_runner::run_agent_mls_keypackage_authorization_suite()?;
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
