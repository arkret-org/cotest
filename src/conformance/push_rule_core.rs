//! Root-harness adapter for the standalone push-rule core runner.

use anyhow::Result;
pub use cotest_push_rule_core_runner::PUSH_RULE_CORE_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub fn run_push_rule_core_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_push_rule_core_runner::run_push_rule_core_suite()?;
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

pub fn run_push_rule_core_fixture_suite() -> Result<()> {
    run_push_rule_core_suite().map(|_| ())
}

/// The client-only carrier check is part of every full runner execution.
pub fn run_push_rule_client_only_vector() -> Result<()> {
    run_push_rule_core_suite().map(|_| ())
}
