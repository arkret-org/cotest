//! Root-harness adapter for the standalone private View / Inbox runner.

use anyhow::Result;
pub use cotest_private_view_inbox_runner::PRIVATE_VIEW_INBOX_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub fn run_private_view_inbox_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_private_view_inbox_runner::run_private_view_inbox_suite()?;
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
