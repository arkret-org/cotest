//! Root-harness adapter for independent backup-source byte conformance.

use anyhow::Result;
pub use cotest_content_backup_source_runner::CONTENT_BACKUP_SOURCE_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub fn run_content_backup_source_suite() -> Result<SuiteExecutionResult> {
    let result = cotest_content_backup_source_runner::run_content_backup_source_suite()?;
    Ok(SuiteExecutionResult {
        entrypoint: result.entrypoint,
        fixture: result.fixture,
        cases: result
            .cases
            .into_iter()
            .map(|case| CaseExecutionResult {
                case_id: case.case_id,
                assertions: case.assertions,
            })
            .collect(),
    })
}
