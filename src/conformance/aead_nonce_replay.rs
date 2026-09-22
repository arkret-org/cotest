//! Root-harness adapter for the standalone AEAD nonce replay runner.

use anyhow::Result;
pub use cotest_aead_nonce_replay_runner::AEAD_NONCE_REPLAY_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub fn run_aead_nonce_replay_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_aead_nonce_replay_runner::run_aead_nonce_replay_suite()?;
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
