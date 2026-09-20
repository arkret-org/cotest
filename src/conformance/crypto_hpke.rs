//! Root-harness adapter for the standalone HPKE runner.

use anyhow::Result;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub use cotest_crypto_hpke_runner::CRYPTO_HPKE_ENTRYPOINT;

pub fn run_crypto_hpke_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_crypto_hpke_runner::run_crypto_hpke_suite()?;
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
