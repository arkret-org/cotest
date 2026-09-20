//! Root-harness adapter for the standalone blob stream-AEAD runner.

use anyhow::Result;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub use cotest_blob_stream_aead_runner::{
    ALL_BLOB_STREAM_AEAD_VECTOR_IDS, BLOB_STREAM_AEAD_ENTRYPOINT,
};

pub fn run_blob_stream_aead_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_blob_stream_aead_runner::run_blob_stream_aead_suite()?;
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

/// Compatibility entrypoint for the existing root integration test. This is
/// still full execution: the standalone runner returns per-case evidence and
/// rejects an assertion-free or incomplete fixture.
pub fn run_blob_stream_aead_fixture_suite() -> Result<()> {
    run_blob_stream_aead_suite().map(|_| ())
}
