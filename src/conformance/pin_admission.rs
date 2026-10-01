//! The canonical Pin suite executes the real PostgreSQL admission boundary.

use anyhow::{Result, anyhow};

use super::{CaseExecutionResult, SuiteExecutionResult};

pub fn run_pin_admission_suite() -> Result<SuiteExecutionResult> {
    // The audit is synchronous and can run inside an existing Tokio runtime.
    // Own a separate runtime so executing admission never nests block_on.
    let cases = std::thread::Builder::new()
        .name("pin-admission-fixture".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap()
                .block_on(soland_storage_postgres::pin_conformance::run_pin_admission_fixture())
        })?
        .join()
        .map_err(|_| anyhow!("Pin admission fixture failed an assertion"))?;
    Ok(SuiteExecutionResult {
        entrypoint: "ak.suite.pin.admission_and_scope.v1",
        fixture: "shared-pin-admission-fixture.json",
        cases: cases
            .into_iter()
            .map(|(case_id, assertions)| CaseExecutionResult {
                case_id: case_id.into(),
                assertions,
            })
            .collect(),
    })
}
