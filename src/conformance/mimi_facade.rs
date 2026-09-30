//! Both suites share one real HTTP/PostgreSQL execution, never a fixture-only pass.
use std::sync::OnceLock;

use anyhow::{Result, anyhow};

use super::SuiteExecutionResult;
const ADMISSION: &str = "ak.suite.mimi.admission_guards.v1";
const MIGRATION: &str = "ak.suite.mimi.room_binding_migration.v1";
static EXECUTION: OnceLock<
    std::result::Result<(SuiteExecutionResult, SuiteExecutionResult), String>,
> = OnceLock::new();
fn execution() -> Result<(SuiteExecutionResult, SuiteExecutionResult)> {
    EXECUTION.get_or_init(|| {
        let run = || -> Result<_> {
            let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
            let (admission,migration)=runtime.block_on(crate::scenarios::mimi_facade_live::run_evidence())?
                .ok_or_else(||anyhow!("MIMI named suites require real database and Soland; skipped live execution is not evidence"))?;
            Ok((SuiteExecutionResult{entrypoint:ADMISSION,fixture:"mimi-admission-guards-fixture.json",cases:admission},
                SuiteExecutionResult{entrypoint:MIGRATION,fixture:"mimi-room-binding-migration-fixture.json",cases:migration}))
        };
        run().map_err(|error|format!("{error:#}"))
    }).clone().map_err(|error|anyhow!(error))
}
pub fn run_mimi_admission_guards_suite() -> Result<SuiteExecutionResult> {
    execution().map(|result| result.0)
}
pub fn run_mimi_room_binding_migration_suite() -> Result<SuiteExecutionResult> {
    execution().map(|result| result.1)
}
