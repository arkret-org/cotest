//! Contract-only adapter; live Applet lifecycle remains a reserved vector.
use anyhow::Result;
pub use cotest_applet_self_actor_runner::APPLET_SELF_ACTOR_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};
pub fn run_applet_self_actor_suite() -> Result<SuiteExecutionResult> {
    let execution = cotest_applet_self_actor_runner::run_applet_self_actor_suite()?;
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
