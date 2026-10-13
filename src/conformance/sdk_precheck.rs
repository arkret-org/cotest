//! Root-suite adapter for the independently buildable SDK precheck runner.

use anyhow::Result;
pub use cotest_sdk_precheck_runner::SDK_PRECHECK_ENTRYPOINT;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub(super) const REVIEWED_CASES: &[&str] = &[
    "an_envelope_that_fails_the_event_schema_never_reaches_the_reducer",
    "a_payload_that_fails_its_payload_class_never_reaches_the_reducer",
    "a_rejected_envelope_is_not_repaired_or_partially_applied",
    "hlc_at_the_event_top_level_is_refused",
    "producer_revision_at_the_event_top_level_is_refused",
    "domain_refs_at_the_event_top_level_is_refused",
    "requirements_at_the_event_top_level_is_refused",
    "producer_proof_cannot_be_omitted_or_defaulted",
    "scope_ref_cannot_be_omitted_or_defaulted",
    "actor_id_cannot_be_omitted_or_defaulted",
];

pub fn run_sdk_precheck_suite() -> Result<SuiteExecutionResult> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?
        .block_on(crate::scenarios::sdk_precheck_live::run_sdk_precheck_production())
}

pub fn run_sdk_precheck_suite_diagnostic() -> Result<SuiteExecutionResult> {
    Ok(adapt(
        cotest_sdk_precheck_runner::run_sdk_precheck_suite_diagnostic()?,
    ))
}

fn adapt(execution: cotest_sdk_precheck_runner::SdkPrecheckExecution) -> SuiteExecutionResult {
    SuiteExecutionResult {
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
    }
}
