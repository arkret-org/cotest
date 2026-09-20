//! Root-suite adapter for the independently buildable test-material runner.

use anyhow::Result;

use super::{CaseExecutionResult, SuiteExecutionResult};

pub use cotest_test_material_runner::TEST_MATERIAL_REJECTION_ENTRYPOINT;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TestMaterialRejectionCoverage {
    pub execution: SuiteExecutionResult,
    pub service_e2e_status: &'static str,
    pub service_e2e_gaps: Vec<&'static str>,
}

pub fn run_test_material_rejection_suite_with_coverage() -> Result<TestMaterialRejectionCoverage> {
    let coverage = cotest_test_material_runner::run_test_material_rejection_suite_with_coverage()?;
    Ok(TestMaterialRejectionCoverage {
        execution: SuiteExecutionResult {
            entrypoint: coverage.execution.entrypoint,
            fixture: coverage.execution.fixture,
            cases: coverage
                .execution
                .cases
                .into_iter()
                .map(|case| CaseExecutionResult {
                    case_id: case.case_id,
                    assertions: case.assertions,
                })
                .collect(),
        },
        service_e2e_status: coverage.service_e2e_status,
        service_e2e_gaps: coverage.service_e2e_gaps,
    })
}

pub fn run_test_material_rejection_suite() -> Result<SuiteExecutionResult> {
    Ok(run_test_material_rejection_suite_with_coverage()?.execution)
}
