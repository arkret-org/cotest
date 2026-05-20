//! Round 4 / A2 — schema-validation-fixture driver.
//!
//! Loads `contrix-spec/spec/v1/artifacts/fixtures/schema-validation-fixture.json`
//! and runs every positive/negative case against its `schema_ref`.
//! Positive cases (`expect_valid: true`) MUST pass; negative cases
//! (`expect_valid: false`) MUST fail. Drift is a hard failure.

use cotest::conformance::run_schema_validation_fixture_suite;

#[test]
fn schema_validation_fixture_positive_and_negative_cases() {
    run_schema_validation_fixture_suite()
        .expect("schema-validation-fixture cases must all match expectations");
}
