//! Round 4 / A2 — schema-validation-fixture driver.
//!
//! Loads `arkret-spec/spec/v1/artifacts/fixtures/schema-validation-fixture.json`
//! and runs every positive/negative case against its `schema_ref`.
//! Positive cases (`expect_valid: true`) MUST pass; negative cases
//! (`expect_valid: false`) MUST fail. Drift is a hard failure.

use cotest::conformance::{
    run_event_payload_value_closure_fixture, run_schema_definition_validator_kat,
    run_schema_validation_fixture_suite,
};

#[test]
fn schema_validation_fixture_positive_and_negative_cases() {
    run_schema_validation_fixture_suite()
        .expect("schema-validation-fixture cases must all match expectations");
}

#[test]
fn event_payload_value_closure_cases_match_reference_semantics() {
    run_event_payload_value_closure_fixture()
        .expect("event payload value closure cases must all match expectations");
}

#[test]
fn schema_definition_validator_kat_matches_sdk_profile() {
    run_schema_definition_validator_kat()
        .expect("schema-definition KAT must match the SDK validator profile");
}
