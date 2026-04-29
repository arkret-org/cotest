use anyhow::Result;

#[test]
fn encoding_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_encoding_fixture_suite()
}

#[test]
fn redaction_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_redaction_fixture_suite()
}

#[test]
fn capability_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_capability_fixture_suite()
}

#[test]
fn state_resolution_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_state_resolution_fixture_suite()
}

#[test]
fn sync_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_sync_fixture_suite()
}

#[test]
fn federation_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_federation_fixture_suite()
}

#[test]
fn privacy_security_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_privacy_security_fixture_suite()
}
