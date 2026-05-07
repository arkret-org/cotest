use anyhow::Result;

#[test]
fn artifact_registry_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_artifact_registry_suite()
}

#[test]
fn schema_validation_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_schema_validation_suite()
}

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
fn event_envelope_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_event_envelope_fixture_suite()
}

#[test]
fn deprecated_event_alias_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_deprecated_event_alias_suite()
}

#[test]
fn capability_facet_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_capability_facet_fixture_suite()
}

#[test]
fn facet_renderer_query_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_facet_renderer_query_fixture_suite()
}

#[test]
fn projection_position_discriminator_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_projection_position_discriminator_fixture_suite()
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

#[test]
fn host_endorsement_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_host_endorsement_fixture_suite()
}

#[test]
fn host_transfer_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_host_transfer_fixture_suite()
}

#[test]
fn consent_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_consent_fixture_suite()
}

#[test]
fn composite_state_subject_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_composite_state_subject_fixture_suite()
}

#[test]
fn mimi_components_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_mimi_components_fixture_suite()
}
