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
fn move_anchor_lattice_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_move_anchor_lattice_fixture_suite()
}

/// C10.C — exercises the SDK's `contrix-lattice` crate against the normative
/// scenarios from `move-anchor-lattice-fixture.json` §2.2-2.5 by reifying
/// the symbolic ops as real `LatticeOp` + `AnchoredOp` values and asserting
/// the spec's join semantics (CasRegister conflict → Bottom, OrSet
/// commutativity, MvRegister multi-value, Counter PN sum, Fsm transitions,
/// OrderedLog monotonic append).
#[test]
fn lattice_round_trip_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_lattice_round_trip_suite()
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

#[test]
fn read_receipt_policy_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_read_receipt_policy_fixture_suite()
}

/// C10.C M6 — multi-leaf Anchor effective_anchor_view + signed compaction
/// equivalence + bottom diagnostic preservation.
#[test]
fn anchor_view_compaction_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_anchor_view_compaction_fixture_suite()
}

/// Round-20 M3 — anchorer cell governance vectors (4 happy-path profiles +
/// concurrent reconfig→Bottom Conflict + signature mismatch + threshold
/// below/over quorum + registry drift). Stand-alone JSON fixture for SUT
/// black-box validation; lattice round-trip stays in lattice_round_trip.rs.
#[test]
fn anchorer_cell_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_anchorer_cell_fixture_suite()
}

/// Round-20 M5 — conflict-repair Move vectors (head_in single-op→Value,
/// self-authorising winner reject at lattice layer, manual repair via
/// recovery_capability + anchorer endorsement). Stand-alone JSON fixture
/// for SUT black-box validation; lattice round-trip stays in
/// lattice_round_trip.rs.
#[test]
fn conflict_repair_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_conflict_repair_fixture_suite()
}

/// Round-20 M7 — MLS covered_frontier or-set vectors (idempotent re-add,
/// rotation→causal remove, governance Move not blocked, MLS commit writes
/// 3 cells in 1 Move, missing/stale covered_frontier precondition→
/// fail_precondition).
#[test]
fn mls_move_covered_frontier_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_mls_move_covered_frontier_fixture_suite()
}
