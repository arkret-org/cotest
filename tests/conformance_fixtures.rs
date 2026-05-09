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

/// Round-21 — Discovery profile (cx.profile.discovery.v1) advertise vs
/// core/extension tier filtering, interop_bridge handling, and post-C16
/// surface naming (blob_storage / realtime_media / moderation_reports).
#[test]
fn discovery_profile_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_discovery_profile_fixture_suite()
}

/// Round-22 — Threshold k-of-n Anchor signing vectors (ThresholdAggregator):
/// k partials accept, k-1 partials reject (`threshold_below_quorum`),
/// signer-not-in-anchorer-set rejected, duplicate signer deduped, aggregated
/// signature has one MoveSignature per partial (each individually checking).
#[test]
fn threshold_multisig_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_threshold_multisig_fixture_suite()
}

/// Round-22 — AnchorerWorker production signing path (Ed25519MoveSigner):
/// configured/service-DID-derived seed produces deterministic JWS, ephemeral
/// seed produces non-deterministic, different seeds produce different
/// signatures, signature verifies via verify_ed25519_move_signature with the
/// signer-derived verifying key.
#[test]
fn production_signing_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_production_signing_fixture_suite()
}

/// Round-22 — Event-kind ↔ LatticeKind dispatch consistency. Cross-checks
/// the live event-kind-registry: every active reducer-input durable kind
/// with cell_family declares one core lattice, no cell_family appears in
/// two lattices, namespace is cx.component.*, bottom ∈ {reject, expose},
/// and the fixture's expected_cell_family_lattice_bindings exactly matches
/// the registry.
#[test]
fn event_kind_lattice_dispatch_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_event_kind_lattice_dispatch_fixture_suite()
}

/// Round-23 A1 — event-kind payload coverage.
#[test]
fn event_kind_payload_coverage_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_event_kind_payload_coverage_fixture_suite()
}

/// Round-23 A3 — operation registry coverage.
#[test]
fn operation_registry_coverage_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_operation_registry_coverage_fixture_suite()
}

/// Round-23 A4 — error code registry coverage.
#[test]
fn error_code_registry_coverage_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_error_code_registry_coverage_fixture_suite()
}

/// Round-23 B1 — quarantine-on-fork algorithm.
#[test]
fn state_resolution_quarantine_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_state_resolution_quarantine_fixture_suite()
}

/// Round-23 B5 — membership transition FSM.
#[test]
fn membership_fsm_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_membership_fsm_fixture_suite()
}

/// Round-23 C1 — constraint family coverage.
#[test]
fn constraint_family_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_constraint_family_fixture_suite()
}

/// Round-24 A5 — device-message / key-verification / key-backup negatives.
#[test]
fn device_message_negative_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_device_message_negative_fixture_suite()
}

/// Round-24 B2 — redaction reducer × history_visibility composition.
#[test]
fn redaction_history_visibility_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_redaction_history_visibility_fixture_suite()
}

/// Round-24 B3 — composite (cell, subject) state-key encoding determinism +
/// reserved-name collision rejection.
#[test]
fn composite_state_key_encoding_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_composite_state_key_encoding_fixture_suite()
}

/// Round-24 D1 — MLS / E2EE basic protocol (genesis, epoch advance, member
/// join/leave, covered_frontier accumulation, AAD digest pinning).
#[test]
fn mls_e2ee_basic_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_mls_e2ee_basic_fixture_suite()
}

/// Round-24 D2 — device verification flow (cross-signing chain, SAS, OOB
/// emoji code).
#[test]
fn device_verification_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_device_verification_fixture_suite()
}

/// Round-25 B4 — history visibility scope vectors (joined / invited /
/// world_readable / shared) — smoke validation.
#[test]
fn history_visibility_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_history_visibility_fixture_suite()
}

/// Round-25 D3 — Megolm-equivalent ratcheting vectors — smoke validation.
#[test]
fn megolm_ratcheting_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_megolm_ratcheting_fixture_suite()
}

/// Round-25 D4 — key backup encryption vectors — smoke validation.
#[test]
fn key_backup_encryption_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_key_backup_encryption_fixture_suite()
}

/// Round-25 C2 — constraint evaluation_class fast-path coverage — smoke
/// validation.
#[test]
fn constraint_evaluation_class_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_constraint_evaluation_class_fixture_suite()
}

/// Round-25 F-1 — recovery bridge full chain (coauth principal-cache →
/// soland recovery ticket → restore executor → final state). Round-26
/// upgraded to full per-step state-machine + transition legality validation.
#[test]
fn recovery_bridge_full_chain_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_recovery_bridge_full_chain_fixture_suite()
}

/// Round-26 D4 — fixture-decoupled key-backup AEAD round-trip primitive
/// check (PBKDF2-HMAC-SHA512 → ChaCha20-Poly1305). Asserts the exact crypto
/// primitive set the spec mandates is callable + correct.
#[test]
fn key_backup_aead_round_trip_round_26() -> Result<()> {
    cotest::conformance::run_key_backup_aead_round_trip_check()
}

/// Round-26 D3 — fixture-decoupled megolm-equivalent HKDF chain check.
/// Asserts the KDF is deterministic + non-identity over a 16-step run.
#[test]
fn megolm_ratchet_kdf_chain_round_26() -> Result<()> {
    cotest::conformance::run_megolm_ratchet_kdf_chain_check()
}

/// Round-26 F-1 — recovery-ticket state-machine legality matrix (legal
/// success / terminal paths accept; illegal transitions reject). Independent
/// of the recovery_bridge_full_chain fixture so the FSM stays self-validating.
#[test]
fn recovery_ticket_state_machine_round_26() -> Result<()> {
    cotest::conformance::run_recovery_ticket_state_machine_check()
}

/// Round-26 B4 — fixture-decoupled history_visibility projection matrix
/// (every (visibility, membership, ts) tuple's expected visible/hidden bit
/// computed from the spec's projection function).
#[test]
fn history_visibility_projection_matrix_round_26() -> Result<()> {
    cotest::conformance::run_history_visibility_projection_matrix_check()
}

/// Round-27 D5 — device cross-signing trust boundary (cross-user master →
/// user-signing → trusted-user master chain; revoke + rotation invariants).
#[test]
fn device_cross_signing_trust_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_device_cross_signing_trust_fixture_suite()
}

/// Round-27 E3 — multi-space federation per-space anchor isolation +
/// cross-space rejection.
#[test]
fn multi_space_federation_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_multi_space_federation_fixture_suite()
}

/// Round-27 E4 — frontier conflict resolution via lattice join.
#[test]
fn frontier_conflict_resolution_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_frontier_conflict_resolution_fixture_suite()
}

/// Round-27 E5 — late-arriving anchor idempotency (no double-effect).
#[test]
fn late_arriving_anchor_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_late_arriving_anchor_fixture_suite()
}

/// Round-27 E6 — redacted Move cross-server projection (round-25 MAL-14
/// viewer-is-author audit-view rules).
#[test]
fn redacted_cross_server_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_redacted_cross_server_fixture_suite()
}

/// Round-27 F-2 — restore approval/executor/artifact full workflows.
#[test]
fn restore_full_workflows_fixture_suite_matches_reference_semantics() -> Result<()> {
    cotest::conformance::run_restore_full_workflows_fixture_suite()
}

/// Round-27 E5 — fixture-decoupled late-arriving-anchor idempotency primitive.
#[test]
fn late_arriving_anchor_idempotency_round_27() -> Result<()> {
    cotest::conformance::run_late_arriving_anchor_idempotency_check()
}

/// Round-27 F-2 — fixture-decoupled multi-admin distinct-approver gate.
#[test]
fn multi_admin_distinct_approver_gate_round_27() -> Result<()> {
    cotest::conformance::run_multi_admin_distinct_approver_gate_check()
}
