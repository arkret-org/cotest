use anyhow::Result;
use cotest::transcripts::{TranscriptGuard, init_transcript_writer};

/// Bind a per-test transcript writer that materialises
/// `target/conformance-transcripts/<scenario>.jsonl`. Used by every
/// conformance fixture entry below so each `cargo test --test
/// conformance_fixtures` run leaves a fresh JSONL stream that release-gate
/// tooling and CI dashboards can consume directly. C34.5 / Q3 follow-up.
fn enter_scenario(scenario: &str) -> TranscriptGuard {
    init_transcript_writer(scenario, None)
        .unwrap_or_else(|err| panic!("failed to init transcript writer for {scenario}: {err}"))
}

/// Helper: run a conformance suite under an auto-init transcript guard. The
/// guard flushes + closes the per-scenario JSONL on drop, so each test entry
/// stays a one-liner. Optional leading attributes (`#[doc = "..."]` from `///`
/// comments, or any other meta) are forwarded onto the generated `#[test]`
/// function.
macro_rules! conformance_test {
    ($(#[$attr:meta])* $name:ident, $scenario:literal, $suite:path $(,)?) => {
        $(#[$attr])*
        #[test]
        fn $name() -> Result<()> {
            let _guard = enter_scenario($scenario);
            $suite()
        }
    };
}

conformance_test!(
    artifact_registry_suite_matches_reference_semantics,
    "artifact_registry",
    cotest::conformance::run_artifact_registry_suite,
);

conformance_test!(
    /// C39.8 — artifact-driven profile matrix. Builds the must-test matrix
    /// from conformance-profiles.json and hard-fails synthetic server claims
    /// that advertise a profile without its required operations.
    profile_matrix_suite_matches_artifact_contracts,
    "profile_matrix",
    cotest::conformance::run_profile_matrix_suite,
);

conformance_test!(
    /// Lane H / spec sync dc01ad7 — runtime profile gate registry. Loads
    /// conformance-profiles.json and emits a per-profile status entry for the
    /// 5 new vector profiles (discovery / event_kind_lattice_dispatch /
    /// event_kind_payload_coverage / operation_registry_coverage /
    /// error_code_registry_coverage) plus the 6 new implementation profiles
    /// (agent_workspace.{v1,lite,governed,strict} / e2ee_relaxed /
    /// directory_service). Vector profiles whose required_cotest_suites
    /// resolve in the suite registry report `certified`; missing suites
    /// report `skipped(suite_not_implemented)`; implementation profiles
    /// report `unsupported` per the spec's default_unsupported_behavior.
    profile_registry_gate_suite_matches_artifact_contracts,
    "profile_registry_gate",
    cotest::conformance::run_profile_registry_gate_suite,
);

conformance_test!(
    schema_validation_suite_matches_reference_semantics,
    "schema_validation",
    cotest::conformance::run_schema_validation_suite,
);

conformance_test!(
    encoding_fixture_suite_matches_reference_semantics,
    "encoding_fixture",
    cotest::conformance::run_encoding_fixture_suite,
);

conformance_test!(
    redaction_fixture_suite_matches_reference_semantics,
    "redaction_fixture",
    cotest::conformance::run_redaction_fixture_suite,
);

conformance_test!(
    capability_fixture_suite_matches_reference_semantics,
    "capability_fixture",
    cotest::conformance::run_capability_fixture_suite,
);

conformance_test!(
    event_envelope_fixture_suite_matches_reference_semantics,
    "event_envelope_fixture",
    cotest::conformance::run_event_envelope_fixture_suite,
);

conformance_test!(
    deprecated_event_alias_suite_matches_reference_semantics,
    "deprecated_event_alias",
    cotest::conformance::run_deprecated_event_alias_suite,
);

conformance_test!(
    capability_facet_suite_matches_reference_semantics,
    "capability_facet",
    cotest::conformance::run_capability_facet_fixture_suite,
);

conformance_test!(
    facet_renderer_query_suite_matches_reference_semantics,
    "facet_renderer_query",
    cotest::conformance::run_facet_renderer_query_fixture_suite,
);

conformance_test!(
    projection_position_discriminator_suite_matches_reference_semantics,
    "projection_position_discriminator",
    cotest::conformance::run_projection_position_discriminator_fixture_suite,
);

conformance_test!(
    state_resolution_fixture_suite_matches_reference_semantics,
    "state_resolution_fixture",
    cotest::conformance::run_state_resolution_fixture_suite,
);

conformance_test!(
    move_anchor_lattice_fixture_suite_matches_reference_semantics,
    "move_anchor_lattice_fixture",
    cotest::conformance::run_move_anchor_lattice_fixture_suite,
);

conformance_test!(
    /// C10.C — exercises the SDK's `contrix-lattice` crate against the normative
    /// scenarios from `move-anchor-lattice-fixture.json` §2.2-2.5 by reifying
    /// the symbolic ops as real `LatticeOp` + `AnchoredOp` values and asserting
    /// the spec's join semantics (CasRegister conflict → Bottom, OrSet
    /// commutativity, MvRegister multi-value, Counter PN sum, Fsm transitions,
    /// OrderedLog monotonic append).
    lattice_round_trip_suite_matches_reference_semantics,
    "lattice_round_trip",
    cotest::conformance::run_lattice_round_trip_suite,
);

conformance_test!(
    sync_fixture_suite_matches_reference_semantics,
    "sync_fixture",
    cotest::conformance::run_sync_fixture_suite,
);

conformance_test!(
    federation_fixture_suite_matches_reference_semantics,
    "federation_fixture",
    cotest::conformance::run_federation_fixture_suite,
);

conformance_test!(
    privacy_security_fixture_suite_matches_reference_semantics,
    "privacy_security_fixture",
    cotest::conformance::run_privacy_security_fixture_suite,
);

conformance_test!(
    /// C40.5 — security negative profile vectors. Hard-fails bad signatures,
    /// canonical-byte conflicts, schema/payload violations, replay, downgrade,
    /// and query-string auth leakage.
    security_negative_profile_suite_matches_reference_semantics,
    "security_negative_profile",
    cotest::conformance::run_security_negative_profile_suite,
);

conformance_test!(
    /// C41.9 — scaffold/profile claim gate. A service cannot claim a full
    /// profile while exposing 501/scaffold/placeholder critical paths or an
    /// unhealthy production signing posture.
    scaffold_profile_gate_suite_matches_reference_semantics,
    "scaffold_profile_gate",
    cotest::conformance::run_scaffold_profile_gate_suite,
);

conformance_test!(
    /// C42.4 — Yougen full/e2ee client black-box manifest. Covers OIDC
    /// callback/session grant, host secure-store handoff, device
    /// verification, and E2EE fail-closed behavior.
    yougen_client_profile_manifest_suite_matches_reference_semantics,
    "yougen_client_profile_manifest",
    cotest::conformance::run_yougen_client_profile_manifest_suite,
);

conformance_test!(
    /// C43.6 — Coauth deployment account lifecycle vectors. Covers local
    /// OIDC provider/JWKS auth-code callback/session grant, DID binding, device revoke,
    /// account status transitions, policy dry-run audit, and production
    /// no-silent-fallback behavior.
    coauth_account_lifecycle_fixture_suite_matches_reference_semantics,
    "coauth_account_lifecycle_fixture",
    cotest::conformance::run_coauth_account_lifecycle_fixture_suite,
);

conformance_test!(
    /// C42.6 — live describe profile-claim gate fixtures for soland,
    /// floria, teabay, starid, and coauth. Full profile claims with
    /// limitation/scaffold/501 blockers hard-fail.
    live_describe_profile_gate_suite_matches_reference_semantics,
    "live_describe_profile_gate",
    cotest::conformance::run_live_describe_profile_gate_suite,
);

conformance_test!(
    /// C43.4 — principal-server full-profile certification gate. Soland must
    /// remain explicitly not_certified while full claims require operations,
    /// schemas, event kinds, durable signed federation, and minimum
    /// admin/agent/applet/media surfaces.
    principal_server_certification_gate_suite_matches_reference_semantics,
    "principal_server_certification_gate",
    cotest::conformance::run_principal_server_certification_gate_suite,
);

conformance_test!(
    consent_fixture_suite_matches_reference_semantics,
    "consent_fixture",
    cotest::conformance::run_consent_fixture_suite,
);

conformance_test!(
    composite_state_subject_fixture_suite_matches_reference_semantics,
    "composite_state_subject_fixture",
    cotest::conformance::run_composite_state_subject_fixture_suite,
);

conformance_test!(
    mimi_components_fixture_suite_matches_reference_semantics,
    "mimi_components_fixture",
    cotest::conformance::run_mimi_components_fixture_suite,
);

conformance_test!(
    read_receipt_policy_fixture_suite_matches_reference_semantics,
    "read_receipt_policy_fixture",
    cotest::conformance::run_read_receipt_policy_fixture_suite,
);

conformance_test!(
    /// C10.C M6 — multi-leaf Anchor effective_anchor_view + signed compaction
    /// equivalence + bottom diagnostic preservation.
    anchor_view_compaction_fixture_suite_matches_reference_semantics,
    "anchor_view_compaction_fixture",
    cotest::conformance::run_anchor_view_compaction_fixture_suite,
);

conformance_test!(
    /// Round-20 M3 — anchorer cell governance vectors (4 happy-path profiles +
    /// concurrent reconfig→Bottom Conflict + signature mismatch + threshold
    /// below/over quorum + registry drift). Stand-alone JSON fixture for SUT
    /// black-box validation; lattice round-trip stays in lattice_round_trip.rs.
    anchorer_cell_fixture_suite_matches_reference_semantics,
    "anchorer_cell_fixture",
    cotest::conformance::run_anchorer_cell_fixture_suite,
);

conformance_test!(
    /// Round-20 M5 — conflict-repair Move vectors (head_in single-op→Value,
    /// self-authorising winner reject at lattice layer, manual repair via
    /// recovery_capability + anchorer endorsement). Stand-alone JSON fixture
    /// for SUT black-box validation; lattice round-trip stays in
    /// lattice_round_trip.rs.
    conflict_repair_fixture_suite_matches_reference_semantics,
    "conflict_repair_fixture",
    cotest::conformance::run_conflict_repair_fixture_suite,
);

conformance_test!(
    /// Round-20 M7 — MLS covered_frontier or-set vectors (idempotent re-add,
    /// rotation→causal remove, governance Move not blocked, MLS commit writes
    /// 3 cells in 1 Move, missing/stale covered_frontier precondition→
    /// fail_precondition).
    mls_move_covered_frontier_fixture_suite_matches_reference_semantics,
    "mls_move_covered_frontier_fixture",
    cotest::conformance::run_mls_move_covered_frontier_fixture_suite,
);

conformance_test!(
    /// Round-21 — Discovery profile (cx.profile.discovery.v1) advertise vs
    /// core/extension tier filtering, interop_bridge handling, and post-C16
    /// surface naming (blob_storage / realtime_media / moderation_reports).
    discovery_profile_fixture_suite_matches_reference_semantics,
    "discovery_profile_fixture",
    cotest::conformance::run_discovery_profile_fixture_suite,
);

conformance_test!(
    /// Round-22 — Threshold k-of-n Anchor signing vectors (ThresholdAggregator):
    /// k partials accept, k-1 partials reject (`threshold_below_quorum`),
    /// signer-not-in-anchorer-set rejected, duplicate signer deduped, aggregated
    /// signature has one MoveSignature per partial (each individually checking).
    threshold_multisig_fixture_suite_matches_reference_semantics,
    "threshold_multisig_fixture",
    cotest::conformance::run_threshold_multisig_fixture_suite,
);

conformance_test!(
    /// Round-22 — AnchorerWorker production signing path (Ed25519MoveSigner):
    /// configured/service-DID-derived seed produces deterministic JWS, ephemeral
    /// seed produces non-deterministic, different seeds produce different
    /// signatures, signature verifies via verify_ed25519_move_signature with the
    /// signer-derived verifying key.
    production_signing_fixture_suite_matches_reference_semantics,
    "production_signing_fixture",
    cotest::conformance::run_production_signing_fixture_suite,
);

conformance_test!(
    /// Round-22 — Event-kind ↔ LatticeKind dispatch consistency. Cross-checks
    /// the live event-kind-registry: every active reducer-input durable kind
    /// with cell_family declares one core lattice, no cell_family appears in
    /// two lattices, namespace is cx.component.*, bottom ∈ {reject, expose},
    /// and the fixture's expected_cell_family_lattice_bindings exactly matches
    /// the registry.
    event_kind_lattice_dispatch_fixture_suite_matches_reference_semantics,
    "event_kind_lattice_dispatch_fixture",
    cotest::conformance::run_event_kind_lattice_dispatch_fixture_suite,
);

conformance_test!(
    /// Round-23 A1 — event-kind payload coverage.
    event_kind_payload_coverage_fixture_suite_matches_reference_semantics,
    "event_kind_payload_coverage_fixture",
    cotest::conformance::run_event_kind_payload_coverage_fixture_suite,
);

conformance_test!(
    /// Round-23 A3 — operation registry coverage.
    operation_registry_coverage_fixture_suite_matches_reference_semantics,
    "operation_registry_coverage_fixture",
    cotest::conformance::run_operation_registry_coverage_fixture_suite,
);

conformance_test!(
    /// Round-23 A4 — error code registry coverage.
    error_code_registry_coverage_fixture_suite_matches_reference_semantics,
    "error_code_registry_coverage_fixture",
    cotest::conformance::run_error_code_registry_coverage_fixture_suite,
);

conformance_test!(
    /// Round-23 B1 — quarantine-on-fork algorithm.
    state_resolution_quarantine_fixture_suite_matches_reference_semantics,
    "state_resolution_quarantine_fixture",
    cotest::conformance::run_state_resolution_quarantine_fixture_suite,
);

conformance_test!(
    /// Round-23 B5 — membership transition FSM.
    membership_fsm_fixture_suite_matches_reference_semantics,
    "membership_fsm_fixture",
    cotest::conformance::run_membership_fsm_fixture_suite,
);

conformance_test!(
    /// Round-23 C1 — constraint family coverage.
    constraint_family_fixture_suite_matches_reference_semantics,
    "constraint_family_fixture",
    cotest::conformance::run_constraint_family_fixture_suite,
);

conformance_test!(
    /// Round-24 A5 — device-message / key-verification / key-backup negatives.
    device_message_negative_fixture_suite_matches_reference_semantics,
    "device_message_negative_fixture",
    cotest::conformance::run_device_message_negative_fixture_suite,
);

conformance_test!(
    /// Round-24 B2 — redaction reducer × history_visibility composition.
    redaction_history_visibility_fixture_suite_matches_reference_semantics,
    "redaction_history_visibility_fixture",
    cotest::conformance::run_redaction_history_visibility_fixture_suite,
);

conformance_test!(
    /// Round-24 B3 — composite (cell, subject) state-key encoding determinism +
    /// reserved-name collision rejection.
    composite_state_key_encoding_fixture_suite_matches_reference_semantics,
    "composite_state_key_encoding_fixture",
    cotest::conformance::run_composite_state_key_encoding_fixture_suite,
);

conformance_test!(
    /// Round-24 D1 — MLS / E2EE basic protocol (genesis, epoch advance, member
    /// join/leave, covered_frontier accumulation, AAD digest pinning).
    mls_e2ee_basic_fixture_suite_matches_reference_semantics,
    "mls_e2ee_basic_fixture",
    cotest::conformance::run_mls_e2ee_basic_fixture_suite,
);

conformance_test!(
    /// Round-24 D2 — device verification flow (cross-signing chain, SAS, OOB
    /// emoji code).
    device_verification_fixture_suite_matches_reference_semantics,
    "device_verification_fixture",
    cotest::conformance::run_device_verification_fixture_suite,
);

conformance_test!(
    /// Round-25 B4 — history visibility scope vectors (joined / invited /
    /// world_readable / shared) — smoke validation.
    history_visibility_fixture_suite_matches_reference_semantics,
    "history_visibility_fixture",
    cotest::conformance::run_history_visibility_fixture_suite,
);

conformance_test!(
    /// Round-25 D3 — Megolm-equivalent ratcheting vectors — smoke validation.
    megolm_ratcheting_fixture_suite_matches_reference_semantics,
    "megolm_ratcheting_fixture",
    cotest::conformance::run_megolm_ratcheting_fixture_suite,
);

conformance_test!(
    /// Round-25 D4 — key backup encryption vectors — smoke validation.
    key_backup_encryption_fixture_suite_matches_reference_semantics,
    "key_backup_encryption_fixture",
    cotest::conformance::run_key_backup_encryption_fixture_suite,
);

conformance_test!(
    /// Round-25 C2 — constraint evaluation_class fast-path coverage — smoke
    /// validation.
    constraint_evaluation_class_fixture_suite_matches_reference_semantics,
    "constraint_evaluation_class_fixture",
    cotest::conformance::run_constraint_evaluation_class_fixture_suite,
);

conformance_test!(
    /// Round-25 F-1 — recovery bridge full chain (coauth principal-cache →
    /// soland recovery ticket → restore executor → final state). Round-26
    /// upgraded to full per-step state-machine + transition legality validation.
    recovery_bridge_full_chain_fixture_suite_matches_reference_semantics,
    "recovery_bridge_full_chain_fixture",
    cotest::conformance::run_recovery_bridge_full_chain_fixture_suite,
);

conformance_test!(
    /// Round-26 D4 — fixture-decoupled key-backup AEAD round-trip primitive
    /// check (PBKDF2-HMAC-SHA512 → ChaCha20-Poly1305). Asserts the exact crypto
    /// primitive set the spec mandates is callable + correct.
    key_backup_aead_round_trip_round_26,
    "key_backup_aead_round_trip_round_26",
    cotest::conformance::run_key_backup_aead_round_trip_check,
);

conformance_test!(
    /// Round-26 D3 — fixture-decoupled megolm-equivalent HKDF chain check.
    /// Asserts the KDF is deterministic + non-identity over a 16-step run.
    megolm_ratchet_kdf_chain_round_26,
    "megolm_ratchet_kdf_chain_round_26",
    cotest::conformance::run_megolm_ratchet_kdf_chain_check,
);

conformance_test!(
    /// Round-26 F-1 — recovery-ticket state-machine legality matrix (legal
    /// success / terminal paths accept; illegal transitions reject). Independent
    /// of the recovery_bridge_full_chain fixture so the FSM stays self-validating.
    recovery_ticket_state_machine_round_26,
    "recovery_ticket_state_machine_round_26",
    cotest::conformance::run_recovery_ticket_state_machine_check,
);

conformance_test!(
    /// Round-26 B4 — fixture-decoupled history_visibility projection matrix
    /// (every (visibility, membership, ts) tuple's expected visible/hidden bit
    /// computed from the spec's projection function).
    history_visibility_projection_matrix_round_26,
    "history_visibility_projection_matrix_round_26",
    cotest::conformance::run_history_visibility_projection_matrix_check,
);

conformance_test!(
    /// Round-27 D5 — device cross-signing trust boundary (cross-user master →
    /// user-signing → trusted-user master chain; revoke + rotation invariants).
    device_cross_signing_trust_fixture_suite_matches_reference_semantics,
    "device_cross_signing_trust_fixture",
    cotest::conformance::run_device_cross_signing_trust_fixture_suite,
);

conformance_test!(
    /// S4 — cx.profile.cross_signing.reset.v1 parser-level conformance
    /// vectors: proof family, generation monotonicity, replay cache, clock
    /// skew, and successor-publish window.
    cross_signing_reset_fixture_suite_matches_reference_semantics,
    "cross_signing_reset_fixture",
    cotest::conformance::run_cross_signing_reset_fixture_suite,
);

conformance_test!(
    /// Round-27 E3 — multi-space federation per-space anchor isolation +
    /// cross-space rejection.
    multi_space_federation_fixture_suite_matches_reference_semantics,
    "multi_space_federation_fixture",
    cotest::conformance::run_multi_space_federation_fixture_suite,
);

conformance_test!(
    /// Round-27 E4 — frontier conflict resolution via lattice join.
    frontier_conflict_resolution_fixture_suite_matches_reference_semantics,
    "frontier_conflict_resolution_fixture",
    cotest::conformance::run_frontier_conflict_resolution_fixture_suite,
);

conformance_test!(
    /// Round-27 E5 — late-arriving anchor idempotency (no double-effect).
    late_arriving_anchor_fixture_suite_matches_reference_semantics,
    "late_arriving_anchor_fixture",
    cotest::conformance::run_late_arriving_anchor_fixture_suite,
);

conformance_test!(
    /// Round-27 E6 — redacted Move cross-server projection (round-25 MAL-14
    /// viewer-is-author audit-view rules).
    redacted_cross_server_fixture_suite_matches_reference_semantics,
    "redacted_cross_server_fixture",
    cotest::conformance::run_redacted_cross_server_fixture_suite,
);

conformance_test!(
    /// Round-27 F-2 — restore approval/executor/artifact full workflows.
    restore_full_workflows_fixture_suite_matches_reference_semantics,
    "restore_full_workflows_fixture",
    cotest::conformance::run_restore_full_workflows_fixture_suite,
);

conformance_test!(
    /// Round-27 E5 — fixture-decoupled late-arriving-anchor idempotency primitive.
    late_arriving_anchor_idempotency_round_27,
    "late_arriving_anchor_idempotency_round_27",
    cotest::conformance::run_late_arriving_anchor_idempotency_check,
);

conformance_test!(
    /// Round-27 F-2 — fixture-decoupled multi-admin distinct-approver gate.
    multi_admin_distinct_approver_gate_round_27,
    "multi_admin_distinct_approver_gate_round_27",
    cotest::conformance::run_multi_admin_distinct_approver_gate_check,
);

conformance_test!(
    /// CT-2 — mixed lattice cell types (cas-register + or-set + mv-register)
    /// updating concurrently in the same Move batch / Anchor frontier. Spec:
    /// models/space-and-place.md (lattice cell registry / co_write_policy) +
    /// authz/event-auth-state-resolution.md §3 / §5.3.
    lattice_mixed_kinds_suite_matches_reference_semantics,
    "lattice_mixed_kinds",
    cotest::conformance::run_lattice_mixed_kinds_suite,
);

conformance_test!(
    /// CT-3 — snapshot v2 tampered Merkle vectors. A snapshot whose chunk
    /// payload or inclusion-proof branch has been mutated MUST be rejected
    /// with `digest_mismatch`, even when a local Merkle recompute is
    /// internally consistent against the mutation. Spec:
    /// conformance/snapshot-schema.md §3 / §4 / §5 / §6.
    snapshot_v2_tampered_merkle_suite_matches_reference_semantics,
    "snapshot_v2_tampered_merkle",
    cotest::conformance::run_snapshot_v2_tampered_merkle_suite,
);

// ── cx.profile.agent_workspace.v1 ──────────────────────────────────────
// Spec: contrix-spec/spec/v1/zh/extensions/agent-workspace-profile.md
// Fixtures: contrix-spec/spec/v1/artifacts/conformance/agent-workspace/
// Tracked in contrix-spec/_todos.md AW-1..AW-4.

conformance_test!(
    /// agent_workspace: event-kinds / capability-actions / operations /
    /// id-kinds / schema-registry all carry the new agent_workspace surface
    /// with profile_gate=cx.profile.agent_workspace.v1.
    agent_workspace_registry_surface,
    "agent_workspace_registry_surface",
    cotest::conformance::run_agent_workspace_registry_suite,
);

conformance_test!(
    /// agent_workspace: 4 new schema files parse + appear in schema-registry
    /// + capability-grant carries the attached_authority oneOf extension
    /// (spec PR 1.2) with only anchored_event_ref + state_witness in v1.
    agent_workspace_schema_surface,
    "agent_workspace_schema_surface",
    cotest::conformance::run_agent_workspace_schema_suite,
);

conformance_test!(
    /// agent_workspace: 9 land FSM / reservation / recovery fixtures parse
    /// + carry the documented invariants (head_eq:"__unset__" for singleton
    /// path, head_in for §8 recovery, bottom_diagnostic for ⊥ collapse, no
    /// unreachable Rev 7 transitions returning `accepted`).
    agent_workspace_fsm_and_reservation_fixtures,
    "agent_workspace_fsm_and_reservation_fixtures",
    cotest::conformance::run_agent_workspace_fsm_fixture_suite,
);

conformance_test!(
    /// T1.1 — shared push blind-payload sanitizer vectors. Asserts the
    /// chime / floria / SDK implementations stay aligned on the allow /
    /// block lists for blind wakeup payloads (`push_target_id`,
    /// `wakeup_kind`, `push_hint`, counts; everything else forbidden;
    /// no `did:` / `cx:` literal in any other slot).
    blind_payload_sanitizer_vectors,
    "blind_payload_sanitizer",
    cotest::conformance::run_blind_payload_sanitizer_suite,
);
