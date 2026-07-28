use anyhow::Result;
use cotest::transcripts::{TranscriptGuard, init_transcript_writer};
use serial_test::serial;

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
        #[serial(conformance_fixtures)]
        fn $name() -> Result<()> {
            let _guard = enter_scenario($scenario);
            $suite()
        }
    };
}

conformance_test!(
    schema_validation_suite_matches_reference_semantics,
    "schema_validation",
    cotest::conformance::run_schema_validation_suite,
);

conformance_test!(
    arkret_private_kdf_and_durability_executes_registered_vectors,
    "arkret_private_kdf_and_durability",
    cotest::conformance::run_arkret_private_kdf_and_durability_suite,
);

conformance_test!(
    /// Round 4 / A2 — schema-validation-fixture positive + negative cases
    /// run against the schema referenced by `schema_ref`. Drift hard-fails.
    schema_validation_fixture_suite_matches_reference_semantics,
    "schema_validation_fixture",
    cotest::conformance::run_schema_validation_fixture_suite,
);

conformance_test!(
    did_webvh_v1_adapter_suite_matches_reference_semantics,
    "did_webvh_v1_adapter",
    cotest::conformance::run_did_webvh_v1_adapter_fixture_suite,
);

conformance_test!(
    operation_clause_registry_closes_universal_behavior,
    "operation_clause_registry",
    cotest::conformance::validate_operation_clause_registry,
);

conformance_test!(
    scalability_limits_fixture_suite_matches_reference_semantics,
    "scalability_limits",
    cotest::conformance::run_scalability_limits_fixture_suite,
);

conformance_test!(
    long_text_content_fixture_suite_matches_reference_semantics,
    "long_text_content",
    cotest::conformance::run_long_text_content_fixture_suite,
);

conformance_test!(
    signal_federation_fixture_suite_matches_reference_semantics,
    "signal_federation",
    cotest::conformance::run_signal_federation_fixture_suite,
);

conformance_test!(
    /// Round 4 / A2 — security-closure-fixture runner contract.
    /// Confirms the 12 `ak.vector.*` ids are present and every step
    /// exposes the full `runner {given_state, operation, transcript,
    /// expected_state_transition, expected_external_response,
    /// expected_audit_reason}` quad.
    security_closure_fixture_suite_matches_reference_semantics,
    "security_closure_fixture",
    cotest::conformance::run_security_closure_fixture_suite,
);

conformance_test!(
    encoding_fixture_suite_matches_reference_semantics,
    "encoding_fixture",
    cotest::conformance::run_encoding_fixture_suite,
);

conformance_test!(
    /// Cross-language canonical-JSON parity: the SDK canonicaliser
    /// (arkret_canonical) must reproduce every golden vector in
    /// e2e/fixtures/canonical-cross-check.json byte-for-byte. The TS port
    /// (e2e/tests/conformance/canonical-cross-lang.spec.ts) asserts the same
    /// golden, so the two implementations are pinned to one shared truth.
    canonical_cross_lang_suite_matches_reference_semantics,
    "canonical_cross_lang",
    cotest::conformance::run_canonical_cross_lang_suite,
);

conformance_test!(
    /// 05-2 — Cross-language golden gate for the device-lifecycle §5.1/§5.2
    /// canonical signing inputs. The SDK (CrossSigningPublish /
    /// DeviceTrustBinding) must reproduce every golden vector in
    /// e2e/fixtures/cross-signing-binding-golden.json byte-for-byte. The TS
    /// byte-mirror (e2e/tests/conformance/cross-signing-binding-golden.spec.ts)
    /// asserts the same golden, so the e2e helpers can no longer silently drift
    /// from the SDK signing-input construction.
    cross_signing_binding_golden_suite_matches_reference_semantics,
    "cross_signing_binding_golden",
    cotest::conformance::run_cross_signing_binding_golden_suite,
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
    policy_server_fixture_suite_matches_reference_semantics,
    "policy_server_fixture",
    cotest::conformance::run_policy_server_fixture_suite,
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
    cba_lattice_fixture_suite_matches_reference_semantics,
    "cba_lattice_fixture",
    cotest::conformance::run_cba_lattice_fixture_suite,
);

conformance_test!(
    control_proposal_bounded_decision_suite_matches_reference_semantics,
    "control_proposal_bounded_decision",
    cotest::conformance::run_control_proposal_bounded_decision_suite,
);

conformance_test!(
    state_reducer_hardening_fixture_suite_matches_reference_semantics,
    "state_reducer_hardening_fixture",
    cotest::conformance::run_state_reducer_hardening_fixture_suite,
);

conformance_test!(
    /// C10.C — exercises the SDK's `arkret-lattice` crate against the normative
    /// scenarios from `cba-lattice-fixture.json` by reifying
    /// the symbolic ops as real `LatticeOp` + `SealedOp` values and asserting
    /// the spec's join semantics (CasRegister conflict ? Bottom, OrSet
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
    service_closure_hardening_fixture_suite_matches_reference_semantics,
    "service_closure_hardening_fixture",
    cotest::conformance::run_service_closure_hardening_fixture_suite,
);

conformance_test!(
    history_crypto_closure_fixture_suite_matches_reference_semantics,
    "history_crypto_closure_fixture",
    cotest::conformance::run_history_crypto_closure_fixture_suite,
);

conformance_test!(
    final_conformance_closure_fixture_suite_matches_reference_semantics,
    "final_conformance_closure_fixture",
    cotest::conformance::run_final_conformance_closure_fixture_suite,
);

conformance_test!(
    /// Realm private pin + direct conversation privacy contracts. Cotest-local
    /// fixture pins ak.contacts.realm.<realm_id> subject matching, prevents
    /// RealmRemark leakage into directory/bridge/push payloads, and locks the
    /// direct resolver shape to peer/state/binding_event_ref/main_strand_id.
    private_chat_privacy_contract_suite_matches_reference_semantics,
    "private_chat_privacy_contract",
    cotest::conformance::run_private_chat_privacy_contract_suite,
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
    /// T-CONF-PROFILE-MUST — profile dependency graph + machine-readable
    /// requirement blocks drive inheritance, dependency, fixture, cell, feature,
    /// capability, and MUST-block conformance gates.
    profile_requirement_gate_matches_spec_artifacts,
    "profile_requirement_gate",
    cotest::conformance::run_profile_requirement_gate_suite,
);

conformance_test!(
    /// C42.4 — Inkson full/e2ee client black-box manifest. Covers OIDC
    /// callback/session grant, host secure-store handoff, device
    /// verification, and E2EE fail-closed behavior.
    inkson_client_profile_manifest_suite_matches_reference_semantics,
    "inkson_client_profile_manifest",
    cotest::conformance::run_inkson_client_profile_manifest_suite,
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
    /// CES-03 - MIMI Provider Facade artifact vectors from arkret-spec.
    /// Covers draft pinning, room binding, KeyPackage claim lifecycle,
    /// content mapping, identifier privacy, consent isolation, proxy download,
    /// and unsupported-draft fail-closed behavior.
    mimi_interop_fixture_suite_matches_reference_semantics,
    "mimi_interop_fixture",
    cotest::conformance::run_mimi_interop_fixture_suite,
);

conformance_test!(
    mimi_components_fixture_suite_matches_reference_semantics,
    "mimi_components_fixture",
    cotest::conformance::run_mimi_components_fixture_suite,
);

conformance_test!(
    /// T-CONF-INTEROP-DOWNGRADE — MIMI downgrade gates are live
    /// fixture checks, not ignored placeholders. Covers DID isolation,
    /// consent-vs-capability separation and the
    /// v1 ban on reachability proof revival.
    interop_downgrade_fixture_suite_matches_reference_semantics,
    "interop_downgrade_fixture",
    cotest::conformance::run_interop_downgrade_fixture_suite,
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
    /// concurrent reconfig?Bottom Conflict + signature mismatch + threshold
    /// below/over quorum + registry drift). Stand-alone JSON fixture for SUT
    /// black-box validation; lattice round-trip stays in lattice_round_trip.rs.
    anchorer_cell_fixture_suite_matches_reference_semantics,
    "anchorer_cell_fixture",
    cotest::conformance::run_anchorer_cell_fixture_suite,
);

conformance_test!(
    /// Round-20 M5 — conflict-repair Move vectors (head_in single-op?Value,
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
    /// rotation?causal remove, governance Move not blocked, MLS commit writes
    /// 3 cells in 1 Move, missing/stale covered_frontier precondition?
    /// fail_precondition).
    mls_move_covered_frontier_fixture_suite_matches_reference_semantics,
    "mls_move_covered_frontier_fixture",
    cotest::conformance::run_mls_move_covered_frontier_fixture_suite,
);

conformance_test!(
    /// Round-21 — Discovery profile (ak.profile.discovery.v1) advertise vs
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
    /// configured/service ID-derived seed produces deterministic JWS, ephemeral
    /// seed produces non-deterministic, different seeds produce different
    /// signatures, signature verifies via verify_ed25519_move_signature with the
    /// signer-derived verifying key.
    production_signing_fixture_suite_matches_reference_semantics,
    "production_signing_fixture",
    cotest::conformance::run_production_signing_fixture_suite,
);

conformance_test!(
    /// Round-22 — Event-kind ? LatticeKind dispatch consistency. Cross-checks
    /// the live event-kind-registry: every active reducer-input durable kind
    /// with cell_family declares one core lattice, no cell_family appears in
    /// two lattices, namespace is ak.component.*, bottom is in {reject, expose},
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
    "mlR_e2ee_basic_fixture",
    cotest::conformance::run_mls_e2ee_basic_fixture_suite,
);

conformance_test!(
    /// Round-24 D2 — device verification strand (cross-signing chain, SAS, OOB
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
    /// Round-25 F-1 — recovery bridge full chain (coauth principal-cache ?
    /// soland recovery ticket ? restore executor ? final state). Round-26
    /// upgraded to full per-step state-machine + transition legality validation.
    recovery_bridge_full_chain_fixture_suite_matches_reference_semantics,
    "recovery_bridge_full_chain_fixture",
    cotest::conformance::run_recovery_bridge_full_chain_fixture_suite,
);

conformance_test!(
    /// Round-26 D4 — fixture-decoupled key-backup AEAD round-trip primitive
    /// check (Argon2id + XChaCha20-Poly1305). Asserts the exact crypto
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
    /// Round-27 D5 — device cross-signing trust boundary (cross-user master ?
    /// user-signing ? trusted-user master chain; revoke + rotation invariants).
    device_cross_signing_trust_fixture_suite_matches_reference_semantics,
    "device_cross_signing_trust_fixture",
    cotest::conformance::run_device_cross_signing_trust_fixture_suite,
);

conformance_test!(
    /// S4 — ak.profile.cross_signing.reset.v1 parser-level conformance
    /// vectors: proof family, generation monotonicity, replay cache, clock
    /// skew, and successor-publish window.
    cross_signing_reset_fixture_suite_matches_reference_semantics,
    "cross_signing_reset_fixture",
    cotest::conformance::run_cross_signing_reset_fixture_suite,
);

conformance_test!(
    /// Round-27 E3 — Multi-Realm federation Per-Realm anchor isolation +
    /// cross-Realm rejection.
    multi_realm_federation_fixture_suite_matches_reference_semantics,
    "multi_realm_federation_fixture",
    cotest::conformance::run_multi_realm_federation_fixture_suite,
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
    /// models/realm-and-space.md (lattice cell registry / co_write_policy) +
    /// authz/event-auth-state-resolution.md §3 / §5.3.
    lattice_mixed_kinds_suite_matches_reference_semantics,
    "lattice_mixed_kinds",
    cotest::conformance::run_lattice_mixed_kinds_suite,
);

conformance_test!(
    /// T1.1 — shared push blind-payload sanitizer vectors. Asserts the
    /// chime / floria / SDK implementations stay aligned on the allow /
    /// block lists for blind wakeup payloads (`push_target_id`,
    /// `wakeup_kind`, `push_hint`, counts; everything else forbidden;
    /// no `did:` / `ak:` literal in any other slot).
    blind_payload_sanitizer_vectors,
    "blind_payload_sanitizer",
    cotest::conformance::run_blind_payload_sanitizer_suite,
);

conformance_test!(
    /// Blob streaming AEAD vectors promoted to spec artifacts. Asserts
    /// segmented encryption/decryption, truncation, sequence/replay rejection,
    /// and schema-level scheme closure stay aligned with the blob profile.
    blob_stream_aead_fixture_suite_matches_reference_semantics,
    "blob_stream_aead_fixture",
    cotest::conformance::run_blob_stream_aead_fixture_suite,
);

conformance_test!(
    /// Media AEAD nonce vectors promoted to spec artifacts. Asserts sender
    /// nonce-prefix domain separation, counter replay rejection, and
    /// deterministic rejection of random 96-bit nonce fallback.
    media_aead_nonce_fixture_suite_matches_reference_semantics,
    "media_aead_nonce_fixture",
    cotest::conformance::run_media_aead_nonce_fixture_suite,
);

conformance_test!(
    /// Push rule core vectors promoted to spec artifacts. Asserts the shared
    /// SDK core used by soland / chime / inkson keeps watch-level delivery,
    /// blind-wakeup, and reason-code semantics aligned.
    push_rule_core_fixture_suite_matches_reference_semantics,
    "push_rule_core_fixture",
    cotest::conformance::run_push_rule_core_fixture_suite,
);

conformance_test!(
    /// Call-state core vectors promoted to spec artifacts. Asserts
    /// participant-binding admission maps semantic failures to
    /// participant_binding_invalid and the call lifecycle FSM keeps initial,
    /// transition, terminal, replay, and sibling-bottom behavior aligned.
    call_state_core_fixture_suite_matches_reference_semantics,
    "call_state_core_fixture",
    cotest::conformance::run_call_state_core_fixture_suite,
);

conformance_test!(
    /// Visibility policy vectors promoted to spec artifacts. Asserts
    /// encryption-floor ratchets, Circle directory projection privacy, and
    /// joined-history pre-join denial remain aligned with the spec.
    visibility_policy_fixture_suite_matches_reference_semantics,
    "visibility_policy_fixture",
    cotest::conformance::run_visibility_policy_fixture_suite,
);

conformance_test!(
    /// Agent participation vectors promoted to spec artifacts. Asserts
    /// selector mention authority, ceiling monotonicity, effective
    /// intersection, session overlay shape, and third-party mention gating.
    agent_participation_fixture_suite_matches_reference_semantics,
    "agent_participation_fixture",
    cotest::conformance::run_agent_participation_fixture_suite,
);

conformance_test!(
    /// KeyPackage lifecycle vectors promoted to spec artifacts. Asserts
    /// claim limits, last-resort reuse/rotation/Realm affinity, and MLS
    /// Welcome KeyPackage digest binding.
    keypackage_lifecycle_fixture_suite_matches_reference_semantics,
    "keypackage_lifecycle_fixture",
    cotest::conformance::run_keypackage_lifecycle_fixture_suite,
);

conformance_test!(
    /// Auth/session proof vectors promoted to spec artifacts. Asserts DID
    /// proof replay bounds, session grant audience binding, and
    /// sender-constrained PoP behavior.
    auth_session_proof_fixture_suite_matches_reference_semantics,
    "auth_session_proof_fixture",
    cotest::conformance::run_auth_session_proof_fixture_suite,
);

conformance_test!(
    /// Key-backup hardening vectors promoted to spec artifacts. Asserts KDF
    /// floors and unlock-proof binding before ciphertext release.
    key_backup_hardening_fixture_suite_matches_reference_semantics,
    "key_backup_hardening_fixture",
    cotest::conformance::run_key_backup_hardening_fixture_suite,
);

conformance_test!(
    /// Protocol-gap closure vectors assert proposal quorum evidence, durable
    /// security-transaction replay, closed track names, and WebSocket fallback.
    protocol_gap_closure_fixture_suite_matches_reference_semantics,
    "protocol_gap_closure_fixture",
    cotest::conformance::run_protocol_gap_closure_fixture_suite,
);
