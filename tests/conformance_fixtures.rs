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

macro_rules! conformance_async_test {
    ($(#[$attr:meta])* $name:ident, $scenario:literal, $suite:path $(,)?) => {
        $(#[$attr])*
        #[tokio::test]
        #[serial(conformance_fixtures)]
        async fn $name() -> Result<()> {
            let _guard = enter_scenario($scenario);
            $suite().await
        }
    };
}

conformance_test!(
    schema_validation_suite_matches_reference_semantics,
    "schema_validation",
    cotest::conformance::run_schema_validation_suite,
);

conformance_test!(
    applet_install_authoring_matches_canonical_binding,
    "applet_install_authoring",
    cotest::conformance::run_applet_install_authoring_suite,
);

conformance_test!(
    applet_managed_actor_authority_consumes_registered_fixture,
    "applet_managed_actor_authority",
    cotest::conformance::run_applet_managed_actor_authority_suite,
);

conformance_test!(
    mls_creator_bootstrap_recovery_executes_the_registered_state_machine,
    "mls_creator_bootstrap_recovery",
    cotest::conformance::run_mls_creator_bootstrap_recovery_suite,
);

conformance_test!(
    device_pairing_code_claim_executes_registered_variants,
    "device_pairing_code_claim",
    cotest::conformance::run_device_pairing_code_claim_suite,
);

conformance_test!(
    applet_registration_epoch_consumes_embedded_canonical_kat,
    "applet_registration_epoch",
    cotest::conformance::run_applet_registration_epoch_kat_suite,
);

conformance_test!(
    arkret_private_kdf_and_durability_executes_registered_vectors,
    "arkret_private_kdf_and_durability",
    cotest::conformance::run_arkret_private_kdf_and_durability_suite,
);

conformance_test!(
    /// A2 — schema-validation-fixture positive + negative cases
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
    service_did_routes_survive_refresh_and_restart,
    "service_did_routes",
    cotest::conformance::run_service_did_routes_suite,
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
    signal_sequence_high_water_fixture_suite_matches_reference_semantics,
    "signal_sequence_high_water",
    cotest::conformance::run_signal_sequence_high_water_suite,
);

conformance_test!(
    /// A2 — security-closure-fixture runner contract.
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
    cbs_lattice_fixture_suite_matches_reference_semantics,
    "cbs_lattice_fixture",
    cotest::conformance::run_cbs_lattice_fixture_suite,
);

conformance_test!(
    control_proposal_bounded_decision_suite_matches_reference_semantics,
    "control_proposal_bounded_decision",
    cotest::conformance::run_control_proposal_bounded_decision_suite,
);

conformance_test!(
    control_proposal_ack_suite_matches_reference_semantics,
    "control_proposal_ack",
    cotest::conformance::run_control_proposal_ack_suite,
);

conformance_test!(
    state_reducer_hardening_fixture_suite_matches_reference_semantics,
    "state_reducer_hardening_fixture",
    cotest::conformance::run_state_reducer_hardening_fixture_suite,
);

conformance_test!(
    state_model_round_trip_suite_matches_reference_semantics,
    "state_model_round_trip",
    cotest::conformance::run_state_model_round_trip_suite,
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

conformance_async_test!(
    history_key_direct_traversal_fixture_matches_shared_sdk_types,
    "history_key_direct_traversal_fixture",
    cotest::conformance::run_history_key_direct_traversal_suite,
);

conformance_test!(
    push_route_revision_fixture_matches_production_sdk,
    "push_route_revision_fixture",
    cotest::conformance::run_push_route_revision_suite,
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
    /// FLOW-002/004/005/008/014 — single derived MLS group, exact first-valid
    /// founding replay, Commit/Welcome finality fences and same-group repair.
    direct_conversation_end_to_end_flow_matches_reference_semantics,
    "direct_conversation_end_to_end_flow",
    cotest::conformance::run_direct_conversation_flow_suite,
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
    /// T-CONF-ProfileId::SIGNAL_PEER_RELAY_V1-MUST — profile dependency graph + machine-readable
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
    /// floria, teabay, and coauth. Full profile claims with
    /// limitation/scaffold/501 blockers hard-fail.
    live_describe_profile_gate_suite_matches_reference_semantics,
    "live_describe_profile_gate",
    cotest::conformance::run_live_describe_profile_gate_suite,
);

conformance_test!(
    /// C43.4 — station full-profile certification gate. Soland must
    /// remain explicitly not_certified while full claims require operations,
    /// schemas, event kinds, durable signed federation, and minimum
    /// admin/agent/applet/media surfaces.
    station_certification_gate_suite_matches_reference_semantics,
    "station_certification_gate",
    cotest::conformance::run_station_certification_gate_suite,
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
    /// MLS Security Frontier KAT plus orthogonality, active-leaf and
    /// Realm/Circle isolation checks through the public SDK projector.
    mls_security_frontier_fixture_suite_matches_reference_semantics,
    "mls_security_frontier_fixture",
    cotest::conformance::run_mls_security_frontier_fixture_suite,
);

conformance_test!(
    /// Discovery profile (ak.profile.discovery.v1) advertise vs
    /// core/extension tier filtering, interop_bridge handling, and post-C16
    /// surface naming (blob_storage / realtime_media / moderation_reports).
    discovery_profile_fixture_suite_matches_reference_semantics,
    "discovery_profile_fixture",
    cotest::conformance::run_discovery_profile_fixture_suite,
);

conformance_test!(
    /// Notary payload-signing path driven through the live SDK
    /// `arkret_signatures::Ed25519PayloadSigner`: a configured seed produces a
    /// byte-deterministic detached JWS, an ephemeral seed does not, distinct
    /// seeds produce distinct signatures over identical bytes, the signature
    /// round-trips through `verify_ed25519_payload_signature` with the
    /// signer-derived verifying key, and `payload_digest` equals sha256 of the
    /// canonical body.
    production_signing_fixture_suite_matches_reference_semantics,
    "production_signing_fixture",
    cotest::conformance::run_production_signing_fixture_suite,
);

conformance_test!(
    /// Event-kind to StateModel dispatch consistency. Cross-checks
    /// the live event-kind-registry: every active reducer-input durable kind
    /// with cell_family declares one core model, no cell_family appears in
    /// two models, namespace is ak.component.*, causal-register families never
    /// declare Bottom, and the fixture's
    /// expected cell-family/model bindings exactly match
    /// the registry.
    event_kind_lattice_dispatch_fixture_suite_matches_reference_semantics,
    "event_kind_lattice_dispatch_fixture",
    cotest::conformance::run_event_kind_lattice_dispatch_fixture_suite,
);

conformance_test!(
    /// A1 — event-kind payload coverage.
    event_kind_payload_coverage_fixture_suite_matches_reference_semantics,
    "event_kind_payload_coverage_fixture",
    cotest::conformance::run_event_kind_payload_coverage_fixture_suite,
);

conformance_test!(
    /// C1 — constraint family coverage.
    constraint_family_fixture_suite_matches_reference_semantics,
    "constraint_family_fixture",
    cotest::conformance::run_constraint_family_fixture_suite,
);

conformance_test!(
    /// A5 — device-message / key-verification / key-backup negatives.
    device_message_negative_fixture_suite_matches_reference_semantics,
    "device_message_negative_fixture",
    cotest::conformance::run_device_message_negative_fixture_suite,
);

conformance_test!(
    /// B3 — composite (cell, subject) state-key encoding determinism +
    /// reserved-name collision rejection.
    composite_state_key_encoding_fixture_suite_matches_reference_semantics,
    "composite_state_key_encoding_fixture",
    cotest::conformance::run_composite_state_key_encoding_fixture_suite,
);

conformance_test!(
    /// D3 — Megolm-equivalent ratcheting vectors — smoke validation.
    megolm_ratcheting_fixture_suite_matches_reference_semantics,
    "megolm_ratcheting_fixture",
    cotest::conformance::run_megolm_ratcheting_fixture_suite,
);

conformance_test!(
    /// D4 — key backup encryption vectors — smoke validation.
    key_backup_encryption_fixture_suite_matches_reference_semantics,
    "key_backup_encryption_fixture",
    cotest::conformance::run_key_backup_encryption_fixture_suite,
);

conformance_test!(
    /// C2 — constraint evaluation_class fast-path coverage — smoke
    /// validation.
    constraint_evaluation_class_fixture_suite_matches_reference_semantics,
    "constraint_evaluation_class_fixture",
    cotest::conformance::run_constraint_evaluation_class_fixture_suite,
);

conformance_test!(
    /// F-1 — recovery bridge full chain (coauth principal-cache ?
    /// soland recovery ticket ? restore executor ? final state). Validates
    /// the full per-step state machine plus transition legality.
    recovery_bridge_full_chain_fixture_suite_matches_reference_semantics,
    "recovery_bridge_full_chain_fixture",
    cotest::conformance::run_recovery_bridge_full_chain_fixture_suite,
);

conformance_test!(
    /// D4 — fixture-decoupled key-backup AEAD round-trip primitive
    /// check (Argon2id + XChaCha20-Poly1305). Asserts the exact crypto
    /// primitive set the spec mandates is callable + correct.
    key_backup_aead_round_trip_round_26,
    "key_backup_aead_round_trip_round_26",
    cotest::conformance::run_key_backup_aead_round_trip_check,
);

conformance_test!(
    /// D3 — fixture-decoupled megolm-equivalent HKDF chain check.
    /// Asserts the KDF is deterministic + non-identity over a 16-step run.
    megolm_ratchet_kdf_chain_round_26,
    "megolm_ratchet_kdf_chain_round_26",
    cotest::conformance::run_megolm_ratchet_kdf_chain_check,
);

conformance_test!(
    /// F-1 — recovery-ticket state-machine legality matrix (legal
    /// success / terminal paths accept; illegal transitions reject). Independent
    /// of the recovery_bridge_full_chain fixture so the lifecycle stays self-validating.
    recovery_ticket_state_machine_round_26,
    "recovery_ticket_state_machine_round_26",
    cotest::conformance::run_recovery_ticket_state_machine_check,
);

conformance_test!(
    /// E6 — redacted Move cross-server projection (MAL-14
    /// viewer-is-author audit-view rules).
    redacted_cross_server_fixture_suite_matches_reference_semantics,
    "redacted_cross_server_fixture",
    cotest::conformance::run_redacted_cross_server_fixture_suite,
);

conformance_test!(
    /// F-2 — restore approval/executor/artifact full workflows.
    restore_full_workflows_fixture_suite_matches_reference_semantics,
    "restore_full_workflows_fixture",
    cotest::conformance::run_restore_full_workflows_fixture_suite,
);

conformance_test!(
    /// F-2 — fixture-decoupled multi-admin distinct-approver gate.
    multi_admin_distinct_approver_gate_round_27,
    "multi_admin_distinct_approver_gate_round_27",
    cotest::conformance::run_multi_admin_distinct_approver_gate_check,
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
    /// File-transfer streaming AEAD vectors consume the authenticated transfer
    /// record rather than the MLS attachment transcript. They pin exact bytes,
    /// Range response geometry, segment authentication, and overall digest.
    file_transfer_stream_aead_fixture_suite_matches_reference_semantics,
    "file_transfer_stream_aead_fixture",
    cotest::conformance::run_file_transfer_stream_aead_fixture_suite,
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
    /// participant_binding_invalid and the call lifecycle keeps initial,
    /// transition, terminal, replay, and competing-predecessor behavior aligned.
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
    /// Auth/session proof vectors promoted to spec artifacts. Asserts session
    /// grant audience binding and sender-constrained PoP behavior.
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
    /// SessionGrant issuer-ledger pure KATs pin canonical IDs/digests and the
    /// durable exact-replay reference semantics.
    session_grant_issuer_ledger,
    "session_grant_issuer_ledger",
    cotest::conformance::run_session_grant_issuer_ledger_suite,
);

conformance_test!(
    /// Bound recovery completion consumes signed root-anchored terminal
    /// evidence and issues one directly usable Standard grant. Exact replay
    /// is byte-identical and every evidence/session mutation fails closed.
    recovery_completion_grant,
    "recovery_completion_grant",
    cotest::conformance::run_recovery_completion_grant_suite,
);

conformance_test!(
    /// Agent membership is immediately AND-gated by the exact
    /// controller generation, while explicit cleanup stays caller-signed,
    /// complete-set, durable and atomic.
    agent_membership_cascade,
    "agent_membership_cascade",
    cotest::conformance::run_agent_membership_cascade_suite,
);

conformance_test!(
    /// Durable accepted revocation blocks every closed action class, while
    /// SessionGrant issue/refresh consume a fresh exact origin-PS receipt and
    /// client material survives pending until a covering Seal is accepted.
    device_revocation_pending,
    "device_revocation_pending",
    cotest::conformance::run_device_revocation_pending_suite,
);

conformance_test!(
    /// A missing verified route remains a durable per-target obligation and
    /// never rolls back an otherwise admitted Realm Event.
    fanout_route_miss,
    "fanout_route_miss",
    cotest::conformance::run_fanout_route_miss_suite,
);

conformance_test!(
    /// The per-holder new-source quota clamps every holder override to the
    /// deployment ceiling, admits exactly up to the effective sliding limits,
    /// never charges or refreshes a seen source, never ledgers a dropped one,
    /// and stays inside the opaque deferred equivalence class throughout.
    invite_new_source_quota,
    "invite_new_source_quota",
    cotest::conformance::run_invite_new_source_quota_suite,
);

conformance_test!(
    /// Protocol-gap closure vectors assert proposal quorum evidence, durable
    /// security-transaction replay, closed track names, and WebSocket fallback.
    protocol_gap_closure_fixture_suite_matches_reference_semantics,
    "protocol_gap_closure_fixture",
    cotest::conformance::run_protocol_gap_closure_fixture_suite,
);
