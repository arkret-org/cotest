mod agent_mls_keypackage_authorization;
mod agent_participation;
mod agent_signer_evidence;
mod agent_vectors;
mod arkret_private_kdf_and_durability;
mod audit_release;
mod auth_session_proof;
mod blind_payload;
mod blob_stream_aead;
mod call_signal;
mod call_state_core;
mod call_state_media_lifecycle;
mod canonical_cross_lang;
mod canonical_fixture;
mod capability;
mod coauth_lifecycle;
mod control_proposal;
mod cross_signing_binding_golden;
mod cursor_vectors;
mod did_webvh_v1;
mod encoding;
mod envelope;
mod federation;
mod final_conformance_closure;
mod handle_claim_rejection_vectors;
mod history_crypto_closure;
mod identity_root;
mod inkson_client;
mod key_backup_hardening;
mod keypackage_lifecycle;
mod lattice_mixed_kinds;
mod lattice_round_trip;
mod list_handles_for_subject_vectors;
mod long_text_content;
mod media_aead_nonce;
mod media_binding;
mod member_identity_vectors;
mod member_roster_vectors;
mod mention_rendering_vectors;
mod object_addressing_vectors;
mod operation_clause_registry;
mod operation_registry_gate;
mod policy_server;
mod presence_signal;
mod primary_handle_vectors;
mod principal_server_certification;
mod privacy;
mod privacy_security;
mod private_chat_privacy;
mod profile_matrix;
mod profile_registry;
mod protocol_gap_closure;
mod push_rule_core;
mod redaction;
mod reducer_profile;
mod scaffold_gate;
mod scalability_limits;
mod schema_validation;
mod schema_validation_fixture;
mod security_closure;
mod security_negative;
mod service_closure_hardening;
mod sidecar_vectors;
mod signal_federation;
mod spec_business_flow;
mod state_reducer_hardening;
mod state_resolution;
mod sync;
mod vector_registry_gate;
mod visibility_policy;
mod wire;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const ARTIFACT_REGISTRY_DIR: &str = "registry";
const ARTIFACT_FIXTURES_DIR: &str = "fixtures";

// ── Public suite re-exports ─────────────────────────────────────────────────

pub use agent_mls_keypackage_authorization::run_agent_mls_keypackage_authorization_vector;
pub use agent_participation::{
    ALL_AGENT_PARTICIPATION_VECTOR_IDS, run_agent_mention_selector_vector,
    run_agent_participation_ceiling_tighten_vector,
    run_agent_participation_effective_intersection_vector, run_agent_participation_fixture_suite,
    run_agent_participation_selection_within_ceiling_vector,
    run_agent_participation_session_overlay_vector,
    run_agent_participation_third_party_mention_gate_vector,
};
pub use agent_signer_evidence::{
    AGENT_SIGNER_EVIDENCE_FIXTURE, AGENT_SIGNER_EVIDENCE_SUITE, ALL_AGENT_SIGNER_EVIDENCE_CASES,
    run_agent_signer_evidence_vector_suite,
};
pub use agent_vectors::{
    ALL_AGENT_VECTOR_IDS, run_agent_act_on_behalf_vector, run_agent_controller_lifecycle_vector,
    run_agent_human_approval_required_vector, run_agent_longevity_no_expiry_vector,
    run_agent_managed_pcr_separation_vector, run_agent_pairing_expiry_vector,
    run_agent_provision_vector, run_agent_repairing_supersede_vector,
    run_agent_runtime_key_binding_vector, run_agent_session_grant_replay_vector,
    run_agent_vector_suite, validate_agent_human_approval_http_response,
};
pub use arkret_private_kdf_and_durability::run_arkret_private_kdf_and_durability_suite;
pub use audit_release::{
    ALL_AUDIT_RELEASE_VECTOR_IDS, run_audit_release_vector_suite,
    run_binding_and_authorization_gate_vector, run_binding_fsm_vector,
    run_close_release_concurrency_vector, run_release_recipient_binding_vector,
    run_release_window_vector, run_ryw_before_output_vector, run_session_fsm_vector,
};
pub use auth_session_proof::{
    ALL_AUTH_SESSION_PROOF_VECTOR_IDS, run_auth_session_grant_audience_binding_vector,
    run_auth_session_proof_fixture_suite, run_auth_soft_logout_did_proof_vector,
    run_identity_did_proof_replay_window_vector, run_session_bare_bearer_rejected_protected_vector,
    run_session_pop_presentation_vector,
};
pub use blind_payload::{
    run_blind_payload_sanitizer_suite, run_blind_payload_sanitizer_suite_counts,
};
pub use blob_stream_aead::{
    ALL_BLOB_STREAM_AEAD_VECTOR_IDS, run_blob_stream_aead_fixture_suite,
    run_stream_aead_reorder_rejected_vector, run_stream_aead_roundtrip_vector,
    run_stream_aead_scheme_closure_vector, run_stream_aead_truncation_rejected_vector,
};
pub use call_signal::{
    ALL_CALL_SIGNAL_VECTOR_IDS, run_call_signal_vector_suite,
    run_outer_metadata_minimal_vector as run_call_signal_outer_metadata_minimal_vector,
    run_proof_detached_jws_vector, run_seq_monotonic_vector, run_signal_kind_enum_vector,
};
pub use call_state_core::{
    ALL_CALL_STATE_CORE_VECTOR_IDS, run_call_state_core_fixture_suite,
    run_concurrent_sibling_bottom_vector, run_initial_state_accepts_allowed_vector,
    run_participant_binding_invalid_vector, run_replay_same_state_noop_vector,
    run_terminal_absorbing_vector, run_transition_matrix_vector,
};
pub use call_state_media_lifecycle::{
    ALL_CALL_STATE_MEDIA_LIFECYCLE_VECTOR_IDS, run_call_state_media_lifecycle_vector_suite,
    run_moderator_kick_ban_vector, run_p2p_to_sfu_upgrade_vector,
    run_recording_result_artifact_shape_vector, run_recording_retention_lock_vector,
    run_transcribe_lifecycle_vector,
};
pub use canonical_cross_lang::run_canonical_cross_lang_suite;
pub use canonical_fixture::{
    CANONICAL_FIXTURE_DEFAULT_KIND, CanonicalFixtureBuilder, CanonicalFixtureSuite,
    CanonicalFixtureVector,
};
pub use capability::{
    run_capability_boundary_fixture_suite, run_capability_facet_fixture_suite,
    run_capability_fixture_suite,
};
pub use coauth_lifecycle::run_coauth_account_lifecycle_fixture_suite;
pub use control_proposal::run_control_proposal_bounded_decision_suite;
pub use cross_signing_binding_golden::run_cross_signing_binding_golden_suite;
pub use cursor_vectors::{
    ALL_CURSOR_VECTOR_IDS, run_cursor_opaque_core_vector, run_cursor_vector_suite,
};
pub use did_webvh_v1::run_did_webvh_v1_adapter_fixture_suite;
pub use encoding::{
    run_encoding_fixture_suite, run_projection_position_discriminator_fixture_suite,
};
pub use envelope::{
    run_container_realm_control_payload_suite, run_deprecated_event_alias_suite,
    run_event_envelope_fixture_suite,
};
pub use federation::run_federation_fixture_suite;
pub use final_conformance_closure::{
    ALL_FINAL_CONFORMANCE_CLOSURE_VECTOR_IDS,
    run_applet_transaction_source_signature_anchor_vector, run_calendar_rsvp_occurrence_key_vector,
    run_federation_timing_bucket_vector, run_final_conformance_closure_fixture_suite,
    run_mls_governance_epoch_binding_vector, run_moderation_appeal_atomicity_vector,
    run_moderation_evidence_package_minimal_disclosure_vector,
    run_moderation_franking_roundtrip_vector,
    run_relation_reference_projection_indistinguishable_vector,
    run_sync_range_completeness_client_query_vector,
};
pub use handle_claim_rejection_vectors::{
    ALL_HANDLE_CLAIM_REJECTION_VECTOR_IDS, run_handle_claim_rejection_vector_suite,
    run_service_handle_rejected_vector, run_subject_not_principal_did_rejected_vector,
};
pub use history_crypto_closure::{
    ALL_HISTORY_CRYPTO_CLOSURE_VECTOR_IDS, run_disappearing_on_last_read_offline_window_vector,
    run_disappearing_read_trigger_anonymous_aggregate_vector,
    run_disappearing_read_trigger_idempotent_replay_vector,
    run_e2ee_late_key_recovery_t0_deterministic_visibility_vector,
    run_history_crypto_closure_fixture_suite,
    run_history_sharing_e2ee_prejoin_key_share_policy_vector,
    run_preview_token_scoped_stripped_state_vector,
};
pub use identity_root::{
    run_identity_model_generation_fence_suite, run_identity_recovery_kdf_fixture_suite,
    run_identity_root_anchor_checkpoint_suite,
};
pub use inkson_client::run_inkson_client_profile_manifest_suite;
pub use key_backup_hardening::{
    ALL_KEY_BACKUP_HARDENING_VECTOR_IDS, run_key_backup_hardening_fixture_suite,
    run_key_backup_kdf_floor_rejected_vector, run_key_backup_unlock_proof_vector,
};
pub use keypackage_lifecycle::{
    ALL_KEYPACKAGE_LIFECYCLE_VECTOR_IDS, run_keypackage_exhaustion_claim_limits_vector,
    run_keypackage_last_resort_affinity_and_optionality_vector,
    run_keypackage_last_resort_claim_and_reuse_vector,
    run_keypackage_last_resort_forced_rotation_vector, run_keypackage_lifecycle_fixture_suite,
    run_mls_welcome_keypackage_hash_vector,
};
pub use lattice_mixed_kinds::run_lattice_mixed_kinds_suite;
pub use lattice_round_trip::run_lattice_round_trip_suite;
pub use list_handles_for_subject_vectors::{
    ALL_LIST_HANDLES_FOR_SUBJECT_VECTOR_IDS, run_as_of_historical_replay_vector,
    run_audience_filter_applied_vector, run_cursor_pagination_vector,
    run_happy_path_single_claim_vector, run_issuer_trust_filter_vector,
    run_list_handles_for_subject_vector_suite, run_primary_handle_field_aligned_with_3_2_1_vector,
    run_subject_mismatch_rejected_vector,
};
pub use long_text_content::run_long_text_content_fixture_suite;
pub use media_aead_nonce::{
    ALL_MEDIA_AEAD_NONCE_VECTOR_IDS, run_aead_nonce_counter_replay_vector,
    run_aead_nonce_random_rejected_vector, run_aead_nonce_sender_domain_collision_vector,
    run_media_aead_nonce_fixture_suite,
};
pub use media_binding::{
    ALL_MEDIA_BINDING_VECTOR_IDS, run_e2ee_key_source_vector,
    run_focus_selection_oldest_membership_vector, run_media_binding_vector_suite,
    run_participant_binding_required_vector, run_participant_identity_unrecognised_vector,
    run_recording_artifact_via_arkret_blob_vector, run_recording_exporter_label_vector,
    run_session_focus_no_split_brain_vector, run_token_exchange_minimal_vector,
    run_token_issuer_unauthorised_vector, run_unknown_type_fail_closed_vector,
};
pub use member_identity_vectors::{
    ALL_MEMBER_IDENTITY_VECTOR_IDS, run_member_identity_cross_subject_replacement_ignored_vector,
    run_member_identity_expected_state_digest_mismatch_vector,
    run_member_identity_handle_field_forbidden_vector, run_member_identity_proof_invalid_vector,
    run_member_identity_replacement_digest_mismatch_vector,
    run_member_identity_unknown_segment_rejected_vector, run_member_identity_update_initial_vector,
    run_member_identity_update_replacement_vector, run_member_identity_vector_suite,
    sample_member_identity_value,
};
pub use member_roster_vectors::{
    ALL_MEMBER_ROSTER_VECTOR_IDS,
    run_member_roster_display_state_digest_stable_under_freshness_hints_vector,
    run_member_roster_handle_claims_limited_semantics_vector,
    run_member_roster_handle_claims_subject_alignment_vector, run_member_roster_limited_vector,
    run_member_roster_shape_vector,
    run_member_roster_subject_undisclosed_omits_gated_fields_vector,
    run_member_roster_vector_suite, run_member_roster_with_inline_identity_events_vector,
};
pub use mention_rendering_vectors::{
    ALL_MENTION_RENDERING_VECTOR_IDS, run_actor_attribution_independent_of_handle_at_time_vector,
    run_mention_rendering_vector_suite, run_new_shape_accepted_vector,
    run_render_fallback_cached_vector, run_render_fallback_name_only_vector,
    run_render_fallback_unresolved_vector, run_render_step1_multi_to_step2_live_vector,
    run_render_step1_unique_success_vector,
};
pub use object_addressing_vectors::{
    ALL_OBJECT_ADDRESSING_VECTOR_IDS, run_grammar_fail_closed_vector,
    run_object_addressing_vector_suite, run_realm_id_vs_alias_vector,
    run_realm_strand_message_forms_vector, run_resolve_target_common_fields_vector,
    run_resolve_target_realm_preview_vector, run_scheme_fragment_equivalence_vector,
    run_scope_confusion_replay_vector, run_scope_token_address_link_kind_wins_vector,
    run_target_digest_ignores_hints_vector, run_target_digest_omits_absent_vector,
    run_target_digest_tracks_object_vector,
};
pub use operation_clause_registry::validate_operation_clause_registry;
pub use operation_registry_gate::{
    OperationRegistryGateEntry, OperationRegistryGatePaths, OperationRegistryGateReport,
    OperationRegistryGateStatus, OperationSourceRoot, build_operation_registry_gate_report,
    build_operation_registry_gate_report_from_paths, validate_operation_registry_gate,
    validate_operation_registry_gate_report,
};
pub use policy_server::run_policy_server_fixture_suite;
pub use presence_signal::{
    ALL_PRESENCE_SIGNAL_VECTOR_IDS, run_last_active_at_bucket_vector,
    run_multi_device_aggregation_vector, run_presence_signal_vector_suite,
    run_state_closed_set_vector, run_status_message_bounds_vector,
};
pub use primary_handle_vectors::{
    ALL_PRIMARY_HANDLE_VECTOR_IDS, run_as_of_replay_vs_realtime_vector,
    run_audience_match_wins_vector, run_claim_digest_stable_under_hint_vector,
    run_empty_candidate_fallback_vector, run_holder_flag_wins_over_most_recent_vector,
    run_holder_primary_null_skips_layer_vector, run_most_recent_wins_when_neither_vector,
    run_policy_snapshot_as_of_replay_vector, run_primary_handle_vector_suite,
    run_single_candidate_passthrough_vector, run_tie_break_by_accepted_issuers_position_vector,
    run_tie_break_by_claim_digest_vector, run_tie_break_by_created_at_vector,
};
pub use principal_server_certification::{
    PrincipalCertificationStatus, run_principal_server_certification_gate_suite,
    validate_principal_server_certification,
};
pub use privacy::run_privacy_security_fixture_suite;
pub use privacy_security::run_minimal_metadata_author_credential_vector;
pub use private_chat_privacy::run_private_chat_privacy_contract_suite;
pub use profile_matrix::{run_profile_requirement_gate_suite, validate_server_profile_claims};
pub use profile_registry::{
    ProfileGateEntry, ProfileGateReport, ProfileGateStatus, build_profile_gate_report,
    render_profile_gate_report_json, render_profile_gate_report_markdown,
};
pub use protocol_gap_closure::run_protocol_gap_closure_fixture_suite;
pub use push_rule_core::{
    run_hardened_mention_routing_hint_vector, run_push_rule_core_fixture_suite,
};
pub use redaction::run_redaction_fixture_suite;
pub use reducer_profile::{FEDERATION_MINIMAL_PROFILE_ID, reducer_profile_digest};
pub use scaffold_gate::{
    run_live_describe_profile_gate_suite, run_scaffold_profile_gate_suite,
    validate_scaffold_profile_gate,
};
pub use scalability_limits::run_scalability_limits_fixture_suite;
pub use schema_validation::run_schema_validation_suite;
pub use schema_validation_fixture::{
    SCHEMA_VALIDATION_FIXTURE, SCHEMA_VALIDATION_PROFILE, SchemaValidationCase,
    SchemaValidationFixture, run_schema_validation_fixture_suite,
};
pub use security_closure::{
    ObservedRunner, REQUIRED_SECURITY_CLOSURE_VECTOR_IDS, SECURITY_CLOSURE_VECTORS_FIXTURE,
    SECURITY_CLOSURE_VECTORS_PROFILE, SecurityClosureExpected, SecurityClosureFixture,
    SecurityClosureRunner, SecurityClosureStep, SecurityClosureVector,
    run_security_closure_fixture_suite, validate_security_closure_fixture,
};
pub use security_negative::run_security_negative_profile_suite;
pub use service_closure_hardening::{
    ALL_SERVICE_CLOSURE_HARDENING_VECTOR_IDS, run_cursor_revoke_high_assurance_vector,
    run_device_recovery_lifecycle_vector, run_device_revocation_seal_binding_vector,
    run_invite_consumed_token_resubject_rejected_vector, run_projection_pagination_shape_vector,
    run_push_wakeup_policy_vector, run_range_completeness_witness_disagreement_vector,
    run_service_closure_hardening_fixture_suite, run_signal_class_ttl_vector,
};
pub use sidecar_vectors::{
    ALL_SIDECAR_VECTOR_IDS, run_sidecar_eligibility_states_vector,
    run_sidecar_ensure_idempotent_vector, run_sidecar_existence_privacy_vector,
    run_sidecar_hosted_projection_vector, run_sidecar_mls_bootstrap_binding_vector,
    run_sidecar_mls_effective_access_vector, run_sidecar_multi_agent_publish_vector,
    run_sidecar_vector_suite,
};
pub use signal_federation::run_signal_federation_fixture_suite;
pub use spec_business_flow::run_spec_business_flow_coverage_suite;
pub use state_reducer_hardening::{
    ALL_STATE_REDUCER_HARDENING_VECTOR_IDS, run_state_reducer_hardening_fixture_suite,
    run_state_root_incremental_vector, run_strand_tracks_update_atomic_vector,
};
pub use state_resolution::{run_cba_lattice_fixture_suite, run_state_resolution_fixture_suite};
pub use sync::{run_stream_frame_sequence_vector, run_sync_fixture_suite};
pub use vector_registry_gate::{
    VectorRegistryGateEntry, VectorRegistryGateMode, VectorRegistryGateReport,
    VectorRegistryGateStatus, build_vector_registry_gate_report,
    build_vector_registry_gate_report_from_paths, fixture_digest_hex,
    validate_vector_registry_gate, validate_vector_registry_gate_report,
    validate_vector_registry_gate_report_with_mode,
};
pub use visibility_policy::{
    ALL_VISIBILITY_POLICY_VECTOR_IDS, run_circle_content_floor_below_realm_rejected_vector,
    run_content_floor_downgrade_rejected_vector,
    run_directory_visibility_members_indistinguishable_vector,
    run_directory_visibility_realm_members_indistinguishable_vector,
    run_history_visibility_joined_prejoin_denied_vector, run_in_place_e2ee_enable_vector,
    run_metadata_floor_downgrade_rejected_vector, run_visibility_policy_fixture_suite,
};
pub use wire::{
    run_anchor_view_compaction_fixture_suite, run_anchorer_cell_fixture_suite,
    run_composite_state_key_encoding_fixture_suite, run_composite_state_subject_fixture_suite,
    run_conflict_repair_fixture_suite, run_consent_fixture_suite,
    run_constraint_evaluation_class_fixture_suite, run_constraint_family_fixture_suite,
    run_cross_signing_reset_fixture_suite, run_device_cross_signing_trust_fixture_suite,
    run_device_message_negative_fixture_suite, run_device_verification_fixture_suite,
    run_discovery_profile_fixture_suite, run_event_kind_lattice_dispatch_fixture_suite,
    run_event_kind_payload_coverage_fixture_suite, run_facet_renderer_query_fixture_suite,
    run_frontier_conflict_resolution_fixture_suite, run_history_visibility_fixture_suite,
    run_history_visibility_projection_matrix_check, run_interop_downgrade_fixture_suite,
    run_key_backup_aead_round_trip_check, run_key_backup_encryption_fixture_suite,
    run_late_arriving_anchor_fixture_suite, run_late_arriving_anchor_idempotency_check,
    run_megolm_ratchet_kdf_chain_check, run_megolm_ratcheting_fixture_suite,
    run_membership_fsm_fixture_suite, run_mimi_components_fixture_suite,
    run_mimi_interop_fixture_suite, run_mls_e2ee_basic_fixture_suite,
    run_mls_move_covered_frontier_fixture_suite, run_multi_admin_distinct_approver_gate_check,
    run_multi_realm_federation_fixture_suite, run_production_signing_fixture_suite,
    run_read_receipt_policy_fixture_suite, run_recovery_bridge_full_chain_fixture_suite,
    run_recovery_ticket_state_machine_check, run_redacted_cross_server_fixture_suite,
    run_redaction_history_visibility_fixture_suite, run_restore_full_workflows_fixture_suite,
    run_state_resolution_quarantine_fixture_suite, run_threshold_multisig_fixture_suite,
};

// ── Shared fixture types ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(crate) struct EncodingFixture {
    pub(crate) suite: String,
    pub(crate) cases: EncodingCases,
}

#[derive(Debug, Deserialize)]
pub(crate) struct EncodingCases {
    pub(crate) canonical_json: Vec<CanonicalJsonCase>,
    pub(crate) hash_digest: Vec<HashDigestCase>,
    pub(crate) proof_payload: Vec<ProofPayloadCase>,
    pub(crate) hlc: Vec<HlcCase>,
    pub(crate) cursor: Vec<CursorCase>,
    pub(crate) fractional_rank: Vec<FractionalRankCase>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CanonicalJsonCase {
    pub(crate) name: String,
    pub(crate) input: Value,
    pub(crate) canonical: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HashDigestCase {
    pub(crate) name: String,
    pub(crate) input_ref: String,
    pub(crate) expected_pattern: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ProofPayloadCase {
    pub(crate) name: String,
    pub(crate) covered_fields: Vec<String>,
    pub(crate) excluded_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct HlcCase {
    pub(crate) name: String,
    pub(crate) values: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct CursorShape {
    pub(crate) v: String,
    pub(crate) x: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CursorCase {
    pub(crate) name: String,
    pub(crate) shape: CursorShape,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FractionalRankCase {
    pub(crate) name: String,
    pub(crate) left: Option<String>,
    pub(crate) right: Option<String>,
    pub(crate) expected: Option<String>,
    pub(crate) input: Option<String>,
    pub(crate) max_length: Option<usize>,
    pub(crate) active_edge_count: Option<usize>,
    pub(crate) assignment_count: Option<usize>,
    pub(crate) ordered_edges: Option<Vec<RankEdge>>,
    pub(crate) expected_assignments: Option<Vec<RankAssignment>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RedactionFixture {
    pub(crate) suite: String,
    pub(crate) cases: Vec<RedactionCase>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RedactionCase {
    pub(crate) name: String,
    pub(crate) preserve: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FederationFixture {
    pub(crate) suite: String,
    pub(crate) cases: Vec<NamedCase>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PrivacySecurityFixture {
    pub(crate) suite: String,
    pub(crate) cases: Vec<NamedCase>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct NamedCase {
    pub(crate) name: String,
    pub(crate) vector_id: Option<String>,
    pub(crate) operation_id: Option<String>,
    pub(crate) operation_ids: Option<Vec<String>>,
    pub(crate) covers_vectors: Option<Vec<String>>,
    pub(crate) input: Option<Value>,
    pub(crate) inputs: Option<Vec<Value>>,
    pub(crate) expected: Option<Value>,
    // ak.vector.federation.reducer_profile_digest.v1 case fields.
    pub(crate) resolved_digest_input_source: Option<ResolvedDigestInputSource>,
    pub(crate) expected_digest: Option<String>,
    pub(crate) sender_reducer_profile_digest: Option<String>,
    pub(crate) receiver_reducer_profile_digest: Option<String>,
    pub(crate) request_contract: Option<Value>,
    pub(crate) cases: Option<Vec<Value>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ResolvedDigestInputSource {
    pub(crate) registry: String,
    pub(crate) profile_id: String,
    pub(crate) field: String,
    pub(crate) recompute_from_local_contracts: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct RankEdge {
    pub(crate) relation_id: String,
    pub(crate) object_ref: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub(crate) struct RankAssignment {
    pub(crate) relation_id: String,
    pub(crate) object_ref: String,
    pub(crate) rank: String,
}

// ── Shared utility functions ────────────────────────────────────────────────

pub(crate) fn spec_artifacts_root() -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ARTIFACTS_ROOT") {
        return PathBuf::from(root);
    }

    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        let root = PathBuf::from(root);
        for candidate in spec_artifact_candidates(&root) {
            if candidate.join(ARTIFACT_REGISTRY_DIR).is_dir() {
                return candidate;
            }
        }
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts")
}

pub(crate) fn fixture_path(file_name: &str) -> PathBuf {
    if let Some(root) = std::env::var_os("COTEST_SPEC_ROOT") {
        let root = PathBuf::from(root);
        for artifact_root in spec_artifact_candidates(&root) {
            let candidate = artifact_root.join(ARTIFACT_FIXTURES_DIR).join(file_name);
            if candidate.is_file() {
                return candidate;
            }
        }
    }

    spec_artifacts_root()
        .join(ARTIFACT_FIXTURES_DIR)
        .join(file_name)
}

/// Resolve a fixture that lives in cotest's own `tests/fixtures/` tree (as
/// opposed to [`fixture_path`], which resolves arkret-spec artifact fixtures).
/// Exposed to the integration-test crate so `tests/*.rs` can share one local
/// loader instead of re-deriving the root.
pub fn local_fixture_path(file_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(file_name)
}

/// Read and parse a cotest-local fixture (`tests/fixtures/<file_name>`).
pub fn load_local_fixture_value(file_name: &str) -> Result<Value> {
    let path = local_fixture_path(file_name);
    let raw = fs::read_to_string(&path)?;
    serde_json::from_str(&raw)
        .map_err(|error| anyhow!("failed to parse local fixture {}: {error}", path.display()))
}

fn spec_artifact_candidates(root: &Path) -> Vec<PathBuf> {
    vec![
        root.to_owned(),
        root.join("spec").join("v1").join("artifacts"),
    ]
}

pub(crate) fn load_fixture<T>(file_name: &str) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    parse_fixture_value(file_name, load_fixture_value(file_name)?)
}

pub(crate) fn load_fixture_value(file_name: &str) -> Result<Value> {
    let path = fixture_path(file_name);
    let raw = fs::read_to_string(&path)?;
    serde_json::from_str(&raw)
        .map_err(|error| anyhow!("failed to parse fixture {}: {error}", path.display()))
}

pub(crate) fn parse_fixture_value<T>(file_name: &str, value: Value) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(value)
        .map_err(|error| anyhow!("failed to parse fixture {file_name}: {error}"))
}

pub(crate) fn load_artifact_json(relative_path: &str) -> Result<Value> {
    let path = spec_artifacts_root().join(relative_path);
    let raw = fs::read_to_string(&path)?;
    serde_json::from_str(&raw)
        .map_err(|error| anyhow!("failed to parse artifact {}: {error}", path.display()))
}

pub(crate) fn validate_profile(value: &Value, expected: &str) -> Result<()> {
    let profile = value
        .get("profile")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("fixture artifact missing profile"))?;
    if profile != expected {
        bail!("fixture profile drifted: expected {expected}, got {profile}");
    }
    Ok(())
}

pub(crate) fn string_array_field<'a>(value: &'a Value, field: &str) -> Result<Vec<&'a str>> {
    value
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| anyhow!("{field} entry must be a string"))
        })
        .collect::<Result<Vec<_>>>()
}

pub(crate) fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {field}"))
}

pub(crate) fn fixture_runner_entrypoint(value: &Value) -> Result<&str> {
    value
        .get("runner")
        .and_then(Value::as_object)
        .and_then(|runner| runner.get("entrypoint"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("fixture runner must be an object with string entrypoint"))
}

pub(crate) fn required_field<'a>(value: &'a Value, field: &str) -> Result<&'a Value> {
    value
        .as_object()
        .and_then(|object| object.get(field))
        .ok_or_else(|| anyhow!("missing object field {field}"))
}

pub(crate) fn value_array<'a>(value: &'a Value, context: &str) -> Result<&'a Vec<Value>> {
    value
        .as_array()
        .ok_or_else(|| anyhow!("{context} must be an array"))
}

pub(crate) fn value_field_str<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    required_field(value, field)?
        .as_str()
        .ok_or_else(|| anyhow!("object field {field} must be a string"))
}

pub(crate) fn value_field_u64(value: &Value, field: &str) -> Result<u64> {
    required_field(value, field)?
        .as_u64()
        .ok_or_else(|| anyhow!("object field {field} must be an unsigned integer"))
}

pub(crate) fn canonical_json(value: &Value) -> Result<String> {
    // Delegate to the SDK's canonical encoder so every Arkret implementation
    // sorts keys / encodes numbers identically. `canonical_json_bytes` is the
    // single normative source of canonical bytes (spec encoding.md §9.5); the
    // bytes are valid UTF-8 so the historical `String` return type is preserved.
    let bytes = arkret_canonical::canonical_json_bytes(value)
        .map_err(|err| anyhow!("canonical JSON encoding failed: {err}"))?;
    String::from_utf8(bytes).map_err(|err| anyhow!("canonical JSON produced invalid UTF-8: {err}"))
}

pub(crate) fn sha256_prefixed(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity("sha256:".len() + digest.len() * 2);
    out.push_str("sha256:");
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

pub(crate) fn looks_like_sha256_digest(value: &str) -> bool {
    value.starts_with("sha256:")
        && value.len() == "sha256:".len() + 64
        && value["sha256:".len()..]
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase())
}

pub(crate) fn canonical_proof_payload(event: &Value) -> Result<Map<String, Value>> {
    let object = event
        .as_object()
        .ok_or_else(|| anyhow!("proof payload source must be an object"))?;
    let mut payload = Map::new();
    for (key, value) in object {
        if key != "unsigned" {
            payload.insert(key.clone(), value.clone());
        }
    }
    Ok(payload)
}

pub(crate) fn encode_cursor_shape(shape: &CursorShape) -> Result<String> {
    let canonical = canonical_json(&serde_json::to_value(shape)?)?;
    Ok(format!(
        "ak:cursor:{}",
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            canonical.as_bytes()
        )
    ))
}

pub(crate) fn decode_cursor_shape(encoded: &str) -> Result<CursorShape> {
    use base64::Engine as _;
    let payload = encoded
        .strip_prefix("ak:cursor:")
        .ok_or_else(|| anyhow!("cursor must start with ak:cursor:"))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload)?;
    serde_json::from_slice(&bytes).map_err(Into::into)
}

pub(crate) const RANK_ALPHABET: &str =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
pub(crate) const RANK_MAX_LENGTH: usize = 128;

pub(crate) fn rank_between(left: Option<&str>, right: Option<&str>) -> Result<String> {
    let left = left.unwrap_or("");
    let right = right.unwrap_or("");
    validate_rank_boundary(left)?;
    validate_rank_boundary(right)?;
    if !left.is_empty() && !right.is_empty() && left >= right {
        bail!("left rank must be lower than right rank");
    }

    let alphabet = RANK_ALPHABET.as_bytes();
    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();
    let mut prefix: Vec<u8> = Vec::with_capacity(8);
    let mut index = 0usize;
    while prefix.len() < RANK_MAX_LENGTH {
        let lower = left_bytes
            .get(index)
            .map(|byte| rank_byte_index(*byte).expect("validated rank boundary"))
            .unwrap_or(-1);
        let upper = if right_bytes.is_empty() {
            alphabet.len() as i32
        } else {
            right_bytes
                .get(index)
                .map(|byte| rank_byte_index(*byte).expect("validated rank boundary"))
                .unwrap_or(alphabet.len() as i32)
        };
        if upper - lower > 1 {
            prefix.push(alphabet[((lower + upper) / 2) as usize]);
            return String::from_utf8(prefix).map_err(Into::into);
        }
        if let Some(byte) = left_bytes.get(index) {
            prefix.push(*byte);
        } else {
            prefix.push(alphabet[0]);
            if !right_bytes.is_empty() && prefix.as_slice() == right_bytes {
                bail!("no rank available between boundaries");
            }
            return String::from_utf8(prefix).map_err(Into::into);
        }
        index += 1;
    }
    bail!("no rank available between boundaries");
}

fn validate_rank_boundary(rank: &str) -> Result<()> {
    if rank.len() > RANK_MAX_LENGTH || !rank.bytes().all(|byte| rank_byte_index(byte).is_some()) {
        bail!("invalid_rank");
    }
    Ok(())
}

fn rank_byte_index(byte: u8) -> Option<i32> {
    RANK_ALPHABET
        .as_bytes()
        .iter()
        .position(|candidate| *candidate == byte)
        .map(|index| index as i32)
}

pub(crate) fn validate_rank(rank: &str, max_length: usize) -> Result<()> {
    if rank.is_empty() || rank.len() > max_length {
        bail!("invalid_rank");
    }
    if !rank.chars().all(|ch| RANK_ALPHABET.contains(ch)) {
        bail!("invalid_rank");
    }
    Ok(())
}

pub(crate) fn rebalance_assignments(edges: &[RankEdge]) -> Result<Vec<RankAssignment>> {
    let count = edges.len();
    validate_rebalance_assignment_count(count, count)?;
    if count == 0 {
        return Ok(Vec::new());
    }
    let denominator = count as u128 + 1;
    let required_capacity = denominator
        .checked_mul(2)
        .ok_or_else(|| anyhow!("too many rank rebalance assignments"))?;
    let mut width = 0usize;
    let mut capacity = 1u128;
    while capacity < required_capacity {
        width += 1;
        if width > RANK_MAX_LENGTH {
            bail!("too many rank rebalance assignments");
        }
        capacity = capacity
            .checked_mul(RANK_ALPHABET.len() as u128)
            .ok_or_else(|| anyhow!("too many rank rebalance assignments"))?;
    }
    edges
        .iter()
        .enumerate()
        .map(|(index, edge)| {
            let rank_number = (index as u128 + 1)
                .checked_mul(capacity)
                .map(|product| product / denominator)
                .ok_or_else(|| anyhow!("too many rank rebalance assignments"))?;
            Ok(RankAssignment {
                relation_id: edge.relation_id.clone(),
                object_ref: edge.object_ref.clone(),
                rank: format_rank_number(rank_number, width),
            })
        })
        .collect()
}

fn format_rank_number(mut value: u128, width: usize) -> String {
    let alphabet = RANK_ALPHABET.as_bytes();
    let mut output = vec![alphabet[0]; width];
    for byte in output.iter_mut().rev() {
        *byte = alphabet[(value % alphabet.len() as u128) as usize];
        value /= alphabet.len() as u128;
    }
    String::from_utf8(output).expect("rank alphabet is valid UTF-8")
}

pub(crate) fn validate_rebalance_assignment_count(
    active_edge_count: usize,
    assignment_count: usize,
) -> Result<()> {
    if active_edge_count != assignment_count {
        bail!("invalid_rebalance_assignment");
    }
    Ok(())
}
