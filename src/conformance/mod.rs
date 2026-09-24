mod account_blocklist_projection;
mod account_data_cas_convergence;
mod account_status_issuer_ledger;
mod aead_nonce_replay;
mod agent_draft_pending_intent_account_subscribe;
mod agent_membership_cascade;
mod agent_mls_keypackage_authorization;
mod agent_pairing_coordination;
mod agent_participation;
#[cfg(test)]
mod agent_runtime_scope;
mod agent_signer_evidence;
mod agent_vectors;
mod applet_install;
mod arkret_private_kdf_and_durability;
mod auth_session_proof;
mod authority_commit;
mod authority_event_submit_carriers;
mod blind_payload;
mod blob_stream_aead;
mod call_signal;
mod call_state_core_executable;
mod call_state_media_lifecycle;
mod canonical_cross_lang;
mod canonical_fixture;
mod capability;
mod capability_relinquish_authoring;
mod coauth_lifecycle;
mod crypto_hpke;
mod cursor_negative;
mod cursor_vectors;
mod decision_0017_vectors;
mod detached_object_signature;
mod device_pairing_code_claim;
mod device_revocation_pending;
mod did_binding_digests;
mod did_webvh_v1;
mod digest_construction;
mod direct_conversation_admission;
mod direct_conversation_flow;
mod downstream_impact;
mod encoding;
mod envelope;
mod fanout_route_miss;
mod federation;
mod file_transfer_stream_aead;
mod final_conformance_closure;
mod fixture_dsl;
mod franking_proof;
mod handle_claim_rejection_vectors;
mod helpers;
mod identity_root;
mod inkson_client;
mod invite_new_source_quota;
mod key_backup_hardening;
mod keypackage_lifecycle;
mod keypackage_write_transcripts;
mod long_text_content;
mod media_binding;
mod member_identity_vectors;
mod member_roster_vectors;
mod mention_rendering_vectors;
mod mls_creator_bootstrap_recovery;
mod mls_governance_binding;
mod named_suite_audit;
mod object_addressing_vectors;
mod object_identity_collision;
mod operation_clause_registry;
mod operation_registry_gate;
mod poll_reducer;
mod presence_signal;
mod primary_handle_vectors;
mod privacy;
mod privacy_security;
mod private_chat_privacy;
mod private_view_inbox;
mod producer_identity;
mod profile_matrix;
mod profile_registry;
mod proof_context_domain_separation;
mod protocol_gap_closure;
mod protocol_time_tolerance;
mod protocol_version;
mod push_route_revision;
mod push_rule_core;
mod read_receipt_signal;
mod realm_join_candidate;
mod recovery_completion_grant;
pub mod recovery_transaction_faults;
mod redaction;
mod relation_structural_realm;
mod scaffold_gate;
mod scalability_limits;
mod schema_validation;
mod schema_validation_fixture;
mod sdk_precheck;
mod security_negative;
mod security_transaction_resilience;
mod security_transaction_resilience_reference;
mod session_grant_issuer_ledger;
mod sidecar_vectors;
mod signal_federation;
#[cfg(test)]
mod signal_recipient;
mod signal_sequence_high_water;
mod spec_business_flow;
mod station_certification;
mod strand_watch_current;
mod string_profiles;
mod suite_execution;
mod sync;
mod test_material_rejection;
mod vector_registry_gate;
mod view_write_contract;
mod visibility_policy;
mod webrtc_media_plaintext;
mod websocket_binding;
mod wire;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

const ARTIFACT_REGISTRY_DIR: &str = "registry";
const ARTIFACT_FIXTURES_DIR: &str = "fixtures";

// ── Public suite re-exports ─────────────────────────────────────────────────

pub use account_blocklist_projection::{
    ACCOUNT_BLOCKLIST_PROJECTION_ENTRYPOINT, VECTOR_ID_ACCOUNT_BLOCKLIST_PROJECTION,
    run_account_blocklist_projection_vector,
};
pub use account_data_cas_convergence::{
    ACCOUNT_DATA_CAS_CONVERGENCE_ENTRYPOINT, run_account_data_cas_convergence_suite,
};
pub use account_status_issuer_ledger::{
    VECTOR_ID_ACCOUNT_STATUS_ISSUER_LEDGER, run_account_status_issuer_ledger_vector,
};
pub use aead_nonce_replay::{AEAD_NONCE_REPLAY_ENTRYPOINT, run_aead_nonce_replay_suite};
pub use agent_draft_pending_intent_account_subscribe::{
    AgentDraftPendingIntentAccountSubscribeCoverage,
    run_agent_draft_pending_intent_account_subscribe_conformance,
};
pub use agent_membership_cascade::run_agent_membership_cascade_suite;
pub use agent_mls_keypackage_authorization::{
    AGENT_MLS_KEYPACKAGE_AUTHORIZATION_ENTRYPOINT, run_agent_mls_keypackage_authorization_suite,
};
pub use agent_pairing_coordination::run_agent_pairing_durable_coordination_matrix;
pub use agent_participation::{
    ALL_AGENT_PARTICIPATION_VECTOR_IDS, run_agent_participation_ceiling_tighten_vector,
    run_agent_participation_effective_intersection_vector, run_agent_participation_fixture_suite,
    run_agent_participation_selection_cas_vector, run_agent_participation_session_overlay_vector,
    run_agent_participation_third_party_mention_gate_vector,
    run_agent_selector_label_known_account_vector,
};
pub use agent_signer_evidence::{
    AGENT_SIGNER_EVIDENCE_FIXTURE, AGENT_SIGNER_EVIDENCE_SUITE, ALL_AGENT_SIGNER_EVIDENCE_CASES,
    run_agent_signer_evidence_vector_suite,
};
pub use agent_vectors::{
    ALL_AGENT_VECTOR_IDS, run_agent_act_on_behalf_vector, run_agent_controller_lifecycle_vector,
    run_agent_human_approval_required_vector, run_agent_longevity_no_expiry_vector,
    run_agent_pairing_expiry_vector, run_agent_pcr_separation_vector, run_agent_provision_vector,
    run_agent_repairing_supersede_vector, run_agent_runtime_key_binding_vector,
    run_agent_session_grant_replay_vector, run_agent_vector_suite,
    validate_agent_human_approval_http_response,
};
pub use applet_install::{
    run_applet_install_authoring_suite, run_applet_managed_actor_authority_suite,
    run_applet_registration_epoch_kat_suite,
};
pub use arkret_private_kdf_and_durability::run_arkret_private_kdf_and_durability_suite;
pub use auth_session_proof::{
    ALL_AUTH_SESSION_PROOF_VECTOR_IDS, run_auth_session_grant_audience_binding_vector,
    run_auth_session_proof_fixture_suite, run_http_signature_freshness_boundaries_vector,
    run_session_bare_bearer_rejected_protected_vector, run_session_pop_presentation_vector,
};
pub use authority_commit::{
    VECTOR_ID_AUTHORITY_COMMIT_INDEPENDENT_STREAMS, run_authority_commit_suite,
};
pub use authority_event_submit_carriers::{
    AuthorityEventSubmitCarrierCoverage, run_authority_event_submit_carrier_conformance,
};
pub use blind_payload::{
    run_blind_payload_sanitizer_suite, run_blind_payload_sanitizer_suite_counts,
};
pub use blob_stream_aead::{
    ALL_BLOB_STREAM_AEAD_VECTOR_IDS, BLOB_STREAM_AEAD_ENTRYPOINT,
    run_blob_stream_aead_fixture_suite, run_blob_stream_aead_suite,
};
pub use call_signal::{
    ALL_CALL_SIGNAL_VECTOR_IDS, run_call_signal_vector_suite, run_plaintext_closed_schema_vector,
    run_proof_detached_jws_vector, run_seq_monotonic_vector, run_signal_kind_enum_vector,
};
pub use call_state_core_executable::{CALL_STATE_CORE_ENTRYPOINT, run_call_state_core_suite};
pub use call_state_media_lifecycle::{
    ALL_CALL_STATE_MEDIA_LIFECYCLE_VECTOR_IDS, CALL_MEDIA_LIFECYCLE_ENTRYPOINT,
    run_call_media_lifecycle_suite, run_call_state_media_lifecycle_vector_suite,
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
pub use capability_relinquish_authoring::{
    CAPABILITY_RELINQUISH_AUTHORING_ENTRYPOINT, run_capability_relinquish_authoring_suite,
};
pub use coauth_lifecycle::run_coauth_account_lifecycle_fixture_suite;
pub use crypto_hpke::{CRYPTO_HPKE_ENTRYPOINT, run_crypto_hpke_suite};
pub use cursor_negative::{CURSOR_NEGATIVE_ENTRYPOINT, run_cursor_negative_suite};
pub use cursor_vectors::{
    ALL_CURSOR_VECTOR_IDS, run_cursor_handle_reject_vector, run_cursor_opaque_core_vector,
    run_cursor_vector_suite,
};
pub use decision_0017_vectors::{
    run_account_data_cas_convergence_vector_suite, run_read_cursor_multi_device_merge_vector_suite,
};
pub use detached_object_signature::{
    DETACHED_OBJECT_SIGNATURE_ENTRYPOINT, run_detached_object_signature_suite,
};
pub use device_pairing_code_claim::run_device_pairing_code_claim_suite;
pub use device_revocation_pending::run_device_revocation_pending_suite;
pub use did_binding_digests::{
    ALL_DID_BINDING_DIGEST_VECTOR_IDS, VECTOR_ID_DID_BINDING_DOCUMENT_DIGEST_KAT,
    VECTOR_ID_DID_BINDING_EVIDENCE_RECEIPT_KAT, VECTOR_ID_DID_BINDING_POLICY_SNAPSHOT_KAT,
    run_did_binding_digest_kat_suite, run_did_binding_document_digest_kat_vector,
    run_did_binding_evidence_receipt_kat_vector, run_did_binding_policy_snapshot_kat_vector,
};
pub use did_webvh_v1::run_did_webvh_v1_adapter_fixture_suite;
pub use digest_construction::{
    CANONICAL_JSON_DIGEST_DOMAINS, run_digest_construction_known_answers,
};
pub use direct_conversation_admission::{
    DirectConversationAdmissionCoverage, audit_direct_conversation_admission_contract,
};
pub use direct_conversation_flow::run_direct_conversation_flow_suite;
pub use downstream_impact::{
    run_downstream_impact_contract_suite, run_error_status_context_vector,
    run_moderation_dismiss_and_concurrent_fold_vector, run_private_view_account_data_vector,
};
pub use encoding::{
    run_encoding_fixture_suite, run_projection_position_discriminator_fixture_suite,
};
pub use envelope::{run_container_realm_control_payload_suite, run_event_envelope_fixture_suite};
pub use fanout_route_miss::run_fanout_route_miss_suite;
pub use federation::run_federation_fixture_suite;
pub use file_transfer_stream_aead::{
    ALL_FILE_TRANSFER_STREAM_AEAD_VECTOR_IDS, run_file_transfer_overall_digest_rejected_vector,
    run_file_transfer_range_binding_rejected_vector,
    run_file_transfer_stream_aead_byte_exact_vector, run_file_transfer_stream_aead_fixture_suite,
};
pub use final_conformance_closure::{
    ALL_FINAL_CONFORMANCE_CLOSURE_VECTOR_IDS,
    run_applet_transaction_delivery_authentication_record_digest_vector,
    run_calendar_rsvp_occurrence_key_vector, run_federation_timing_bucket_vector,
    run_final_conformance_closure_fixture_suite, run_mls_governance_epoch_binding_vector,
    run_mls_security_frontier_vector, run_moderation_evidence_package_minimal_disclosure_vector,
    run_moderation_franking_roundtrip_vector,
    run_relation_reference_projection_indistinguishable_vector,
};
pub use franking_proof::{FRANKING_PROOF_ENTRYPOINT, run_franking_proof_suite};
pub use handle_claim_rejection_vectors::{
    ALL_HANDLE_CLAIM_REJECTION_VECTOR_IDS, run_handle_claim_rejection_vector_suite,
    run_service_handle_rejected_vector, run_subject_not_principal_did_rejected_vector,
};
pub use identity_root::{
    run_identity_model_generation_fence_suite, run_identity_recovery_kdf_fixture_suite,
    run_identity_root_anchor_checkpoint_suite,
};
pub use inkson_client::run_inkson_client_profile_manifest_suite;
pub use invite_new_source_quota::{
    CanonicalAdmissionCase, CanonicalContact, Decision as NewSourceQuotaDecision,
    INVITE_NEW_SOURCE_QUOTA_FIXTURE, VECTOR_ID_NEW_SOURCE_QUOTA_EFFECTIVE_BOUNDS,
    VECTOR_ID_NEW_SOURCE_QUOTA_HOLDER_ADMISSION, canonical_admission_case,
    run_invite_new_source_quota_suite,
};
pub use key_backup_hardening::{
    ALL_KEY_BACKUP_HARDENING_VECTOR_IDS, KEY_BACKUP_HARDENING_ENTRYPOINT,
    VECTOR_ID_KEY_BACKUP_DELETE_AUTHORITY, VECTOR_ID_KEY_BACKUP_PASSPHRASE_KDF_KAT,
    run_key_backup_delete_authority_vector, run_key_backup_hardening_fixture_suite,
    run_key_backup_hardening_suite, run_key_backup_kdf_floor_rejected_vector,
    run_key_backup_passphrase_kdf_kat_vector, run_key_backup_unlock_proof_vector,
};
pub use keypackage_lifecycle::{
    ALL_KEYPACKAGE_LIFECYCLE_VECTOR_IDS, VECTOR_ID_KEYPACKAGE_SELF_CLAIM_AUTHORIZATION_IDEMPOTENCY,
    run_keypackage_exhaustion_claim_limits_vector,
    run_keypackage_last_resort_affinity_and_optionality_vector,
    run_keypackage_last_resort_claim_and_reuse_vector,
    run_keypackage_last_resort_forced_rotation_vector, run_keypackage_lifecycle_fixture_suite,
    run_keypackage_self_claim_authorization_idempotency_vector,
    run_mls_welcome_keypackage_hash_vector,
};
pub use keypackage_write_transcripts::{
    KEYPACKAGE_WRITE_TRANSCRIPTS_ENTRYPOINT, run_keypackage_write_transcripts_suite,
};
pub use long_text_content::run_long_text_content_fixture_suite;
pub use media_binding::{
    ALL_MEDIA_BINDING_VECTOR_IDS, MEDIA_BINDING_ENTRYPOINT, run_e2ee_key_source_vector,
    run_focus_selection_oldest_membership_vector, run_media_binding_suite,
    run_media_binding_vector_suite, run_participant_binding_required_vector,
    run_participant_id_unrecognised_vector, run_recording_artifact_via_arkret_blob_vector,
    run_recording_exporter_label_vector, run_session_focus_no_split_brain_vector,
    run_token_exchange_minimal_vector, run_token_issuer_unauthorised_vector,
    run_unknown_type_fail_closed_vector,
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
pub use mls_creator_bootstrap_recovery::run_mls_creator_bootstrap_recovery_suite;
pub use mls_governance_binding::{
    MLS_GOVERNANCE_BINDING_ENTRYPOINT, run_mls_governance_binding_suite,
};
pub use named_suite_audit::{NamedSuiteAuditReport, run_named_suite_audit};
pub use object_addressing_vectors::{
    ALL_OBJECT_ADDRESSING_VECTOR_IDS, run_grammar_fail_closed_vector,
    run_object_addressing_vector_suite, run_realm_id_vs_alias_vector,
    run_realm_strand_message_forms_vector, run_scheme_fragment_equivalence_vector,
    run_scope_confusion_replay_vector, run_scope_token_address_link_kind_wins_vector,
    run_target_digest_ignores_hints_vector, run_target_digest_omits_absent_vector,
    run_target_digest_tracks_object_vector,
};
pub use object_identity_collision::{
    OBJECT_IDENTITY_COLLISION_ENTRYPOINT, run_object_identity_collision_suite,
};
pub use operation_clause_registry::validate_operation_clause_registry;
pub use operation_registry_gate::{
    OperationRegistryGateEntry, OperationRegistryGatePaths, OperationRegistryGateReport,
    OperationRegistryGateStatus, OperationSourceRoot, build_operation_registry_gate_report,
    build_operation_registry_gate_report_from_paths, validate_operation_registry_gate,
    validate_operation_registry_gate_report,
};
pub use poll_reducer::run_poll_reducer_fixture_suite;
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
    run_single_candidate_passthrough_vector, run_tie_break_by_accepted_issuer_ids_position_vector,
    run_tie_break_by_claim_digest_vector, run_tie_break_by_created_at_vector,
};
pub use privacy::run_privacy_security_fixture_suite;
pub use private_chat_privacy::run_private_chat_privacy_contract_suite;
pub use private_view_inbox::{PRIVATE_VIEW_INBOX_ENTRYPOINT, run_private_view_inbox_suite};
pub use producer_identity::{PRODUCER_IDENTITY_ENTRYPOINT, run_producer_identity_suite};
pub use profile_matrix::{run_profile_requirement_gate_suite, validate_server_profile_claims};
pub use profile_registry::{
    ProfileGateEntry, ProfileGateReport, ProfileGateStatus, build_profile_gate_report,
    render_profile_gate_report_json, render_profile_gate_report_markdown,
};
pub use proof_context_domain_separation::{
    MIMI_PER_FAMILY_PROOF_CONTEXTS, run_proof_context_domain_separation_vector,
};
pub use protocol_gap_closure::run_protocol_gap_closure_fixture_suite;
pub use protocol_time_tolerance::{
    PROTOCOL_TIME_TOLERANCE_ENTRYPOINT, run_protocol_time_tolerance_suite,
};
pub use protocol_version::{PROTOCOL_VERSION_ENTRYPOINT, run_protocol_version_suite};
pub use push_route_revision::{
    PUSH_REGISTRATION_HANDOFF_VECTOR_ID, PushRegistrationHandoffExecution,
    run_push_registration_handoff_lifecycle_vector,
    run_push_registration_handoff_lifecycle_with_database_url, run_push_route_revision_suite,
};
pub use push_rule_core::{
    PUSH_RULE_CORE_ENTRYPOINT, run_push_rule_client_only_vector, run_push_rule_core_fixture_suite,
    run_push_rule_core_suite,
};
pub use read_receipt_signal::{
    ALL_READ_RECEIPT_SIGNAL_VECTOR_IDS, VECTOR_ID_GENESIS_JOIN_POLICY_BUNDLE,
    VECTOR_ID_READ_RECEIPT_ROUND_TRIP, run_genesis_join_policy_bundle_vector,
    run_read_receipt_round_trip_vector, run_read_receipt_signal_vector_suite,
};
pub use realm_join_candidate::{REALM_JOIN_CANDIDATE_ENTRYPOINT, run_realm_join_candidate_suite};
pub use recovery_completion_grant::run_recovery_completion_grant_suite;
pub use redaction::run_redaction_fixture_suite;
pub use relation_structural_realm::{
    RELATION_STRUCTURAL_REALM_ENTRYPOINT, run_relation_structural_realm_suite,
};
pub use scaffold_gate::{
    run_live_describe_profile_gate_suite, run_scaffold_profile_gate_suite,
    validate_scaffold_profile_gate,
};
pub use scalability_limits::run_scalability_limits_fixture_suite;
pub use schema_validation::run_schema_validation_suite;
pub use schema_validation_fixture::{
    EVENT_PAYLOAD_VALUE_CLOSURE_FIXTURE, SCHEMA_DEFINITION_VALIDATOR_KAT,
    SCHEMA_VALIDATION_FIXTURE, SchemaValidationCase, SchemaValidationFixture,
    run_event_payload_value_closure_fixture, run_schema_definition_validator_kat,
    run_schema_validation_fixture_file, run_schema_validation_fixture_suite,
};
pub use sdk_precheck::{SDK_PRECHECK_ENTRYPOINT, run_sdk_precheck_suite};
pub use security_negative::run_security_negative_profile_suite;
pub use security_transaction_resilience::run_security_transaction_resilience_joint_gate;
pub use session_grant_issuer_ledger::{
    run_session_grant_issuance_kat_suite, run_session_grant_issuer_ledger_reference_model_suite,
    run_session_grant_issuer_ledger_suite,
};
pub use sidecar_vectors::{
    ALL_SIDECAR_VECTOR_IDS, run_sidecar_accepted_request_identity_vector,
    run_sidecar_canonical_sibling_digest_vector, run_sidecar_context_locator_recovery_vector,
    run_sidecar_eligibility_states_vector, run_sidecar_ensure_idempotent_vector,
    run_sidecar_exchange_binding_closed_loop_vector,
    run_sidecar_exchange_binding_containment_vector,
    run_sidecar_exchange_projection_recovery_vector, run_sidecar_existence_privacy_vector,
    run_sidecar_explicit_publish_vector, run_sidecar_hosted_projection_vector,
    run_sidecar_hosted_ui_matrix_vector, run_sidecar_mls_bootstrap_binding_vector,
    run_sidecar_mls_effective_access_vector, run_sidecar_multi_agent_publish_vector,
    run_sidecar_non_disclosure_surface_matrix_vector, run_sidecar_revoke_fail_closed_vector,
    run_sidecar_union_history_frontier_vector, run_sidecar_vector_suite,
};
pub use signal_federation::{
    VECTOR_ID_SIGNAL_DEVICE_AUTHORIZATION_DOMAIN, run_signal_device_authorization_domain_vector,
    run_signal_federation_fixture_suite,
};
pub use signal_sequence_high_water::run_signal_sequence_high_water_suite;
pub use spec_business_flow::run_spec_business_flow_coverage_suite;
pub use station_certification::run_station_certification_gate_suite;
pub use strand_watch_current::{STRAND_WATCH_CURRENT_ENTRYPOINT, run_strand_watch_current_suite};
pub use string_profiles::{STRING_PROFILE_ENTRYPOINT, run_string_profile_suite};
pub use suite_execution::{CaseExecutionResult, SuiteExecutionResult};
pub use sync::{VECTOR_ID_CLIENT_ACCOUNT_STREAM, run_sync_fixture_suite};
pub use test_material_rejection::{
    TEST_MATERIAL_REJECTION_ENTRYPOINT, TestMaterialRejectionCoverage,
    run_test_material_rejection_suite, run_test_material_rejection_suite_with_coverage,
};
pub use vector_registry_gate::{
    VectorRegistryGateEntry, VectorRegistryGateMode, VectorRegistryGateReport,
    VectorRegistryGateStatus, build_vector_registry_gate_report,
    build_vector_registry_gate_report_from_paths, fixture_digest_hex,
    validate_vector_registry_gate, validate_vector_registry_gate_report,
    validate_vector_registry_gate_report_with_mode,
};
pub use view_write_contract::{VIEW_WRITE_CONTRACT_ENTRYPOINT, run_view_write_contract_suite};
pub use visibility_policy::run_visibility_policy_fixture_suite;
pub use webrtc_media_plaintext::{
    WEBRTC_MEDIA_PLAINTEXT_ENTRYPOINT, run_webrtc_media_plaintext_suite,
};
pub use websocket_binding::run_websocket_binding_suite;
pub use wire::{
    run_composite_state_key_encoding_fixture_suite, run_composite_state_subject_fixture_suite,
    run_device_message_negative_fixture_suite, run_discovery_profile_fixture_suite,
    run_event_kind_payload_coverage_fixture_suite, run_facet_renderer_query_fixture_suite,
    run_interop_downgrade_fixture_suite, run_key_backup_aead_round_trip_check,
    run_key_backup_encryption_fixture_suite, run_megolm_ratchet_kdf_chain_check,
    run_megolm_ratcheting_fixture_suite, run_mimi_components_fixture_suite,
    run_multi_admin_distinct_approver_gate_check, run_production_signing_fixture_suite,
    run_read_receipt_policy_fixture_suite, run_recovery_bridge_full_chain_fixture_suite,
    run_recovery_ticket_state_machine_check, run_redacted_cross_server_fixture_suite,
    run_restore_full_workflows_fixture_suite,
};

// ── Shared fixture types ────────────────────────────────────────────────────

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
    pub(crate) request_contract: Option<Value>,
    pub(crate) cases: Option<Vec<Value>>,
    pub(crate) mutations: Option<Vec<String>>,
}

// ── Shared utility functions ────────────────────────────────────────────────

// The fixture accessor layer (`required_*`, `expected_*`, `string_*`) lives in
// `fixture_dsl` and is re-exported here so suites keep importing it as
// `super::required_str` and friends.
pub(crate) use fixture_dsl::{
    FixtureRunner, expected, expected_bool, expected_str, expected_str_opt, expected_u64,
    expected_u64_opt, required_array, required_bool, required_field, required_i64, required_object,
    required_str, required_str_obj, required_u64, required_u64_obj, string_array_field, string_set,
    string_set_of, string_vec,
};

pub fn spec_artifacts_root() -> PathBuf {
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

pub fn fixture_path(file_name: &str) -> PathBuf {
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

/// One `security_evidence[]` row of a formal fixture: a normative clause and
/// vector mapped to the decision points the fixture's own cases evidence.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecurityEvidenceRow {
    pub(crate) vector_id: String,
    pub(crate) clause_id: String,
    pub(crate) decision_points: Vec<SecurityDecisionPoint>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SecurityDecisionPoint {
    pub(crate) id: String,
    pub(crate) requirement: String,
    pub(crate) evidence: Vec<String>,
}

/// Every evidence row names a vector the fixture covers and a clause, every
/// decision point is unique and non-empty, and every evidence pointer resolves
/// inside the same fixture document.
pub(crate) fn verify_security_evidence(
    file_name: &str,
    fixture: &Value,
    rows: &[SecurityEvidenceRow],
    covers_vectors: &[String],
) -> Result<()> {
    if rows.is_empty() {
        bail!("{file_name} security_evidence must not be empty");
    }
    for row in rows {
        if !covers_vectors.iter().any(|vector| vector == &row.vector_id) {
            bail!(
                "{file_name} security_evidence vector {} is not in covers_vectors",
                row.vector_id
            );
        }
        if !row.clause_id.starts_with("AK-") {
            bail!(
                "{file_name} security_evidence {} has malformed clause_id {}",
                row.vector_id,
                row.clause_id
            );
        }
        if row.decision_points.is_empty() {
            bail!(
                "{file_name} security_evidence {} has no decision points",
                row.vector_id
            );
        }
        let mut seen = std::collections::BTreeSet::new();
        for point in &row.decision_points {
            if !seen.insert(point.id.as_str()) {
                bail!(
                    "{file_name} security_evidence {} repeats decision point {}",
                    row.vector_id,
                    point.id
                );
            }
            if point.requirement.trim().is_empty() || point.evidence.is_empty() {
                bail!(
                    "{file_name} decision point {} lacks a requirement or evidence",
                    point.id
                );
            }
            for pointer in &point.evidence {
                if fixture.pointer(pointer).is_none() {
                    bail!(
                        "{file_name} decision point {} evidence pointer {pointer} does not resolve",
                        point.id
                    );
                }
            }
        }
    }
    Ok(())
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

pub(crate) fn fixture_runner_entrypoint(value: &Value) -> Result<&str> {
    value
        .get("runner")
        .and_then(Value::as_object)
        .and_then(|runner| runner.get("entrypoint"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("fixture runner must be an object with string entrypoint"))
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

pub(crate) fn value_field_actor(value: &Value, field: &str) -> Result<arkret_wire::ActorId> {
    Ok(serde_json::from_value(
        required_field(value, field)?.clone(),
    )?)
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

pub(crate) const RANK_ALPHABET: &str =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
pub(crate) const RANK_MAX_LENGTH: usize = 128;

pub(crate) fn validate_rank(rank: &str, max_length: usize) -> Result<()> {
    if rank.is_empty() || rank.len() > max_length {
        bail!("invalid_rank");
    }
    if !rank.chars().all(|ch| RANK_ALPHABET.contains(ch)) {
        bail!("invalid_rank");
    }
    Ok(())
}

mod service_did_routes;
pub use service_did_routes::run_service_did_routes_suite;
