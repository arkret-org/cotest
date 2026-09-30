//! Explicit audit of `runner.kind = named_suite` fixtures.
//!
//! Loading a fixture is not execution. Only entrypoints in `RUNNERS` count as
//! wired here, and case-oriented runners must return one assertion-bearing
//! result per fixture case. The report intentionally retains every unwired
//! entrypoint so migration work cannot be hidden by a green fixture parser.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use anyhow::{Result, anyhow, ensure};
use serde_json::Value;

use super::{
    ACCOUNT_BLOCKLIST_PROJECTION_ENTRYPOINT, ACCOUNT_DATA_CAS_CONVERGENCE_ENTRYPOINT,
    ACTOR_PRIVATE_EVENTS_SUBMIT_ENTRYPOINT, AEAD_NONCE_REPLAY_ENTRYPOINT,
    AGENT_MLS_KEYPACKAGE_AUTHORIZATION_ENTRYPOINT, AUTHORITY_FORWARD_GENESIS_MATERIAL_ENTRYPOINT,
    BLOB_STREAM_AEAD_ENTRYPOINT, CALL_MEDIA_LIFECYCLE_ENTRYPOINT, CALL_STATE_CORE_ENTRYPOINT,
    CAPABILITY_RELINQUISH_AUTHORING_ENTRYPOINT, CRYPTO_HPKE_ENTRYPOINT, CURSOR_NEGATIVE_ENTRYPOINT,
    DETACHED_OBJECT_SIGNATURE_ENTRYPOINT, FRANKING_PROOF_ENTRYPOINT,
    KEY_BACKUP_HARDENING_ENTRYPOINT, KEYPACKAGE_LIFECYCLE_ENTRYPOINT,
    KEYPACKAGE_RECIPIENT_CLAIM_READ_ENTRYPOINT, KEYPACKAGE_WRITE_TRANSCRIPTS_ENTRYPOINT,
    MEDIA_BINDING_ENTRYPOINT, MLS_CROSS_STATION_WELCOME_REPLICATION_ENTRYPOINT,
    MLS_GOVERNANCE_BINDING_ENTRYPOINT, OBJECT_IDENTITY_COLLISION_ENTRYPOINT,
    PRIVATE_VIEW_INBOX_ENTRYPOINT, PRODUCER_IDENTITY_ENTRYPOINT,
    PROTOCOL_TIME_TOLERANCE_ENTRYPOINT, PROTOCOL_VERSION_ENTRYPOINT, PUSH_RULE_CORE_ENTRYPOINT,
    REALM_JOIN_CANDIDATE_ENTRYPOINT, RELATION_STRUCTURAL_REALM_ENTRYPOINT, SDK_PRECHECK_ENTRYPOINT,
    STRAND_WATCH_CURRENT_ENTRYPOINT, STRING_PROFILE_ENTRYPOINT, SuiteExecutionResult,
    TEST_MATERIAL_REJECTION_ENTRYPOINT, VIEW_WRITE_CONTRACT_ENTRYPOINT,
    run_account_blocklist_projection_suite, run_account_data_cas_convergence_suite,
    run_account_status_issuer_ledger_vector, run_actor_private_events_submit_suite,
    run_aead_nonce_replay_suite, run_agent_membership_cascade_suite,
    run_agent_mls_keypackage_authorization_suite, run_applet_registration_epoch_kat_suite,
    run_authority_commit_suite, run_authority_forward_genesis_material_suite,
    run_blob_stream_aead_suite, run_call_media_lifecycle_suite, run_call_state_core_suite,
    run_capability_relinquish_authoring_suite, run_crypto_hpke_suite, run_cursor_negative_suite,
    run_detached_object_signature_suite, run_encoding_fixture_suite,
    run_event_envelope_fixture_suite, run_fanout_route_miss_suite,
    run_file_transfer_stream_aead_fixture_suite, run_franking_proof_suite,
    run_invite_new_source_quota_suite, run_key_backup_hardening_suite,
    run_keypackage_lifecycle_suite, run_keypackage_recipient_claim_read_suite,
    run_keypackage_write_transcripts_suite, run_media_binding_suite,
    run_mimi_admission_guards_suite, run_mimi_room_binding_migration_suite,
    run_mls_creator_bootstrap_recovery_suite, run_mls_cross_station_welcome_replication_suite,
    run_mls_governance_binding_suite, run_object_identity_collision_suite,
    run_private_view_inbox_suite, run_producer_identity_suite, run_protocol_time_tolerance_suite,
    run_protocol_version_suite, run_push_rule_core_suite, run_realm_join_candidate_suite,
    run_relation_structural_realm_suite, run_sdk_precheck_suite,
    run_security_transaction_resilience_joint_gate, run_session_grant_issuer_ledger_suite,
    run_signal_sequence_high_water_suite, run_strand_watch_current_suite, run_string_profile_suite,
    run_sync_fixture_suite, run_test_material_rejection_suite, run_view_write_contract_suite,
    run_webrtc_media_plaintext_suite, run_websocket_binding_suite, spec_artifacts_root,
};

const ACCOUNT_STATUS_ENTRYPOINT: &str = "ak.suite.account_status.issuer_ledger.v1";

/// Exact acknowledged gap ledger. This is deliberately closed: adding or
/// renaming a canonical named suite cannot remain invisible merely because the
/// total number of unwired suites happened to stay constant.
const KNOWN_UNWIRED_ENTRYPOINTS: [&str; 30] = [
    "ak.suite.agent.draft_pending_intent.v1",
    "ak.suite.agent.participation.v1",
    "ak.suite.agent.vectors.v1",
    "ak.suite.applet.managed_actor_authority.v1",
    "ak.suite.applet.revoke_saga.v1",
    "ak.suite.auth.session_proof.v1",
    "ak.suite.authz.approval_signature.v1",
    "ak.suite.call.force_mute_v1_boundary.v1",
    "ak.suite.conformance.final_closure.v1",
    "ak.suite.consent.cache_invalidation.v1",
    "ak.suite.contact.bilateral_continuity_checkpoint.v1",
    "ak.suite.current.cas_failure_read_boundary.v1",
    "ak.suite.direct_conversation.admission_producers.v1",
    "ak.suite.direct_conversation.signal_admission.v1",
    "ak.suite.encoding.content_bound_event_id.v1",
    "ak.suite.events.redaction.v1",
    "ak.suite.federation.idempotency_after_key_revoke.v1",
    "ak.suite.identity.independent_admission.v1",
    "ak.suite.identity.pcr_genesis.v1",
    "ak.suite.invite.claim_security.v1",
    "ak.suite.mls.rfc9420_kat.v1",
    "ak.suite.mls.roster_authority.v1",
    "ak.suite.peer.event_submit.semantic_union.v1",
    "ak.suite.privacy.security.v1",
    "ak.suite.protocol.edge_cases.v1",
    "ak.suite.reaction.authority_order.v1",
    "ak.suite.scope.circle.v1",
    "ak.suite.sdk.event_type_axes.v1",
    "ak.suite.signer_key.historical_commit_coordinate.v1",
    "ak.suite.visibility.policy.v1",
];

enum Runner {
    Cases(fn() -> Result<SuiteExecutionResult>),
    CasesAt {
        run: fn() -> Result<SuiteExecutionResult>,
        pointer: &'static str,
    },
    CasesAcross {
        run: fn() -> Result<SuiteExecutionResult>,
        pointers: &'static [&'static str],
    },
    EvidenceMapped(fn() -> Result<()>),
}

const RUNNERS: [(&str, Runner); 52] = [
    (
        "ak.suite.mimi.admission_guards.v1",
        Runner::Cases(run_mimi_admission_guards_suite),
    ),
    (
        "ak.suite.mimi.room_binding_migration.v1",
        Runner::Cases(run_mimi_room_binding_migration_suite),
    ),
    (
        ACCOUNT_BLOCKLIST_PROJECTION_ENTRYPOINT,
        Runner::Cases(run_account_blocklist_projection_suite),
    ),
    (
        AUTHORITY_FORWARD_GENESIS_MATERIAL_ENTRYPOINT,
        Runner::Cases(run_authority_forward_genesis_material_suite),
    ),
    (
        KEYPACKAGE_RECIPIENT_CLAIM_READ_ENTRYPOINT,
        Runner::Cases(run_keypackage_recipient_claim_read_suite),
    ),
    (
        MLS_CROSS_STATION_WELCOME_REPLICATION_ENTRYPOINT,
        Runner::Cases(run_mls_cross_station_welcome_replication_suite),
    ),
    (
        ACCOUNT_DATA_CAS_CONVERGENCE_ENTRYPOINT,
        Runner::Cases(run_account_data_cas_convergence_suite),
    ),
    (
        ACTOR_PRIVATE_EVENTS_SUBMIT_ENTRYPOINT,
        Runner::Cases(run_actor_private_events_submit_suite),
    ),
    (
        "ak.suite.agent.membership_cascade.v1",
        Runner::EvidenceMapped(run_agent_membership_cascade_suite),
    ),
    (
        AGENT_MLS_KEYPACKAGE_AUTHORIZATION_ENTRYPOINT,
        Runner::Cases(run_agent_mls_keypackage_authorization_suite),
    ),
    (
        "ak.suite.applet.registration_epoch.v1",
        Runner::EvidenceMapped(run_applet_registration_epoch_kat_suite),
    ),
    (
        "ak.suite.auth.session_grant_issuer_record.v1",
        Runner::EvidenceMapped(run_session_grant_issuer_ledger_suite),
    ),
    (
        "ak.suite.authority_commit.v1",
        Runner::EvidenceMapped(run_authority_commit_suite),
    ),
    (
        "ak.suite.binding.websocket.v1",
        Runner::EvidenceMapped(run_websocket_binding_suite),
    ),
    (
        BLOB_STREAM_AEAD_ENTRYPOINT,
        Runner::Cases(run_blob_stream_aead_suite),
    ),
    (
        CALL_STATE_CORE_ENTRYPOINT,
        Runner::Cases(run_call_state_core_suite),
    ),
    (
        CALL_MEDIA_LIFECYCLE_ENTRYPOINT,
        Runner::Cases(run_call_media_lifecycle_suite),
    ),
    (
        CAPABILITY_RELINQUISH_AUTHORING_ENTRYPOINT,
        Runner::Cases(run_capability_relinquish_authoring_suite),
    ),
    (
        AEAD_NONCE_REPLAY_ENTRYPOINT,
        Runner::Cases(run_aead_nonce_replay_suite),
    ),
    (
        "ak.suite.crypto.signature.v1",
        Runner::EvidenceMapped(run_event_envelope_fixture_suite),
    ),
    (
        CRYPTO_HPKE_ENTRYPOINT,
        Runner::CasesAcross {
            run: run_crypto_hpke_suite,
            pointers: &["/vectors", "/negative_cases"],
        },
    ),
    (
        "ak.suite.encoding.core.v1",
        Runner::EvidenceMapped(run_encoding_fixture_suite),
    ),
    (
        "ak.suite.fanout.route_miss.v1",
        Runner::EvidenceMapped(run_fanout_route_miss_suite),
    ),
    (
        "ak.suite.file_transfer.stream_aead.v1",
        Runner::EvidenceMapped(run_file_transfer_stream_aead_fixture_suite),
    ),
    (
        "ak.suite.invite.new_source_quota.v1",
        Runner::EvidenceMapped(run_invite_new_source_quota_suite),
    ),
    (
        "ak.suite.mls.creator_bootstrap_recovery.v1",
        Runner::EvidenceMapped(run_mls_creator_bootstrap_recovery_suite),
    ),
    (
        MLS_GOVERNANCE_BINDING_ENTRYPOINT,
        Runner::Cases(run_mls_governance_binding_suite),
    ),
    (
        "ak.suite.security_transaction.resilience.v1",
        Runner::EvidenceMapped(run_security_transaction_resilience_joint_gate),
    ),
    (
        "ak.suite.signal.sequence_high_water.v1",
        Runner::EvidenceMapped(run_signal_sequence_high_water_suite),
    ),
    (
        "ak.suite.sync.client_account_stream.v1",
        Runner::EvidenceMapped(run_sync_fixture_suite),
    ),
    (
        ACCOUNT_STATUS_ENTRYPOINT,
        Runner::EvidenceMapped(run_account_status_issuer_ledger_vector),
    ),
    (
        CURSOR_NEGATIVE_ENTRYPOINT,
        Runner::CasesAt {
            run: run_cursor_negative_suite,
            pointer: "/vectors/0/cases",
        },
    ),
    (
        DETACHED_OBJECT_SIGNATURE_ENTRYPOINT,
        Runner::Cases(run_detached_object_signature_suite),
    ),
    (
        FRANKING_PROOF_ENTRYPOINT,
        Runner::CasesAt {
            run: run_franking_proof_suite,
            pointer: "/case/bound_field_mutations",
        },
    ),
    (
        KEYPACKAGE_LIFECYCLE_ENTRYPOINT,
        Runner::Cases(run_keypackage_lifecycle_suite),
    ),
    (
        KEYPACKAGE_WRITE_TRANSCRIPTS_ENTRYPOINT,
        Runner::Cases(run_keypackage_write_transcripts_suite),
    ),
    (
        KEY_BACKUP_HARDENING_ENTRYPOINT,
        Runner::Cases(run_key_backup_hardening_suite),
    ),
    (
        MEDIA_BINDING_ENTRYPOINT,
        Runner::Cases(run_media_binding_suite),
    ),
    (
        PROTOCOL_TIME_TOLERANCE_ENTRYPOINT,
        Runner::Cases(run_protocol_time_tolerance_suite),
    ),
    (
        PRIVATE_VIEW_INBOX_ENTRYPOINT,
        Runner::Cases(run_private_view_inbox_suite),
    ),
    (
        OBJECT_IDENTITY_COLLISION_ENTRYPOINT,
        Runner::Cases(run_object_identity_collision_suite),
    ),
    (
        PRODUCER_IDENTITY_ENTRYPOINT,
        Runner::Cases(run_producer_identity_suite),
    ),
    (
        PROTOCOL_VERSION_ENTRYPOINT,
        Runner::Cases(run_protocol_version_suite),
    ),
    (
        PUSH_RULE_CORE_ENTRYPOINT,
        Runner::Cases(run_push_rule_core_suite),
    ),
    (
        RELATION_STRUCTURAL_REALM_ENTRYPOINT,
        Runner::Cases(run_relation_structural_realm_suite),
    ),
    (
        REALM_JOIN_CANDIDATE_ENTRYPOINT,
        Runner::CasesAcross {
            run: run_realm_join_candidate_suite,
            pointers: &[
                "/rejected_additional_members",
                "/rejected_locator_arrays",
                "/authority_assertion_cases",
                "/authority_chain_cases",
            ],
        },
    ),
    (
        SDK_PRECHECK_ENTRYPOINT,
        Runner::Cases(run_sdk_precheck_suite),
    ),
    (
        STRAND_WATCH_CURRENT_ENTRYPOINT,
        Runner::Cases(run_strand_watch_current_suite),
    ),
    (
        STRING_PROFILE_ENTRYPOINT,
        Runner::CasesAt {
            run: run_string_profile_suite,
            pointer: "/vectors",
        },
    ),
    (
        TEST_MATERIAL_REJECTION_ENTRYPOINT,
        Runner::Cases(run_test_material_rejection_suite),
    ),
    (
        VIEW_WRITE_CONTRACT_ENTRYPOINT,
        Runner::Cases(run_view_write_contract_suite),
    ),
    (
        "ak.suite.webrtc.media_plaintext_downgrade.v1",
        Runner::Cases(run_webrtc_media_plaintext_suite),
    ),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedSuiteAuditReport {
    pub fixture_count: usize,
    pub executed_entrypoints: Vec<String>,
    pub unwired_entrypoints: Vec<String>,
}

pub fn run_named_suite_audit() -> Result<NamedSuiteAuditReport> {
    let fixture_dir = spec_artifacts_root().join("fixtures");
    let mut fixtures = BTreeMap::new();
    for entry in fs::read_dir(&fixture_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let value: Value = serde_json::from_slice(&fs::read(&path)?)?;
        if value.pointer("/runner/kind").and_then(Value::as_str) != Some("named_suite") {
            continue;
        }
        let entrypoint = value
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("{} has no runner entrypoint", path.display()))?
            .to_owned();
        ensure!(
            fixtures.insert(entrypoint.clone(), value).is_none(),
            "duplicate named-suite entrypoint {entrypoint}"
        );
    }

    let registered = RUNNERS
        .iter()
        .map(|(entrypoint, _)| *entrypoint)
        .collect::<BTreeSet<_>>();
    ensure!(
        registered.len() == RUNNERS.len(),
        "explicit named-suite registry contains a duplicate"
    );

    let mut executed = Vec::new();
    for (entrypoint, runner) in RUNNERS {
        let fixture = fixtures
            .get(entrypoint)
            .ok_or_else(|| anyhow!("registered runner {entrypoint} has no canonical fixture"))?;
        execute_runner(entrypoint, runner, fixture)?;
        executed.push(entrypoint.to_owned());
    }
    executed.sort();

    let unwired = fixtures
        .keys()
        .filter(|entrypoint| !registered.contains(entrypoint.as_str()))
        .cloned()
        .collect();
    let expected_unwired = KNOWN_UNWIRED_ENTRYPOINTS
        .iter()
        .map(|entrypoint| (*entrypoint).to_owned())
        .collect::<Vec<_>>();
    ensure!(
        unwired == expected_unwired,
        "named-suite gap ledger drifted: expected {expected_unwired:?}, got {unwired:?}"
    );
    Ok(NamedSuiteAuditReport {
        fixture_count: fixtures.len(),
        executed_entrypoints: executed,
        unwired_entrypoints: unwired,
    })
}

fn execute_runner(entrypoint: &str, runner: Runner, fixture: &Value) -> Result<()> {
    match runner {
        Runner::Cases(run) => {
            let result = run()?;
            ensure!(
                result.entrypoint == entrypoint,
                "runner returned the wrong entrypoint"
            );
            result.assert_complete_against(fixture)
        }
        Runner::CasesAt { run, pointer } => {
            let result = run()?;
            ensure!(
                result.entrypoint == entrypoint,
                "runner returned the wrong entrypoint"
            );
            let cases = fixture
                .pointer(pointer)
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("{} has no cases at {pointer}", result.fixture))?;
            result.assert_complete_against_cases(cases)
        }
        Runner::CasesAcross { run, pointers } => {
            let result = run()?;
            ensure!(
                result.entrypoint == entrypoint,
                "runner returned the wrong entrypoint"
            );
            let mut cases = Vec::new();
            for pointer in pointers {
                cases.extend_from_slice(
                    fixture
                        .pointer(pointer)
                        .and_then(Value::as_array)
                        .ok_or_else(|| anyhow!("{} has no cases at {pointer}", result.fixture))?,
                );
            }
            result.assert_complete_against_cases(&cases)
        }
        Runner::EvidenceMapped(run) => {
            ensure!(
                fixture
                    .get("cases")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty),
                "{entrypoint} declares cases[] but its registered runner returns no per-case execution results"
            );
            run()
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn passing_evidence_runner() -> Result<()> {
        Ok(())
    }

    #[test]
    fn evidence_only_runner_cannot_claim_a_fixture_with_cases() {
        let fixture = json!({"cases": [{"name": "must_execute"}]});
        let error = execute_runner(
            "ak.suite.test.v1",
            Runner::EvidenceMapped(passing_evidence_runner),
            &fixture,
        )
        .unwrap_err();
        assert!(error.to_string().contains("no per-case execution results"));
    }
}
