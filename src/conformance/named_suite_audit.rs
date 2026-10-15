//! Explicit audit of `runner.kind = named_suite` fixtures.
//!
//! Loading a fixture is not execution. Only entrypoints in `RUNNERS` count as
//! wired here, and case-oriented runners must return one assertion-bearing
//! result per fixture case. The report intentionally retains every unwired
//! entrypoint so migration work cannot be hidden by a green fixture parser.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use anyhow::{Result, anyhow, ensure};
use cotest_suite_evidence::{CaseRef, DecisionPointGap, audit_decision_points};
use serde_json::Value;

use super::test_material_rejection::run_test_material_rejection_suite;
use super::{
    ACCOUNT_DATA_CAS_CONVERGENCE_ENTRYPOINT, ACTOR_PRIVATE_EVENTS_SUBMIT_ENTRYPOINT,
    AEAD_NONCE_REPLAY_ENTRYPOINT, AGENT_MLS_KEYPACKAGE_AUTHORIZATION_ENTRYPOINT,
    AUTHORITY_FORWARD_GENESIS_MATERIAL_ENTRYPOINT, BLOB_STREAM_AEAD_ENTRYPOINT,
    CALL_MEDIA_LIFECYCLE_ENTRYPOINT, CALL_STATE_CORE_ENTRYPOINT,
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
    run_account_data_cas_convergence_suite, run_account_status_issuer_ledger_vector,
    run_actor_private_events_submit_suite, run_aead_nonce_replay_suite,
    run_agent_membership_cascade_suite, run_agent_mls_keypackage_authorization_suite,
    run_applet_registration_epoch_kat_suite, run_authority_commit_suite,
    run_authority_forward_genesis_material_suite, run_blob_stream_aead_suite,
    run_call_media_lifecycle_suite, run_call_state_core_suite,
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
    run_view_write_contract_suite, run_websocket_binding_suite, spec_artifacts_root,
};

const ACCOUNT_STATUS_ENTRYPOINT: &str = "ak.suite.account_status.issuer_ledger.v1";
pub const SYNC_CLIENT_ENTRYPOINT: &str = "ak.suite.sync.client_account_stream.v1";

/// Sync's canonical cases live in four semantic sections rather than cases[].
/// Partial native execution is visible evidence, never a complete-suite claim.
pub fn missing_sync_production_cases(
    execution: &SuiteExecutionResult,
    fixture: &Value,
) -> Result<Vec<String>> {
    ensure!(
        execution.entrypoint == SYNC_CLIENT_ENTRYPOINT
            && execution.fixture == "client-sync-fixture.json"
            && fixture
                .pointer("/runner/entrypoint")
                .and_then(Value::as_str)
                == Some(SYNC_CLIENT_ENTRYPOINT),
        "Sync execution does not name its canonical suite and fixture"
    );
    let mut cases = Vec::new();
    for section in [
        "stream_tails",
        "checkpoint_ordering",
        "reconnect",
        "delivery_cancellation",
    ] {
        cases.extend_from_slice(
            fixture
                .get(section)
                .and_then(Value::as_array)
                .filter(|cases| !cases.is_empty())
                .ok_or_else(|| anyhow!("Sync fixture has no {section} cases"))?,
        );
    }
    execution.missing_against_cases(&cases)
}

/// Exact acknowledged gap ledger. This is deliberately closed: adding or
/// renaming a canonical named suite cannot remain invisible merely because the
/// total number of unwired suites happened to stay constant.
// Content-key KATs run in arkret-mls; complete authorized-checkpoint
// remains owned by 0805. Terminal live scenarios execute below.
const KNOWN_UNWIRED_ENTRYPOINTS: [&str; 33] = [
    "ak.suite.agent.draft_pending_intent.v1",
    "ak.suite.agent.participation.v1",
    "ak.suite.applet.managed_actor_authority.v1",
    "ak.suite.applet.revoke_saga.v1",
    "ak.suite.auth.session_proof.v1",
    "ak.suite.authority_commit_projection.result_consumption_roles.v1",
    "ak.suite.authz.approval_signature.v1",
    "ak.suite.blob.content_key.v1",
    "ak.suite.call.force_mute_v1_boundary.v1",
    "ak.suite.circle.parent_membership.v1",
    "ak.suite.conformance.final_closure.v1",
    "ak.suite.contact.bilateral_continuity_checkpoint.v1",
    "ak.suite.current.cas_failure_read_boundary.v1",
    "ak.suite.direct_conversation.admission_producers.v1",
    "ak.suite.direct_conversation.chat_topic_structure.v1",
    "ak.suite.direct_conversation.signal_admission.v1",
    "ak.suite.encoding.content_bound_event_id.v1",
    "ak.suite.events.redaction.v1",
    "ak.suite.identity.independent_admission.v1",
    "ak.suite.identity.pcr_genesis.v1",
    "ak.suite.invite.claim_security.v1",
    "ak.suite.mls.rfc9420_kat.v1",
    "ak.suite.mls.roster_authority.v1",
    "ak.suite.mls.roster_client_roles.v1",
    "ak.suite.peer.event_submit.semantic_union.v1",
    "ak.suite.privacy.security.v1",
    "ak.suite.protocol.edge_cases.v1",
    "ak.suite.reaction.authority_order.v1",
    "ak.suite.scope.circle.v1",
    "ak.suite.sdk.event_type_axes.v1",
    "ak.suite.signer_key.historical_commit_coordinate.v1",
    "ak.suite.state.registered_atomic_units_and_watch_audit.v1",
    "ak.suite.visibility.policy.v1",
];

#[derive(Clone, Copy)]
enum Runner {
    Cases(fn() -> Result<SuiteExecutionResult>),
    // Each returned case has completed production-consumer review. A partial
    // result credits only those cases and retains every absent obligation.
    ProductionCases {
        run: fn() -> Result<SuiteExecutionResult>,
        reviewed_cases: &'static [&'static [&'static str]],
        pointers: &'static [&'static str],
    },
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

// These cases exercise the production SDK decoder and exact pair matcher.
// They do not prove managed Device HTTP/PG operation admission.
const REVIEWED_APPLET_DEVICE_SCOPE_CASES: [&str; 15] = [
    "a_read",
    "b_write",
    "no_cross_pair",
    "all_actions_required",
    "realm_does_not_include_circle",
    "empty",
    "ordinary_strings",
    "duplicate_scope",
    "unsorted_scopes",
    "unknown_action",
    "wildcard_action",
    "empty_actions",
    "duplicate_actions",
    "unsorted_actions",
    "sidecar",
];

const RUNNERS: [(&str, Runner); 55] = [
    (
        super::APPLET_DEVICE_SCOPES_ENTRYPOINT,
        Runner::ProductionCases {
            run: super::run_applet_device_scopes_suite,
            reviewed_cases: &[&REVIEWED_APPLET_DEVICE_SCOPE_CASES],
            pointers: &["/cases"],
        },
    ),
    (
        super::TERMINAL_REPLICATION_AUTHORITY_ENTRYPOINT,
        Runner::ProductionCases {
            run: super::run_terminal_replication_authority_suite,
            reviewed_cases: &[&super::TERMINAL_CASES],
            pointers: &["/cases"],
        },
    ),
    (
        super::federation_idempotency_production::ENTRYPOINT,
        Runner::ProductionCases {
            run: super::run_federation_idempotency_production_suite,
            reviewed_cases: &[&super::federation_idempotency_production::REVIEWED_CASES],
            pointers: &["/cases"],
        },
    ),
    (
        "ak.suite.agent.vectors.v1",
        Runner::ProductionCases {
            run: super::run_agent_vectors_production_suite,
            reviewed_cases: super::agent_vectors_production::REVIEWED_CASE_GROUPS,
            pointers: &[
                "/schema_validation_cases",
                "/cases",
                "/session_content_authority_contract/cases",
            ],
        },
    ),
    (
        super::MANAGED_GOVERNANCE_ENTRYPOINT,
        Runner::EvidenceMapped(super::run_managed_governance_suite),
    ),
    (
        "ak.suite.pin.admission_and_scope.v1",
        Runner::Cases(super::pin_admission::run_pin_admission_suite),
    ),
    (
        "ak.suite.mimi.admission_guards.v1",
        Runner::Cases(run_mimi_admission_guards_suite),
    ),
    (
        "ak.suite.mimi.room_binding_migration.v1",
        Runner::Cases(run_mimi_room_binding_migration_suite),
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
        Runner::ProductionCases {
            run: run_sdk_precheck_suite,
            reviewed_cases: &[super::sdk_precheck::REVIEWED_CASES],
            pointers: &["/cases"],
        },
    ),
    (
        STRAND_WATCH_CURRENT_ENTRYPOINT,
        Runner::CasesAcross {
            run: run_strand_watch_current_suite,
            pointers: &[
                "/cases",
                "/schema_validation_cases",
                "/cross_station_cases",
                "/submit_cas_cases",
            ],
        },
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
        Runner::ProductionCases {
            run: run_test_material_rejection_suite,
            reviewed_cases: &[cotest_test_material_runner::EXECUTED_CASES],
            pointers: &["/cases"],
        },
    ),
    (
        VIEW_WRITE_CONTRACT_ENTRYPOINT,
        Runner::Cases(run_view_write_contract_suite),
    ),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NamedSuiteAuditReport {
    pub fixture_count: usize,
    pub executed_entrypoints: Vec<String>,
    pub unwired_entrypoints: Vec<String>,
    pub deferred_client_entrypoints: Vec<String>,
    pub unproved_entrypoints: Vec<String>,
    pub failed_executions: Vec<(String, String, String)>,
    pub decision_point_gaps: Vec<DecisionPointGap>,
    pub missing_production_cases: Vec<CaseRef>,
}

impl NamedSuiteAuditReport {
    /// A diagnostic audit may finish while evidence is missing. A full claim may not.
    pub fn assert_complete(&self) -> Result<()> {
        ensure!(
            self.missing_production_cases.is_empty(),
            "production cases were not executed: {:?}",
            self.missing_production_cases
        );
        ensure!(
            self.failed_executions.is_empty(),
            "named-suite executions failed: {:?}",
            self.failed_executions
        );
        ensure!(
            self.unwired_entrypoints.is_empty(),
            "unwired named suites: {:?}",
            self.unwired_entrypoints
        );
        ensure!(
            self.deferred_client_entrypoints.is_empty(),
            "client evidence is deferred: {:?}",
            self.deferred_client_entrypoints
        );
        ensure!(
            self.unproved_entrypoints.is_empty(),
            "production consumption is unproved: {:?}",
            self.unproved_entrypoints
        );
        ensure!(
            self.decision_point_gaps.is_empty(),
            "SDK decision-point execution gaps: {:?}",
            self.decision_point_gaps
        );
        Ok(())
    }
}

/// Execute the SDK/server registry. Native callers supply explicit client runners.
pub fn run_named_suite_audit() -> Result<NamedSuiteAuditReport> {
    run_named_suite_audit_with_clients(&[])
}

pub type ClientNamedSuiteRunner = (&'static str, fn() -> Result<SuiteExecutionResult>);

pub fn run_named_suite_audit_with_clients(
    client_runners: &[ClientNamedSuiteRunner],
) -> Result<NamedSuiteAuditReport> {
    let report = inspect_named_suite_execution_with_clients(client_runners)?;
    report.assert_complete()?;
    Ok(report)
}

const CLIENT_ENTRYPOINTS: [&str; 4] = [
    "ak.suite.account.blocklist_projection.v1",
    "ak.suite.webrtc.media_plaintext_downgrade.v1",
    "ak.suite.consent.cache_invalidation.v1",
    SYNC_CLIENT_ENTRYPOINT,
];

type NamedFixtureInventory = BTreeMap<String, Vec<(String, Value)>>;

fn load_named_fixture_inventory() -> Result<(BTreeMap<String, Value>, NamedFixtureInventory)> {
    let fixture_dir = spec_artifacts_root().join("fixtures");
    let mut all_fixtures = BTreeMap::new();
    let mut fixtures: BTreeMap<String, Vec<(String, Value)>> = BTreeMap::new();
    for entry in fs::read_dir(&fixture_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let value: Value = serde_json::from_slice(&fs::read(&path)?)?;
        all_fixtures.insert(
            format!("fixtures/{}", path.file_name().unwrap().to_string_lossy()),
            value.clone(),
        );
        if value.pointer("/runner/kind").and_then(Value::as_str) != Some("named_suite") {
            continue;
        }
        let entrypoint = value
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("{} has no runner entrypoint", path.display()))?
            .to_owned();
        fixtures.entry(entrypoint).or_default().push((
            path.file_name().unwrap().to_string_lossy().into_owned(),
            value,
        ));
    }
    for (entrypoint, originals) in &fixtures {
        if originals.len() > 1 {
            let names = originals
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<BTreeSet<_>>();
            ensure!(
                entrypoint == "ak.suite.direct_conversation.admission_producers.v1"
                    && names
                        == [
                            "direct-conversation-admission-fixture.json",
                            "direct-conversation-runtime-endpoint-repair-fixture.json"
                        ]
                        .into_iter()
                        .collect(),
                "unregistered duplicate named-suite fixture family {entrypoint}"
            );
        }
    }
    Ok((all_fixtures, fixtures))
}

fn assert_named_gap_inventory(
    fixtures: &NamedFixtureInventory,
    registered: &BTreeSet<&str>,
) -> Result<Vec<String>> {
    // Validate the closed inventory before executing any case. A failing
    // earlier runner must not hide drift in newly declared semantic suites.
    let unwired: Vec<_> = fixtures
        .keys()
        .filter(|entrypoint| {
            !registered.contains(entrypoint.as_str())
                && !CLIENT_ENTRYPOINTS.contains(&entrypoint.as_str())
        })
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
    Ok(unwired)
}

/// Diagnostic execution retains gaps; unlike the claim gate, its success is
/// not a conformance claim. Consumers must report every gap in the result.
pub fn inspect_named_suite_execution_with_clients(
    client_runners: &[ClientNamedSuiteRunner],
) -> Result<NamedSuiteAuditReport> {
    let declared_clients = client_runners
        .iter()
        .map(|(name, _)| *name)
        .collect::<BTreeSet<_>>();
    ensure!(
        client_runners.is_empty()
            || ((2..=CLIENT_ENTRYPOINTS.len()).contains(&client_runners.len())
                && declared_clients.len() == client_runners.len()
                && declared_clients.contains(CLIENT_ENTRYPOINTS[0])
                && declared_clients.contains(CLIENT_ENTRYPOINTS[1])
                && declared_clients
                    .iter()
                    .all(|name| CLIENT_ENTRYPOINTS.contains(name))),
        "audit requires the exact client runners, with optional Sync and Consent production evidence"
    );
    let (all_fixtures, fixtures) = load_named_fixture_inventory()?;
    let registered = RUNNERS
        .iter()
        .map(|(entrypoint, _)| *entrypoint)
        .chain(client_runners.iter().map(|(name, _)| *name))
        .collect::<BTreeSet<_>>();
    ensure!(
        registered.len() == RUNNERS.len() + client_runners.len(),
        "explicit named-suite registry contains a duplicate"
    );
    let unwired = assert_named_gap_inventory(&fixtures, &registered)?;
    let mut executed = Vec::new();
    let mut executed_cases = BTreeSet::new();
    let mut unproved = Vec::new();
    let mut failed_executions = Vec::new();
    let mut missing_production_cases = Vec::new();
    for (entrypoint, runner) in RUNNERS.iter().copied().chain(
        client_runners
            .iter()
            .map(|(name, run)| (*name, Runner::Cases(*run))),
    ) {
        // Diagnostic model results are not production evidence. Reviewed root
        // runners and native consumers credit only successfully executed cases;
        // incomplete production suites remain unproved with their exact gaps.
        let production_proved = client_runners.iter().any(|(name, _)| *name == entrypoint)
            || matches!(runner, Runner::ProductionCases { .. });
        if !production_proved {
            unproved.push(entrypoint.to_owned());
        }
        let mut runner_passed = true;
        for (file_name, fixture) in fixtures
            .get(entrypoint)
            .ok_or_else(|| anyhow!("registered runner {entrypoint} has no canonical fixture"))?
        {
            let result = (if entrypoint == SYNC_CLIENT_ENTRYPOINT {
                match runner {
                    Runner::Cases(run) => run().and_then(|execution| {
                        let missing = missing_sync_production_cases(&execution, fixture)?;
                        if !missing.is_empty() {
                            unproved.push(entrypoint.to_owned());
                            missing_production_cases.extend(missing.into_iter().map(|case_id| {
                                CaseRef {
                                    fixture_ref: format!("fixtures/{file_name}"),
                                    case_id,
                                }
                            }));
                        }
                        Ok(Some(execution))
                    }),
                    _ => Err(anyhow!("Sync requires a production case runner")),
                }
            } else {
                execute_runner(entrypoint, runner, fixture)
            })
            .and_then(|result| {
                if let Some(result) = &result {
                    ensure!(
                        result.fixture == file_name.as_str(),
                        "{entrypoint}: runner fixture {} differs from canonical {file_name}",
                        result.fixture
                    );
                    if let Runner::ProductionCases { pointers, .. } = runner {
                        let missing =
                            result.missing_against_cases(&case_sections(fixture, pointers)?)?;
                        if !missing.is_empty() {
                            unproved.push(entrypoint.to_owned());
                            missing_production_cases.extend(missing.into_iter().map(|case_id| {
                                CaseRef {
                                    fixture_ref: format!("fixtures/{file_name}"),
                                    case_id,
                                }
                            }));
                        }
                    }
                }
                Ok(result)
            });
            let result = match result {
                Ok(result) => result,
                Err(error) => {
                    runner_passed = false;
                    failed_executions.push((
                        entrypoint.to_owned(),
                        file_name.clone(),
                        format!("{error:#}"),
                    ));
                    continue;
                }
            };
            if let Some(result) = result
                && production_proved
            {
                executed_cases.extend(result.cases.into_iter().map(|case| CaseRef {
                    fixture_ref: format!("fixtures/{file_name}"),
                    case_id: case.case_id,
                }));
            }
        }
        if runner_passed {
            executed.push(entrypoint.to_owned());
        }
    }
    executed.sort();
    unproved.sort();
    unproved.dedup();
    let profiles: Value = serde_json::from_slice(&fs::read(
        spec_artifacts_root().join("profiles/conformance-profiles.json"),
    )?)?;
    let decision_point_gaps = audit_decision_points(&profiles, &all_fixtures, &executed_cases)?;
    Ok(NamedSuiteAuditReport {
        fixture_count: fixtures.values().map(Vec::len).sum(),
        executed_entrypoints: executed,
        unproved_entrypoints: unproved,
        failed_executions,
        decision_point_gaps,
        missing_production_cases,
        unwired_entrypoints: unwired,
        deferred_client_entrypoints: CLIENT_ENTRYPOINTS
            .iter()
            .filter(|name| !declared_clients.contains(**name))
            .map(|name| (*name).to_owned())
            .collect(),
    })
}

fn execute_runner(
    entrypoint: &str,
    runner: Runner,
    fixture: &Value,
) -> Result<Option<SuiteExecutionResult>> {
    match runner {
        Runner::ProductionCases {
            run,
            reviewed_cases,
            pointers,
        } => {
            let result = run()?;
            ensure!(
                result.entrypoint == entrypoint,
                "runner returned the wrong entrypoint"
            );
            ensure!(
                result
                    .cases
                    .iter()
                    .map(|case| case.case_id.as_str())
                    .eq(reviewed_cases
                        .iter()
                        .flat_map(|section| section.iter().copied())),
                "{entrypoint}: execution differs from the reviewed production case set"
            );
            result.missing_against_cases(&case_sections(fixture, pointers)?)?;
            Ok(Some(result))
        }
        Runner::Cases(run) => {
            let result = run()?;
            ensure!(
                result.entrypoint == entrypoint,
                "runner returned the wrong entrypoint"
            );
            result.assert_complete_against(fixture)?;
            Ok(Some(result))
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
            result.assert_complete_against_cases(cases)?;
            Ok(Some(result))
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
            result.assert_complete_against_cases(&cases)?;
            Ok(Some(result))
        }
        Runner::EvidenceMapped(run) => {
            ensure!(
                fixture
                    .get("cases")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty),
                "{entrypoint} declares cases[] but its registered runner returns no per-case execution results"
            );
            run()?;
            Ok(None)
        }
    }
}

fn case_sections(fixture: &Value, pointers: &[&str]) -> Result<Vec<Value>> {
    ensure!(
        !pointers.is_empty(),
        "production runner has no declared case sections"
    );
    let mut cases = Vec::new();
    for pointer in pointers {
        cases.extend_from_slice(
            fixture
                .pointer(pointer)
                .and_then(Value::as_array)
                .filter(|cases| !cases.is_empty())
                .ok_or_else(|| anyhow!("production fixture has no cases at {pointer}"))?,
        );
    }
    Ok(cases)
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use serde_json::json;

    use super::*;

    #[test]
    fn named_agent_reviewed_nested_groups_match_canonical_producer_order() -> Result<()> {
        let fixture = super::super::load_fixture_value("agent-vectors-fixture.json")?;
        let cases = fixture["session_content_authority_contract"]["cases"]
            .as_array()
            .context("canonical nested Agent cases")?;
        for reviewed in [
            &crate::scenarios::agent_runtime_live::REVIEWED_CONTENT_CASES[..],
            &crate::scenarios::agent_runtime_live::REVIEWED_GRANT_CONTENT_CASES[..],
            &crate::scenarios::agent_runtime_live::REVIEWED_POLICY_CONTENT_CASES[..],
            &crate::scenarios::agent_runtime_live::REVIEWED_DIRECT_CONTENT_CASES[..],
            &crate::scenarios::agent_runtime_live::REVIEWED_HISTORY_CONTENT_CASES[..],
        ] {
            let canonical = cases
                .iter()
                .filter_map(|case| case["name"].as_str())
                .filter(|name| reviewed.contains(name))
                .collect::<Vec<_>>();
            ensure!(
                canonical == reviewed,
                "registered Agent IDs must retain the exact canonical producer order"
            );
        }
        println!(
            "[named-agent-order] reviewed_nested_groups_match_canonical=1 removed=0 runtime_credit=0"
        );
        Ok(())
    }

    #[test]
    fn named_preflight_inventory_rejects_unacknowledged_additions_and_removals() -> Result<()> {
        let (_, fixtures) = load_named_fixture_inventory()?;
        let registered = RUNNERS
            .iter()
            .map(|(name, _)| *name)
            .chain(CLIENT_ENTRYPOINTS)
            .collect::<BTreeSet<_>>();
        ensure!(registered.len() == RUNNERS.len() + CLIENT_ENTRYPOINTS.len());
        let unwired = assert_named_gap_inventory(&fixtures, &registered)?;
        ensure!(unwired.len() == 33);
        let mut added = fixtures.clone();
        added.insert("unregistered_test_entrypoint".to_owned(), Vec::new());
        ensure!(assert_named_gap_inventory(&added, &registered).is_err());
        let mut removed = fixtures;
        ensure!(removed.remove(KNOWN_UNWIRED_ENTRYPOINTS[0]).is_some());
        ensure!(assert_named_gap_inventory(&removed, &registered).is_err());
        println!(
            "[named-preflight] acknowledged_unwired=33 added_rejected=1 removed_rejected=1 runtime_credit=0"
        );
        Ok(())
    }

    #[test]
    fn named_preflight_sdk_device_pairs_cross_registered_production_matcher() -> Result<()> {
        let entrypoint = super::super::APPLET_DEVICE_SCOPES_ENTRYPOINT;
        let runner = RUNNERS
            .iter()
            .find(|(name, _)| *name == entrypoint)
            .map(|(_, runner)| *runner)
            .context("registered SDK Device pair runner")?;
        ensure!(matches!(runner, Runner::ProductionCases { .. }));
        let fixture = super::super::load_fixture_value("applet-device-scope-fixture.json")?;
        let result = execute_runner(entrypoint, runner, &fixture)?
            .context("registered SDK matcher omitted evidence")?;
        result.assert_complete_against(&fixture)?;
        ensure!(result.cases.len() == REVIEWED_APPLET_DEVICE_SCOPE_CASES.len());
        println!("[named-sdk-device-pairs] {result:#?}");
        Ok(())
    }

    #[test]
    #[ignore = "requires current Station, Coauth, browser bundle and native Savfox worker"]
    fn reviewed_agent_primary_sections_cross_the_registered_executor() -> Result<()> {
        let entrypoint = "ak.suite.agent.vectors.v1";
        let runner = RUNNERS
            .iter()
            .find(|(name, _)| *name == entrypoint)
            .map(|(_, runner)| *runner)
            .ok_or_else(|| anyhow!("Agent production runner is not registered"))?;
        let fixture = super::super::load_fixture_value("agent-vectors-fixture.json")?;
        let mut execution = execute_runner(entrypoint, runner, &fixture)?
            .ok_or_else(|| anyhow!("Agent runner omitted production results"))?;
        let primary = case_sections(&fixture, &["/schema_validation_cases", "/cases"])?;
        execution.cases.retain(|case| {
            primary
                .iter()
                .any(|declared| declared["name"] == case.case_id)
        });
        let missing = execution.missing_against_cases(&case_sections(
            &fixture,
            &["/schema_validation_cases", "/cases"],
        )?)?;
        ensure!(
            execution.cases.len() == 30 && missing.is_empty(),
            "reviewed Agent result did not complete its exact canonical coverage"
        );
        ensure!(
            !missing.iter().any(|name| name == "agent_provision"),
            "registered executor did not consume full Agent provision"
        );
        ensure!(
            execution
                .cases
                .iter()
                .any(|case| case.case_id == "agent_controller_lifecycle" && case.assertions == 8),
            "registered executor did not consume the live lifecycle conjunction"
        );
        println!("[named-agent] {execution:#?}\nmissing={missing:?}");
        Ok(())
    }

    #[test]
    fn agent_nested_content_contract_cannot_disappear_behind_primary_coverage() -> Result<()> {
        let entrypoint = "ak.suite.agent.vectors.v1";
        let pointers = RUNNERS
            .iter()
            .find_map(|(name, runner)| match runner {
                Runner::ProductionCases { pointers, .. } if *name == entrypoint => Some(*pointers),
                _ => None,
            })
            .context("registered Agent production sections")?;
        let fixture = super::super::load_fixture_value("agent-vectors-fixture.json")?;
        let primary = case_sections(&fixture, &["/schema_validation_cases", "/cases"])?;
        // These placeholders test accounting only and earn no runtime evidence.
        let partial = SuiteExecutionResult {
            entrypoint,
            fixture: "agent-vectors-fixture.json",
            cases: primary
                .iter()
                .map(|case| {
                    Ok(super::super::CaseExecutionResult {
                        case_id: case["name"].as_str().context("primary name")?.into(),
                        assertions: 1,
                    })
                })
                .collect::<Result<_>>()?,
        };
        let declared = case_sections(&fixture, pointers)?;
        let missing = partial.missing_against_cases(&declared)?;
        let required = fixture["session_content_authority_contract"]["required_case_names"]
            .as_array()
            .context("required nested Agent cases")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .context("nested case name")
                    .map(str::to_owned)
            })
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(partial.cases.len() == 30 && declared.len() == 96);
        ensure!(
            missing.len() == 66 && missing.iter().cloned().collect::<BTreeSet<_>>() == required
        );
        ensure!(partial.assert_complete_against_cases(&declared).is_err());
        println!(
            "[named-agent-inventory] primary_placeholders=30 nested_required_missing=66 total_required=96 runtime_evidence_credit=0"
        );
        Ok(())
    }

    #[test]
    fn sync_partial_production_results_keep_every_other_case_open() -> Result<()> {
        let fixture = super::super::load_fixture_value("client-sync-fixture.json")?;
        let id = "sidecar_history_current_projection_same_cut_before_checkpoint";
        let mut execution = SuiteExecutionResult {
            entrypoint: SYNC_CLIENT_ENTRYPOINT,
            fixture: "client-sync-fixture.json",
            cases: vec![super::super::CaseExecutionResult {
                case_id: id.into(),
                assertions: 1,
            }],
        };
        let missing = missing_sync_production_cases(&execution, &fixture)?;
        let declared = [
            "stream_tails",
            "checkpoint_ordering",
            "reconnect",
            "delivery_cancellation",
        ]
        .into_iter()
        .map(|section| fixture[section].as_array().unwrap().len())
        .sum::<usize>();
        assert_eq!(missing.len(), declared - 1);
        assert!(!missing.iter().any(|name| name == id));
        execution.cases.push(execution.cases[0].clone());
        assert!(missing_sync_production_cases(&execution, &fixture).is_err());
        execution.cases.pop();
        execution.cases[0].assertions = 0;
        assert!(missing_sync_production_cases(&execution, &fixture).is_err());
        execution.cases[0].assertions = 1;
        execution.cases[0].case_id = "not_in_the_canonical_fixture".into();
        assert!(missing_sync_production_cases(&execution, &fixture).is_err());
        execution.fixture = "unrelated.json";
        assert!(missing_sync_production_cases(&execution, &fixture).is_err());
        Ok(())
    }

    fn passing_evidence_runner() -> Result<()> {
        Ok(())
    }

    #[test]
    fn strand_watch_registered_executor_consumes_every_canonical_section() -> Result<()> {
        let fixture = super::super::load_fixture_value("strand-watch-current-read-fixture.json")?;
        let runner = RUNNERS
            .iter()
            .find(|(entrypoint, _)| *entrypoint == STRAND_WATCH_CURRENT_ENTRYPOINT)
            .context("Strand Watch has no registered executor")?;
        let execution = execute_runner(STRAND_WATCH_CURRENT_ENTRYPOINT, runner.1, &fixture)?
            .context("Strand Watch returned no per-case results")?;
        ensure!(execution.cases.len() == 58);
        println!("[named-watch] {execution:#?}");
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
