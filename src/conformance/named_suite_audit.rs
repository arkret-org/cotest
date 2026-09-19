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
    KEYPACKAGE_WRITE_TRANSCRIPTS_ENTRYPOINT, PROTOCOL_TIME_TOLERANCE_ENTRYPOINT,
    SuiteExecutionResult, run_account_status_issuer_ledger_vector,
    run_agent_membership_cascade_suite, run_applet_registration_epoch_kat_suite,
    run_authority_commit_suite, run_encoding_fixture_suite, run_event_envelope_fixture_suite,
    run_fanout_route_miss_suite, run_file_transfer_stream_aead_fixture_suite,
    run_invite_new_source_quota_suite, run_keypackage_write_transcripts_suite,
    run_mls_creator_bootstrap_recovery_suite, run_protocol_time_tolerance_suite,
    run_security_transaction_resilience_joint_gate, run_session_grant_issuer_ledger_suite,
    run_signal_sequence_high_water_suite, run_sync_fixture_suite, run_webrtc_media_plaintext_suite,
    run_websocket_binding_suite, spec_artifacts_root,
};

const ACCOUNT_STATUS_ENTRYPOINT: &str = "ak.suite.account_status.issuer_ledger.v1";

/// Exact acknowledged gap ledger. This is deliberately closed: adding or
/// renaming a canonical named suite cannot remain invisible merely because the
/// total number of unwired suites happened to stay constant.
const KNOWN_UNWIRED_ENTRYPOINTS: [&str; 45] = [
    "ak.suite.account.blocklist_projection.v1",
    "ak.suite.account_data.cas_convergence.v1",
    "ak.suite.account_data.private_view_inbox_binding.v1",
    "ak.suite.agent.mls_keypackage_authorization.v1",
    "ak.suite.agent.participation.v1",
    "ak.suite.agent.vectors.v1",
    "ak.suite.applet.managed_actor_authority.v1",
    "ak.suite.applet.revoke_saga.v1",
    "ak.suite.auth.session_proof.v1",
    "ak.suite.authz.approval_signature.v1",
    "ak.suite.authz.authorization_lease_issuance.v1",
    "ak.suite.blob.stream_aead.v1",
    "ak.suite.call.media_lifecycle.v1",
    "ak.suite.call.state_core.v1",
    "ak.suite.conformance.final_closure.v1",
    "ak.suite.consent.cache_invalidation.v1",
    "ak.suite.contact.bilateral_continuity_checkpoint.v1",
    "ak.suite.crypto.hpke.v1",
    "ak.suite.crypto.key_backup_hardening.v1",
    "ak.suite.crypto.keypackage_lifecycle.v1",
    "ak.suite.encoding.content_bound_event_id.v1",
    "ak.suite.encoding.cursor_negative.v1",
    "ak.suite.encoding.string_profiles.v1",
    "ak.suite.events.redaction.v1",
    "ak.suite.federation.idempotency_after_key_revoke.v1",
    "ak.suite.identity.independent_admission.v1",
    "ak.suite.identity.pcr_genesis.v1",
    "ak.suite.identity.producer_allocated_collision.v1",
    "ak.suite.identity.test_material_rejection.v1",
    "ak.suite.identity_link.invalidation.v1",
    "ak.suite.invite.claim_security.v1",
    "ak.suite.media.binding.v1",
    "ak.suite.mls.governance_binding_closure.v1",
    "ak.suite.mls.rfc9420_kat.v1",
    "ak.suite.moderation.franking_proof_transcript.v1",
    "ak.suite.object_identity.producer_allocated_collision.v1",
    "ak.suite.privacy.security.v1",
    "ak.suite.protocol.edge_cases.v1",
    "ak.suite.push.rule_core.v1",
    "ak.suite.scope.circle.v1",
    "ak.suite.sdk.event_type_axes.v1",
    "ak.suite.sdk.precheck.v1",
    "ak.suite.service.protocol_version_bootstrap.v1",
    "ak.suite.view.write_contract.v1",
    "ak.suite.visibility.policy.v1",
];

enum Runner {
    Cases(fn() -> Result<SuiteExecutionResult>),
    EvidenceMapped(fn() -> Result<()>),
}

const RUNNERS: [(&str, Runner); 18] = [
    (
        "ak.suite.agent.membership_cascade.v1",
        Runner::EvidenceMapped(run_agent_membership_cascade_suite),
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
        "ak.suite.crypto.signature.v1",
        Runner::EvidenceMapped(run_event_envelope_fixture_suite),
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
        KEYPACKAGE_WRITE_TRANSCRIPTS_ENTRYPOINT,
        Runner::Cases(run_keypackage_write_transcripts_suite),
    ),
    (
        PROTOCOL_TIME_TOLERANCE_ENTRYPOINT,
        Runner::Cases(run_protocol_time_tolerance_suite),
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
            .ok_or_else(|| anyhow!("{} has no runner entrypoint", path.display()))?;
        ensure!(
            fixtures.insert(entrypoint.to_owned(), value).is_none(),
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
