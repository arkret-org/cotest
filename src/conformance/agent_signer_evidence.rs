use std::collections::BTreeSet;

use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;

use super::load_fixture_value;

pub const AGENT_SIGNER_EVIDENCE_FIXTURE: &str = "agent-signer-evidence-fixture.json";
pub const AGENT_SIGNER_EVIDENCE_SUITE: &str = "ak.suite.agent.signer_evidence.v1";

pub const ALL_AGENT_SIGNER_EVIDENCE_CASES: &[&str] = &[
    "query_success_returns_cas_frozen_authenticated_root",
    "current_stale_attestation_is_unresolved",
    "current_paused_agent_rejected",
    "current_inactive_controller_account_rejected",
    "current_revoked_or_superseded_key_rejected",
    "account_gate_never_discloses_local_identity",
    "producer_fetches_controller_gate_from_account_authority",
    "controller_gate_exact_request_replay_is_byte_identical",
    "controller_gate_request_id_conflict_is_zero_issuance",
    "controller_gate_wrong_source_and_unknown_principal_are_indistinguishable",
    "controller_gate_inactive_status_is_signed_not_forged_by_producer",
    "agent_genesis_active_witness_binds_admitted_genesis",
    "organization_pcr_cannot_materialize_agent_active",
    "state_witness_uses_canonical_event_dot",
    "bare_event_id_state_tag_rejected",
    "minimal_metadata_forbids_agent_evidence_query",
    "current_valid_relation_reuses_signed_state_across_signals",
    "current_shared_state_does_not_share_device_verification",
    "current_reconnect_and_trusted_restore_do_not_renew_state",
    "current_delta_hydrates_same_canonical_root",
    "current_delta_missing_state_or_dependency_unresolved",
    "current_state_substitution_rejected",
    "current_cross_account_station_or_scope_rejected",
    "current_state_age_cannot_exceed_300_seconds",
    "current_repackaging_does_not_extend_original_deadline",
    "current_gate_expiry_shortens_effective_deadline",
    "current_known_revocation_invalidates_before_deadline",
    "agent_pcr_resume_retains_original_genesis_notary",
    "controller_device_binding_uses_authorization_event_admitted_key",
    "historical_portable_producer_evidence_at_any_receiver",
    "historical_missing_original_dependency",
    "historical_query_window_expiry_does_not_invalidate_evidence",
    "historical_applicable_closure_excludes_event",
    "historical_current_key_cannot_replace_original_key",
];

pub fn run_agent_signer_evidence_vector_suite() -> Result<()> {
    let fixture = load_fixture_value(AGENT_SIGNER_EVIDENCE_FIXTURE)?;
    ensure!(
        fixture.get("profile").and_then(Value::as_str)
            == Some("ak.profile.agent_signer_evidence.v1")
    );
    ensure!(
        fixture
            .pointer("/runner/entrypoint")
            .and_then(Value::as_str)
            == Some(AGENT_SIGNER_EVIDENCE_SUITE)
    );
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .context("agent signer evidence fixture omits cases[]")?;
    let names = cases
        .iter()
        .map(|case| {
            case.get("name")
                .and_then(Value::as_str)
                .context("agent signer evidence case omits name")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(names == ALL_AGENT_SIGNER_EVIDENCE_CASES);
    ensure!(names.iter().collect::<BTreeSet<_>>().len() == names.len());

    let encoded = arkret_canonical::canonical_json_bytes(&fixture)?;
    for removed in [
        b"station_admission".as_slice(),
        b"original_admission",
        b"current_stale_lease",
        b"state_digest_matches_lease",
        b"lease_remaining_seconds",
        b"lease_cache_expired",
    ] {
        if encoded
            .windows(removed.len())
            .any(|window| window == removed)
        {
            bail!(
                "agent signer evidence fixture retains removed origin admission term {}",
                String::from_utf8_lossy(removed)
            );
        }
    }

    let portable = case(
        cases,
        "historical_portable_producer_evidence_at_any_receiver",
    )?;
    ensure!(portable.get("expected").and_then(Value::as_str) == Some("verified"));
    ensure!(
        portable
            .get("receiver_receipt_required")
            .and_then(Value::as_bool)
            == Some(false)
    );
    ensure!(
        portable
            .get("original_authority_verified")
            .and_then(Value::as_bool)
            == Some(true)
    );
    let missing = case(cases, "historical_missing_original_dependency")?;
    ensure!(missing.get("expected").and_then(Value::as_str) == Some("unresolved"));
    let expired_query_window = case(
        cases,
        "historical_query_window_expiry_does_not_invalidate_evidence",
    )?;
    ensure!(
        expired_query_window
            .get("attestation_query_window_expired")
            .and_then(Value::as_bool)
            == Some(true)
            && expired_query_window.get("expected").and_then(Value::as_str) == Some("verified")
    );
    let revocation = case(
        cases,
        "current_known_revocation_invalidates_before_deadline",
    )?;
    ensure!(revocation.get("expected").and_then(Value::as_str) == Some("rejected"));

    // The private controller-gate adapter authenticates caller, target and
    // trust domain at the channel boundary. That authenticated identity is the
    // only source of the caller; a body field, path segment or deployment
    // bearer MUST NOT stand in for it, and the request MUST NOT carry a
    // service-resolution carrier.
    let controller_gate = case(
        cases,
        "producer_fetches_controller_gate_from_account_authority",
    )?;
    ensure!(controller_gate.get("operation_id").is_none());
    for (field, expected) in [
        (
            "internal_authentication_binds_caller_station_domain_and_operation",
            true,
        ),
        ("request_carries_service_resolution_carrier", false),
        ("caller_identity_from_request_body", false),
        ("bearer_used_as_identity_substitute", false),
        ("authenticated_source_matches_agent_authority_id", true),
        (
            "authenticated_station_matches_principal_current_binding_authority",
            true,
        ),
    ] {
        ensure!(
            controller_gate.get(field).and_then(Value::as_bool) == Some(expected),
            "controller gate fixture must pin the internal-channel contract field {field} = {expected}"
        );
    }

    // A wrong or unauthorized caller is indistinguishable from an unknown
    // principal: a distinguishable error would turn the private channel into
    // an account-existence oracle.
    let wrong_source = case(
        cases,
        "controller_gate_wrong_source_and_unknown_principal_are_indistinguishable",
    )?;
    let scenarios = wrong_source
        .get("scenarios")
        .and_then(Value::as_array)
        .context("controller gate wrong-source case omits scenarios[]")?;
    for required in [
        "unknown_principal",
        "missing_current_station",
        "source_service_mismatch",
        "unauthorized_service",
    ] {
        ensure!(
            scenarios.iter().any(|scenario| scenario == required),
            "controller gate wrong-source case is missing scenario {required}"
        );
    }
    ensure!(
        wrong_source
            .get("same_error_envelope")
            .and_then(Value::as_bool)
            == Some(true)
            && wrong_source
                .get("account_status_disclosed")
                .and_then(Value::as_bool)
                == Some(false)
            && wrong_source.get("expected").and_then(Value::as_str) == Some("rejected")
            && wrong_source.get("reason").and_then(Value::as_str) == Some("not_found")
    );
    Ok(())
}

fn case<'a>(cases: &'a [Value], name: &str) -> Result<&'a Value> {
    cases
        .iter()
        .find(|case| case.get("name").and_then(Value::as_str) == Some(name))
        .with_context(|| format!("agent signer evidence fixture omits {name}"))
}
