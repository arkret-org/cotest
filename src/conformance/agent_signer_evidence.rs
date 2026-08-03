//! Executable shape checks for the current/historical Agent-signer evidence fixture.
//!
//! Spec 1936d1c0 deliberately stopped publishing synthetic authorization
//! snapshots and fake signatures as conformance vectors.  The fixture now
//! declares the two verification regimes and their closed result matrix;
//! cryptographic construction and verification remain owned by the SDK.

use anyhow::{Context, Result, bail};
use arkret_signatures::agent_evidence::{
    AgentEvidenceRejectedReason, SignerPrincipalKind, SignerRegime,
    agent_authorization_dot_matches_event, dispatch_signer_regime, verify_event_signer_controller,
};
use arkret_wire::{Did, DidUrl, Event, EventKind, Hlc, RealmId, ScopeRef};
use serde_json::Value;

use super::{fixture_runner_entrypoint, load_fixture_value, validate_profile};

pub const AGENT_SIGNER_EVIDENCE_FIXTURE: &str = "agent-signer-evidence-fixture.json";
pub const AGENT_SIGNER_EVIDENCE_SUITE: &str = "ak.suite.agent.signer_evidence.v1";

pub const ALL_AGENT_SIGNER_EVIDENCE_CASES: &[&str] = &[
    "current_exact_request_and_three_active_gates_verified",
    "current_cross_verifier_replay_rejected",
    "current_request_or_challenge_replay_rejected",
    "current_snapshot_digest_mix_and_match_rejected",
    "current_stale_lease_is_unresolved",
    "current_paused_agent_rejected",
    "current_inactive_controller_account_rejected",
    "current_revoked_or_superseded_key_rejected",
    "historical_destination_receipt_preserves_admission",
    "historical_current_snapshot_substitution_rejected",
    "historical_wrong_destination_receipt_rejected",
    "historical_inactive_gate_at_receipt_time_rejected",
    "account_gate_never_discloses_local_identity",
    "agent_genesis_active_requires_provision_ref",
    "organization_pcr_cannot_materialize_agent_active",
    "state_witness_uses_canonical_event_dot",
    "bare_event_id_state_tag_rejected",
    "outer_attestation_prevents_mode_splice",
    "historical_mls_leaf_cross_binding_verified",
    "duplicate_or_mismatched_mls_leaf_rejected",
    "minimal_metadata_forbids_agent_evidence_query",
];

pub fn run_agent_signer_evidence_vector_suite() -> Result<()> {
    let fixture = load_fixture_value(AGENT_SIGNER_EVIDENCE_FIXTURE)?;
    validate_profile(&fixture, "ak.profile.agent_signer_evidence.v1")?;
    if fixture_runner_entrypoint(&fixture)? != AGENT_SIGNER_EVIDENCE_SUITE {
        bail!("Agent signer-evidence fixture runner entrypoint drifted");
    }

    validate_binding_requirements(&fixture)?;
    validate_case_matrix(&fixture)?;
    exercise_sdk_owned_dispatch_and_event_binding()?;
    Ok(())
}

fn validate_binding_requirements(fixture: &Value) -> Result<()> {
    let binding = fixture
        .get("binding_vector")
        .and_then(Value::as_object)
        .context("Agent signer-evidence fixture missing binding_vector")?;
    for field in [
        "agent_id",
        "controller_id",
        "verification_method",
        "agent_key_authorize_event_id",
        "public_key",
        "binding_digest",
    ] {
        binding
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .with_context(|| format!("binding_vector.{field} must be a non-empty string"))?;
    }
    let requirements = binding
        .get("requirements")
        .and_then(Value::as_array)
        .context("binding_vector.requirements missing")?;
    let expected = [
        "recompute_controller_proof_transcript",
        "recompute_public_key_digest",
        "match_authorize_event_commitment",
        "match_agent_and_controller",
    ];
    if requirements
        .iter()
        .map(|value| value.as_str())
        .collect::<Option<Vec<_>>>()
        .as_deref()
        != Some(expected.as_slice())
    {
        bail!("Agent signer binding requirements drifted");
    }
    Ok(())
}

fn validate_case_matrix(fixture: &Value) -> Result<()> {
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .context("Agent signer-evidence fixture cases missing")?;
    let names = cases
        .iter()
        .map(|case| case.get("name").and_then(Value::as_str))
        .collect::<Option<Vec<_>>>()
        .context("Agent signer-evidence case name missing")?;
    if names != ALL_AGENT_SIGNER_EVIDENCE_CASES {
        bail!("Agent signer-evidence case registry drifted");
    }

    for case in cases {
        let expected = case
            .get("expected")
            .and_then(Value::as_str)
            .context("Agent signer-evidence case expected result missing")?;
        if !matches!(
            expected,
            "verified" | "rejected" | "unresolved" | "verified_by_minimal_metadata_only"
        ) {
            bail!("Agent signer-evidence case has open expected result {expected}");
        }
        if let Some(mode) = case.get("verification_mode").and_then(Value::as_str)
            && !matches!(mode, "current_admission" | "historical_event")
        {
            bail!("Agent signer-evidence case has open verification mode {mode}");
        }
        let reason = case.get("reason").and_then(Value::as_str);
        if matches!(expected, "rejected" | "unresolved") && reason.is_none() {
            bail!("negative Agent signer-evidence case must name a reason");
        }
    }
    Ok(())
}

fn exercise_sdk_owned_dispatch_and_event_binding() -> Result<()> {
    if dispatch_signer_regime(false, SignerPrincipalKind::NativeAgent)
        .map_err(|reason| anyhow::anyhow!("{reason:?}"))?
        != SignerRegime::OrdinaryNativeAgent
        || dispatch_signer_regime(true, SignerPrincipalKind::NativeAgent)
            .map_err(|reason| anyhow::anyhow!("{reason:?}"))?
            != SignerRegime::MinimalMetadata
        || dispatch_signer_regime(false, SignerPrincipalKind::Unknown)
            != Err(AgentEvidenceRejectedReason::SigningKeyMismatch)
    {
        bail!("SDK Agent signer regime dispatch drifted");
    }

    let actor = Did::new("did:webvh:z6mkactor:actor.example")?;
    let signer = Did::new("did:webvh:z6mkagent:agent.example")?;
    let mut event = Event::new(
        EventKind::MESSAGE_CREATE,
        ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:01964137-0000-7000-8000-000000000009")?,
        },
        actor.clone(),
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e")?,
        serde_json::json!({}),
    )?;
    event.executed_by = Some(signer.clone());
    let binding = verify_event_signer_controller(
        &event,
        &DidUrl::new(format!("{signer}#runtime-1")).map_err(anyhow::Error::msg)?,
    )
    .map_err(|reason| anyhow::anyhow!("{reason:?}"))?;
    if binding.binding_actor_id != actor || binding.signer_id != signer {
        bail!("SDK delegated Agent actor/signer binding drifted");
    }
    if !agent_authorization_dot_matches_event(
        "ak:event:01964137-0000-7000-8000-000000000001:0",
        "ak:event:01964137-0000-7000-8000-000000000001",
    ) || agent_authorization_dot_matches_event(
        "ak:event:01964137-0000-7000-8000-000000000001",
        "ak:event:01964137-0000-7000-8000-000000000001",
    ) {
        bail!("SDK Agent authorization dot validation drifted");
    }
    Ok(())
}
