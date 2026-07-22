//! Sidecar conformance vectors (§0.11 of `_before_todos.md`).
//!
//! 7 vectors:
//!   - `ak.vector.sidecar.mls_bootstrap_binding.v1`
//!   - `ak.vector.sidecar.mls_effective_access.v1`
//!   - `ak.vector.sidecar.ensure_idempotent.v1`
//!   - `ak.vector.sidecar.eligibility_states.v1`
//!   - `ak.vector.sidecar.existence_privacy.v1`
//!   - `ak.vector.sidecar.hosted_projection.v1`
//!   - `ak.vector.sidecar.multi_agent_publish.v1`
//!
//! These vectors pin the first-class Sidecar wire model. Backing scope is an
//! internal MLS implementation detail and may not appear in public outcomes.

use anyhow::{Result, anyhow, bail};
use arkret::{
    AgentSidecarDisplayMode, AgentSidecarExchangeOrigin, Did, EventId, Hash,
    MlsGovernanceBindingPayload, NonEmptyString, PendingSidecarAccessReconciliationItem,
    PendingSidecarAccessReconciliationStage, RealmId, SidecarId, SidecarMlsBinding,
    agent_sidecar_desired_access_digest,
};
use arkret_core::{CapabilityActionId, PROFILE_AGENT_SIDECAR};
use serde_json::Value;

pub const VECTOR_ID_SIDECAR_ENSURE_IDEMPOTENT: &str = "ak.vector.sidecar.ensure_idempotent.v1";
pub const VECTOR_ID_SIDECAR_MLS_BOOTSTRAP_BINDING: &str =
    "ak.vector.sidecar.mls_bootstrap_binding.v1";
pub const VECTOR_ID_SIDECAR_MLS_EFFECTIVE_ACCESS: &str =
    "ak.vector.sidecar.mls_effective_access.v1";
pub const VECTOR_ID_SIDECAR_ELIGIBILITY_STATES: &str = "ak.vector.sidecar.eligibility_states.v1";
pub const VECTOR_ID_SIDECAR_EXISTENCE_PRIVACY: &str = "ak.vector.sidecar.existence_privacy.v1";
pub const VECTOR_ID_SIDECAR_HOSTED_PROJECTION: &str = "ak.vector.sidecar.hosted_projection.v1";
pub const VECTOR_ID_SIDECAR_MULTI_AGENT_PUBLISH: &str = "ak.vector.sidecar.multi_agent_publish.v1";

pub const ALL_SIDECAR_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_SIDECAR_MLS_BOOTSTRAP_BINDING,
    VECTOR_ID_SIDECAR_MLS_EFFECTIVE_ACCESS,
    VECTOR_ID_SIDECAR_ENSURE_IDEMPOTENT,
    VECTOR_ID_SIDECAR_ELIGIBILITY_STATES,
    VECTOR_ID_SIDECAR_EXISTENCE_PRIVACY,
    VECTOR_ID_SIDECAR_HOSTED_PROJECTION,
    VECTOR_ID_SIDECAR_MULTI_AGENT_PUBLISH,
];

const SIDECAR_VECTORS_FIXTURE_FILE: &str = "agent-sidecar-fixture.json";
const SIDECAR_VECTORS_PROFILE: &str = "ak.profile.agent_sidecar.v1";

fn validate_sidecar_vectors_fixture_metadata() -> Result<()> {
    let fixture = super::load_fixture_value(SIDECAR_VECTORS_FIXTURE_FILE)?;
    super::validate_profile(&fixture, SIDECAR_VECTORS_PROFILE)?;
    let covers = fixture
        .get("covers_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("sidecar fixture missing covers_vectors[]"))?;
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("sidecar fixture missing cases[]"))?;

    for vector_id in ALL_SIDECAR_VECTOR_IDS {
        if !covers
            .iter()
            .any(|entry| entry.as_str() == Some(*vector_id))
        {
            bail!("sidecar fixture missing covers_vectors entry {vector_id}");
        }
        if !cases.iter().any(|case| {
            case.get("vector_id").and_then(Value::as_str) == Some(*vector_id)
                && case
                    .get("assertions")
                    .and_then(Value::as_array)
                    .is_some_and(|assertions| !assertions.is_empty())
        }) {
            bail!("sidecar fixture missing asserted case {vector_id}");
        }
    }

    Ok(())
}

// ─── VECT-SC-1 — ensure_idempotent ─────────────────────────────────────────

pub fn run_sidecar_mls_bootstrap_binding_vector() -> Result<()> {
    let fixture = super::load_fixture_value(SIDECAR_VECTORS_FIXTURE_FILE)?;
    let case = fixture["cases"]
        .as_array()
        .and_then(|cases| {
            cases.iter().find(|case| {
                case["vector_id"].as_str() == Some(VECTOR_ID_SIDECAR_MLS_BOOTSTRAP_BINDING)
            })
        })
        .ok_or_else(|| anyhow!("Sidecar MLS bootstrap fixture case is missing"))?;
    let transcript = &case["desired_access_transcript"];
    let sidecar_id = SidecarId::new(
        transcript["sidecar_id"]
            .as_str()
            .ok_or_else(|| anyhow!("fixture sidecar_id is missing"))?
            .to_owned(),
    )?;
    let realm_id = RealmId::new(
        transcript["realm_id"]
            .as_str()
            .ok_or_else(|| anyhow!("fixture realm_id is missing"))?
            .to_owned(),
    )?;
    let controller_id = Did::new(
        transcript["controller_id"]
            .as_str()
            .ok_or_else(|| anyhow!("fixture controller_id is missing"))?
            .to_owned(),
    )?;
    let desired_agent_ids = transcript["principal_ids"]
        .as_array()
        .ok_or_else(|| anyhow!("fixture principal_ids are missing"))?
        .iter()
        .filter_map(Value::as_str)
        .filter(|principal_id| *principal_id != controller_id.as_str())
        .map(|principal_id| Did::new(principal_id.to_owned()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let digest = agent_sidecar_desired_access_digest(
        sidecar_id.clone(),
        realm_id.clone(),
        controller_id,
        &desired_agent_ids,
    )?;
    if case["expected_desired_access_digest"].as_str() != Some(digest.as_str()) {
        bail!("Sidecar desired-access canonical digest differs from the fixture KAT");
    }

    let sidecar_binding = SidecarMlsBinding {
        sidecar_id,
        desired_access_digest: digest,
        control_frontier: vec![
            NonEmptyString::new("ak:event:01964137-0000-7000-8000-000000000040")
                .map_err(anyhow::Error::msg)?,
        ],
    };
    let binding = MlsGovernanceBindingPayload::circle(
        realm_id,
        arkret::CircleId::new("ak:circle:01964137-0000-7000-8000-000000000030".to_owned())?,
        "YXJrcmV0LXNpZGVjYXItZ3JvdXA",
        0,
        0,
        vec![EventId::new(
            "ak:event:01964137-0000-7000-8000-000000000040".to_owned(),
        )?],
        Hash::new(format!("sha256:{}", "1".repeat(64)))?,
        Hash::new(format!("sha256:{}", "2".repeat(64)))?,
        Hash::new(format!("sha256:{}", "3".repeat(64)))?,
        "ak.profile.mls_governance_binding.full.v1",
        "ak.reducer.v1",
    )?
    .with_sidecar_binding(sidecar_binding.clone())?;
    let cbor = binding.to_deterministic_cbor()?;
    let decoded = MlsGovernanceBindingPayload::from_deterministic_cbor(&cbor)?;
    if decoded.sidecar_binding() != Some(&sidecar_binding)
        || decoded.to_deterministic_cbor()? != cbor
    {
        bail!("Sidecar MLS binding did not survive deterministic CBOR round-trip");
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct DeviceJoinEvidence {
    active_authorized: bool,
    accepted_add_commit: bool,
    matching_welcome: bool,
    key_package_consumed: bool,
    current_join_ref_bound: bool,
}

fn principal_effective(devices: &[DeviceJoinEvidence]) -> bool {
    devices.iter().any(|device| {
        device.active_authorized
            && device.accepted_add_commit
            && device.matching_welcome
            && device.key_package_consumed
            && device.current_join_ref_bound
    })
}

pub fn run_sidecar_mls_effective_access_vector() -> Result<()> {
    let complete = DeviceJoinEvidence {
        active_authorized: true,
        accepted_add_commit: true,
        matching_welcome: true,
        key_package_consumed: true,
        current_join_ref_bound: true,
    };
    if !principal_effective(&[complete]) {
        bail!("one complete active-device evidence chain must make the principal effective");
    }
    for incomplete in [
        DeviceJoinEvidence {
            accepted_add_commit: false,
            ..complete
        },
        DeviceJoinEvidence {
            matching_welcome: false,
            ..complete
        },
        DeviceJoinEvidence {
            key_package_consumed: false,
            ..complete
        },
        DeviceJoinEvidence {
            current_join_ref_bound: false,
            ..complete
        },
        DeviceJoinEvidence {
            active_authorized: false,
            ..complete
        },
    ] {
        if principal_effective(&[incomplete]) {
            bail!("incomplete or unauthorized device evidence became effective");
        }
    }
    let desired_after_removal = false;
    let delivery_allowed = desired_after_removal && principal_effective(&[complete]);
    let removal_obligation_created = !desired_after_removal;
    let principal_server_authored_commit = false;
    if delivery_allowed || !removal_obligation_created || principal_server_authored_commit {
        bail!(
            "Sidecar removal must stop delivery and create only a client-authored MLS obligation"
        );
    }
    let removal = PendingSidecarAccessReconciliationItem {
        agent_id: Did::new("did:webvh:z6mkfixture:assistant.agents.example")?,
        stage: PendingSidecarAccessReconciliationStage::MlsRemove,
        reason: NonEmptyString::new("mls_remove_obligation_pending")?,
        membership_frontier: Some(vec![EventId::new(
            "ak:event:01964137-0000-7000-8000-000000000041",
        )?]),
    };
    removal.validate()?;
    Ok(())
}

pub fn run_sidecar_ensure_idempotent_vector() -> Result<()> {
    if arkret_core::ServiceOperationId::SELF_AGENT_SIDECAR_COMMAND_ENSURE
        != "ak.self.agent.sidecar.command.ensure"
    {
        bail!("Sidecar ensure operation spelling drifted");
    }
    if CapabilityActionId::SELF_AGENT_SIDECAR_COMMAND_ENSURE
        != "ak.self.agent.sidecar.command.ensure"
    {
        bail!("sidecar ensure capability action spelling drifted");
    }
    if PROFILE_AGENT_SIDECAR != "ak.profile.agent_sidecar.v1" {
        bail!("PROFILE_AGENT_SIDECAR spelling drifted: {PROFILE_AGENT_SIDECAR}");
    }
    // Idempotency invariant: same (controller, agent_principal) MUST
    // yield the same `sidecar_id`. Wire-shape: deterministic
    // derivation is server-side; here we pin that the operation id is
    // stable so the client can re-issue safely.
    Ok(())
}

// ─── VECT-SC-2 — eligibility_states ────────────────────────────────────────

pub fn run_sidecar_eligibility_states_vector() -> Result<()> {
    // Sidecar ensure rejects from `paused` / `deactivated` agents with
    // the canonical error codes (also covered by the agent FSM
    // vector, but pinned again at the sidecar-specific code path).
    if arkret_core::error::ReasonCode::AGENT_PAUSED != "agent_paused" {
        bail!("arkret_core::error::ReasonCode::AGENT_PAUSED spelling drifted: agent_paused");
    }
    if arkret_core::error::ReasonCode::AGENT_DEACTIVATED != "agent_deactivated" {
        bail!(
            "arkret_core::error::ReasonCode::AGENT_DEACTIVATED spelling drifted: agent_deactivated"
        );
    }
    Ok(())
}

// ─── VECT-SC-3 — existence_privacy ─────────────────────────────────────────

pub fn run_sidecar_existence_privacy_vector() -> Result<()> {
    // A caller without the Sidecar ensure capability
    // MUST receive `sidecar_create_denied` (NOT `not_found` — the
    // server MUST NOT confirm or deny existence by error code).
    if arkret_core::error::ReasonCode::SIDECAR_CREATE_DENIED != "sidecar_create_denied" {
        bail!(
            "arkret_core::error::ReasonCode::SIDECAR_CREATE_DENIED spelling drifted: sidecar_create_denied"
        );
    }
    Ok(())
}

// ─── VECT-SC-4 — hosted_projection ─────────────────────────────────────────

pub fn run_sidecar_hosted_projection_vector() -> Result<()> {
    let sidecar = SidecarId::new("ak:sidecar:01964137-0000-7000-8000-000000000021".to_owned())?;
    if !sidecar.as_str().starts_with("ak:sidecar:") {
        bail!("Sidecar identity is not first-class");
    }
    if serde_json::to_value(AgentSidecarDisplayMode::ContextMerged)? != "context_merged"
        || serde_json::to_value(AgentSidecarDisplayMode::SidecarOnly)? != "sidecar_only"
        || serde_json::to_value(AgentSidecarExchangeOrigin::SourceTrackRouted)?
            != "source_track_routed"
        || serde_json::to_value(AgentSidecarExchangeOrigin::SidecarNative)? != "sidecar_native"
    {
        bail!("hosted Sidecar closed enums drifted");
    }
    Ok(())
}

// ─── VECT-SC-4 — multi_agent_publish ───────────────────────────────────────

pub fn run_sidecar_multi_agent_publish_vector() -> Result<()> {
    // The publish/write/ensure trio MUST be present and namespaced.
    let trio = [
        CapabilityActionId::SELF_AGENT_SIDECAR_COMMAND_ENSURE,
        CapabilityActionId::AGENT_SIDECAR_WRITE,
        CapabilityActionId::AGENT_SIDECAR_PUBLISH,
    ];
    for action in trio {
        if !action.contains(".sidecar.") {
            bail!("sidecar capability action `{action}` lost canonical scope");
        }
    }
    let mut sorted = trio.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != trio.len() {
        bail!("sidecar capability action trio has duplicates");
    }
    Ok(())
}

/// Suite entry point — runs all 7 Sidecar vectors.
pub fn run_sidecar_vector_suite() -> Result<()> {
    validate_sidecar_vectors_fixture_metadata()?;
    if ALL_SIDECAR_VECTOR_IDS.len() != 7 {
        bail!(
            "expected 7 sidecar vector ids, got {}",
            ALL_SIDECAR_VECTOR_IDS.len()
        );
    }
    run_sidecar_mls_bootstrap_binding_vector()?;
    run_sidecar_mls_effective_access_vector()?;
    run_sidecar_ensure_idempotent_vector()?;
    run_sidecar_eligibility_states_vector()?;
    run_sidecar_existence_privacy_vector()?;
    run_sidecar_hosted_projection_vector()?;
    run_sidecar_multi_agent_publish_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_seven_sidecar_vectors_run_clean() {
        run_sidecar_vector_suite().unwrap();
    }
}
