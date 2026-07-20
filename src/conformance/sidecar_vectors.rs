//! Sidecar conformance vectors (§0.11 of `_before_todos.md`).
//!
//! 5 vectors:
//!   - `ak.vector.sidecar.ensure_idempotent.v1`
//!   - `ak.vector.sidecar.eligibility_states.v1`
//!   - `ak.vector.sidecar.existence_privacy.v1`
//!   - `ak.vector.sidecar.hosted_projection.v1`
//!   - `ak.vector.sidecar.multi_agent_publish.v1`
//!
//! These vectors pin the first-class Sidecar wire model. Backing scope is an
//! internal MLS implementation detail and may not appear in public outcomes.

use anyhow::{Result, anyhow, bail};
use arkret::{AgentSidecarDisplayMode, AgentSidecarExchangeOrigin, SidecarId};
use arkret_core::{CapabilityActionId, PROFILE_AGENT_SIDECAR};
use serde_json::Value;

pub const VECTOR_ID_SIDECAR_ENSURE_IDEMPOTENT: &str = "ak.vector.sidecar.ensure_idempotent.v1";
pub const VECTOR_ID_SIDECAR_ELIGIBILITY_STATES: &str = "ak.vector.sidecar.eligibility_states.v1";
pub const VECTOR_ID_SIDECAR_EXISTENCE_PRIVACY: &str = "ak.vector.sidecar.existence_privacy.v1";
pub const VECTOR_ID_SIDECAR_HOSTED_PROJECTION: &str = "ak.vector.sidecar.hosted_projection.v1";
pub const VECTOR_ID_SIDECAR_MULTI_AGENT_PUBLISH: &str = "ak.vector.sidecar.multi_agent_publish.v1";

pub const ALL_SIDECAR_VECTOR_IDS: &[&str] = &[
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

/// Suite entry point — runs all 5 Sidecar vectors.
pub fn run_sidecar_vector_suite() -> Result<()> {
    validate_sidecar_vectors_fixture_metadata()?;
    if ALL_SIDECAR_VECTOR_IDS.len() != 5 {
        bail!(
            "expected 5 sidecar vector ids, got {}",
            ALL_SIDECAR_VECTOR_IDS.len()
        );
    }
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
    fn all_five_sidecar_vectors_run_clean() {
        run_sidecar_vector_suite().unwrap();
    }
}
