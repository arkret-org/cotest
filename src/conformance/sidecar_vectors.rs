//! Sidecar conformance vectors (§0.11 of `_before_todos.md`).
//!
//! 4 vectors:
//!   - `ck.vector.sidecar.ensure_idempotent.v1`
//!   - `ck.vector.sidecar.eligibility_states.v1`
//!   - `ck.vector.sidecar.existence_privacy.v1`
//!   - `ck.vector.sidecar.multi_agent_publish.v1`
//!
//! Wire-shape pins only. Live `POST /_arkret/self/agent-sidecar-threads:ensure`
//! and the multi-agent fan-out reducer path land in soland P2-impl;
//! this suite hard-fails on registry drift today.

use anyhow::{Result, anyhow, bail};
use arkret_core::error::{
    REASON_AGENT_DEACTIVATED, REASON_AGENT_PAUSED, REASON_SIDECAR_CREATE_DENIED,
};
use arkret_core::{
    AGENT_SIDECAR_HOME_POLICY_CONTEXT_REALM_PREFERRED, CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE,
    CAP_ACTION_AGENT_SIDECAR_THREAD_PUBLISH, CAP_ACTION_AGENT_SIDECAR_THREAD_WRITE,
    OP_AGENT_SIDECAR_THREAD_ENSURE, PROFILE_AGENT_SIDECAR_THREAD,
};
use serde_json::Value;

pub const VECTOR_ID_SIDECAR_ENSURE_IDEMPOTENT: &str = "ak.vector.sidecar.ensure_idempotent.v1";
pub const VECTOR_ID_SIDECAR_ELIGIBILITY_STATES: &str = "ak.vector.sidecar.eligibility_states.v1";
pub const VECTOR_ID_SIDECAR_EXISTENCE_PRIVACY: &str = "ak.vector.sidecar.existence_privacy.v1";
pub const VECTOR_ID_SIDECAR_MULTI_AGENT_PUBLISH: &str = "ak.vector.sidecar.multi_agent_publish.v1";

pub const ALL_SIDECAR_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_SIDECAR_ENSURE_IDEMPOTENT,
    VECTOR_ID_SIDECAR_ELIGIBILITY_STATES,
    VECTOR_ID_SIDECAR_EXISTENCE_PRIVACY,
    VECTOR_ID_SIDECAR_MULTI_AGENT_PUBLISH,
];

const SIDECAR_VECTORS_FIXTURE_FILE: &str = "agent-sidecar-fixture.json";
const SIDECAR_VECTORS_PROFILE: &str = "ak.profile.agent_sidecar_thread.v1";

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
    if OP_AGENT_SIDECAR_THREAD_ENSURE != "ak.self.agent.sidecar_thread.command.ensure" {
        bail!("OP_AGENT_SIDECAR_THREAD_ENSURE spelling drifted: {OP_AGENT_SIDECAR_THREAD_ENSURE}");
    }
    if CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE != "ak.self.agent.sidecar_thread.command.ensure" {
        bail!(
            "CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE spelling drifted: {CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE}"
        );
    }
    if PROFILE_AGENT_SIDECAR_THREAD != "ak.profile.agent_sidecar_thread.v1" {
        bail!("PROFILE_AGENT_SIDECAR_THREAD spelling drifted: {PROFILE_AGENT_SIDECAR_THREAD}");
    }
    // Idempotency invariant: same (controller, agent_principal) MUST
    // yield the same `sidecar_circle_id`. Wire-shape: deterministic
    // derivation is server-side; here we pin that the operation id is
    // stable so the client can re-issue safely.
    Ok(())
}

// ─── VECT-SC-2 — eligibility_states ────────────────────────────────────────

pub fn run_sidecar_eligibility_states_vector() -> Result<()> {
    // Sidecar ensure rejects from `paused` / `deactivated` agents with
    // the canonical error codes (also covered by the agent FSM
    // vector, but pinned again at the sidecar-specific code path).
    if REASON_AGENT_PAUSED != "agent_paused" {
        bail!("REASON_AGENT_PAUSED spelling drifted: {REASON_AGENT_PAUSED}");
    }
    if REASON_AGENT_DEACTIVATED != "agent_deactivated" {
        bail!("REASON_AGENT_DEACTIVATED spelling drifted: {REASON_AGENT_DEACTIVATED}");
    }
    // Default home-policy is `context_realm_preferred` (B-F).
    if AGENT_SIDECAR_HOME_POLICY_CONTEXT_REALM_PREFERRED != "context_realm_preferred" {
        bail!(
            "AGENT_SIDECAR_HOME_POLICY_CONTEXT_REALM_PREFERRED drifted: {}",
            AGENT_SIDECAR_HOME_POLICY_CONTEXT_REALM_PREFERRED
        );
    }
    Ok(())
}

// ─── VECT-SC-3 — existence_privacy ─────────────────────────────────────────

pub fn run_sidecar_existence_privacy_vector() -> Result<()> {
    // A caller without the `ck.self.agent.sidecar_thread.command.ensure` capability
    // MUST receive `sidecar_create_denied` (NOT `not_found` — the
    // server MUST NOT confirm or deny existence by error code).
    if REASON_SIDECAR_CREATE_DENIED != "sidecar_create_denied" {
        bail!("REASON_SIDECAR_CREATE_DENIED spelling drifted: {REASON_SIDECAR_CREATE_DENIED}");
    }
    Ok(())
}

// ─── VECT-SC-4 — multi_agent_publish ───────────────────────────────────────

pub fn run_sidecar_multi_agent_publish_vector() -> Result<()> {
    // The publish/write/ensure trio MUST be present and namespaced.
    let trio = [
        CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE,
        CAP_ACTION_AGENT_SIDECAR_THREAD_WRITE,
        CAP_ACTION_AGENT_SIDECAR_THREAD_PUBLISH,
    ];
    for action in trio {
        if !action.contains(".sidecar_thread.") {
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

/// Suite entry point — runs all 4 sidecar vectors.
pub fn run_sidecar_vector_suite() -> Result<()> {
    validate_sidecar_vectors_fixture_metadata()?;
    if ALL_SIDECAR_VECTOR_IDS.len() != 4 {
        bail!(
            "expected 4 sidecar vector ids, got {}",
            ALL_SIDECAR_VECTOR_IDS.len()
        );
    }
    run_sidecar_ensure_idempotent_vector()?;
    run_sidecar_eligibility_states_vector()?;
    run_sidecar_existence_privacy_vector()?;
    run_sidecar_multi_agent_publish_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_four_sidecar_vectors_run_clean() {
        run_sidecar_vector_suite().unwrap();
    }
}
