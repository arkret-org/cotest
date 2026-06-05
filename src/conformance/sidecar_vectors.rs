//! Sidecar conformance vectors (§0.11 of `_before_todos.md`).
//!
//! 4 vectors:
//!   - `ck.vector.sidecar.ensure_idempotent.v1`
//!   - `ck.vector.sidecar.eligibility_states.v1`
//!   - `ck.vector.sidecar.existence_privacy.v1`
//!   - `ck.vector.sidecar.multi_agent_publish.v1`
//!
//! Wire-shape pins only. Live `POST /agents/{id}/sidecar-thread:ensure`
//! and the multi-agent fan-out reducer path land in soland P2-impl;
//! this suite hard-fails on registry drift today.

use anyhow::{Result, bail};
use cokret_core::error::{
    ERROR_CODE_AGENT_DEACTIVATED, ERROR_CODE_AGENT_PAUSED, ERROR_CODE_SIDECAR_CREATE_DENIED,
};
use cokret_core::{
    AGENT_SIDECAR_HOME_POLICY_CONTEXT_REALM_PREFERRED, CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE,
    CAP_ACTION_AGENT_SIDECAR_THREAD_PUBLISH, CAP_ACTION_AGENT_SIDECAR_THREAD_WRITE,
    OP_AGENT_SIDECAR_THREAD_ENSURE, PROFILE_AGENT_SIDECAR_THREAD,
};

pub const VECTOR_ID_SIDECAR_ENSURE_IDEMPOTENT: &str = "ck.vector.sidecar.ensure_idempotent.v1";
pub const VECTOR_ID_SIDECAR_ELIGIBILITY_STATES: &str = "ck.vector.sidecar.eligibility_states.v1";
pub const VECTOR_ID_SIDECAR_EXISTENCE_PRIVACY: &str = "ck.vector.sidecar.existence_privacy.v1";
pub const VECTOR_ID_SIDECAR_MULTI_AGENT_PUBLISH: &str = "ck.vector.sidecar.multi_agent_publish.v1";

pub const ALL_SIDECAR_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_SIDECAR_ENSURE_IDEMPOTENT,
    VECTOR_ID_SIDECAR_ELIGIBILITY_STATES,
    VECTOR_ID_SIDECAR_EXISTENCE_PRIVACY,
    VECTOR_ID_SIDECAR_MULTI_AGENT_PUBLISH,
];

// ─── VECT-SC-1 — ensure_idempotent ─────────────────────────────────────────

pub fn run_sidecar_ensure_idempotent_vector() -> Result<()> {
    if OP_AGENT_SIDECAR_THREAD_ENSURE != "ck.self.agent.sidecar_thread.ensure" {
        bail!("OP_AGENT_SIDECAR_THREAD_ENSURE spelling drifted: {OP_AGENT_SIDECAR_THREAD_ENSURE}");
    }
    if CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE != "ck.self.agent.sidecar_thread.ensure" {
        bail!(
            "CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE spelling drifted: {CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE}"
        );
    }
    if PROFILE_AGENT_SIDECAR_THREAD != "ck.profile.agent_sidecar_thread.v1" {
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
    if ERROR_CODE_AGENT_PAUSED != "agent_paused" {
        bail!("ERROR_CODE_AGENT_PAUSED spelling drifted: {ERROR_CODE_AGENT_PAUSED}");
    }
    if ERROR_CODE_AGENT_DEACTIVATED != "agent_deactivated" {
        bail!("ERROR_CODE_AGENT_DEACTIVATED spelling drifted: {ERROR_CODE_AGENT_DEACTIVATED}");
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
    // A caller without the `ck.self.agent.sidecar_thread.ensure` capability
    // MUST receive `sidecar_create_denied` (NOT `not_found` — the
    // server MUST NOT confirm or deny existence by error code).
    if ERROR_CODE_SIDECAR_CREATE_DENIED != "sidecar_create_denied" {
        bail!(
            "ERROR_CODE_SIDECAR_CREATE_DENIED spelling drifted: {ERROR_CODE_SIDECAR_CREATE_DENIED}"
        );
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
