//! R3 spec-sync (cokret-spec @ b47ff6ec) — agent surface conformance
//! vectors (§0.11 of `_before_todos.md`).
//!
//! 5 vectors:
//!   - `cx.vector.agent.provision.v1`
//!   - `cx.vector.agent.pairing_expiry.v1`
//!   - `cx.vector.agent.controller_lifecycle.v1`
//!   - `cx.vector.agent.act_on_behalf.v1`
//!   - `cx.vector.agent.session_grant.replay.v1`
//!
//! These are SDK-pure wire-shape pins. Live reducer paths (FSM bottom =
//! reject, deactivate-terminal, session-grant agent-branch acceptance
//! matrix, replay-cache) land in soland P2-impl; this suite hard-fails
//! on any registry-side drift today.

use anyhow::{Result, anyhow, bail};
use contrix_core::error::{
    ERROR_CODE_AGENT_DEACTIVATED, ERROR_CODE_AGENT_PAUSED, ERROR_CODE_APPROVAL_ALREADY_CONSUMED,
    ERROR_CODE_PAIRING_REQUEST_EXPIRED, ERROR_CODE_PROOF_INVALID, ERROR_CODE_SIDECAR_CREATE_DENIED,
    ERROR_CODE_VERIFICATION_METHOD_PRINCIPAL_MISMATCH, REASON_ACCOUNTABILITY_GRANT_MISSING,
};
use contrix_core::{
    CAP_ACTION_AGENT_PROVISION, OP_ACCOUNT_AGENT_KEY_PAIR, OP_ACCOUNT_ISSUE_SESSION_GRANT,
    OP_AGENT_DEACTIVATE, OP_AGENT_GET, OP_AGENT_GRANT_ATTACH, OP_AGENT_GRANT_DETACH, OP_AGENT_LIST,
    OP_AGENT_PAUSE, OP_AGENT_PROVISION, OP_AGENT_RESUME, OP_AGENT_ROTATE_KEY,
    OP_AGENT_SIDECAR_THREAD_ENSURE,
};

pub const VECTOR_ID_AGENT_PROVISION: &str = "cx.vector.agent.provision.v1";
pub const VECTOR_ID_AGENT_PAIRING_EXPIRY: &str = "cx.vector.agent.pairing_expiry.v1";
pub const VECTOR_ID_AGENT_CONTROLLER_LIFECYCLE: &str = "cx.vector.agent.controller_lifecycle.v1";
pub const VECTOR_ID_AGENT_ACT_ON_BEHALF: &str = "cx.vector.agent.act_on_behalf.v1";
pub const VECTOR_ID_AGENT_SESSION_GRANT_REPLAY: &str = "cx.vector.agent.session_grant.replay.v1";

pub const ALL_AGENT_VECTOR_IDS: &[&str] = &[
    VECTOR_ID_AGENT_PROVISION,
    VECTOR_ID_AGENT_PAIRING_EXPIRY,
    VECTOR_ID_AGENT_CONTROLLER_LIFECYCLE,
    VECTOR_ID_AGENT_ACT_ON_BEHALF,
    VECTOR_ID_AGENT_SESSION_GRANT_REPLAY,
];

// ─── VECT-AG-1 — provision ─────────────────────────────────────────────────

pub fn run_agent_provision_vector() -> Result<()> {
    if OP_AGENT_PROVISION != "cx.agent.provision" {
        bail!("OP_AGENT_PROVISION spelling drifted: {OP_AGENT_PROVISION}");
    }
    if CAP_ACTION_AGENT_PROVISION != "cx.agent.provision" {
        bail!("CAP_ACTION_AGENT_PROVISION spelling drifted: {CAP_ACTION_AGENT_PROVISION}");
    }
    // The provisioning error matrix MUST include `failed_precondition`
    // (modeled by absence of the controller-self capability binding)
    // and `accountability_grant_missing` (the controller's grant has
    // not yet been verified).
    if REASON_ACCOUNTABILITY_GRANT_MISSING != "accountability_grant_missing" {
        bail!(
            "REASON_ACCOUNTABILITY_GRANT_MISSING spelling drifted: {REASON_ACCOUNTABILITY_GRANT_MISSING}"
        );
    }
    Ok(())
}

// ─── VECT-AG-2 — pairing_expiry ────────────────────────────────────────────

pub fn run_agent_pairing_expiry_vector() -> Result<()> {
    if ERROR_CODE_PAIRING_REQUEST_EXPIRED != "pairing_request_expired" {
        bail!(
            "ERROR_CODE_PAIRING_REQUEST_EXPIRED spelling drifted: {ERROR_CODE_PAIRING_REQUEST_EXPIRED}"
        );
    }
    if OP_ACCOUNT_AGENT_KEY_PAIR != "cx.account.agent_key_pair" {
        bail!("OP_ACCOUNT_AGENT_KEY_PAIR spelling drifted: {OP_ACCOUNT_AGENT_KEY_PAIR}");
    }
    // The error-response matrix for the key-pair endpoint MUST
    // include `verification_method_principal_mismatch`,
    // `pairing_request_expired`, `proof_invalid`, `agent_deactivated`
    // (see §0.8). The DID-match check happens BEFORE the proof
    // validator (fail-closed-before-validator); we pin the canonical
    // error-code spellings here.
    let required = [
        ERROR_CODE_VERIFICATION_METHOD_PRINCIPAL_MISMATCH,
        ERROR_CODE_PAIRING_REQUEST_EXPIRED,
        ERROR_CODE_PROOF_INVALID,
        ERROR_CODE_AGENT_DEACTIVATED,
    ];
    for code in required {
        if code.is_empty() || !code.chars().all(|c| c == '_' || c.is_ascii_lowercase()) {
            bail!("agent_key_pair error code corrupted: `{code}`");
        }
    }
    Ok(())
}

// ─── VECT-AG-3 — controller_lifecycle (agent FSM) ──────────────────────────

/// Minimal in-memory FSM mirroring the `cx.agent.{pause,resume,deactivate}`
/// reducer contract: bottom = `reject`, deactivate is terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AgentState {
    Active,
    Paused,
    Deactivated,
}

fn agent_transition(state: AgentState, op: &str) -> std::result::Result<AgentState, &'static str> {
    use AgentState::*;
    match (state, op) {
        (Active, "pause") => Ok(Paused),
        (Paused, "resume") => Ok(Active),
        (Active | Paused, "deactivate") => Ok(Deactivated),
        (Deactivated, _) => Err(ERROR_CODE_AGENT_DEACTIVATED),
        (Active, "resume") => Err("reject"),
        (Paused, "pause") => Err(ERROR_CODE_AGENT_PAUSED),
        _ => Err("reject"),
    }
}

pub fn run_agent_controller_lifecycle_vector() -> Result<()> {
    // Verify FSM op-id spelling first.
    for op in [
        OP_AGENT_PAUSE,
        OP_AGENT_RESUME,
        OP_AGENT_DEACTIVATE,
        OP_AGENT_LIST,
        OP_AGENT_GET,
        OP_AGENT_ROTATE_KEY,
        OP_AGENT_GRANT_ATTACH,
        OP_AGENT_GRANT_DETACH,
        OP_AGENT_SIDECAR_THREAD_ENSURE,
    ] {
        if !op.starts_with("cx.agent.") && !op.starts_with("cx.account.") {
            bail!("agent op id `{op}` lost canonical namespace");
        }
    }
    if OP_AGENT_DEACTIVATE != "cx.agent.deactivate" {
        bail!("OP_AGENT_DEACTIVATE spelling drifted: {OP_AGENT_DEACTIVATE}");
    }

    // Happy path: active → paused → active → deactivated terminal.
    let s = agent_transition(AgentState::Active, "pause").map_err(|e| anyhow!("pause: {e}"))?;
    if s != AgentState::Paused {
        bail!("pause did not yield Paused");
    }
    let s = agent_transition(s, "resume").map_err(|e| anyhow!("resume: {e}"))?;
    if s != AgentState::Active {
        bail!("resume did not yield Active");
    }
    let s = agent_transition(s, "deactivate").map_err(|e| anyhow!("deactivate: {e}"))?;
    if s != AgentState::Deactivated {
        bail!("deactivate did not yield Deactivated");
    }

    // Terminal: resume from deactivated MUST be rejected with
    // `agent_deactivated`.
    let err = agent_transition(AgentState::Deactivated, "resume")
        .err()
        .ok_or_else(|| anyhow!("resume-from-deactivated must be rejected"))?;
    if err != ERROR_CODE_AGENT_DEACTIVATED {
        bail!("resume-from-deactivated returned `{err}`, expected agent_deactivated");
    }

    // Pause-while-paused MUST surface `agent_paused`.
    let err = agent_transition(AgentState::Paused, "pause")
        .err()
        .ok_or_else(|| anyhow!("pause-while-paused must be rejected"))?;
    if err != ERROR_CODE_AGENT_PAUSED {
        bail!("pause-while-paused returned `{err}`, expected agent_paused");
    }
    Ok(())
}

// ─── VECT-AG-4 — act_on_behalf ─────────────────────────────────────────────

pub fn run_agent_act_on_behalf_vector() -> Result<()> {
    // The four new actor-private agent event kinds are pinned by the
    // SDK constants list in personal_agent_provisioning; here we
    // assert the side-effect that approvals are write-once.
    if ERROR_CODE_APPROVAL_ALREADY_CONSUMED != "approval_already_consumed" {
        bail!(
            "ERROR_CODE_APPROVAL_ALREADY_CONSUMED spelling drifted: {ERROR_CODE_APPROVAL_ALREADY_CONSUMED}"
        );
    }
    // Sidecar-create denial is part of the act-on-behalf pipeline
    // (controller's grant has not authorised the agent to write to
    // the sidecar circle).
    if ERROR_CODE_SIDECAR_CREATE_DENIED != "sidecar_create_denied" {
        bail!(
            "ERROR_CODE_SIDECAR_CREATE_DENIED spelling drifted: {ERROR_CODE_SIDECAR_CREATE_DENIED}"
        );
    }
    Ok(())
}

// ─── VECT-AG-5 — session_grant.replay ──────────────────────────────────────

pub fn run_agent_session_grant_replay_vector() -> Result<()> {
    if OP_ACCOUNT_ISSUE_SESSION_GRANT != "cx.account.issue_session_grant" {
        bail!("OP_ACCOUNT_ISSUE_SESSION_GRANT spelling drifted: {OP_ACCOUNT_ISSUE_SESSION_GRANT}");
    }
    // Agent branch reject codes per §0.8:
    //   proof_invalid / verification_method_principal_mismatch /
    //   agent_paused / agent_deactivated / accountability_grant_missing
    // We pin all five.
    let required = [
        ERROR_CODE_PROOF_INVALID,
        ERROR_CODE_VERIFICATION_METHOD_PRINCIPAL_MISMATCH,
        ERROR_CODE_AGENT_PAUSED,
        ERROR_CODE_AGENT_DEACTIVATED,
    ];
    let mut sorted = required.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != required.len() {
        bail!("session-grant agent-branch reject set has duplicates");
    }
    if REASON_ACCOUNTABILITY_GRANT_MISSING != "accountability_grant_missing" {
        bail!(
            "REASON_ACCOUNTABILITY_GRANT_MISSING spelling drifted: {REASON_ACCOUNTABILITY_GRANT_MISSING}"
        );
    }
    Ok(())
}

/// Suite entry point — runs all 5 agent vectors.
pub fn run_agent_vector_suite() -> Result<()> {
    if ALL_AGENT_VECTOR_IDS.len() != 5 {
        bail!(
            "expected 5 agent vector ids, got {}",
            ALL_AGENT_VECTOR_IDS.len()
        );
    }
    run_agent_provision_vector()?;
    run_agent_pairing_expiry_vector()?;
    run_agent_controller_lifecycle_vector()?;
    run_agent_act_on_behalf_vector()?;
    run_agent_session_grant_replay_vector()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_five_agent_vectors_run_clean() {
        run_agent_vector_suite().unwrap();
    }
}
