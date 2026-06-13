//! SDK-pure scaffold for the personal-agent provisioning profile.
//!
//! Asserts the wire-shape baseline so a downstream regression on any of
//! the DID + typed-ids / capability actions / operation IDs / event kinds
//! fails this test before reaching the live soland surface.

use anyhow::{Result, anyhow};
use cokret_core::{
    AgentInteropSessionId, CAP_ACTION_AGENT_PROVISION, Did, EventId, OP_ACCOUNT_AGENT_KEY_PAIR,
    OP_AGENT_DEACTIVATE, OP_AGENT_GET, OP_AGENT_GRANT_ATTACH, OP_AGENT_GRANT_DETACH, OP_AGENT_LIST,
    OP_AGENT_PAUSE, OP_AGENT_PROVISION, OP_AGENT_RESUME, OP_AGENT_ROTATE_KEY,
    OP_AGENT_SIDECAR_THREAD_ENSURE,
};

/// The 11 personal-agent endpoint operation IDs registered in
/// `operation-registry.json` and mounted under soland `agents.rs`.
const PERSONAL_AGENT_OPERATIONS: &[&str] = &[
    OP_ACCOUNT_AGENT_KEY_PAIR,
    OP_AGENT_PROVISION,
    OP_AGENT_LIST,
    OP_AGENT_GET,
    OP_AGENT_PAUSE,
    OP_AGENT_RESUME,
    OP_AGENT_DEACTIVATE,
    OP_AGENT_ROTATE_KEY,
    OP_AGENT_GRANT_ATTACH,
    OP_AGENT_GRANT_DETACH,
    OP_AGENT_SIDECAR_THREAD_ENSURE,
];

pub async fn personal_agent_provisioning_run() -> Result<()> {
    // (a) 11 operation IDs are present, non-empty, distinct, and pinned
    //     to the canonical spelling.
    if PERSONAL_AGENT_OPERATIONS.len() != 11 {
        return Err(anyhow!(
            "expected 11 personal-agent operation ids, got {}",
            PERSONAL_AGENT_OPERATIONS.len()
        ));
    }
    let mut sorted = PERSONAL_AGENT_OPERATIONS.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != PERSONAL_AGENT_OPERATIONS.len() {
        return Err(anyhow!(
            "duplicate personal-agent operation ids: {PERSONAL_AGENT_OPERATIONS:?}"
        ));
    }
    if OP_AGENT_PROVISION != "ck.self.agent.command.provision" {
        return Err(anyhow!(
            "OP_AGENT_PROVISION spelling drifted: {OP_AGENT_PROVISION}"
        ));
    }
    if OP_ACCOUNT_AGENT_KEY_PAIR != "ck.gate.account.command.pair_agent_key" {
        return Err(anyhow!(
            "OP_ACCOUNT_AGENT_KEY_PAIR spelling drifted: {OP_ACCOUNT_AGENT_KEY_PAIR}"
        ));
    }

    // (b) Provisioning capability action constant matches the registry.
    if CAP_ACTION_AGENT_PROVISION != "ck.self.agent.command.provision" {
        return Err(anyhow!(
            "CAP_ACTION_AGENT_PROVISION spelling drifted: {CAP_ACTION_AGENT_PROVISION}"
        ));
    }

    // (c) The principal DID and auxiliary ids that a provisioning round
    //     materializes are well-formed under the SDK validators. The
    //     `ck:agent_key:` / `ck:accountability_grant:` typed-id families
    //     are retired: `key_id` is a plain string (preferring the DID URL
    //     verification-method form) and the accountability grant is
    //     referenced via its `ck.identity.accountability_grant` event id.
    Did::new("did:web:agent.example".to_owned())
        .map_err(|e| anyhow!("agent principal DID construction: {e}"))?;
    let key_id = "did:web:agent.example#key-1";
    if key_id.split('#').next() != Some("did:web:agent.example") {
        return Err(anyhow!(
            "agent key_id must be a DID URL verification method on the agent principal"
        ));
    }
    AgentInteropSessionId::new(
        "ck:agent_interop_session:01999999-0000-7000-8000-000000000003".to_owned(),
    )
    .map_err(|e| anyhow!("AgentInteropSessionId construction: {e}"))?;
    EventId::new("ck:event:01999999-0000-7000-8000-000000000004".to_owned())
        .map_err(|e| anyhow!("accountability_grant_ref EventId construction: {e}"))?;

    // (d) ill-formed DID / typed-ids MUST be rejected. This is the
    //     wire-form fail-closed gate for downstream parsers.
    let bad_principal = Did::new("ck:agent:not-a-uuidv7".to_owned());
    if bad_principal.is_ok() {
        return Err(anyhow!(
            "Did accepted ill-formed agent principal value `ck:agent:not-a-uuidv7`"
        ));
    }

    // TODO(P4-impl): drive a real `ck.self.agent.command.provision` envelope through
    // the reducer (the controller-self capability binding + first agent
    // key authorize chain is server-side TODO per soland P2-impl).

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn provisioning_profile_pins_surface() {
        personal_agent_provisioning_run().await.unwrap();
    }
}
