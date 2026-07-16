//! SDK-pure scaffold for the personal-agent provisioning profile.
//!
//! Asserts the wire-shape baseline so a downstream regression on any of
//! the DID + typed-ids / capability actions / operation IDs / event kinds
//! fails this test before reaching the live soland surface.

use anyhow::{Result, anyhow};
use arkret_core::{
    CAP_ACTION_AGENT_PROVISION, Did, EventId};

/// The 11 personal-agent endpoint operation IDs registered in
/// `operation-registry.json` and mounted under soland `agents.rs`. Key
/// rotation is expressed through runtime replacement re-pairing
/// (`renew_pairing`), not a dedicated rotate operation.
const PERSONAL_AGENT_OPERATIONS: &[&str] = &[
    arkret_core::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
    arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_PROVISION,
    arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_RENEW_PAIRING,
    arkret_core::ServiceOperationId::SELF_AGENT_QUERY_LIST,
    arkret_core::ServiceOperationId::SELF_AGENT_RESOURCE_GET,
    arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_PAUSE,
    arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_RESUME,
    arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_DEACTIVATE,
    arkret_core::ServiceOperationId::SELF_AGENT_GRANT_COMMAND_ATTACH,
    arkret_core::ServiceOperationId::SELF_AGENT_GRANT_RESOURCE_DELETE,
    arkret_core::ServiceOperationId::SELF_AGENT_SIDECAR_THREAD_COMMAND_ENSURE,
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
    if arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_PROVISION != "ak.self.agent.command.provision" {
        return Err(anyhow!(
            "arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_PROVISION spelling drifted: {arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_PROVISION}"
        ));
    }
    if arkret_core::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY != "ak.gate.account.command.pair_agent_key" {
        return Err(anyhow!(
            "arkret_core::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY spelling drifted: {arkret_core::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY}"
        ));
    }

    // (b) Provisioning capability action constant matches the registry.
    if CAP_ACTION_AGENT_PROVISION != "ak.self.agent.command.provision" {
        return Err(anyhow!(
            "CAP_ACTION_AGENT_PROVISION spelling drifted: {CAP_ACTION_AGENT_PROVISION}"
        ));
    }

    // (c) The principal DID and auxiliary ids that a provisioning round
    //     materializes are well-formed under the SDK validators. The
    //     `ak:agent_key:` / `ak:accountability_grant:` typed-id families
    //     are retired: `key_id` is a plain string (preferring the DID URL
    //     verification-method form) and the accountability grant is
    //     referenced via its `ak.identity.accountability_grant` event id.
    Did::new("did:web:agent.example".to_owned())
        .map_err(|e| anyhow!("agent principal DID construction: {e}"))?;
    let key_id = "did:web:agent.example#key-1";
    if key_id.split('#').next() != Some("did:web:agent.example") {
        return Err(anyhow!(
            "agent key_id must be a DID URL verification method on the agent principal"
        ));
    }
    EventId::new("ak:event:01999999-0000-7000-8000-000000000004".to_owned())
        .map_err(|e| anyhow!("accountability_grant_ref EventId construction: {e}"))?;

    // (d) ill-formed DID / typed-ids MUST be rejected. This is the
    //     wire-form fail-closed gate for downstream parsers.
    let bad_principal = Did::new("ak:agent:not-a-uuidv7".to_owned());
    if bad_principal.is_ok() {
        return Err(anyhow!(
            "Did accepted ill-formed agent principal value `ak:agent:not-a-uuidv7`"
        ));
    }

    // TODO(P4-impl): drive a real `ak.self.agent.command.provision` envelope through
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
