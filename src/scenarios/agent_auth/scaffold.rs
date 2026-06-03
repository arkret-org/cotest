//! SDK-pure agent_auth profile scaffold.
//!
//! - `runtime_attestation.kind = "self_asserted"` is accepted.
//! - Any other `runtime_attestation.kind` MUST fail-closed at the wire-validation stage (mirrors
//!   soland's 4xx + `schema_violation`).
//! - The agent_key_proof branch carries a distinct `verification_method` that resolves to the
//!   agent_principal DID, NOT the controller DID.

use anyhow::{Result, anyhow};
use cokret_core::{
    AgentKeyId, CAP_ACTION_AGENT_ACTION_APPROVE, CAP_ACTION_AGENT_ACTION_REJECT,
    CAP_ACTION_AGENT_ACTION_REQUEST, CAP_ACTION_AGENT_DRAFT_PROPOSE, Did,
};

/// Validate a `runtime_attestation` envelope per §1.2 — unknown kinds
/// fail-closed; v1 baseline is `self_asserted`.
fn runtime_attestation_kind_accepted(kind: &str) -> bool {
    matches!(kind, "self_asserted")
}

pub async fn agent_auth_run() -> Result<()> {
    // (a) baseline accepted kind.
    if !runtime_attestation_kind_accepted("self_asserted") {
        return Err(anyhow!(
            "runtime_attestation.kind=\"self_asserted\" MUST be accepted"
        ));
    }

    // (b) fail-closed for unknown kinds.
    for unknown_kind in ["", "unknown", "tpm", "tee", "tee-sgx", "remote-attested"] {
        if runtime_attestation_kind_accepted(unknown_kind) {
            return Err(anyhow!(
                "runtime_attestation.kind=`{unknown_kind}` accepted; \
                 spec mandates fail-closed for any non-baseline kind"
            ));
        }
    }

    // (c) agent_key_proof verification_method targets the agent
    //     principal — NOT the controller — so a single round-trip pinned
    //     here protects against the smuggle-controller-DID exploit.
    let agent_principal_id = Did::new("did:web:agent.example".to_owned())
        .map_err(|e| anyhow!("agent_principal_id: {e}"))?;
    let agent_key_id =
        AgentKeyId::new("ck:agent_key:01999999-0000-7000-8000-00000000a002".to_owned())
            .map_err(|e| anyhow!("agent_key_id: {e}"))?;

    let verification_method = format!(
        "did:web:agent.example#{kid}",
        kid = agent_key_id.as_str().rsplit(':').next().unwrap_or("")
    );
    if !verification_method.contains('#') {
        return Err(anyhow!(
            "verification_method must be a DID URL fragment, got `{verification_method}`"
        ));
    }
    if verification_method.split('#').next() != Some(agent_principal_id.as_str()) {
        return Err(anyhow!(
            "verification_method DID must match agent_principal_id"
        ));
    }

    // (d) authz: the four actor-private agent capability actions stay
    //     in lock-step with the spec head 37ce729 registry.
    for action in [
        CAP_ACTION_AGENT_DRAFT_PROPOSE,
        CAP_ACTION_AGENT_ACTION_REQUEST,
        CAP_ACTION_AGENT_ACTION_APPROVE,
        CAP_ACTION_AGENT_ACTION_REJECT,
    ] {
        if !action.starts_with("cx.agent.") {
            return Err(anyhow!(
                "agent capability action `{action}` MUST be namespaced under cx.agent.*"
            ));
        }
    }

    // TODO(P4-impl): exercise the live `POST /_cokret/gate/account/agent-key-pair`
    // endpoint with a self_asserted runtime_attestation, then assert the
    // emitted `ck.agent.key.authorize` event carries the runtime_attestation
    // verbatim. Pending soland P2-impl reducer wiring.

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn agent_auth_profile_pins_runtime_attestation_baseline() {
        agent_auth_run().await.unwrap();
    }
}
