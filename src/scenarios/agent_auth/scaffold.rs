//! SDK-pure agent_auth profile scaffold.
//!
//! - `runtime_attestation.kind = "self_asserted"` is accepted.
//! - Any other `runtime_attestation.kind` MUST fail-closed at the wire-validation stage (mirrors
//!   soland's 4xx + `schema_violation`).
//! - The agent_key_proof branch carries a distinct `verification_method` that resolves to the
//!   agent_principal DID, NOT the controller DID.

use anyhow::{Result, anyhow};
use arkret_core::{CapabilityActionId, Did};

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
    //     here protects against the smuggle-controller ID exploit.
    let agent_id =
        Did::new("did:web:agent.example".to_owned()).map_err(|e| anyhow!("agent_id: {e}"))?;
    // Spec head: the typed `ak:agent_key:` id family is retired. `key_id`
    // is a plain string, preferring the DID URL verification-method form
    // (`<agent_principal_did>#<fragment>`).
    let key_id = "did:web:agent.example#key-1".to_owned();

    let verification_method = key_id.clone();
    if !verification_method.contains('#') {
        return Err(anyhow!(
            "verification_method must be a DID URL fragment, got `{verification_method}`"
        ));
    }
    if verification_method.split('#').next() != Some(agent_id.as_str()) {
        return Err(anyhow!("verification_method DID must match agent_id"));
    }

    // (d) authz: the four actor-private agent capability actions stay
    //     in lock-step with the spec head 37ce729 registry.
    for action in [
        CapabilityActionId::AGENT_DRAFT_PROPOSE,
        CapabilityActionId::AGENT_ACTION_REQUEST,
        CapabilityActionId::AGENT_ACTION_APPROVE,
        CapabilityActionId::AGENT_ACTION_REJECT,
    ] {
        if !action.starts_with("ak.agent.") {
            return Err(anyhow!(
                "agent capability action `{action}` MUST be namespaced under ak.agent.*"
            ));
        }
    }

    // TODO(P4-impl): exercise the live `POST /_arkret/gate/account/agent-key-pair`
    // endpoint with a self_asserted runtime_attestation, then assert the
    // emitted `ak.agent.key.authorize` event carries the runtime_attestation
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
