//! §11.1 — provisioning + pairing + grant MUST land in spec order.
//!
//! Spec: provisioning fires `ak.self.agent.command.provision`; pairing fires
//! `ak.gate.account.command.pair_agent_key` (the agent_key_authorize_payload); grant
//! attach fires `ak.self.agent.grant.command.attach`. Any reorder (pairing-before-
//! provision, grant-before-pairing) MUST be rejected.

use anyhow::{Result, anyhow};
/// Canonical landing order. Index = step number.
const SPEC_ORDER: &[&str] = &[
    arkret_core::ServiceOperationId::SELF_AGENT_COMMAND_PROVISION,
    arkret_core::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
    arkret_core::ServiceOperationId::SELF_AGENT_GRANT_COMMAND_ATTACH,
];

pub async fn provisioning_pairing_grant_order_run() -> Result<()> {
    if SPEC_ORDER.len() != 3 {
        return Err(anyhow!(
            "expected 3 steps in the provisioning sequence, got {}",
            SPEC_ORDER.len()
        ));
    }
    // sanity: each step is a unique operation id.
    let mut sorted = SPEC_ORDER.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != SPEC_ORDER.len() {
        return Err(anyhow!(
            "duplicate steps in provisioning sequence: {SPEC_ORDER:?}"
        ));
    }
    if arkret_wire::events::EventKind::SELF_AGENT_PAUSE != "ak.self.agent.pause" {
        return Err(anyhow!(
            "arkret_wire::events::EventKind::SELF_AGENT_PAUSE event kind drifted; reducer pause invariant cannot anchor"
        ));
    }
    // TODO(P4-impl): walk a real envelope sequence:
    //   1. POST /_arkret/self/agents          (ak.self.agent.command.provision)  → 201
    //   2. POST /_arkret/gate/account/agent-key-pair (ak.gate.account.command.pair_agent_key) → 200
    //   3. POST /_arkret/self/agents/{id}/grants (ak.self.agent.grant.command.attach) → 201
    // then re-submit steps in (2,1,3) order and assert each out-of-order
    // step is rejected with `provisioning_order_violation`. Pending
    // soland reducer wiring (P2-impl agent_principal projection).
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn order_constants_pinned() {
        provisioning_pairing_grant_order_run().await.unwrap();
    }
}
