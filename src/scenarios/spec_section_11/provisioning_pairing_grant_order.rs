//! §11.1 — provisioning + pairing + grant MUST land in spec order.
//!
//! Spec: provisioning fires `cx.agent.provision`; pairing fires
//! `cx.account.agent_key_pair` (the agent_key_authorize_payload); grant
//! attach fires `cx.agent.grant.attach`. Any reorder (pairing-before-
//! provision, grant-before-pairing) MUST be rejected.

use anyhow::{Result, anyhow};

use contrix_core::{
    OP_ACCOUNT_AGENT_KEY_PAIR, OP_AGENT_GRANT_ATTACH, OP_AGENT_PROVISION,
    events::kinds::AGENT_PAUSE,
};

/// Canonical landing order. Index = step number.
const SPEC_ORDER: &[&str] = &[
    OP_AGENT_PROVISION,
    OP_ACCOUNT_AGENT_KEY_PAIR,
    OP_AGENT_GRANT_ATTACH,
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
    if AGENT_PAUSE != "cx.agent.pause" {
        return Err(anyhow!(
            "AGENT_PAUSE event kind drifted; reducer pause invariant cannot anchor"
        ));
    }
    // TODO(P4-impl): walk a real envelope sequence:
    //   1. POST /api/v1/agents          (cx.agent.provision)  → 201
    //   2. POST /auth/account/agent-key-pair (cx.account.agent_key_pair) → 200
    //   3. POST /api/v1/agents/{id}/grants (cx.agent.grant.attach) → 201
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
