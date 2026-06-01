//! §11.4 — controller deactivate cascade.
//!
//! When the controller principal is deactivated, every agent_principal
//! it owns MUST cascade through:
//!     1. `cx.agent.deactivate` per agent
//!     2. `cx.agent.key.revoke` per outstanding agent_key
//!     3. `cx.capability.revoke` per attached accountability_grant
//!     4. runtime endpoint revocation (DID Document service entry removal)

use anyhow::{Result, anyhow};
use contrix_core::events::kinds::AGENT_DEACTIVATE;

/// Canonical fan-out chain for controller deactivate.
const CASCADE_KINDS: &[&str] = &[
    "cx.agent.deactivate",
    "cx.agent.key.revoke",
    "cx.capability.revoke",
];

pub async fn controller_deactivate_cascade_run() -> Result<()> {
    if AGENT_DEACTIVATE != "cx.agent.deactivate" {
        return Err(anyhow!(
            "AGENT_DEACTIVATE event-kind constant drifted from canonical spelling"
        ));
    }
    if !CASCADE_KINDS.contains(&AGENT_DEACTIVATE) {
        return Err(anyhow!(
            "cascade list does not include AGENT_DEACTIVATE; reducer would skip step 1"
        ));
    }
    // TODO(P4-impl): live vector — provision 2 agents, attach grants,
    // then deactivate the controller. Assert the resulting event log
    // carries exactly N×3 cascade events (where N = agent count) in
    // deterministic order, plus the runtime endpoint revocation event
    // on the DID Document. Pending soland reducer wiring + DID Document
    // mutate path on starid.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn cascade_chain_pinned() {
        controller_deactivate_cascade_run().await.unwrap();
    }
}
