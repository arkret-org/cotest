//! §11.4 — controller deactivate cascade.
//!
//! When the controller principal is deactivated, every agent_principal
//! it owns MUST cascade through:
//!     1. `ak.self.agent.deactivate` per agent
//!     2. `ak.agent.key.revoke` per outstanding agent_key
//!     3. `ak.capability.revoke` per attached accountability_grant
//!     4. runtime endpoint revocation (DID Document service entry removal)

use anyhow::{Result, anyhow};
/// Canonical fan-out chain for controller deactivate.
const CASCADE_KINDS: &[&str] = &[
    "ak.self.agent.deactivate",
    "ak.agent.key.revoke",
    "ak.capability.revoke",
];

pub async fn controller_deactivate_cascade_run() -> Result<()> {
    if arkret_wire::events::EventKind::SELF_AGENT_DEACTIVATE != "ak.self.agent.deactivate" {
        return Err(anyhow!(
            "arkret_wire::events::EventKind::SELF_AGENT_DEACTIVATE event-kind constant drifted from canonical spelling"
        ));
    }
    if !CASCADE_KINDS.contains(&arkret_wire::events::EventKind::SELF_AGENT_DEACTIVATE) {
        return Err(anyhow!(
            "cascade list does not include arkret_wire::events::EventKind::SELF_AGENT_DEACTIVATE; reducer would skip step 1"
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
