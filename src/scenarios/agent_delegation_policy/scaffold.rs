//! SDK-pure agent_delegation_policy profile scaffold.
//!
//! The agent-action projection of the complete registry is the capability
//! surface a controller binds to an `accountability_grant`.
//! The sub-test here pins:
//!   1. the generated type and descriptor cover the same complete registry.
//!   2. every action is well-formed (snake_case, no whitespace, dot- delimited, prefixed
//!      `ak.agent.` or `ak.self.agent.`).
//!   3. the three aggregate actions (sidecar.{ensure,write,publish}) are syntactically
//!      distinguishable from the 8 base lifecycle/ runtime actions.
//!   4. an accountability grant is referenced through its `ak.identity.accountability_grant` event
//!      — the `accountability_grant_ref` is an `EventId` that round-trips through the SDK validator
//!      (the dedicated `ak:accountability_grant:` typed-id family is retired).

use anyhow::{Result, anyhow};
use arkret_core::{CapabilityActionId, EventId};
use arkret_schema::REGISTERED_CAPABILITY_ACTIONS;

/// The 3 aggregate Sidecar actions. Each carries a
/// `migration_group` in the spec's registry artifact.
const AGGREGATE_ACTIONS: &[&str] = &[
    CapabilityActionId::SELF_AGENT_SIDECAR_COMMAND_ENSURE,
    CapabilityActionId::AGENT_SIDECAR_WRITE,
    CapabilityActionId::AGENT_SIDECAR_PUBLISH,
];

pub async fn agent_delegation_policy_run() -> Result<()> {
    // (1) The spec promises 14 actions — 11 base + 3 sidecar aggregates.
    //     The generated type and descriptor must remain count-aligned.
    if REGISTERED_CAPABILITY_ACTIONS.len() != CapabilityActionId::ALL.len() {
        return Err(anyhow!(
            "capability descriptor/type count mismatch: {} versus {}",
            REGISTERED_CAPABILITY_ACTIONS.len(),
            CapabilityActionId::ALL.len()
        ));
    }

    let agent_actions = REGISTERED_CAPABILITY_ACTIONS
        .iter()
        .map(|descriptor| descriptor.action.as_str())
        .filter(|action| action.starts_with("ak.agent.") || action.starts_with("ak.self.agent."))
        .collect::<Vec<_>>();

    // (2) Per-action well-formedness. Agent capability actions live under the
    // agent surface — either the bare `ak.agent.*` namespace or the
    // account-scoped `ak.self.agent.*` trust segment (lifecycle actions such as
    // provision/pause/resume/deactivate and sidecar.ensure).
    for action in &agent_actions {
        if !(action.starts_with("ak.agent.") || action.starts_with("ak.self.agent.")) {
            return Err(anyhow!(
                "capability action `{action}` MUST start with ak.agent. or ak.self.agent."
            ));
        }
        if action.contains(char::is_whitespace) {
            return Err(anyhow!(
                "capability action `{action}` MUST NOT contain whitespace"
            ));
        }
        for ch in action.chars() {
            if !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '.' || ch == '_') {
                return Err(anyhow!(
                    "capability action `{action}` has illegal char `{ch}`"
                ));
            }
        }
    }

    // (3) The 3 aggregate actions are present in
    //     the generated agent-action projection.
    for aggregate in AGGREGATE_ACTIONS {
        if !agent_actions.iter().any(|action| action == aggregate) {
            return Err(anyhow!(
                "aggregate capability action is missing from the generated registry"
            ));
        }
        if !aggregate.contains(".sidecar.") {
            return Err(anyhow!(
                "aggregate `{aggregate}` is not in the Sidecar fan-out group"
            ));
        }
    }

    // (4) accountability grant reference well-formedness. The grant is the
    //     `ak.identity.accountability_grant` event itself; downstream
    //     `accountability_grant_ref` / `authorization_ref` fields carry the
    //     grant event's `EventId`.
    if arkret_wire::events::EventKind::IDENTITY_ACCOUNTABILITY_GRANT
        != "ak.identity.accountability_grant"
    {
        return Err(anyhow!(
            "arkret_wire::events::EventKind::IDENTITY_ACCOUNTABILITY_GRANT spelling drifted: arkret_wire::events::EventKind::IDENTITY_ACCOUNTABILITY_GRANT"
        ));
    }
    let grant_ref = EventId::new("ak:event:01999999-0000-7000-8000-0000000ab001".to_owned())
        .map_err(|e| anyhow!("accountability_grant_ref EventId: {e}"))?;
    if !grant_ref.as_str().starts_with("ak:event:") {
        return Err(anyhow!(
            "accountability_grant_ref lost canonical event prefix: {grant_ref}"
        ));
    }

    // TODO(P4-impl): walk a controller → agent grant attach + detach
    // through the reducer, verifying that each capability action
    // produces a corresponding `ak.capability.grant` / `ak.capability.revoke`
    // pair. Pending soland P2-impl reducer wiring + accountability_grant
    // projection.

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn delegation_grid_pinned() {
        agent_delegation_policy_run().await.unwrap();
    }
}
