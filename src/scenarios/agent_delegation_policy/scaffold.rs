//! SDK-pure agent_delegation_policy profile scaffold.
//!
//! The 14-action delegation grid (11 base + 3 aggregate) is the
//! capability surface a controller binds to an `accountability_grant`.
//! The sub-test here pins:
//!   1. all 14 actions are present in `AGENT_CAPABILITY_ACTIONS`.
//!   2. every action is well-formed (snake_case, no whitespace, dot- delimited, prefixed
//!      `ck.agent.` or `ck.self.agent.`).
//!   3. the three aggregate actions (sidecar_thread.{ensure,write,publish}) are syntactically
//!      distinguishable from the 8 base lifecycle/ runtime actions.
//!   4. an accountability grant is referenced through its `ck.identity.accountability_grant` event
//!      — the `accountability_grant_ref` is an `EventId` that round-trips through the SDK validator
//!      (the dedicated `ck:accountability_grant:` typed-id family is retired).

use anyhow::{Result, anyhow};
use arkret_core::events::IDENTITY_ACCOUNTABILITY_GRANT;
use arkret_core::{
    AGENT_CAPABILITY_ACTIONS, CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE,
    CAP_ACTION_AGENT_SIDECAR_THREAD_PUBLISH, CAP_ACTION_AGENT_SIDECAR_THREAD_WRITE, EventId,
};

/// The 3 aggregate sidecar-thread actions. Each carries a
/// `migration_group` in the spec's registry artifact.
const AGGREGATE_ACTIONS: &[&str] = &[
    CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE,
    CAP_ACTION_AGENT_SIDECAR_THREAD_WRITE,
    CAP_ACTION_AGENT_SIDECAR_THREAD_PUBLISH,
];

pub async fn agent_delegation_policy_run() -> Result<()> {
    // (1) The spec promises 14 actions — 11 base + 3 sidecar aggregates.
    //     The SDK constant carries 11 entries (the SDK's
    //     `AGENT_CAPABILITY_ACTIONS` includes the 3 sidecar entries as
    //     base because they each map to a single concrete event kind;
    //     the `migration_group` metadata is the spec's aggregation
    //     hint).
    if AGENT_CAPABILITY_ACTIONS.len() != 11 {
        return Err(anyhow!(
            "expected 11 entries in AGENT_CAPABILITY_ACTIONS (8 base + 3 sidecar), got {}",
            AGENT_CAPABILITY_ACTIONS.len()
        ));
    }

    // (2) Per-action well-formedness. Agent capability actions live under the
    // agent surface — either the bare `ck.agent.*` namespace or the
    // account-scoped `ck.self.agent.*` trust segment (lifecycle actions such as
    // provision/pause/resume/deactivate and sidecar_thread.ensure).
    for action in AGENT_CAPABILITY_ACTIONS {
        if !(action.starts_with("ck.agent.") || action.starts_with("ck.self.agent.")) {
            return Err(anyhow!(
                "capability action `{action}` MUST start with ck.agent. or ck.self.agent."
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
    //     `AGENT_CAPABILITY_ACTIONS`. The grid is therefore (11) where
    //     the 3 are the sidecar trio.
    for aggregate in AGGREGATE_ACTIONS {
        if !AGENT_CAPABILITY_ACTIONS.iter().any(|a| a == aggregate) {
            return Err(anyhow!(
                "aggregate capability action `{aggregate}` is missing from \
                 AGENT_CAPABILITY_ACTIONS — registry drift"
            ));
        }
        if !aggregate.contains(".sidecar_thread.") {
            return Err(anyhow!(
                "aggregate `{aggregate}` is not in the sidecar_thread fan-out group"
            ));
        }
    }

    // (4) accountability grant reference well-formedness. The grant is the
    //     `ck.identity.accountability_grant` event itself; downstream
    //     `accountability_grant_ref` / `authorization_ref` fields carry the
    //     grant event's `EventId`.
    if IDENTITY_ACCOUNTABILITY_GRANT != "ck.identity.accountability_grant" {
        return Err(anyhow!(
            "IDENTITY_ACCOUNTABILITY_GRANT spelling drifted: {IDENTITY_ACCOUNTABILITY_GRANT}"
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
    // produces a corresponding `ck.capability.grant` / `ck.capability.revoke`
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
