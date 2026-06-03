//! SDK-pure agent_sidecar_thread profile scaffold.
//!
//! Pins:
//!   1. `PROFILE_AGENT_SIDECAR_THREAD` is spelled exactly per registry
//!      (`ck.profile.agent_sidecar_thread.v1`).
//!   2. The home-policy constant carries the canonical value `context_realm_preferred` (B-F).
//!   3. `SidecarCircleId` round-trips through the SDK validator.
//!   4. The 3 sidecar capability actions are all present and form a cohesive ensure / write /
//!      publish fan-out group.

use anyhow::{Result, anyhow};
use cokret_core::{
    AGENT_SIDECAR_HOME_POLICY_CONTEXT_REALM_PREFERRED, CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE,
    CAP_ACTION_AGENT_SIDECAR_THREAD_PUBLISH, CAP_ACTION_AGENT_SIDECAR_THREAD_WRITE,
    PROFILE_AGENT_SIDECAR_THREAD, SidecarCircleId,
};

pub async fn agent_sidecar_thread_run() -> Result<()> {
    // (1) Profile id pinned to the registry spelling.
    if PROFILE_AGENT_SIDECAR_THREAD != "ck.profile.agent_sidecar_thread.v1" {
        return Err(anyhow!(
            "PROFILE_AGENT_SIDECAR_THREAD spelling drifted: {PROFILE_AGENT_SIDECAR_THREAD}"
        ));
    }

    // (2) Home-policy default is "context_realm_preferred" (B-F).
    if AGENT_SIDECAR_HOME_POLICY_CONTEXT_REALM_PREFERRED != "context_realm_preferred" {
        return Err(anyhow!(
            "AGENT_SIDECAR_HOME_POLICY_CONTEXT_REALM_PREFERRED spelling drifted: {}",
            AGENT_SIDECAR_HOME_POLICY_CONTEXT_REALM_PREFERRED
        ));
    }

    // (3) typed-id round-trip.
    let sidecar =
        SidecarCircleId::new("ck:sidecar_circle:01999999-0000-7000-8000-00000000c001".to_owned())
            .map_err(|e| anyhow!("SidecarCircleId: {e}"))?;
    if !sidecar.as_str().starts_with("ck:sidecar_circle:") {
        return Err(anyhow!("SidecarCircleId lost canonical prefix: {sidecar}"));
    }

    // (4) The 3 sidecar actions form the canonical ensure/write/publish
    //     trio (CXP-0009 §3 invariant 10).
    let trio = [
        CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE,
        CAP_ACTION_AGENT_SIDECAR_THREAD_WRITE,
        CAP_ACTION_AGENT_SIDECAR_THREAD_PUBLISH,
    ];
    for action in trio {
        if !action.contains(".sidecar_thread.") {
            return Err(anyhow!(
                "sidecar capability action `{action}` MUST contain .sidecar_thread."
            ));
        }
    }
    let mut sorted = trio.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != trio.len() {
        return Err(anyhow!("sidecar capability action trio has duplicates"));
    }

    // TODO(P4-impl): exercise live `POST /_cokret/self/agents/{id}/sidecar-
    // thread/ensure` against a soland server. The endpoint MUST be
    // idempotent (same controller/agent pair returns the same
    // sidecar_circle_id). Pending soland P2-impl deterministic Circle
    // key derivation.

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sidecar_profile_pinned() {
        agent_sidecar_thread_run().await.unwrap();
    }
}
