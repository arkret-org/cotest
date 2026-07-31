//! SDK-pure first-class Agent Sidecar profile scaffold.

use anyhow::{Result, anyhow};
use arkret::{
    AgentSidecarContextRef, AgentSidecarDisplayMode, AgentSidecarEnsureRequestBody,
    AgentSidecarExchangeOrigin, Did, RealmId, SidecarId, StrandId,
};
use arkret_wire::{CapabilityActionId, ProfileId};

pub async fn agent_sidecar_run() -> Result<()> {
    if ProfileId::AGENT_SIDECAR_V1 != "ak.profile.agent_sidecar.v1" {
        return Err(anyhow!(
            "ProfileId::AGENT_SIDECAR_V1 spelling drifted: {profileid_agent_sidecar_v1}",
            profileid_agent_sidecar_v1 = ProfileId::AGENT_SIDECAR_V1
        ));
    }
    let sidecar = SidecarId::new("ak:sidecar:01999999-0000-7000-8000-00000000c001".to_owned())?;
    if !sidecar.as_str().starts_with("ak:sidecar:") {
        return Err(anyhow!("SidecarId lost canonical prefix: {sidecar}"));
    }

    let request = AgentSidecarEnsureRequestBody {
        controller_id: Did::new("did:web:controller.example.com".to_owned())?,
        addressed_agent_ids: Vec::new(),
        context_ref: AgentSidecarContextRef::strand(
            RealmId::new("ak:realm:01999999-0000-7000-8000-00000000c002".to_owned())?,
            StrandId::new("ak:strand:01999999-0000-7000-8000-00000000c003".to_owned())?,
        ),
    };
    request.validate()?;
    let wire = serde_json::to_value(request)?;
    if wire.pointer("/context_ref/track_name").is_some() || wire.get("private_circle_id").is_some()
    {
        return Err(anyhow!(
            "ensure wire leaked Track identity or backing Circle"
        ));
    }

    let actions = [
        CapabilityActionId::SELF_AGENT_SIDECAR_COMMAND_ENSURE,
        CapabilityActionId::AGENT_SIDECAR_WRITE,
        CapabilityActionId::AGENT_SIDECAR_PUBLISH,
    ];
    if actions.iter().any(|action| !action.contains(".sidecar.")) {
        return Err(anyhow!("Sidecar action family drifted: {actions:?}"));
    }

    // Hosted view state and echo origin are closed SDK enums, not UI strings.
    let _default_mode = AgentSidecarDisplayMode::ContextMerged;
    let _routed_origin = AgentSidecarExchangeOrigin::SourceTrackRouted;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sidecar_profile_pinned() {
        agent_sidecar_run().await.unwrap();
    }
}
