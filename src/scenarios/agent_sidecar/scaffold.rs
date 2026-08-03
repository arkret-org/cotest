//! SDK-pure first-class Agent Sidecar profile scaffold.

use anyhow::{Result, anyhow};
use arkret::{
    AgentSidecarDisplayMode, AgentSidecarExchangeOrigin, Did, RealmId, SidecarId, StrandId,
};
use arkret_models_collaboration::protocol_journey::{
    SidecarCommitPhase, SidecarContextRef, SidecarEnsureCommitRequestBody,
    SidecarEnsurePrepareRequestBody, SidecarEnsureRequestBody, SidecarPreparePhase,
};
use arkret_wire::{
    CapabilityActionId, Event, EventKind, Hlc, ProfileId, ProtocolOpaqueId, ProtocolOperationId,
    ScopeRef,
};

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

    let controller_id = Did::new("did:web:controller.example.com".to_owned())?;
    let source_realm_id = RealmId::new("ak:realm:01999999-0000-7000-8000-00000000c002".to_owned())?;
    let strand_id = StrandId::new("ak:strand:01999999-0000-7000-8000-00000000c003".to_owned())?;
    let operation_id = ProtocolOperationId::new("ak:operation:cotest.sidecar.scaffold")
        .map_err(anyhow::Error::msg)?;
    let prepare = SidecarEnsureRequestBody::Prepare(SidecarEnsurePrepareRequestBody {
        phase: SidecarPreparePhase::Prepare,
        operation_id: operation_id.clone(),
        idempotency_key: ProtocolOpaqueId::new("cotest-sidecar-scaffold-prepare")
            .map_err(anyhow::Error::msg)?,
        source_realm_id: source_realm_id.clone(),
        controller_id: controller_id.clone(),
        context_ref: SidecarContextRef::Strand {
            strand_id: strand_id.clone(),
        },
    });
    let wire = serde_json::to_value(&prepare)?;
    if wire.pointer("/context_ref/track_name").is_some() || wire.get("private_circle_id").is_some()
    {
        return Err(anyhow!(
            "ensure wire leaked Track identity or backing Circle"
        ));
    }
    if wire.get("phase").and_then(serde_json::Value::as_str) != Some("prepare") {
        return Err(anyhow!(
            "Sidecar prepare phase did not serialize canonically"
        ));
    }

    let create_event = Event::new(
        EventKind::SIDECAR_CREATE,
        ScopeRef::Realm {
            realm_id: source_realm_id.clone(),
        },
        controller_id.clone(),
        1,
        Hlc::new("01970e589d21-0000-a13f9c2e")?,
        serde_json::json!({"sidecar_id": sidecar}),
    )?;
    let context_attach_event = Event::new(
        EventKind::SIDECAR_CONTEXT_ATTACH,
        ScopeRef::Realm {
            realm_id: source_realm_id,
        },
        controller_id,
        1,
        Hlc::new("01970e589d21-0001-a13f9c2e")?,
        serde_json::json!({"sidecar_id": sidecar, "strand_id": strand_id}),
    )?;
    let commit = SidecarEnsureRequestBody::Commit(SidecarEnsureCommitRequestBody {
        phase: SidecarCommitPhase::Commit,
        operation_id,
        idempotency_key: ProtocolOpaqueId::new("cotest-sidecar-scaffold-commit")
            .map_err(anyhow::Error::msg)?,
        reservation_handle: ProtocolOpaqueId::new("cotest-sidecar-reservation")
            .map_err(anyhow::Error::msg)?,
        create_event,
        context_attach_event,
    });
    let commit_wire = serde_json::to_value(commit)?;
    if commit_wire.get("phase").and_then(serde_json::Value::as_str) != Some("commit")
        || commit_wire.get("create_event").is_none()
        || commit_wire.get("context_attach_event").is_none()
    {
        return Err(anyhow!("Sidecar commit transcript is incomplete"));
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
