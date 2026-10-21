//! Fixture intents use the same complete read and exact replacement as native editors.
use anyhow::{Context, Result};
use arkret_models_collaboration::consent_operations::ConsentView;
use arkret_models_collaboration::events_payloads::consent::{
    ConsentPeer, ConsentPermission, ConsentReplacePayload,
};
use arkret_wire::{ActorId, ConsentScope, EventAdmissionSubmission, EventKind};
use cotest::harness::expect_json;
use cotest::scenarios::mls_lifecycle_live::Member;

#[derive(Clone, Debug)]
pub(crate) struct PermissionGrant {
    pub view: ConsentView,
    pub scopes: Vec<ConsentScope>,
}
impl std::ops::Deref for PermissionGrant {
    type Target = ConsentView;
    fn deref(&self) -> &ConsentView {
        &self.view
    }
}
pub(crate) fn permission(scope: ConsentScope) -> ConsentPermission {
    ConsentPermission {
        consent_scope: scope,
        not_before: None,
        expires_at: None,
        constraints: None,
        evidence_ref: None,
        reason: None,
    }
}
pub(crate) async fn grant(
    holder: &Member,
    peer: &ActorId,
    entries: Vec<ConsentPermission>,
) -> Result<(PermissionGrant, EventAdmissionSubmission)> {
    let peer = ConsentPeer::Actor {
        actor_id: peer.clone(),
    };
    let (expected_current, mut permissions) =
        cotest::scenarios::invite_service_fanout_live::complete_peer_current(
            &holder.client,
            peer.clone(),
        )
        .await?;
    let scopes = entries.iter().map(|p| p.consent_scope).collect::<Vec<_>>();
    permissions.retain(|p| !scopes.contains(&p.consent_scope));
    permissions.extend(entries);
    permissions.sort_by_key(|p| p.consent_scope);
    let payload = ConsentReplacePayload {
        peer,
        expected_current,
        permissions,
    };
    payload.validate()?;
    let (view, event) = submit(holder, payload).await?;
    Ok((PermissionGrant { view, scopes }, event))
}
pub(crate) async fn revoke(
    holder: &Member,
    grant: &PermissionGrant,
) -> Result<(ConsentView, EventAdmissionSubmission)> {
    let (expected_current, mut permissions) =
        cotest::scenarios::invite_service_fanout_live::complete_peer_current(
            &holder.client,
            grant.peer.clone(),
        )
        .await?;
    permissions.retain(|p| !grant.scopes.contains(&p.consent_scope));
    submit(
        holder,
        ConsentReplacePayload {
            peer: grant.peer.clone(),
            expected_current,
            permissions,
        },
    )
    .await
}
pub(crate) async fn clear(
    holder: &Member,
    peer: &ActorId,
) -> Result<(ConsentView, EventAdmissionSubmission)> {
    let peer = ConsentPeer::Actor {
        actor_id: peer.clone(),
    };
    let (expected_current, _) =
        cotest::scenarios::invite_service_fanout_live::complete_peer_current(
            &holder.client,
            peer.clone(),
        )
        .await?;
    submit(
        holder,
        ConsentReplacePayload {
            peer,
            expected_current,
            permissions: Vec::new(),
        },
    )
    .await
}
async fn submit(
    holder: &Member,
    payload: ConsentReplacePayload,
) -> Result<(ConsentView, EventAdmissionSubmission)> {
    let realm = &holder
        .client
        .principal
        .as_ref()
        .context("actual holder PCR")?
        .pcr_realm_id;
    let event = holder
        .client
        .author_event(
            realm.as_str(),
            EventKind::ConsentReplace.as_str(),
            serde_json::to_value(payload)?,
        )
        .await?;
    let submission = EventAdmissionSubmission::new(event);
    let view = serde_json::from_value(
        expect_json(
            holder
                .client
                .post("/_arkret/self/consent/results/replace")
                .json(
                    &arkret_models_collaboration::consent_operations::ConsentReplaceRequestBody {
                        consent_event: submission.clone(),
                    },
                ),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    Ok((view, submission))
}
