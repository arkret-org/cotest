//! Bulk fixture edits share the independently verified full peer current read.
use anyhow::{Context, Result};
use arkret_models_collaboration::consent_operations::{ConsentReplaceRequestBody, ConsentView};
use arkret_models_collaboration::events_payloads::consent::{
    ConsentPeer, ConsentPermission, ConsentReplacePayload,
};
use arkret_wire::{ActorId, ConsentScope, Event, EventAdmissionSubmission, EventKind};
use cotest::scenarios::mls_lifecycle_live::Member;

pub(super) fn permission(scope: ConsentScope) -> ConsentPermission {
    ConsentPermission {
        consent_scope: scope,
        not_before: None,
        expires_at: None,
        constraints: None,
        evidence_ref: None,
        reason: None,
    }
}

pub(super) async fn grant(
    holder: &Member,
    peer: &ActorId,
    entries: Vec<ConsentPermission>,
) -> Result<(ConsentView, Event)> {
    let peer = ConsentPeer::Actor {
        actor_id: peer.clone(),
    };
    let current = super::consent_set::read(holder, &peer).await?;
    let expected_current = current.expected_current();
    let mut permissions = current.current_permissions().unwrap_or_default().to_vec();
    permissions.retain(|permission| {
        !entries
            .iter()
            .any(|entry| entry.consent_scope == permission.consent_scope)
    });
    permissions.extend(entries);
    permissions.sort_by_key(|permission| permission.consent_scope);
    submit(
        holder,
        ConsentReplacePayload {
            peer,
            expected_current,
            permissions,
        },
    )
    .await
}

pub(super) async fn clear(holder: &Member, peer: &ActorId) -> Result<(ConsentView, Event)> {
    let peer = ConsentPeer::Actor {
        actor_id: peer.clone(),
    };
    let current = super::consent_set::read(holder, &peer).await?;
    submit(
        holder,
        ConsentReplacePayload {
            peer,
            expected_current: current.expected_current(),
            permissions: Vec::new(),
        },
    )
    .await
}

async fn submit(holder: &Member, payload: ConsentReplacePayload) -> Result<(ConsentView, Event)> {
    payload.validate()?;
    let principal = holder
        .client
        .principal
        .as_ref()
        .context("actual holder PCR")?;
    let event = holder
        .client
        .author_event(
            principal.pcr_realm_id.as_str(),
            EventKind::ConsentReplace.as_str(),
            serde_json::to_value(payload)?,
        )
        .await?;
    let view = serde_json::from_value(
        cotest::harness::expect_json(
            holder
                .client
                .post("/_arkret/self/consent/results/replace")
                .json(&ConsentReplaceRequestBody {
                    consent_event: EventAdmissionSubmission::new(event.clone()),
                }),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    Ok((view, event))
}
