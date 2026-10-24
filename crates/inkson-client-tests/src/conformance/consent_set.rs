//! Real full-value Consent fixture writes; no display summary supplies a CAS basis.
use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::call_invitation::{
    ConsentCurrentReadRequestBody, ConsentCurrentReadResponseBody,
};
use arkret_models_collaboration::consent_operations::{ConsentReplaceRequestBody, ConsentView};
use arkret_models_collaboration::events_payloads::consent::{
    ConsentPeer, ConsentPermission, ConsentReplacePayload,
};
use arkret_wire::{ActorId, ConsentScope, Event, EventAdmissionSubmission, EventKind};
use cotest::scenarios::mls_lifecycle_live::Member;

#[derive(Clone, Debug, PartialEq)]
pub(super) struct PermissionWrite {
    pub view: ConsentView,
    pub scope: ConsentScope,
}
impl std::ops::Deref for PermissionWrite {
    type Target = ConsentView;
    fn deref(&self) -> &Self::Target {
        &self.view
    }
}

pub(super) async fn read(
    holder: &Member,
    peer: &ConsentPeer,
) -> Result<ConsentCurrentReadResponseBody> {
    let request = ConsentCurrentReadRequestBody {
        holder_account_id: holder.account.clone(),
        peer: peer.clone(),
        audience_actor_id: ActorId::service(holder.account.station_id.clone()),
        nonce: {
            let mut bytes = [0_u8; 32];
            getrandom::fill(&mut bytes).map_err(anyhow::Error::msg)?;
            arkret_canonical::base64url_encode(bytes)
        },
    };
    let outcome = holder.client.sdk().consent_current_read(&request).await?;
    holder
        .client
        .verify_consent_current_read(&request, &outcome)?;
    let mut bad_proof = outcome.clone();
    bad_proof.proof.jws.clear();
    ensure!(
        holder
            .client
            .verify_consent_current_read(&request, &bad_proof)
            .is_err()
    );
    Ok(outcome)
}

pub(super) async fn replace_scope(
    holder: &Member,
    peer: &ConsentPeer,
    scope: ConsentScope,
    replacement: Option<ConsentPermission>,
) -> Result<(PermissionWrite, Event)> {
    let current = read(holder, peer).await?;
    let mut permissions = current.current_permissions().unwrap_or_default().to_vec();
    permissions.retain(|p| p.consent_scope != scope);
    if let Some(replacement) = replacement {
        ensure!(replacement.consent_scope == scope);
        permissions.push(replacement);
    }
    permissions.sort_by_key(|p| match p.consent_scope {
        ConsentScope::Invite => 0,
        ConsentScope::VoiceCall => 1,
        ConsentScope::VideoCall => 2,
        ConsentScope::Presence => 3,
    });
    let payload = ConsentReplacePayload {
        peer: peer.clone(),
        expected_current: current.expected_current(),
        permissions,
    };
    payload.validate()?;
    let principal = holder.client.principal.as_ref().context("holder PCR")?;
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
    Ok((PermissionWrite { view, scope }, event))
}

pub(super) async fn grant(
    holder: &Member,
    peer: &ActorId,
    permission: ConsentPermission,
) -> Result<(PermissionWrite, Event)> {
    replace_scope(
        holder,
        &ConsentPeer::Actor {
            actor_id: peer.clone(),
        },
        permission.consent_scope,
        Some(permission),
    )
    .await
}
pub(super) async fn remove(
    holder: &Member,
    previous: &PermissionWrite,
) -> Result<(PermissionWrite, Event)> {
    replace_scope(holder, &previous.peer, previous.scope, None).await
}
