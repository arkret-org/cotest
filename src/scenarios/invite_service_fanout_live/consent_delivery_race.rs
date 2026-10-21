//! Actual accepted preflight/revoke/private CAS race with a positive control.

use super::*;
use crate::scenarios::mls_lifecycle_live::Member;

pub(crate) async fn verify_consent_delivery_race(
    inviter: &Member,
    holder: &Member,
    realm: &arkret_wire::RealmId,
    probe: &std::path::Path,
) -> Result<()> {
    let mut policy: InviteReceivePolicy = serde_json::from_value(
        expect_json(
            holder.client.get("/_arkret/self/invite-receive-policy"),
            StatusCode::OK,
        )
        .await?,
    )?;
    policy.consent_profile = arkret_wire::ConsentProfile::RequireExplicitConsent;
    policy.disclosure = Some(
        arkret_models_collaboration::governance::invite_addressing::DisclosurePolicy {
            high_trust: Some(
                arkret_models_collaboration::governance::invite_addressing::DisclosureLevel::Opaque,
            ),
            discovery_trust: None,
            low_trust: None,
        },
    );
    expect_json(
        holder
            .client
            .put("/_arkret/self/invite-receive-policy")
            .json(&policy),
        StatusCode::OK,
    )
    .await?;
    for deny in [false, true] {
        let (grant, event) = super::grant_invite_consent(&holder.client, &inviter.client).await?;
        let evidence = IntroductionEvidence::ConsentGrant {
            consent_grant_ref: event.event_id.clone(),
        };
        let create = holder_independent_invite(inviter, holder, realm, evidence).await?;
        let before = delivery_cell(&holder.client).await?;
        let reached = probe.with_extension("reached");
        if reached.exists() {
            std::fs::remove_file(&reached)?;
        }
        std::fs::write(
            probe,
            serde_json::to_vec(&(&holder.account, &create.invite_id))?,
        )?;
        let dispatch = dispatch_explicit_invite(&inviter.client, create);
        let race = async {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            while !reached.exists() {
                ensure!(
                    tokio::time::Instant::now() < deadline,
                    "actual invite preflight never reached its final CAS"
                );
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            if deny {
                super::revoke_invite_consent(&holder.client, grant.clone()).await?;
            }
            std::fs::remove_file(probe)?;
            Ok::<(), anyhow::Error>(())
        };
        let (outcome, raced) = tokio::join!(dispatch, race);
        raced?;
        let outcome = outcome?;
        ensure!(
            outcome.outcome["status"] == if deny { "deferred" } else { "accepted" }
                && outcome.outcome.get("disclosed_outcome").is_none(),
            "requester learned a private CAS decision"
        );
        let after = delivery_cell(&holder.client).await?;
        if deny {
            ensure!(
                after == before,
                "pre-revoke preflight wrote holder-private delivery after revoke"
            );
        } else {
            let after = after.context("positive control must write actual delivery")?;
            ensure!(
                after.content["delivery_entries"]
                    .as_array()
                    .is_some_and(|entries| entries.iter().any(
                        |entry| entry["invite_id"].as_str() == Some(outcome.invite_id.as_str())
                    )),
                "positive control did not commit the actual invite"
            );
            super::revoke_invite_consent(&holder.client, grant).await?;
        }
        use arkret_models_collaboration::governance::membership_invite::{
            InviteCancelPayload, InviteCancelTargetState, InvitePreviousState,
        };
        let cancelled = inviter
            .client
            .author_event(
                realm.as_str(),
                "ak.invite.cancel",
                InviteCancelPayload::new(
                    outcome.invite_id,
                    InvitePreviousState::Pending,
                    holder.account.clone(),
                    InviteCancelTargetState::Revoked,
                )
                .to_value()?,
            )
            .await?;
        crate::scenarios::human_device_producer_live::submit_and_expect_commit(
            &inviter.client,
            &inviter.account,
            inviter.device.as_str(),
            &cancelled,
        )
        .await?;
        std::fs::remove_file(reached)?;
    }
    eprintln!(
        "[consent-invite] real_preflight_positive=1 revoke_before_private_cas_denied=1 opaque_outcomes=2"
    );
    Ok(())
}

pub(super) async fn delivery_cell(holder: &TestActorClient) -> Result<Option<AccountDataRow>> {
    let listed: AccountDataList = serde_json::from_value(
        expect_json(holder.get("/_arkret/self/account_data"), StatusCode::OK).await?,
    )?;
    Ok(listed
        .account_data_entries
        .into_iter()
        .find(|row| row.account_data_key == AccountDataKey::ACCOUNT_INVITE_DELIVERY))
}

pub(super) async fn holder_independent_invite(
    inviter: &Member,
    holder: &Member,
    realm: &arkret_wire::RealmId,
    evidence: IntroductionEvidence,
) -> Result<PreparedInvite> {
    let payload =
        arkret_models_collaboration::governance::membership_invite::InviteCreatePayload::new(
            holder.account.clone(),
            arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&evidence)?)?,
            Utc::now() + ChronoDuration::days(1),
        );
    let event = inviter
        .client
        .author_event(
            realm.as_str(),
            "ak.invite.create",
            serde_json::to_value(payload)?,
        )
        .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &inviter.client,
        &inviter.account,
        inviter.device.as_str(),
        &event,
    )
    .await?;
    Ok(PreparedInvite {
        invite_id: InviteId::from_event_id(&event.event_id),
        request: SelfInviteDispatchRequestBody {
            schema: arkret_wire::SchemaId::INVITE_DELIVERY_REQUEST_V1.into(),
            invite_event_id: event.event_id.clone(),
            invite_address: InviteAddress {
                account_id: holder.account.clone(),
                service_resolution: ServiceResolutionCarrier::ResolutionUrl {
                    resolution_url: format!(
                        "https://cotest.invalid{}",
                        arkret_models_identity::canonical_service_resolution_path(
                            &holder.account.station_id
                        )
                    ),
                },
                route_assistance: None,
            },
            introduction_evidence: evidence,
            idempotency_key: event.event_id.to_string(),
        },
    })
}
