//! Real independent grants and requester equivalence on the private writer.

use super::consent_delivery_race::{delivery_cell, holder_independent_invite};
use super::*;
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, station_env, submit_and_expect_commit,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use crate::scenarios::mls_lifecycle_live::Member;

pub async fn run_current_invite_matrix() -> Result<()> {
    const GROUP: &str = "consent-current-invite-matrix";
    let db = database(GROUP)?.context("Consent evidence requires isolated PostgreSQL")?;
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let probe = tempfile::tempdir()?;
    let path = probe.path().join("invite.pause");
    let mut environment = station_env(&db.connect_url, &coauth);
    environment.push((
        "COLAND_CONFORMANCE_INVITE_DELIVERY_PAUSE_FILE".into(),
        path.to_string_lossy().into_owned(),
    ));
    let group = TestServerGroup::try_multi_external_with_node_envs(GROUP, &[environment])
        .await?
        .context("Consent evidence requires a prebuilt real Coland")?;
    let server = group.server(0);
    let alice = Box::pin(Member::provision(
        server,
        &coauth,
        "consent-invite-alice",
        "ak:device:01904100-0000-7000-8000-000000004101",
    ))
    .await?;
    let bob = Box::pin(Member::provision(
        server,
        &coauth,
        "consent-invite-bob",
        "ak:device:01904100-0000-7000-8000-000000004102",
    ))
    .await?;
    let claire = Box::pin(Member::provision(
        server,
        &coauth,
        "consent-invite-claire",
        "ak:device:01904100-0000-7000-8000-000000004103",
    ))
    .await?;
    let realm = create_realm_with_join_rule(
        &alice.client,
        "Consent invite controls",
        "public",
        &[server],
    )
    .await?
    .parse()?;
    super::verify_consent_delivery_race(&alice, &bob, &realm, &path).await?;
    let any = super::grant_scoped_consent(&bob.client, &alice.client, ConsentScope::Any).await?;
    let concrete = super::grant_invite_consent(&bob.client, &alice.client).await?;
    let consent_evidence =
        |grant: &(ConsentView, arkret_wire::Event)| IntroductionEvidence::ConsentGrant {
            consent_grant_ref: grant.1.event_id.clone(),
            consent_id: Some(grant.0.consent_id.to_string()),
        };
    positive(&alice, &bob, &realm, consent_evidence(&any)).await?;
    super::revoke_invite_consent(&bob.client, any.0).await?;
    negative(
        &alice,
        &bob,
        &realm,
        IntroductionEvidence::ConsentGrant {
            consent_grant_ref: any.1.event_id,
            consent_id: None,
        },
    )
    .await?;
    let current: arkret_models_collaboration::consent_operations::ConsentList =
        serde_json::from_value(
            expect_json(
                bob.client.get("/_arkret/self/consent/results"),
                StatusCode::OK,
            )
            .await?,
        )?;
    ensure!(
        current.consents.iter().any(|value| value == &concrete.0),
        "any revoke changed the independent concrete revision"
    );
    positive(&alice, &bob, &realm, consent_evidence(&concrete)).await?;
    super::revoke_invite_consent(&bob.client, concrete.0).await?;
    negative(
        &alice,
        &bob,
        &realm,
        IntroductionEvidence::ConsentGrant {
            consent_grant_ref: concrete.1.event_id,
            consent_id: None,
        },
    )
    .await?;
    eprintln!(
        "[consent-invite] any_permitted=1 revoked_any_rejected=1 concrete_revision_preserved=1 concrete_permitted=1 all_revoked_rejected=1"
    );

    let (revoked, grant_event) = super::grant_invite_consent(&bob.client, &alice.client).await?;
    super::revoke_invite_consent(&bob.client, revoked).await?;
    let claire_realm =
        create_realm_with_join_rule(&claire.client, "Never granted source", "public", &[server])
            .await?
            .parse()?;
    let before = delivery_cell(&bob.client).await?;
    let mut revoked_times = Vec::new();
    let mut never_times = Vec::new();
    for round in 0..4 {
        for revoked in if round % 2 == 0 {
            [true, false]
        } else {
            [false, true]
        } {
            let (sender, target) = if revoked {
                (&alice, &realm)
            } else {
                (&claire, &claire_realm)
            };
            let evidence = IntroductionEvidence::ConsentGrant {
                // The never-granted source cannot borrow Alice's actual grant.
                consent_grant_ref: grant_event.event_id.clone(),
                consent_id: None,
            };
            let invite = holder_independent_invite(sender, &bob, target, evidence).await?;
            let id = invite.invite_id.clone();
            let started = Instant::now();
            let response = dispatch_explicit_invite(&sender.client, invite).await?;
            let elapsed = started.elapsed();
            let outcome: arkret_models_collaboration::governance::invite_addressing::InviteDeliveryOutcome = serde_json::from_value(response.outcome)?;
            ensure!(outcome.status == arkret_models_collaboration::governance::invite_addressing::InviteDeliveryOutcomeStatus::Deferred
                && outcome.disclosed_outcome.is_none() && outcome.retry_after_ms.is_none() && outcome.received_at.is_some(), "requester learned a private Consent decision");
            if revoked {
                revoked_times.push(elapsed);
            } else {
                never_times.push(elapsed);
            }
            cancel(sender, &bob, target, id).await?;
        }
    }
    ensure!(
        delivery_cell(&bob.client).await? == before,
        "equivalent negative requests wrote holder delivery"
    );
    revoked_times.sort();
    never_times.sort();
    let a = revoked_times[revoked_times.len() / 2];
    let b = never_times[never_times.len() / 2];
    ensure!(
        a.abs_diff(b) <= Duration::from_millis(50),
        "requester timing separates revoked and never-granted peers: {a:?} vs {b:?}"
    );
    eprintln!(
        "[consent-invite] revoked_never_opaque_pairs=4 median_gap_ms={} holder_delivery_writes=0",
        a.abs_diff(b).as_millis()
    );
    Ok(())
}

async fn positive(
    sender: &Member,
    holder: &Member,
    realm: &arkret_wire::RealmId,
    evidence: IntroductionEvidence,
) -> Result<()> {
    let invite = holder_independent_invite(sender, holder, realm, evidence).await?;
    let id = invite.invite_id.clone();
    let response = dispatch_explicit_invite(&sender.client, invite).await?;
    ensure!(
        response.outcome["status"] == "accepted"
            && response.outcome.get("disclosed_outcome").is_none()
    );
    let after = delivery_cell(&holder.client)
        .await?
        .context("actual positive delivery")?;
    ensure!(
        after.content["delivery_entries"]
            .as_array()
            .is_some_and(|rows| rows
                .iter()
                .any(|row| row["invite_id"].as_str() == Some(id.as_str())))
    );
    cancel(sender, holder, realm, id).await
}

async fn negative(
    sender: &Member,
    holder: &Member,
    realm: &arkret_wire::RealmId,
    evidence: IntroductionEvidence,
) -> Result<()> {
    let before = delivery_cell(&holder.client).await?;
    let invite = holder_independent_invite(sender, holder, realm, evidence).await?;
    let id = invite.invite_id.clone();
    let response = dispatch_explicit_invite(&sender.client, invite).await?;
    ensure!(
        response.outcome["status"] == "deferred"
            && response.outcome.get("disclosed_outcome").is_none()
    );
    ensure!(
        delivery_cell(&holder.client).await? == before,
        "stale Consent proof wrote private delivery"
    );
    cancel(sender, holder, realm, id).await
}

async fn cancel(
    sender: &Member,
    holder: &Member,
    realm: &arkret_wire::RealmId,
    invite: InviteId,
) -> Result<()> {
    use arkret_models_collaboration::governance::membership_invite::{
        InviteCancelPayload, InviteCancelTargetState, InvitePreviousState,
    };
    let event = sender
        .client
        .author_event(
            realm.as_str(),
            "ak.invite.cancel",
            InviteCancelPayload::new(
                invite,
                InvitePreviousState::Pending,
                holder.account.clone(),
                InviteCancelTargetState::Revoked,
            )
            .to_value()?,
        )
        .await?;
    submit_and_expect_commit(
        &sender.client,
        &sender.account,
        sender.device.as_str(),
        &event,
    )
    .await?;
    Ok(())
}
