//! Ordinary discussion messages share one authenticated Realm stream.

use anyhow::{Context, Result, ensure};
use arkret::{EventKind, RealmId, ScopeRef};

use super::{MlsApiContext, scan};
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, membership_payload, submit_and_expect_commit,
};
use crate::scenarios::mls_lifecycle_live::Member;
use crate::scenarios::signal_live::scoped_event;

async fn plain_realm(ctx: &MlsApiContext<'_>) -> Result<(RealmId, String)> {
    let realm = RealmId::new(
        create_realm_with_join_rule(
            &ctx.source.client,
            "API discussion parent",
            "public",
            &[ctx.station],
        )
        .await?,
    )?;
    join(ctx.holder, &realm).await?;
    crate::scenarios::human_device_producer_live::grant_realm_actions(
        &ctx.source.client,
        ctx.station,
        realm.as_str(),
        &ctx.holder.account,
        &["ak.message.create"],
    )
    .await?;
    let strand = ctx.source.client.default_strand_id(realm.as_str())?;
    Ok((realm, strand))
}

async fn join(member: &Member, realm: &RealmId) -> Result<()> {
    let event = member.client.author_event(realm.as_str(),"ak.member.state",membership_payload(realm.as_str(),member.account.clone(),
        arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join,"API discussion member")?).await?;
    submit_and_expect_commit(
        &member.client,
        &member.account,
        member.device.as_str(),
        &event,
    )
    .await?;
    Ok(())
}

async fn scoped_message(
    member: &Member,
    scope: &ScopeRef,
    strand: &str,
    text: &str,
) -> Result<arkret::RealmCommit> {
    let event = scoped_event(
        member,
        scope,
        EventKind::MessageCreate,
        crate::harness::message_create_text_payload(strand, text)?,
    )
    .await?;
    submit_and_expect_commit(
        &member.client,
        &member.account,
        member.device.as_str(),
        &event,
    )
    .await
}

pub(super) async fn run(ctx: &mut MlsApiContext<'_>) -> Result<()> {
    let (realm, public_strand) = plain_realm(ctx).await?;
    let realm_scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let first = scoped_message(
        ctx.source,
        &realm_scope,
        &public_strand,
        "inline source message",
    )
    .await?;
    let second = scoped_message(
        ctx.holder,
        &realm_scope,
        &public_strand,
        "inline peer message",
    )
    .await?;
    let before = scan(&ctx.holder.client, &realm_scope).await?;
    for id in [&first.event_ref, &second.event_ref] {
        let event = before
            .committed_events
            .iter()
            .filter_map(arkret::CommittedEventView::reducer_input)
            .find(|event| &event.event_id == id)
            .context("inline Message missing from the peer's stream")?;
        ensure!(
            event.payload["strand_id"] == public_strand
                && event.payload["track_name"] == "discussion",
            "inline discussion changed its routing identity"
        );
    }
    super::receipts::scope_policy_acceptance(ctx, &realm).await
}
