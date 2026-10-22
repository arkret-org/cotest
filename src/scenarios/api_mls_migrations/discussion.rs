//! Real Circle promotion, independent streams, crypto scope and zero-write refusals.

use anyhow::{Context, Result, ensure};
use arkret::{Event, EventKind, RealmId, ScopeRef};
use serde_json::json;

use super::{MlsApiContext, scan};
use crate::harness::CanonicalJsonBody;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, membership_payload, submit_and_expect_commit,
};
use crate::scenarios::mls_lifecycle_live::Member;
use crate::scenarios::signal_live::{circle_discussion_basis, circle_mls_fixture, scoped_event};

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

async fn reject_without_write(
    ctx: &MlsApiContext<'_>,
    scope: &ScopeRef,
    event: Event,
    status: reqwest::StatusCode,
    code: &str,
) -> Result<()> {
    let before = scan(&ctx.source.client, scope).await?;
    crate::harness::expect_api_error(
        ctx.source
            .client
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(event, "")?),
        status,
        code,
    )
    .await?;
    let after = scan(&ctx.source.client, scope).await?;
    ensure!(
        arkret_canonical::canonical_json_bytes(&before)?
            == arkret_canonical::canonical_json_bytes(&after)?,
        "refused discussion operation changed the canonical stream"
    );
    Ok(())
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
    let basis = circle_discussion_basis(ctx.source, ctx.holder, &realm).await?;
    for member in [ctx.source, ctx.holder] {
        crate::scenarios::circle_parent_membership_live::grant_circle_actions_with(
            ctx.source,
            realm.as_str(),
            &basis.circle,
            member,
            &["ak.message.create", "ak.relation.create"],
        )
        .await?;
    }
    let private = scoped_message(
        ctx.source,
        &basis.scope,
        basis.strand_id.as_str(),
        "private source discussion",
    )
    .await?;
    let peer_private = scoped_message(
        ctx.holder,
        &basis.scope,
        basis.strand_id.as_str(),
        "private peer discussion",
    )
    .await?;
    let relation_payload: arkret_models_collaboration::events_payloads::RelationCreatePayload =
        serde_json::from_value(json!({
            "primary_conflict_domain":{"domain_kind":"from","relation_kind":"confidential_discussion_of","from_ref":basis.strand_id},
            "expected_revision":null,"relation":{"scope_circle_id":basis.circle,"relation_kind":"confidential_discussion_of",
                "from_ref":basis.strand_id,"to_ref":public_strand,"fields":{"role":"promoted_discussion"}}
        }))?;
    let relation = scoped_event(
        ctx.source,
        &basis.scope,
        EventKind::RelationCreate,
        relation_payload.to_value()?,
    )
    .await?;
    let relation = submit_and_expect_commit(
        &ctx.source.client,
        &ctx.source.account,
        ctx.source.device.as_str(),
        &relation,
    )
    .await?;
    let private_scan = scan(&ctx.holder.client, &basis.scope).await?;
    for id in [
        &private.event_ref,
        &peer_private.event_ref,
        &relation.event_ref,
    ] {
        let item = private_scan
            .committed_events
            .iter()
            .find(|item| &item.commit().event_ref == id)
            .context("Circle stream omitted an accepted private Event")?;
        ensure!(
            item.commit().stream_ref.realm_id() == &realm
                && item
                    .reducer_input()
                    .context("private Circle Event withheld from a member")?
                    .scope_ref
                    == basis.scope,
            "Circle discussion left its original Realm or changed its independent stream scope"
        );
    }
    let relation_event = private_scan
        .committed_events
        .iter()
        .filter_map(arkret::CommittedEventView::reducer_input)
        .find(|e| e.event_id == relation.event_ref)
        .unwrap();
    ensure!(
        relation_event.payload["relation"]["from_ref"] == basis.strand_id.as_str()
            && relation_event.payload["relation"]["to_ref"] == public_strand,
        "promotion changed its confidential relation endpoints"
    );
    let outsider = Member::provision(
        ctx.station,
        ctx.issuer,
        "discussion-outsider",
        &arkret_identifiers::new_prefixed_uuid7("ak:device:"),
    )
    .await?;
    join(&outsider, &realm).await?;
    let public_after_join = scoped_message(
        ctx.source,
        &realm_scope,
        &public_strand,
        "public target after outsider join",
    )
    .await?;
    let outsider_scan = scan(&outsider.client, &realm_scope).await?;
    ensure!(
        outsider_scan
            .committed_events
            .iter()
            .any(|item| item.commit().event_ref == public_after_join.event_ref),
        "Realm member could not read the positive public target"
    );
    ensure!(
        outsider_scan.committed_events.iter().all(|item| ![
            &private.event_ref,
            &peer_private.event_ref,
            &relation.event_ref
        ]
        .contains(&&item.commit().event_ref)),
        "Realm stream leaked Circle discussion or its relation"
    );
    ensure!(
        scan(&outsider.client, &basis.scope).await.is_err()
            && outsider
                .client
                .sdk()
                .committed_event_get(&private.event_ref)
                .await
                .is_err(),
        "non-Circle member could read the private stream or Event"
    );

    let mut encrypted =
        circle_mls_fixture(ctx.source, ctx.holder, ctx.station, ctx.station, &realm).await?;
    for member in [ctx.source, ctx.holder] {
        crate::scenarios::circle_parent_membership_live::grant_circle_actions_with(
            ctx.source,
            realm.as_str(),
            &encrypted.basis.circle,
            member,
            &["ak.message.create"],
        )
        .await?;
    }
    let encrypted_message =
        crate::scenarios::message_mls_cross_station_live::submit_and_open_content(
            ctx.holder,
            ctx.source,
            &mut encrypted.holder_group,
            &mut encrypted.source_group,
            &realm,
            encrypted.basis.strand_id.as_str(),
            &encrypted.state_ref,
            arkret::ContentBlock::text("actual independent Circle MLS ciphertext"),
            encrypted.basis.scope.clone(),
        )
        .await?;
    let public_after = scoped_message(
        ctx.source,
        &realm_scope,
        &public_strand,
        "parent remains plaintext",
    )
    .await?;
    let circle_scan = scan(&ctx.source.client, &encrypted.basis.scope).await?;
    let message = circle_scan
        .committed_events
        .iter()
        .filter_map(arkret::CommittedEventView::reducer_input)
        .find(|e| e.event_id == encrypted_message.event_ref)
        .context("Circle MLS Message")?;
    ensure!(
        message.payload.contains_key("encrypted_content")
            && !message.payload.contains_key("content"),
        "Circle MLS content was not sealed"
    );
    let public_scan = scan(&ctx.source.client, &realm_scope).await?;
    ensure!(
        public_scan
            .committed_events
            .iter()
            .all(|item| item.commit().event_ref != encrypted_message.event_ref),
        "Circle ciphertext leaked into the Realm stream"
    );
    let public = public_scan
        .committed_events
        .iter()
        .filter_map(arkret::CommittedEventView::reducer_input)
        .find(|e| e.event_id == public_after.event_ref)
        .unwrap();
    ensure!(
        public.payload.contains_key("content") && !public.payload.contains_key("encrypted_content"),
        "Circle activation encrypted its parent Realm"
    );
    super::receipts::scope_policy_acceptance(
        ctx,
        &realm,
        &basis.scope,
        &encrypted.basis.scope,
        &outsider,
    )
    .await?;
    let parent =
        crate::scenarios::websocket_live::realm_head(&ctx.source.client, realm.as_str()).await?;
    super::receipts::deliver(
        ctx.holder,
        ctx.source,
        &mut encrypted.holder_group,
        &encrypted.source_group,
        &realm,
        encrypted.basis.strand_id.as_str(),
        &encrypted.state_ref,
        &encrypted.basis.scope,
        Some(&parent.commit_id),
        &encrypted_message.event_ref,
        1,
    )
    .await?;

    let orphan: arkret::CircleId =
        "ak:circle:ATJ_DJ_0dc3yFbBW3UWM7qysprZ6zJPZzhxGzqahfHEA".parse()?;
    let orphan_scope = ScopeRef::Circle {
        realm_id: realm.clone(),
        circle_id: orphan.clone(),
    };
    let mut object = arkret_models_collaboration::objects::strand::Strand::new_create(
        realm.clone(),
        "orphan discussion",
        ctx.source.actor.clone(),
    );
    object.stage = None;
    object.scope_circle_id = Some(orphan);
    object.tracks.clear();
    object.tracks.insert(
        "discussion".into(),
        arkret_models_collaboration::objects::object_facets::StrandTrack::discussion_primary(),
    );
    let mut event = scoped_event(
        ctx.source,
        &orphan_scope,
        EventKind::StrandCreate,
        serde_json::to_value(
            arkret_models_collaboration::events_payloads::StrandCreatePayload { object },
        )?,
    )
    .await?;
    event.payload.get_mut("object").context("Strand object")?["created_at"] = json!(
        arkret_canonical::format_timestamp_canonical(event.created_at)
    );
    crate::harness::refresh_typed_event_proof_with_signing_seed(
        &mut event,
        ctx.source.key.to_bytes(),
    )?;
    reject_without_write(
        ctx,
        &realm_scope,
        event,
        reqwest::StatusCode::CONFLICT,
        "failed_precondition",
    )
    .await?;
    let patch: arkret_models_collaboration::events_payloads::StrandPatchPayload =
        serde_json::from_value(
            json!({"target_ref":public_strand,"patch":{"scope_circle_id":{"$op":"set","value":basis.circle}}}),
        )?;
    let event = ctx
        .source
        .client
        .author_event(
            realm.as_str(),
            "ak.strand.update",
            serde_json::to_value(patch)?,
        )
        .await?;
    let before = scan(&ctx.source.client, &realm_scope).await?;
    let response = ctx
        .source
        .client
        .post("/_arkret/self/events")
        .canonical_json(&crate::publication::initial_submission(event, "")?)?
        .send()
        .await?;
    ensure!(
        !response.status().is_success(),
        "Strand scope rebind was accepted"
    );
    let refusal = response.text().await?;
    ensure!(
        refusal.contains("scope_rebind_forbidden"),
        "scope rebind failed at an unrelated boundary: {refusal}"
    );
    ensure!(
        arkret_canonical::canonical_json_bytes(&scan(&ctx.source.client, &realm_scope).await?)?
            == arkret_canonical::canonical_json_bytes(&before)?,
        "scope rebind changed the Realm stream"
    );
    println!(
        "discussion: inline pair, independent Circle stream, outsider isolation, confidential relation, actual Circle MLS over plaintext parent, scoped encrypted receipt, zero-write orphan/rebind refusals verified"
    );
    Ok(())
}

pub(super) async fn markers(ctx: &MlsApiContext<'_>) -> Result<()> {
    let (realm, strand) = plain_realm(ctx).await?;
    let basis = circle_discussion_basis(ctx.source, ctx.holder, &realm).await?;
    crate::scenarios::circle_parent_membership_live::grant_circle_actions_with(
        ctx.source,
        realm.as_str(),
        &basis.circle,
        ctx.source,
        &["ak.message.create"],
    )
    .await?;
    let public = scoped_message(
        ctx.source,
        &ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        &strand,
        "public marker target",
    )
    .await?;
    let private = scoped_message(
        ctx.source,
        &basis.scope,
        basis.strand_id.as_str(),
        "actual Circle marker target",
    )
    .await?;
    let public_position = crate::scenarios::private_read_marker_api::position(public.event_ref, 1)?;
    let private_position =
        crate::scenarios::private_read_marker_api::position(private.event_ref, 2)?;
    let realm_scope = serde_json::from_value(json!({"kind":"realm"}))?;
    let circle_scope =
        serde_json::from_value(json!({"kind":"circle","container_ref":basis.circle}))?;
    crate::scenarios::private_read_marker_api::advance(
        &ctx.source.client,
        &realm,
        &realm_scope,
        &public_position,
    )
    .await?;
    crate::scenarios::private_read_marker_api::advance(
        &ctx.source.client,
        &realm,
        &circle_scope,
        &private_position,
    )
    .await?;
    let list = crate::scenarios::private_read_marker_api::list(&ctx.source.client, &realm).await?;
    ensure!(
        list.markers.len() == 2
            && list
                .markers
                .iter()
                .any(|m| m.read_scope == realm_scope && m.position == public_position)
            && list
                .markers
                .iter()
                .any(|m| m.read_scope == circle_scope && m.position == private_position),
        "Circle and Realm private markers did not remain independent"
    );
    let outsider = Member::provision(
        ctx.station,
        ctx.issuer,
        "circle-marker-outsider",
        &arkret_identifiers::new_prefixed_uuid7("ak:device:"),
    )
    .await?;
    join(&outsider, &realm).await?;
    let absent = crate::scenarios::private_read_marker_api::list(&outsider.client, &realm).await?;
    ensure!(
        absent.markers.is_empty(),
        "outsider already holds another Account's private markers"
    );
    let refusal = crate::scenarios::private_read_marker_api::advance(
        &outsider.client,
        &realm,
        &circle_scope,
        &private_position,
    )
    .await
    .expect_err("a Realm member outside the Circle cannot advance to its private Event");
    ensure!(
        refusal.to_string().contains("param_invalid"),
        "invisible Circle position failed at an unrelated gate: {refusal}"
    );
    ensure!(
        crate::scenarios::private_read_marker_api::list(&outsider.client, &realm)
            .await?
            .markers
            .is_empty(),
        "refused Circle marker wrote actor-private state"
    );
    crate::scenarios::signal_live::circle_membership(
        ctx.source,
        &ctx.source.client,
        &basis.scope,
        false,
    )
    .await?;
    let before =
        crate::scenarios::private_read_marker_api::list(&ctx.source.client, &realm).await?;
    let refusal = crate::scenarios::private_read_marker_api::advance(
        &ctx.source.client,
        &realm,
        &circle_scope,
        &private_position,
    )
    .await
    .expect_err("a departed Circle member cannot advance its old private position");
    ensure!(
        refusal.to_string().contains("param_invalid"),
        "departed Circle position failed at an unrelated gate: {refusal}"
    );
    ensure!(
        arkret_canonical::canonical_json_bytes(&before)?
            == arkret_canonical::canonical_json_bytes(
                &crate::scenarios::private_read_marker_api::list(&ctx.source.client, &realm)
                    .await?
            )?,
        "departed Circle position replaced the durable winner"
    );
    Ok(())
}
