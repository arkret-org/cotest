//! Actual SinceJoin current disclosure after a post-join Message revision.
use arkret_models_collaboration::events_payloads::MessageReactionsCurrentValue;
use arkret_wire::{
    CommittedEventRef, CurrentRevision, CurrentSelector, CurrentState, Event, EventId,
    HistoryAccess, MemberStateValue, MembershipState, MessageId, RealmCommit, RealmStateSnapshot,
};
use garth::own_station_results::OwnStationReplica;
use serde_json::json;

use super::*;

const LABEL: &str = "since-join-reaction-current";
const KEY: &str = "like";
const ORIGINAL_BODY: &str = "old body accepted before the new member joined";
const REVISED_BODY: &str = "current revised body accepted after the new member joined";

fn committed_ref(event: &Event, commit: &RealmCommit) -> CommittedEventRef {
    CommittedEventRef {
        event_id: event.event_id.clone(),
        commit_id: commit.commit_id.clone(),
        stream_ref: commit.stream_ref.clone(),
        stream_position: commit.stream_position,
    }
}

fn row<'a>(
    snapshot: &'a RealmStateSnapshot,
    wanted: &CurrentSelector,
) -> Option<(&'a CommitStreamRef, &'a CurrentRevision, &'a Value)> {
    snapshot.current_state_entries.iter().find_map(|entry| {
        let CurrentState::Value {
            selector,
            source_stream_ref,
            revision,
            value,
        } = entry;
        (selector == wanted).then_some((source_stream_ref, revision, value))
    })
}

fn require_floor(snapshot: &RealmStateSnapshot, join: &RealmCommit) -> Result<()> {
    ensure!(
        snapshot.retention_and_history_floor.history_access == HistoryAccess::SinceJoin,
        "fixture changed its actual history policy instead of exercising SinceJoin"
    );
    let floor = snapshot
        .retention_and_history_floor
        .stream_floors
        .iter()
        .find(|floor| floor.stream_ref == join.stream_ref)
        .context("current cut omitted its member floor")?;
    ensure!(
        floor.oldest_position == join.stream_position,
        "current disclosure moved the original join floor"
    );
    Ok(())
}

async fn install_at(
    client: &TestActorClient,
    replica: &mut OwnStationReplica,
    realm: &RealmId,
    expected: &RealmCommit,
) -> Result<()> {
    let source = client
        .sdk()
        .own_station_result_client()?
        .context("actual bound own-Station source absent")?;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let response = match source.snapshot_head(realm).await {
            Ok(response) => response,
            Err(arkret_http_client::Error::Api { status: 503, .. })
                if Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let snapshot = response.value()?;
        let reached = snapshot.visible_stream_heads.iter().any(|head| {
            head.stream_ref == expected.stream_ref
                && head.stream_position >= expected.stream_position
                && (head.stream_position != expected.stream_position
                    || head.commit_id == expected.commit_id)
        });
        if reached {
            source.check_session()?;
            // The real bound response is installed whole; no Event reducer or
            // old Reaction original is supplied to the ordinary client.
            replica.install_bound_snapshot(&response)?;
            source.check_session()?;
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "member Station never reached the native accepting cut"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn require_old_original_refused(client: &TestActorClient, event: &EventId) -> Result<()> {
    let error = client
        .sdk()
        .committed_event_get(event)
        .await
        .expect_err("below-floor original became readable through current metadata");
    match error {
        arkret_http_client::Error::Api { status: 404, error } => {
            ensure!(
                error.error_code() == Some(arkret_wire::ErrorCode::NotFound),
                "old original refusal did not use the non-enumerating history boundary"
            );
            Ok(())
        }
        other => bail!("old original was not refused by the real history gate: {other}"),
    }
}

async fn require_scan_floor(
    client: &TestActorClient,
    realm: &RealmId,
    join: &RealmCommit,
    originals: &[&EventId],
) -> Result<()> {
    let page = wait_for_member_scan(client, realm).await?;
    let floor = page
        .readable_floor
        .as_ref()
        .context("real scan omitted its SinceJoin floor")?;
    ensure!(
        floor.oldest_position == join.stream_position
            && floor.floor_commit_id == join.commit_id
            && floor.floor_reason == ReadableFloorReason::MembershipJoin,
        "real scan changed the member's accepted floor"
    );
    ensure!(
        page.committed_events
            .iter()
            .all(|item| item.commit().stream_position >= join.stream_position),
        "the ordinary scan returned a below-floor Commit"
    );
    ensure!(
        page.committed_events
            .iter()
            .all(|item| !originals.contains(&&item.commit().event_ref)),
        "the ordinary scan returned an old original after current disclosure"
    );
    Ok(())
}

fn require_joined_roster(snapshot: &RealmStateSnapshot, expected: &[ActorId]) -> Result<()> {
    let mut joined = Vec::new();
    for entry in &snapshot.current_state_entries {
        if let CurrentState::Value {
            selector: CurrentSelector::MemberState { actor_id },
            value,
            ..
        } = entry
        {
            let current: MemberStateValue = serde_json::from_value(value.clone())?;
            if current.membership == MembershipState::Join {
                joined.push(actor_id.clone());
            }
        }
    }
    ensure!(
        joined.len() == expected.len() && expected.iter().all(|actor| joined.contains(actor)),
        "typed current cannot supply the actual joined-member roster/count"
    );
    Ok(())
}

pub async fn since_join_current_reaction_survives_a_new_message_revision() -> Result<()> {
    let governance_db = database(LABEL)?.context("actual governance PostgreSQL is required")?;
    let member_db = database(LABEL)?.context("independent member PostgreSQL is required")?;
    ensure!(
        governance_db.connect_url != member_db.connect_url,
        "member and governance must use independent databases"
    );
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = TestServerGroup::try_multi_external_with_node_envs(
        LABEL,
        &[
            station_env(&governance_db.connect_url, &issuer),
            station_env(&member_db.connect_url, &issuer),
        ],
    )
    .await?
    .context("two actual owned Station processes are required")?;
    let (alice, alice_account) = standard_client(
        group.server(0),
        &issuer,
        "reaction-current-alice",
        ALICE_DEVICE,
    )
    .await?;
    let (bob, bob_account) =
        standard_client(group.server(1), &issuer, "reaction-current-bob", BOB_DEVICE).await?;
    let source = bob
        .sdk()
        .own_station_result_client()?
        .context("actual member source absent")?;
    let source_session = source.session()?.clone();
    ensure!(
        source_session.account_id() == &bob_account
            && source_session.binding().service_id == bob_account.station_id,
        "ordinary current source is not bound to the actual new member's own Station Account"
    );
    let realm = create_realm_with_join_rule(
        &alice,
        "SinceJoin current Reaction",
        "invite",
        &[group.server(0), group.server(1)],
    )
    .await?;
    let realm_id = RealmId::new(realm.clone())?;
    let stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    let strand = alice.default_strand_id(&realm)?;
    let original = alice
        .author_event(
            &realm,
            EventKind::MessageCreate.as_str(),
            message_create_text_payload(&strand, ORIGINAL_BODY)?,
        )
        .await?;
    let message_commit =
        submit_and_expect_commit(&alice, &alice_account, &alice.device_id, &original).await?;
    let message_id = MessageId::from_event_id(&original.event_id);
    let target = message_id.to_string();
    let add=alice.author_event(&realm,EventKind::ReactionAdd.as_str(),json!({"target_ref":target,"key":KEY,"annotation":"old original annotation is not current metadata"})).await?;
    let add_commit =
        submit_and_expect_commit(&alice, &alice_account, &alice.device_id, &add).await?;
    let retained_add = wait_for_committed(&alice, &add.event_id).await?;
    ensure_same_commit(&add_commit, &retained_add)?;
    ensure!(
        retained_add
            .reducer_input()
            .is_some_and(|event| event == &add),
        "the authorized original author cannot read the actual retained old ADD"
    );

    let invite = alice
        .author_event(
            &realm,
            EventKind::InviteCreate.as_str(),
            invite_create_payload(
                &bob.actor,
                bob.service_id(),
                format!("sha256:{}", "c".repeat(64)),
                Utc::now() + ChronoDuration::days(7),
            )?,
        )
        .await?;
    submit_and_expect_commit(&alice, &alice_account, &alice.device_id, &invite).await?;
    let invite_id = InviteId::from_event_id(&invite.event_id);
    prepare_join(
        &bob,
        &realm,
        group.server(0),
        &format!(
            "ak:request:{}",
            crate::scenarios::mls_lifecycle_live::fresh_uuid_v7()
        ),
        RealmJoinIntent::InviteAccept {
            invite_id: invite_id.clone(),
        },
    )
    .await?;
    let accept = bob
        .author_event(
            &realm,
            EventKind::InviteAccept.as_str(),
            serde_json::to_value(InviteAcceptPayload::directed(
                invite_id,
                bob_account.clone(),
                InvitePreviousState::Pending,
            ))?,
        )
        .await?;
    let join_commit = submit_and_expect_commit(&bob, &bob_account, &bob.device_id, &accept).await?;
    ensure!(
        message_commit.stream_ref == stream
            && add_commit.stream_ref == stream
            && join_commit.stream_ref == stream
            && message_commit.stream_position < add_commit.stream_position
            && add_commit.stream_position < join_commit.stream_position,
        "old message/reaction were not actually accepted before the new member joined"
    );
    wait_for_committed(&bob, &accept.event_id).await?;
    wait_for_joined_row(&bob, &realm).await?;
    wait_for_titled_row(&bob, &realm, "SinceJoin current Reaction").await?;
    require_scan_floor(
        &bob,
        &realm_id,
        &join_commit,
        &[&original.event_id, &add.event_id],
    )
    .await?;
    let message_selector = CurrentSelector::MessageRevision { message_id };
    let reaction_selector = CurrentSelector::MessageReactions {
        target_ref: target.clone(),
    };
    let mut replica = OwnStationReplica::new(realm_id.clone());
    install_at(&bob, &mut replica, &realm_id, &join_commit).await?;
    let hidden = replica
        .snapshot()
        .context("joined current Snapshot absent")?;
    require_floor(hidden, &join_commit)?;
    let joined_snapshot_id = hidden.snapshot_id.clone();
    ensure!(
        row(hidden, &message_selector).is_none() && row(hidden, &reaction_selector).is_none(),
        "old reaction metadata disclosed its still invisible pre-join target"
    );
    require_old_original_refused(&bob, &original.event_id).await?;
    require_old_original_refused(&bob, &add.event_id).await?;

    let revised = alice
        .author_event(
            &realm,
            EventKind::MessageRevise.as_str(),
            crate::harness::message_revise_text_payload(original.event_id.as_str(), REVISED_BODY)?,
        )
        .await?;
    let revision_commit =
        submit_and_expect_commit(&alice, &alice_account, &alice.device_id, &revised).await?;
    ensure!(
        revision_commit.stream_ref == stream
            && revision_commit.stream_position > join_commit.stream_position,
        "the visible Message carrier was not a real post-join revision"
    );
    install_at(&bob, &mut replica, &realm_id, &revision_commit).await?;
    let visible = replica
        .snapshot()
        .context("revised current Snapshot absent")?;
    require_floor(visible, &join_commit)?;
    let visible_snapshot_id = visible.snapshot_id.clone();
    let (body_stream, body_revision, body) =
        row(visible, &message_selector).context("post-join current body absent")?;
    ensure!(
        body_stream == &stream
            && body_revision.commit_id == revision_commit.commit_id
            && body_revision.stream_position == revision_commit.stream_position
            && body == &serde_json::to_value(&revised.payload)?,
        "current Message body does not come from the actual accepted revision"
    );
    ensure!(
        body["content"]["body"] == REVISED_BODY,
        "current body contains the wrong plaintext revision"
    );
    let (reaction_stream, reaction_revision, value) = row(visible, &reaction_selector)
        .context("active pre-join Reaction current absent after target becomes visible")?;
    let active: MessageReactionsCurrentValue = serde_json::from_value(value.clone())?;
    let alice_actor = ActorId::account(alice_account.clone());
    ensure!(
        reaction_stream == &stream
            && reaction_revision.commit_id == add_commit.commit_id
            && reaction_revision.stream_position == add_commit.stream_position
            && active.entries().len() == 1
            && active.entries()[0].actor_id == alice_actor
            && active.entries()[0].key == KEY
            && active.entries()[0].source == committed_ref(&add, &add_commit),
        "current Reaction changed its original active actor/key/source or manufactured a newer source"
    );
    let count = active
        .entries()
        .iter()
        .filter(|entry| entry.key == KEY)
        .count();
    ensure!(
        count == 1,
        "active metadata cannot supply the current per-key member count"
    );
    ensure!(
        value["entries"]
            .as_array()
            .context("active current entries absent")?
            .iter()
            .all(|entry| entry.get("annotation").is_none()
                && entry.get("encrypted_payload").is_none()),
        "current metadata copied below-floor original-only fields"
    );
    let accepted_active_metadata = serde_json::to_value(&active)?;
    require_joined_roster(
        visible,
        &[alice_actor, ActorId::account(bob_account.clone())],
    )?;
    bob.sdk()
        .own_station_result_client()?
        .context("current source absent")?
        .check_session()?;
    require_old_original_refused(&bob, &original.event_id).await?;
    require_old_original_refused(&bob, &add.event_id).await?;
    require_scan_floor(
        &bob,
        &realm_id,
        &join_commit,
        &[&original.event_id, &add.event_id],
    )
    .await?;

    let remove = alice
        .author_event(
            &realm,
            EventKind::ReactionRemove.as_str(),
            json!({"target_ref":target,"key":KEY}),
        )
        .await?;
    let remove_commit =
        submit_and_expect_commit(&alice, &alice_account, &alice.device_id, &remove).await?;
    install_at(&bob, &mut replica, &realm_id, &remove_commit).await?;
    let cleared = replica
        .snapshot()
        .context("removed current Snapshot absent")?;
    require_floor(cleared, &join_commit)?;
    let removed_snapshot_id = cleared.snapshot_id.clone();
    let (_, revision, value) =
        row(cleared, &reaction_selector).context("empty Reaction row lost its revision")?;
    let empty: MessageReactionsCurrentValue = serde_json::from_value(value.clone())?;
    ensure!(
        empty.entries().is_empty()
            && revision.commit_id == remove_commit.commit_id
            && revision.stream_position == remove_commit.stream_position,
        "REMOVE left a tombstone entry or lost its actual empty-row revision"
    );
    require_old_original_refused(&bob, &add.event_id).await?;

    let redact = alice
        .author_event(
            &realm,
            EventKind::MessageRedact.as_str(),
            crate::harness::message_redact_payload(
                original.event_id.as_str(),
                Some("M07 current disclosure closes with its target"),
            )?,
        )
        .await?;
    let redact_commit =
        submit_and_expect_commit(&alice, &alice_account, &alice.device_id, &redact).await?;
    install_at(&bob, &mut replica, &realm_id, &redact_commit).await?;
    let redacted = replica
        .snapshot()
        .context("redacted current Snapshot absent")?;
    require_floor(redacted, &join_commit)?;
    let redacted_snapshot_id = redacted.snapshot_id.clone();
    ensure!(
        row(redacted, &message_selector).is_none() && row(redacted, &reaction_selector).is_none(),
        "redacted target left its body or Reaction current visible"
    );
    require_old_original_refused(&bob, &add.event_id).await?;
    for commit in [
        &message_commit,
        &add_commit,
        &join_commit,
        &revision_commit,
        &remove_commit,
        &redact_commit,
    ] {
        ensure_commit_signed_by(commit, group.server(0))?;
    }
    source.check_session()?;
    ensure!(
        source.session()? == &source_session,
        "ordinary current source changed its captured issuer/holder context"
    );
    eprintln!(
        "[since-join-reaction-current] {}",
        json!({"source":"two owned Stations with independent PostgreSQL; original bound whole current Snapshots","account":bob_account,"grant_ref":source_session.grant_ref(),"snapshot_ids":{"joined":joined_snapshot_id,"visible":visible_snapshot_id,"removed":removed_snapshot_id,"redacted":redacted_snapshot_id},"active_metadata":accepted_active_metadata,"message":message_commit,"reaction_add":add_commit,"join":join_commit,"message_revision":revision_commit,"reaction_remove":remove_commit,"redaction":redact_commit,"key_count_from_current":count,"joined_members_from_current":2,"old_original_get":"404/not_found before and after current disclosure","history_floor_unchanged":true})
    );
    Ok(())
}
