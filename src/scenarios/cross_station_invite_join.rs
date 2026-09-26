//! S4 — a Station Y Account joins a Station X Realm by accepting its directed
//! Invite, and then writes into it (`zh/sync/federation.md` §3–§4.1.1,
//! `zh/sync/authority-commit-log.md` §4, `zh/authz/offline-publication.md` §3).
//!
//! Against two live Solands with separate PostgreSQL databases:
//!
//! 1. Alice on X creates an invite-only Realm and invites Bob, whose Account lives on Y; Bob's
//!    realm list on Y does not name the Realm.
//! 2. Bob prepares his accept on Y, which verifies X as the Realm's current authority.
//! 3. While X is down, Bob's accept submitted to Y is `temporarily_unavailable`: Y reports no
//!    Commit, holds no committed Event and lists no Realm, since it has no RealmCommit.
//! 4. With X back, the exact same accept is forwarded to X and committed under X's signature; X
//!    replicates the committed accept to Y, where it opens Y's held Realm stream with the exact
//!    source Commit; the membership current Y derives from it lists the Realm as joined in Bob's
//!    realm list on Y.
//! 5. Y anchors its held stream on X's bootstrap snapshot (`federation.md` §4.1.1, member Station
//!    bootstrap): Bob's own scan on Y is served from his accept Commit (`membership_join`), and his
//!    realm list on Y carries the Realm title from the installed typed current.
//! 6. Joining grants no writing: Bob's Message is refused by X and relayed by Y. After Alice's
//!    grant, Bob's Message submitted to Y is committed by X, Alice's scan on X returns it in full,
//!    and X replicates it back to Y.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use arkret_models_collaboration::governance::membership_invite::{
    InviteAcceptPayload, InvitePreviousState,
};
use arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent;
use arkret_models_collaboration::sync_frames::demand_sync::RealmListMembership;
use arkret_wire::{
    ActorId, CommitStreamRef, EventKind, InviteId, ReadableFloorReason, RealmId,
    StreamScanDirection, StreamScanOutcome, StreamScanRequest,
};
use chrono::{Duration as ChronoDuration, Utc};
use reqwest::StatusCode;
use serde_json::Value;

use crate::harness::{
    CanonicalJsonBody, TestActorClient, TestServerGroup, invite_create_payload,
    message_create_text_payload, submitted_event_id,
};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, ensure_commit_signed_by, ensure_never_committed,
    ensure_same_commit, grant_message_create, prepare_join, standard_client, station_env,
    submit_and_expect_commit, wait_for_committed,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use crate::scenarios::protocol_payloads::account_summary::{account_frames, listed_row};

const GROUP: &str = "cross-station-invite-join";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002401";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002402";
const TITLE: &str = "Cross-Station invite";

/// Submit `event` through Bob's own Station and return the raw answer.
async fn submit_raw(
    client: &TestActorClient,
    event: &arkret_wire::Event,
) -> Result<(StatusCode, Value)> {
    let response = client
        .post("/_arkret/self/events")
        .canonical_json(&crate::publication::initial_submission(event.clone(), "")?)?
        .send()
        .await?;
    let status = response.status();
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    Ok((status, body))
}

async fn local_event_row(
    database_url: &str,
    event_id: &str,
) -> Result<(i64, String, Vec<u8>, Value)> {
    let database_url = database_url.to_owned();
    let event_id = event_id.to_owned();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut db = postgres::Client::connect(&database_url, postgres::NoTls)?;
        let rows = db
            .query(
                "SELECT pk, state, canonical_bytes, envelope::text FROM canonical_events \
                 WHERE envelope->>'event_id'=$1",
                &[&event_id],
            )
            .context("find the forwarded Event's local rows")?;
        ensure!(
            rows.len() == 1,
            "forwarded Event must have exactly one local row"
        );
        let row = &rows[0];
        Ok((
            row.get(0),
            row.get(1),
            row.get(2),
            serde_json::from_str::<Value>(&row.get::<_, String>(3))?,
        ))
    })
    .await?
}

fn problem_is(body: &Value, code: &str) -> bool {
    body["type"]
        .as_str()
        .is_some_and(|kind| kind.ends_with(&format!("/{code}")))
}

/// Poll Bob's realm list on his own Station until it names `realm_id` as
/// joined.
async fn wait_for_joined_row(client: &TestActorClient, realm_id: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let frames = account_frames(client, None).await?;
        if let Ok(row) = listed_row(&frames, realm_id) {
            ensure!(
                row.membership == RealmListMembership::Join,
                "Bob's realm list names the Realm with another membership: {row:?}"
            );
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("Bob's realm list on his Station never named the joined Realm");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Poll Bob's own Realm stream scan on his Station until the held stream is
/// anchored and served, and return that first page.
pub(crate) async fn wait_for_member_scan(
    client: &TestActorClient,
    realm_id: &RealmId,
) -> Result<StreamScanOutcome> {
    let request = StreamScanRequest {
        realm_id: realm_id.clone(),
        stream_ref: CommitStreamRef::Realm {
            realm_id: realm_id.clone(),
        },
        direction: StreamScanDirection::After(None),
        limit: 50,
    };
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match client.sdk().scan_commit_stream(&request).await {
            Ok(page) => return Ok(page),
            Err(error) if Instant::now() >= deadline => {
                bail!("Bob's scan on his Station was never served: {error}");
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }
}

/// Poll Bob's realm list on his Station until the Realm's row carries
/// `title`.
pub(crate) async fn wait_for_titled_row(
    client: &TestActorClient,
    realm_id: &str,
    title: &str,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let frames = account_frames(client, None).await?;
        if let Ok(row) = listed_row(&frames, realm_id)
            && row.title.as_deref() == Some(title)
        {
            ensure!(
                row.membership == RealmListMembership::Join,
                "Bob's titled realm row names another membership: {row:?}"
            );
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("Bob's realm list on his Station never carried the Realm title");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

pub async fn cross_station_invite_join_run() -> Result<()> {
    let Some(governance_database) = database(GROUP)? else {
        return Ok(());
    };
    let Some(member_database) = database(GROUP)? else {
        return Ok(());
    };
    ensure!(
        governance_database.connect_url != member_database.connect_url,
        "the governance and member Stations must use separate databases"
    );
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(mut group) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[
            station_env(&governance_database.connect_url, &coauth),
            station_env(&member_database.connect_url, &coauth),
        ],
    )
    .await?
    else {
        return skip_or_fail(GROUP, "prebuilt Soland unavailable");
    };

    // (1) Alice's invite-only Realm on X and her directed Invite to Bob on Y.
    let (alice, _) =
        standard_client(group.server(0), &coauth, "xinvite-alice", ALICE_DEVICE).await?;
    let (bob, bob_account) =
        standard_client(group.server(1), &coauth, "xinvite-bob", BOB_DEVICE).await?;
    let realm =
        create_realm_with_join_rule(&alice, TITLE, "invite", &[group.server(0), group.server(1)])
            .await?;
    let realm_id = RealmId::new(realm.clone())?;
    let strand_id = alice.default_strand_id(&realm)?;
    let created = alice
        .submit_event(
            &realm,
            EventKind::InviteCreate.as_str(),
            invite_create_payload(
                &bob.actor,
                bob.service_id(),
                format!("sha256:{}", "d".repeat(64)),
                Utc::now() + ChronoDuration::days(7),
            )?,
        )
        .await
        .context("commit the directed Invite to Bob's Station Y Account")?;
    let invite_id = InviteId::from_event_id(&submitted_event_id(&created)?);
    ensure!(
        listed_row(&account_frames(&bob, None).await?, &realm).is_err(),
        "an invited Account is not listed as a member on its own Station"
    );

    // (2) Bob prepares on Y: X is verified as the Realm's current authority.
    prepare_join(
        &bob,
        &realm,
        group.server(0),
        "ak:request:019b0000-0000-7000-8000-000000002403",
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
                invite_id.clone(),
                bob_account.clone(),
                InvitePreviousState::Pending,
            ))?,
        )
        .await?;

    // (3) Without X, Y has no RealmCommit to report.
    group.server_mut(0).stop_external_process().await?;
    let (status, body) = submit_raw(&bob, &accept).await?;
    ensure!(
        !status.is_success() && problem_is(&body, "temporarily_unavailable"),
        "Y answered the accept without its governance Station: {status} {body}"
    );
    let queued = local_event_row(&member_database.connect_url, accept.event_id.as_str()).await?;
    ensure!(
        queued.1 == "queued",
        "Y did not retain the forwarded Event as queued"
    );
    ensure!(
        queued.2 == arkret_canonical::canonical_json_bytes(&accept.digest_payload()?)?,
        "Y changed the producer-signed canonical Event bytes"
    );
    ensure!(
        queued.3 == serde_json::to_value(&accept)?,
        "Y changed the exact producer proof or Event envelope"
    );
    ensure!(
        bob.sdk()
            .committed_event_get(&accept.event_id)
            .await
            .is_err(),
        "Y holds the accept as committed without a RealmCommit"
    );
    ensure!(
        listed_row(&account_frames(&bob, None).await?, &realm).is_err(),
        "Y lists the Realm before the accept is committed"
    );
    group.server_mut(0).start_external_process().await?;

    // (4) The exact same accept, forwarded to X, is committed under X's
    //     signature and replicated back to Y.
    let accept_commit = submit_and_expect_commit(&bob, &bob_account, BOB_DEVICE, &accept).await?;
    ensure_commit_signed_by(&accept_commit, group.server(0))?;
    ensure_same_commit(
        &accept_commit,
        &wait_for_committed(&alice, &accept.event_id).await?,
    )?;
    ensure_same_commit(
        &accept_commit,
        &wait_for_committed(&bob, &accept.event_id).await?,
    )?;
    let committed = local_event_row(&member_database.connect_url, accept.event_id.as_str()).await?;
    ensure!(
        committed.0 == queued.0
            && committed.1 == "committed"
            && committed.2 == queued.2
            && committed.3 == queued.3,
        "Y did not upgrade the same exact queued Event row on replica arrival"
    );
    wait_for_joined_row(&bob, &realm).await?;

    // (5) Y anchors its held stream: Bob's own scan starts at his accept.
    let page = wait_for_member_scan(&bob, &realm_id).await?;
    let floor = page
        .readable_floor
        .as_ref()
        .context("Bob's scan on Y names no readable floor")?;
    ensure!(
        floor.oldest_position == accept_commit.stream_position
            && floor.floor_commit_id == accept_commit.commit_id
            && floor.floor_reason == ReadableFloorReason::MembershipJoin,
        "Bob's scan on Y does not start at his accept Commit: {floor:?}"
    );
    ensure!(
        page.committed_events
            .first()
            .is_some_and(|item| item.commit() == &accept_commit),
        "Bob's scan on Y does not begin with his accept"
    );
    wait_for_titled_row(&bob, &realm, TITLE).await?;

    // (6) Joining grants no writing; X refuses and Y relays the refusal.
    let early = bob
        .author_event(
            &realm,
            EventKind::MessageCreate.as_str(),
            message_create_text_payload(&strand_id, "before the grant")?,
        )
        .await?;
    let (status, body) = submit_raw(&bob, &early).await?;
    ensure!(
        status == StatusCode::FORBIDDEN && problem_is(&body, "capability_denied"),
        "a member without ak.message.create is refused: {status} {body}"
    );
    ensure_never_committed(&alice, &early.event_id, Duration::from_secs(2)).await?;

    grant_message_create(&alice, group.server(0), &realm, &bob_account).await?;
    let message = bob
        .author_event(
            &realm,
            EventKind::MessageCreate.as_str(),
            message_create_text_payload(&strand_id, "hello from Station Y")?,
        )
        .await?;
    let message_commit = submit_and_expect_commit(&bob, &bob_account, BOB_DEVICE, &message).await?;
    ensure_commit_signed_by(&message_commit, group.server(0))?;
    let bob_actor = ActorId::account(bob_account.clone());
    let scanned = alice
        .sdk()
        .scan_commit_stream_to_head(
            realm_id.clone(),
            CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            None,
            200,
        )
        .await?;
    ensure!(
        scanned.committed_events.iter().any(|item| {
            item.reducer_input().is_some_and(|event| {
                event.event_id == message.event_id && event.actor_id == bob_actor
            })
        }),
        "Alice's scan on X does not return Bob's Message in full"
    );
    ensure_same_commit(
        &message_commit,
        &wait_for_committed(&bob, &message.event_id).await?,
    )?;
    drop(coauth);
    Ok(())
}
