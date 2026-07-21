//! Soland `ak.self.account.stream.subscribe` long-poll + realms-incremental coverage.
//!
//! Pins the two behaviors that landed in `routing::events::sync`:
//!
//! 1. Incremental syncs hold on `event_broadcast` until something interesting happens.
//! 2. Incremental delta frames omit realms whose timeline position and `realm_meta.updated_at` are
//!    both unchanged since the cursor was issued. The realm's baseline
//!    (`summary`/`strands`/`state_after`/ `members`) is no longer re-sent on every quiet poll.

use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use base64::Engine as _;
use chrono::Duration as ChronoDuration;
use reqwest::StatusCode;
use serde_json::Value;

use crate::fixtures::TestActorBuilder;
use crate::harness::{
    TestServerGroup, eventually, expect_account_subscribe_delta,
    expect_account_subscribe_realm_delta, invite_create_payload,
    member_join_payload_with_invite_ref, message_create_text_payload,
};

const QUIET_LONG_POLL_TEST_DEADLINE: Duration = Duration::from_secs(45);

pub async fn account_subscribe_omits_quiet_realm_at_unchanged_cursor() -> Result<()> {
    let group = TestServerGroup::single("account-subscribe-quiet-realm").await?;
    let server = group.server(0);
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let realm_id = alice.create_realm("Quiet Incremental Realm").await?;
    alice
        .send_message(&realm_id, "ak:thread:quiet-realm", "baseline message")
        .await?;

    let baseline = fetch_account_subscribe(&alice, "catchup=true").await?;
    assert!(
        baseline["realms"][&realm_id].is_object(),
        "full sync MUST include the realm baseline: {baseline}"
    );
    let cursor = baseline["cursor"]
        .as_str()
        .ok_or_else(|| anyhow!("baseline sync missing cursor: {baseline}"))?
        .to_owned();

    let quiet = tokio::time::timeout(
        QUIET_LONG_POLL_TEST_DEADLINE,
        fetch_account_subscribe_frontier(&alice, &format!("catchup=true&after={cursor}")),
    )
    .await
    .map_err(|_| anyhow!("quiet incremental subscribe exceeded its controlled deadline"))??;

    let quiet_cursor = quiet["cursor"]
        .as_str()
        .ok_or_else(|| anyhow!("quiet incremental response missing cursor: {quiet}"))?;
    assert_eq!(
        cursor_frontier_handle(quiet_cursor)?,
        cursor_frontier_handle(&cursor)?,
        "an empty incremental response MUST preserve the cursor frontier: {quiet}"
    );
    assert_eq!(
        quiet["kind"], "frontier",
        "quiet poll must end with frontier"
    );
    assert!(
        quiet.get("realms").is_none_or(Value::is_null),
        "frontier MUST omit every quiet realm, including {realm_id}: {quiet}"
    );

    Ok(())
}

fn cursor_frontier_handle(cursor: &str) -> Result<String> {
    let encoded = cursor
        .strip_prefix("ak:cursor:")
        .ok_or_else(|| anyhow!("account subscribe cursor has the wrong prefix"))?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded)?;
    let payload: Value = serde_json::from_slice(&bytes)?;
    payload["h"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("account subscribe cursor missing frontier handle: {payload}"))
}

pub async fn account_subscribe_long_poll_wakes_on_visible_event() -> Result<()> {
    let group = TestServerGroup::single("account-subscribe-long-poll").await?;
    let server = group.server(0);
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let realm_id = alice.create_realm("Long-Poll Recovery Realm").await?;
    alice
        .send_message(&realm_id, "ak:thread:long-poll", "baseline message")
        .await?;

    // Full sync establishes the baseline + a cursor the rest of the
    // scenario re-uses. After this point the realm is "quiet" — every
    // subsequent assertion drives the delta-empty path.
    let baseline = fetch_account_subscribe(&alice, "catchup=true").await?;
    let baseline_realm = baseline["realms"][&realm_id].clone();
    assert!(
        baseline_realm.is_object(),
        "full sync MUST include the realm baseline: {baseline}"
    );
    let cursor = baseline["cursor"]
        .as_str()
        .ok_or_else(|| anyhow!("baseline sync missing cursor: {baseline}"))?
        .to_owned();

    // A real timeline event must wake the long-poll — fire a
    //     concurrent send and verify the incremental subscribe returns
    //     well inside the deadline with the new realm baseline + event.
    let alice_for_wake = alice.clone();
    let realm_id_for_wake = realm_id.clone();
    let waker = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        alice_for_wake
            .send_message(&realm_id_for_wake, "ak:thread:long-poll", "wake the poll")
            .await
    });

    let wake_start = Instant::now();
    let woken = expect_account_subscribe_realm_delta(
        alice
            .get(&format!(
                "/_arkret/self/account/subscribe?catchup=true&after={cursor}"
            ))
            .header("accept", "application/x-ndjson"),
        StatusCode::OK,
    )
    .await?;
    let wake_elapsed = wake_start.elapsed();
    let sent_event = waker.await.expect("waker task did not panic")?;
    let sent_event_id = submitted_event_id(&sent_event)
        .ok_or_else(|| anyhow!("send response missing event_id: {sent_event}"))?;

    assert!(
        wake_elapsed < Duration::from_secs(3),
        "broadcast should wake long-poll well before its deadline (got {wake_elapsed:?})"
    );
    let timeline_events = woken["realms"][&realm_id]["timeline"]["events"]
        .as_array()
        .ok_or_else(|| anyhow!("woken delta missing realm timeline: {woken}"))?;
    assert!(
        timeline_events
            .iter()
            .any(|event| event["event_id"] == sent_event_id),
        "woken delta MUST include the wake-up event: {woken}"
    );

    Ok(())
}

pub async fn invited_members_exchange_post_join_messages_over_account_subscribe() -> Result<()> {
    let group = TestServerGroup::single("account-subscribe-invite-two-way").await?;
    let server = group.server(0);
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let bob = TestActorBuilder::new(server, "@bob-sync")
        .with_did("did:web:bob-sync.example")
        .with_device("ak:device:01904100-0000-7000-8000-0000000000b1")
        .create()
        .await?;
    let bob_client = bob.client();

    let created = alice
        .create_realm_with(serde_json::json!({
            "title": "Joined History Sync Realm",
            "summary": "Joined History Sync Realm",
            "public": false,
            "history_visibility": "joined",
            "plaintext_visible_services": [alice.service_id().to_owned()]
        }))
        .await?;
    let realm_id = created["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow!("create realm response missing realm_id: {created}"))?
        .to_owned();

    let pre_join = alice
        .send_message(
            &realm_id,
            "ak:thread:joined-history",
            "alice before bob joined",
        )
        .await?;
    let pre_join_event_id = submitted_event_id(&pre_join)
        .ok_or_else(|| anyhow!("pre-join send response missing event_id: {pre_join}"))?
        .to_owned();
    let invite_id = create_invite_now(&alice, &realm_id, bob_client).await?;
    eventually(
        "Bob sees pending invite before joining",
        Duration::from_secs(5),
        Duration::from_millis(100),
        || {
            let invite_id = invite_id.clone();
            let realm_id = realm_id.clone();
            async move {
                let invites = bob_client
                    .sdk()
                    .authz_invites(&bob_client.actor, Some(&realm_id), None)
                    .await?;
                if invites
                    .invites
                    .iter()
                    .any(|invite| invite.id.to_string() == invite_id)
                {
                    Ok(())
                } else {
                    Err(anyhow!("Bob pending invites missing {invite_id}"))
                }
            }
        },
    )
    .await?;
    accept_invite_join_now(bob_client, &realm_id, &invite_id).await?;
    tokio::time::sleep(Duration::from_millis(20)).await;

    let bob_baseline = eventually(
        "Bob joined-history baseline",
        Duration::from_secs(5),
        Duration::from_millis(100),
        || async {
            let sync = bob_client.sync().await?;
            if sync["realms"][&realm_id].is_object() {
                Ok(sync)
            } else {
                Err(anyhow!("Bob baseline missing joined realm: {sync}"))
            }
        },
    )
    .await?;
    let bob_baseline_events = timeline_events(&bob_baseline, &realm_id)?;
    assert!(
        !bob_baseline_events
            .iter()
            .any(|event| event["event_id"] == pre_join_event_id),
        "joined-history invitee MUST NOT receive pre-join timeline events: {bob_baseline}"
    );
    eventually(
        "accepted invite is hidden after Bob joins",
        Duration::from_secs(5),
        Duration::from_millis(100),
        || {
            let realm_id = realm_id.clone();
            let invite_id = invite_id.clone();
            let alice = alice.clone();
            async move {
                let bob_invites = bob_client
                    .sdk()
                    .authz_invites(&bob_client.actor, Some(&realm_id), None)
                    .await?;
                let alice_view = alice
                    .sdk()
                    .authz_invites(&bob_client.actor, Some(&realm_id), None)
                    .await?;
                if bob_invites.invites.is_empty() && alice_view.invites.is_empty() {
                    Ok(())
                } else {
                    Err(anyhow!(
                        "accepted invite {invite_id} still visible: bob={}, alice={}",
                        serde_json::to_string(&bob_invites.invites)?,
                        serde_json::to_string(&alice_view.invites)?
                    ))
                }
            }
        },
    )
    .await?;
    let bob_cursor = cursor_from_sync(&bob_baseline)?;

    let alice_after_join = send_message_now(
        &alice,
        &realm_id,
        "ak:thread:joined-history",
        "alice after bob joined",
    )
    .await?;
    let alice_after_join_event_id = submitted_event_id(&alice_after_join)
        .ok_or_else(|| {
            anyhow!("post-join Alice send response missing event_id: {alice_after_join}")
        })?
        .to_owned();
    let bob_incremental = eventually(
        "Bob sees Alice post-join message",
        Duration::from_secs(5),
        Duration::from_millis(100),
        || {
            let bob_cursor = bob_cursor.clone();
            let alice_after_join_event_id = alice_after_join_event_id.clone();
            let realm_id = realm_id.clone();
            async move {
                let sync = fetch_account_subscribe(
                    bob_client,
                    &format!("catchup=true&after={bob_cursor}"),
                )
                .await?;
                let events = timeline_events(&sync, &realm_id)?;
                if events
                    .iter()
                    .any(|event| event["event_id"] == alice_after_join_event_id)
                {
                    Ok(sync)
                } else {
                    Err(anyhow!("Bob incremental missing Alice event: {sync}"))
                }
            }
        },
    )
    .await?;
    let alice_cursor = cursor_from_sync(&alice.sync().await?)?;

    let bob_after_join = send_message_now(
        bob_client,
        &realm_id,
        "ak:thread:joined-history",
        "bob after joining",
    )
    .await?;
    let bob_after_join_event_id = submitted_event_id(&bob_after_join)
        .ok_or_else(|| anyhow!("post-join Bob send response missing event_id: {bob_after_join}"))?
        .to_owned();
    eventually(
        "Alice sees Bob post-join message",
        Duration::from_secs(5),
        Duration::from_millis(100),
        || {
            let alice_cursor = alice_cursor.clone();
            let bob_after_join_event_id = bob_after_join_event_id.clone();
            let realm_id = realm_id.clone();
            let alice = alice.clone();
            async move {
                let sync =
                    fetch_account_subscribe(&alice, &format!("catchup=true&after={alice_cursor}"))
                        .await?;
                let events = timeline_events(&sync, &realm_id)?;
                if events
                    .iter()
                    .any(|event| event["event_id"] == bob_after_join_event_id)
                {
                    Ok(sync)
                } else {
                    Err(anyhow!("Alice incremental missing Bob event: {sync}"))
                }
            }
        },
    )
    .await?;

    let bob_incremental_events = timeline_events(&bob_incremental, &realm_id)?;
    assert!(
        bob_incremental_events
            .iter()
            .any(|event| event["event_id"] == alice_after_join_event_id),
        "Bob incremental should retain Alice post-join event: {bob_incremental}"
    );

    Ok(())
}

pub async fn cancelled_pending_invite_disappears_from_invite_views() -> Result<()> {
    let group = TestServerGroup::single("account-subscribe-invite-cancel").await?;
    let server = group.server(0);
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let bob = TestActorBuilder::new(server, "@bob-cancel")
        .with_did("did:web:bob-cancel.example")
        .with_device("ak:device:01904100-0000-7000-8000-0000000000b2")
        .create()
        .await?;
    let bob_client = bob.client();
    let realm_id = alice.create_realm("Cancelled Invite Realm").await?;
    let invite_id = create_invite_now(&alice, &realm_id, bob_client).await?;

    eventually(
        "Bob sees pending invite before cancellation",
        Duration::from_secs(5),
        Duration::from_millis(100),
        || {
            let invite_id = invite_id.clone();
            let realm_id = realm_id.clone();
            async move {
                let invites = bob_client
                    .sdk()
                    .authz_invites(&bob_client.actor, Some(&realm_id), None)
                    .await?;
                if invites
                    .invites
                    .iter()
                    .any(|invite| invite.id.to_string() == invite_id)
                {
                    Ok(())
                } else {
                    Err(anyhow!("Bob pending invites missing {invite_id}"))
                }
            }
        },
    )
    .await?;

    cancel_invite_now(&alice, &realm_id, &invite_id).await?;

    eventually(
        "cancelled invite is hidden from invite listings",
        Duration::from_secs(5),
        Duration::from_millis(100),
        || {
            let realm_id = realm_id.clone();
            let invite_id = invite_id.clone();
            let alice = alice.clone();
            async move {
                let bob_invites = bob_client
                    .sdk()
                    .authz_invites(&bob_client.actor, Some(&realm_id), None)
                    .await?;
                let alice_view = alice
                    .sdk()
                    .authz_invites(&bob_client.actor, Some(&realm_id), None)
                    .await?;
                if bob_invites.invites.is_empty() && alice_view.invites.is_empty() {
                    Ok(())
                } else {
                    Err(anyhow!(
                        "cancelled invite {invite_id} still visible: bob={}, alice={}",
                        serde_json::to_string(&bob_invites.invites)?,
                        serde_json::to_string(&alice_view.invites)?
                    ))
                }
            }
        },
    )
    .await?;

    Ok(())
}

fn submitted_event_id(response: &Value) -> Option<&str> {
    response
        .get("event_id")
        .and_then(Value::as_str)
        .or_else(|| {
            response
                .get("accepted")
                .and_then(Value::as_array)
                .and_then(|accepted| accepted.first())
                .and_then(Value::as_str)
        })
}

async fn fetch_account_subscribe(
    actor: &crate::harness::TestActorClient,
    query: &str,
) -> Result<Value> {
    expect_account_subscribe_delta(
        actor
            .get(&format!("/_arkret/self/account/subscribe?{query}"))
            .header("accept", "application/x-ndjson"),
        StatusCode::OK,
    )
    .await
}

async fn fetch_account_subscribe_frontier(
    actor: &crate::harness::TestActorClient,
    query: &str,
) -> Result<Value> {
    let response = actor
        .get(&format!("/_arkret/self/account/subscribe?{query}"))
        .header("accept", "application/x-ndjson")
        .send()
        .await?;
    if response.status() != StatusCode::OK {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!(
            "expected quiet subscribe HTTP 200, got {status}: {body}"
        ));
    }
    let body = response.text().await?;
    for line in body.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let frame: Value = serde_json::from_str(line)?;
        if frame.get("kind").and_then(Value::as_str) == Some("frontier") {
            return Ok(frame);
        }
    }
    Err(anyhow!(
        "quiet account subscribe ended without a frontier frame: {body}"
    ))
}

fn cursor_from_sync(sync: &Value) -> Result<String> {
    sync["cursor"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("sync response missing cursor: {sync}"))
}

fn timeline_events<'a>(sync: &'a Value, realm_id: &str) -> Result<&'a Vec<Value>> {
    sync["realms"][realm_id]["timeline"]["events"]
        .as_array()
        .ok_or_else(|| anyhow!("sync response missing realm timeline events: {sync}"))
}

async fn send_message_now(
    actor: &crate::harness::TestActorClient,
    realm_id: &str,
    _thread_id: &str,
    body: &str,
) -> Result<Value> {
    submit_event_now(
        actor,
        realm_id,
        "ak.message.create",
        message_create_text_payload(realm_id, body)?,
    )
    .await
}

async fn create_invite_now(
    inviter: &crate::harness::TestActorClient,
    realm_id: &str,
    invitee: &crate::harness::TestActorClient,
) -> Result<String> {
    let invite_id = "ak:invite:01999999-0000-7000-8000-00000000b0b1".to_owned();
    let expires_at = chrono::Utc::now() + ChronoDuration::days(7);
    submit_event_now(
        inviter,
        realm_id,
        "ak.invite.create",
        invite_create_payload(
            &invite_id,
            invitee.actor.as_str(),
            invitee.service_id(),
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            expires_at,
        )?,
    )
    .await?;
    Ok(invite_id)
}

async fn accept_invite_join_now(
    invitee: &crate::harness::TestActorClient,
    realm_id: &str,
    invite_id: &str,
) -> Result<Value> {
    submit_event_now(
        invitee,
        realm_id,
        "ak.member.state",
        member_join_payload_with_invite_ref(realm_id, invitee.actor.as_str(), invite_id)?,
    )
    .await
}

async fn cancel_invite_now(
    inviter: &crate::harness::TestActorClient,
    realm_id: &str,
    invite_id: &str,
) -> Result<Value> {
    submit_event_now(
        inviter,
        realm_id,
        "ak.invite.cancel",
        serde_json::json!({
            "invite_id": invite_id,
            "reason": "admin_cancel",
        }),
    )
    .await
}

async fn submit_event_now(
    actor: &crate::harness::TestActorClient,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Result<Value> {
    let frontier = crate::harness::expect_json(
        actor.get(&format!(
            "/_arkret/self/events/frontier?actor_id={}&realm_id={realm_id}",
            actor.actor
        )),
        StatusCode::OK,
    )
    .await?;
    let accepted_seq = frontier["frontier"]["actor_seq"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("actor Realm frontier missing actor_seq: {frontier}"))?;
    let prev_event_id = frontier["frontier"]["event_id"].as_str();
    if (accepted_seq == 0) != prev_event_id.is_none() {
        return Err(anyhow::anyhow!(
            "actor Realm frontier must pair sequence and Event id: {frontier}"
        ));
    }
    let created_at = arkret_core::canonical::format_timestamp_canonical(chrono::Utc::now());
    let mut event = crate::harness::event_envelope_with_chain(
        &actor.actor,
        realm_id,
        kind,
        payload,
        accepted_seq + 1,
        prev_event_id,
    );
    event["created_at"] = Value::String(created_at.clone());
    if let Some(proof) = event
        .get_mut("proofs")
        .and_then(Value::as_array_mut)
        .and_then(|proofs| proofs.first_mut())
    {
        proof["created_at"] = Value::String(created_at);
    }
    crate::harness::refresh_event_proof(&mut event)?;
    let mut response = crate::harness::expect_json(
        actor.post("/_arkret/self/events").json(&event),
        StatusCode::OK,
    )
    .await?;
    if response.get("event_id").and_then(Value::as_str).is_none()
        && let Some(event_id) = event.get("event_id").and_then(Value::as_str)
        && let Some(object) = response.as_object_mut()
    {
        object.insert("event_id".to_owned(), Value::String(event_id.to_owned()));
    }
    Ok(response)
}
