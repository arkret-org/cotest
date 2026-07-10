//! Soland `ak.self.account.stream.subscribe` long-poll + realms-incremental coverage.
//!
//! Pins the two behaviors that landed in `routing::events::sync`:
//!
//! 1. Incremental syncs hold on `event_broadcast` until something interesting happens or
//!    `max_wait_ms` elapses — clients that send `?max_wait_ms=0` keep the legacy immediate-return
//!    semantics.
//! 2. Incremental delta frames omit realms whose timeline position and `realm_meta.updated_at` are
//!    both unchanged since the cursor was issued. The realm's baseline
//!    (`summary`/`strands`/`state_after`/ `members`) is no longer re-sent on every quiet poll.

use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use chrono::{Duration as ChronoDuration, SecondsFormat};
use reqwest::StatusCode;
use reqwest::header::CONTENT_TYPE;
use serde_json::Value;

use crate::fixtures::TestActorBuilder;
use crate::harness::{
    TestServerGroup, eventually, expect_response, invite_create_payload,
    member_join_payload_with_invite_ref, message_create_text_payload,
};

const QUIET_RESPONSE_BYTES_CEILING: usize = 768;

pub async fn account_subscribe_skips_quiet_realms_and_long_polls() -> Result<()> {
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

    let (json_quiet, json_content_type) = fetch_account_subscribe_json(
        &alice,
        &format!("catchup=true&max_wait_ms=0&after={cursor}"),
    )
    .await?;
    assert!(
        json_content_type.contains("application/json"),
        "JSON subscribe should negotiate application/json, got {json_content_type:?}"
    );
    assert!(
        json_quiet.get("kind").is_none(),
        "JSON subscribe returns a SyncOutcome body, not an NDJSON frame wrapper: {json_quiet}"
    );
    assert!(
        json_quiet
            .get("realms")
            .is_none_or(|realms| realms.as_object().is_some_and(|map| map.is_empty())),
        "quiet JSON incremental sync should leave realms empty: {json_quiet}"
    );

    // (1) Quiet incremental sync with long-poll opted out — must drop
    //     the realm from the response so idle clients no longer
    //     re-receive the full baseline.
    let (quiet, quiet_bytes) = fetch_account_subscribe_with_size(
        &alice,
        &format!("catchup=true&max_wait_ms=0&after={cursor}"),
    )
    .await?;
    assert!(
        quiet["realms"][&realm_id].is_null(),
        "quiet incremental sync MUST drop the realm baseline: {quiet}"
    );
    assert!(
        quiet["realms"]
            .as_object()
            .is_some_and(|map| map.is_empty()),
        "quiet incremental sync should leave realms empty: {quiet}"
    );
    assert!(
        quiet_bytes < QUIET_RESPONSE_BYTES_CEILING,
        "quiet response should be tiny (< {QUIET_RESPONSE_BYTES_CEILING}B), was {quiet_bytes}B"
    );

    // (2) Long-poll deadline behavior — with no broadcast in flight,
    //     the request should hold at least to the supplied window and
    //     return an empty delta. Use a short window so the scenario
    //     itself stays fast.
    let timeout_start = Instant::now();
    let timed_out = fetch_account_subscribe(
        &alice,
        &format!("catchup=true&max_wait_ms=400&after={cursor}"),
    )
    .await?;
    let elapsed = timeout_start.elapsed();
    assert!(
        timed_out["realms"]
            .as_object()
            .is_some_and(|map| map.is_empty()),
        "long-poll timeout MUST still return an empty realms delta: {timed_out}"
    );
    assert!(
        elapsed >= Duration::from_millis(300),
        "long-poll should hold ~max_wait_ms before returning empty (got {elapsed:?})"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "long-poll should not overshoot the deadline by much (got {elapsed:?})"
    );

    // (3) A real timeline event must wake the long-poll — fire a
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
    let woken = fetch_account_subscribe(
        &alice,
        &format!("catchup=true&max_wait_ms=5000&after={cursor}"),
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
            "plaintext_visible_services": [alice.service_did().to_owned()]
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
    assert!(
        !sync_notifications_contain_invite(&bob_baseline, &invite_id),
        "accepted invite notification MUST NOT remain in Bob full sync: {bob_baseline}"
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
                    &format!("catchup=true&max_wait_ms=0&after={bob_cursor}"),
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
                let sync = fetch_account_subscribe(
                    &alice,
                    &format!("catchup=true&max_wait_ms=0&after={alice_cursor}"),
                )
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

    let bob_sync = bob_client.sync().await?;
    assert!(
        !sync_notifications_contain_invite(&bob_sync, &invite_id),
        "cancelled invite notification MUST NOT remain in Bob full sync: {bob_sync}"
    );

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
    Ok(fetch_account_subscribe_with_size(actor, query).await?.0)
}

async fn fetch_account_subscribe_with_size(
    actor: &crate::harness::TestActorClient,
    query: &str,
) -> Result<(Value, usize)> {
    let response = expect_response(
        actor
            .get(&format!("/_arkret/self/account/subscribe?{query}"))
            .header("accept", "application/x-ndjson"),
        StatusCode::OK,
    )
    .await?;
    let body = response.text();
    let bytes = body.len();
    let frame = parse_delta_frame(&body)?;
    Ok((frame, bytes))
}

async fn fetch_account_subscribe_json(
    actor: &crate::harness::TestActorClient,
    query: &str,
) -> Result<(Value, String)> {
    let response = expect_response(
        actor
            .get(&format!("/_arkret/self/account/subscribe?{query}"))
            .header("accept", "application/json"),
        StatusCode::OK,
    )
    .await?;
    let content_type = response
        .headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    Ok((response.json()?, content_type))
}

fn parse_delta_frame(ndjson: &str) -> Result<Value> {
    for line in ndjson
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let frame: Value = serde_json::from_str(line)
            .map_err(|error| anyhow!("invalid subscribe frame `{line}`: {error}"))?;
        if frame.get("kind").and_then(Value::as_str) == Some("delta") {
            return Ok(frame);
        }
    }
    Err(anyhow!(
        "account subscribe NDJSON missing delta frame: {ndjson:?}"
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

fn sync_notifications_contain_invite(sync: &Value, invite_id: &str) -> bool {
    sync["notifications"]
        .as_array()
        .is_some_and(|notifications| {
            notifications
                .iter()
                .any(|notification| notification["invite_id"] == invite_id)
        })
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
            invitee.service_did(),
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
    let created_at = chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let mut event = crate::harness::event_envelope(&actor.actor, realm_id, kind, payload);
    event["created_at"] = Value::String(created_at.clone());
    if let Some(proof) = event
        .get_mut("proofs")
        .and_then(Value::as_array_mut)
        .and_then(|proofs| proofs.first_mut())
    {
        proof["created_at"] = Value::String(created_at);
    }
    crate::harness::refresh_event_proof(&mut event);
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
