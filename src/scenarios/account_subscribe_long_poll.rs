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
use arkret_models_collaboration::governance::invite_addressing::IntroductionEvidence;
use base64::Engine as _;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::StatusCode;
use serde_json::Value;

use crate::fixtures::TestActorBuilder;
use crate::harness::{
    account_subscribe_delta_from_text, actor_core_id, dispatch_accepted_invite_and_read_token,
    events_frontier_request_body, eventually, expect_account_subscribe_delta,
    expect_account_subscribe_realm_delta, invite_create_payload, message_create_text_payload,
};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_full_id, spawn_with_harness_account_authority,
};

const QUIET_LONG_POLL_TEST_DEADLINE: Duration = Duration::from_secs(45);

pub async fn account_subscribe_wait_for_barrier_contract() -> Result<()> {
    let server_owner =
        spawn_with_harness_account_authority("account-subscribe-wait-for", &[]).await?;
    let server = &server_owner;
    let alice_did =
        actor_did_for_service_full_id(server.service_full_id(), "account-subscribe-wait-alice")?;
    let bob_did =
        actor_did_for_service_full_id(server.service_full_id(), "account-subscribe-wait-bob")?;
    let alice = server
        .register_client(
            &alice_did,
            "@wait-for-alice",
            "ak:device:01904100-0000-7000-8000-00000000b501",
        )
        .await?;
    let bob = server
        .register_client(
            &bob_did,
            "@wait-for-bob",
            "ak:device:01904100-0000-7000-8000-00000000b502",
        )
        .await?;
    let realm_id = alice.create_realm("Wait-For Barrier Realm").await?;
    let strand_id = alice.default_strand_id(&realm_id)?;

    let stream_baseline = fetch_account_subscribe(&alice, "catchup=true").await?;
    let stream_cursor = cursor_from_sync(&stream_baseline)?;

    let submitted = alice
        .send_message(&realm_id, &strand_id, "barrier target")
        .await?;
    let event_id = submitted_event_id(&submitted)
        .ok_or_else(|| anyhow!("send response missing event id: {submitted}"))?
        .to_owned();
    let barrier_cursor = submitted["cursor"]
        .as_str()
        .ok_or_else(|| anyhow!("send response missing barrier cursor: {submitted}"))?
        .to_owned();

    let response = alice
        .get("/_arkret/self/account/subscribe?catchup=true")
        .header("accept", "application/x-ndjson")
        .header("X-Arkret-Wait-For", &barrier_cursor)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-arkret-wait-for-satisfied")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    let body = tokio::time::timeout(Duration::from_secs(5), response.text())
        .await
        .map_err(|_| anyhow!("barrier subscribe did not complete catchup response"))??;
    let first_delta = account_subscribe_delta_from_text(&body)?;
    let events = first_delta["realms"][&realm_id]["timeline"]["events"]
        .as_array()
        .ok_or_else(|| anyhow!("barrier first delta missing Realm timeline: {first_delta}"))?;
    assert!(
        events.iter().any(|event| event["event_id"] == event_id),
        "first delta after a satisfied barrier must include the target event"
    );

    let wrong_purpose = crate::harness::expect_response(
        alice
            .get("/_arkret/self/account/subscribe?catchup=true")
            .header("X-Arkret-Wait-For", stream_cursor),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let wrong_purpose_body = wrong_purpose.json()?;
    assert_eq!(
        wrong_purpose_body
            .pointer("/error/code")
            .or_else(|| wrong_purpose_body.pointer("/error/errcode"))
            .and_then(Value::as_str),
        Some("param_invalid")
    );

    let wrong_scope = crate::harness::expect_response(
        bob.get("/_arkret/self/account/subscribe?catchup=true")
            .header("X-Arkret-Wait-For", barrier_cursor),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    let wrong_scope_body = wrong_scope.json()?;
    assert_eq!(
        wrong_scope_body
            .pointer("/error/code")
            .or_else(|| wrong_scope_body.pointer("/error/errcode"))
            .and_then(Value::as_str),
        Some("cursor_integrity_invalid")
    );

    Ok(())
}

pub async fn account_subscribe_omits_quiet_realm_at_unchanged_cursor() -> Result<()> {
    let server_owner =
        spawn_with_harness_account_authority("account-subscribe-quiet-realm", &[]).await?;
    let server = &server_owner;
    let alice_did =
        actor_did_for_service_full_id(server.service_full_id(), "account-subscribe-quiet-alice")?;
    let alice = server
        .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let realm_id = alice.create_realm("Quiet Incremental Realm").await?;
    let strand_id = alice.default_strand_id(&realm_id)?;
    alice
        .send_message(&realm_id, &strand_id, "baseline message")
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
    let server_owner =
        spawn_with_harness_account_authority("account-subscribe-long-poll", &[]).await?;
    let server = &server_owner;
    let alice_did =
        actor_did_for_service_full_id(server.service_full_id(), "account-subscribe-poll-alice")?;
    let alice = server
        .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let realm_id = alice.create_realm("Long-Poll Recovery Realm").await?;
    let strand_id = alice.default_strand_id(&realm_id)?;
    alice
        .send_message(&realm_id, &strand_id, "baseline message")
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
    let strand_id_for_wake = strand_id.clone();
    let waker = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        alice_for_wake
            .send_message(&realm_id_for_wake, &strand_id_for_wake, "wake the poll")
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
    let server_owner =
        spawn_with_harness_account_authority("account-subscribe-invite-two-way", &[]).await?;
    let server = &server_owner;
    let alice_did =
        actor_did_for_service_full_id(server.service_full_id(), "account-subscribe-invite-alice")?;
    let bob_did =
        actor_did_for_service_full_id(server.service_full_id(), "account-subscribe-invite-bob")?;
    let alice = server
        .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let bob = TestActorBuilder::new(server, "@bob-sync")
        .with_did(&bob_did)
        .with_device("ak:device:01904100-0000-7000-8000-0000000000b1")
        .create()
        .await?;
    let bob_client = bob.client();

    let created = alice
        .create_realm_with(serde_json::json!({
            "title": "Joined History Sync Realm",
            "summary": "Joined History Sync Realm",
            "public": false,
            "history_access": "since_join",
            "plaintext_visible_services": [alice.service_id().to_owned()]
        }))
        .await?;
    let realm_id = created["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow!("create realm response missing realm_id: {created}"))?
        .to_owned();
    let strand_id = created["default_strand_id"]
        .as_str()
        .ok_or_else(|| anyhow!("create realm response missing default_strand_id: {created}"))?
        .to_owned();

    let pre_join = alice
        .send_message(&realm_id, &strand_id, "alice before bob joined")
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
                    .authz_invites(&actor_core_id(&bob_client.actor)?, Some(&realm_id), None)
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
    accept_invite_join_now(bob_client, &alice, &realm_id, &invite_id).await?;
    // Membership derives read access only. Bob still needs a covering grant to
    // author into the Realm (`capabilities.md` line 700).
    alice
        .grant_realm_actions_to_client(&realm_id, bob_client, &["ak.message.create"])
        .await?;
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
                    .authz_invites(&actor_core_id(&bob_client.actor)?, Some(&realm_id), None)
                    .await?;
                let alice_view = alice
                    .sdk()
                    .authz_invites(&actor_core_id(&bob_client.actor)?, Some(&realm_id), None)
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

    let alice_after_join =
        send_message_now(&alice, &realm_id, &strand_id, "alice after bob joined").await?;
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

    let bob_after_join =
        send_message_now(bob_client, &realm_id, &strand_id, "bob after joining").await?;
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
    let server_owner =
        spawn_with_harness_account_authority("account-subscribe-invite-cancel", &[]).await?;
    let server = &server_owner;
    let alice_did =
        actor_did_for_service_full_id(server.service_full_id(), "account-subscribe-cancel-alice")?;
    let bob_did =
        actor_did_for_service_full_id(server.service_full_id(), "account-subscribe-cancel-bob")?;
    let alice = server
        .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let bob = TestActorBuilder::new(server, "@bob-cancel")
        .with_did(&bob_did)
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
                    .authz_invites(&actor_core_id(&bob_client.actor)?, Some(&realm_id), None)
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

    cancel_invite_now(&alice, &realm_id, &invite_id, bob_client.actor.as_str()).await?;

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
                    .authz_invites(&actor_core_id(&bob_client.actor)?, Some(&realm_id), None)
                    .await?;
                let alice_view = alice
                    .sdk()
                    .authz_invites(&actor_core_id(&bob_client.actor)?, Some(&realm_id), None)
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
    strand_id: &str,
    body: &str,
) -> Result<Value> {
    submit_event_now(
        actor,
        actor,
        realm_id,
        "ak.message.create",
        message_create_text_payload(strand_id, body)?,
    )
    .await
}

async fn create_invite_now(
    inviter: &crate::harness::TestActorClient,
    realm_id: &str,
    invitee: &crate::harness::TestActorClient,
) -> Result<String> {
    let expires_at = chrono::Utc::now() + ChronoDuration::days(7);
    let (payload, introduction_evidence) =
        same_service_invite_payload(invitee.actor.as_str(), invitee.service_id(), expires_at)?;
    let accepted =
        submit_event_now(inviter, inviter, realm_id, "ak.invite.create", payload).await?;
    let event_id = accepted["event_id"]
        .as_str()
        .ok_or_else(|| anyhow!("accepted invite create omitted event_id: {accepted}"))?;
    let invite_id =
        arkret_identifiers::InviteId::from_event_id(&arkret_identifiers::EventId::new(event_id)?)
            .to_string();
    let invite_token = dispatch_accepted_invite_and_read_token(
        inviter,
        invitee,
        event_id,
        &invite_id,
        introduction_evidence,
    )
    .await?;
    if invite_token.is_empty() {
        return Err(anyhow!(
            "formal invite dispatch returned an empty private token for {invite_id}"
        ));
    }
    Ok(invite_id)
}

fn same_service_invite_payload(
    invitee: &str,
    recipient_service_id: &str,
    expires_at: DateTime<Utc>,
) -> Result<(Value, IntroductionEvidence)> {
    let evidence = IntroductionEvidence::SamePrincipalServer;
    let evidence_digest = arkret_canonical::canonical_sha256(&evidence)?;
    let payload =
        invite_create_payload(invitee, recipient_service_id, &evidence_digest, expires_at)?;
    Ok((payload, evidence))
}

async fn accept_invite_join_now(
    invitee: &crate::harness::TestActorClient,
    seal_source: &crate::harness::TestActorClient,
    realm_id: &str,
    invite_id: &str,
) -> Result<Value> {
    submit_event_now(
        invitee,
        seal_source,
        realm_id,
        "ak.invite.accept",
        serde_json::json!({
            "invite_id": invite_id,
            "delivery_status": "unroutable",
        }),
    )
    .await
}

async fn cancel_invite_now(
    inviter: &crate::harness::TestActorClient,
    realm_id: &str,
    invite_id: &str,
    invitee: &str,
) -> Result<Value> {
    let invitee = actor_core_id(invitee)?;
    submit_event_now(
        inviter,
        inviter,
        realm_id,
        "ak.invite.cancel",
        serde_json::json!({
            "invite_id": invite_id,
            "invitee": invitee,
            "target_state": "revoked",
            "reason": "admin_cancel",
        }),
    )
    .await
}

async fn submit_event_now(
    actor: &crate::harness::TestActorClient,
    seal_source: &crate::harness::TestActorClient,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Result<Value> {
    let frontier = crate::harness::expect_json(
        actor
            .query("/_arkret/self/events/frontier")
            .json(&events_frontier_request_body(
                Some(actor.actor.as_str()),
                Some(realm_id),
            )?),
        StatusCode::OK,
    )
    .await?;
    let state: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        serde_json::from_value(frontier)?;
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmActor(frontier) =
        state.frontier
    else {
        return Err(anyhow::anyhow!(
            "combined selector returned the wrong frontier variant"
        ));
    };
    frontier.validate()?;
    let created_at = arkret_canonical::format_timestamp_canonical(chrono::Utc::now());
    let mut event = crate::harness::event_envelope_with_chain(
        &actor.actor,
        realm_id,
        kind,
        payload,
        frontier.next_actor_seq,
        None,
    );
    event.prev_refs = frontier.frontier_event_ids;
    event.created_at = DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc);
    let descriptor = arkret_wire::EventKind::from(kind).descriptor();
    let is_control_move = descriptor
        .is_some_and(|descriptor| descriptor.reducer_input && descriptor.plane == Some("control"));
    let is_data_event = descriptor
        .is_some_and(|descriptor| descriptor.reducer_input && descriptor.plane == Some("data"));
    let mut previous_control_seal_id = None;
    if is_control_move || is_data_event {
        let seal_frontier = seal_source.realm_seal_frontier(realm_id).await?;
        let state: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
            serde_json::from_value(seal_frontier)?;
        let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(frontier) =
            state.frontier
        else {
            return Err(anyhow::anyhow!(
                "Realm selector returned the wrong frontier variant"
            ));
        };
        if is_data_event {
            // A DataEvent anchors on `seal_ref`; carrying `seal_basis` is what
            // marks an Event as a Control Move.
            event.seal_ref = Some(frontier.sole_leaf()?.clone());
            event.auth_context = Some(arkret_wire::AuthContext {
                key_id: crate::harness::auth_context_key_id(
                    crate::harness::default_event_verification_method(&actor.actor).as_str(),
                ),
                key_epoch: 0,
                credential_epoch: None,
            });
            if actor.controls_realm_authority_root(realm_id) {
                event.authorization_ref = Some(
                    arkret_wire::AuthorizationRef::new(arkret_wire::REALM_AUTHORITY_ROOT_CELL)
                        .map_err(anyhow::Error::msg)?,
                );
            } else {
                event.refs = actor
                    .covering_grants_for(realm_id, kind)
                    .into_iter()
                    .map(|grant_id| {
                        arkret_wire::EventRef::new(
                            grant_id,
                            arkret_wire::EVENT_REF_ROLE_AUTHORIZED_BY,
                        )
                    })
                    .collect();
            }
        } else {
            previous_control_seal_id = Some(frontier.sole_leaf()?.to_string());
            event.seal_basis = Some(frontier.seal_basis());
            let physical_millis = chrono::Utc::now().timestamp_millis();
            event.hlc = Some(arkret_identifiers::Hlc::new(format!(
                "{physical_millis:012x}-0000-a13f9c2e"
            ))?);
        }
    }
    crate::harness::refresh_typed_event_proof(&mut event)?;
    let mut response = crate::harness::expect_json(
        actor
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(event.clone(), "")?),
        StatusCode::OK,
    )
    .await?;
    if response.get("event_id").and_then(Value::as_str).is_none()
        && let Some(object) = response.as_object_mut()
    {
        object.insert(
            "event_id".to_owned(),
            Value::String(event.event_id.to_string()),
        );
    }
    if let Some(previous_seal_id) = previous_control_seal_id {
        let proposal_digest = response["control_proposal_acks"][0]["proposal_digest"]
            .as_str()
            .ok_or_else(|| anyhow!("Control Move response omitted its proposal Ack: {response}"))?;
        seal_source
            .await_control_proposal_settled(realm_id, proposal_digest, &previous_seal_id)
            .await?;
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_service_invite_commits_to_the_evidence_used_by_formal_dispatch() {
        let expires_at = DateTime::parse_from_rfc3339("2026-09-01T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let (payload, evidence) = same_service_invite_payload(
            "did:webvh:z6mkinvitee:invitee.example",
            "ak:did_core:webvh:z6mkservice",
            expires_at,
        )
        .unwrap();
        assert_eq!(evidence, IntroductionEvidence::SamePrincipalServer);
        assert_eq!(
            payload["introduction_evidence_digest"],
            arkret_canonical::canonical_sha256(&evidence).unwrap()
        );
    }
}
