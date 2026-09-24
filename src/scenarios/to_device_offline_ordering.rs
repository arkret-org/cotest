//! CT-10 — To-device queue offline ordering.
//!
//! Spec:
//!   - `arkret-spec/spec/v1/zh/sync/client-sync.md` §2 — `to_device` cursor / position progresses
//!     monotonically per (actor, device).
//!   - `arkret-spec/spec/v1/zh/sync/client-sync.md` §10.1 — explicit acknowledgement prunes
//!     delivered messages; pagination cursors never delete queue entries.
//!
//! Scenario walk-through:
//!   1. Alice and Bob log in with verified dev devices.
//!   2. Alice sends message 1 to dev_bob_a (POST /_arkret/self/device_messages with
//!      `Idempotency-Key: msg-1`).
//!   3. Bob's device polls and receives msg 1 without acknowledging delivery.
//!   4. "Disconnect": bob does NOT poll between steps 4 and 7.
//!   5. Alice sends message 2 (Idempotency-Key: msg-2).
//!   6. Alice sends message 3 (Idempotency-Key: msg-3).
//!   7. Bob reconnects and polls from the start: all three unacknowledged messages remain.
//!   8. Bob acks the latest delivery token → next poll returns no messages.
//!   9. Assert: msg 1 < msg 2 < msg 3 in the returned message order.
//!   10. Also assert idempotency: re-sending msg-2 with a new HTTP key but the same logical ID
//!       delivers nothing new (defends against reconnect-time duplicate-fan-out at the sender
//!       side).
//!
//! ──────────────────────────────────────────────────────────────────────────
//! Status: real test, runs against the in-process soland harness.
//!
//! Uses the normal Soland harness prerequisites and authorized device bootstrap.
//! Additional probes cover read-only pagination, cumulative and cross-bound
//! acknowledgements, concurrent retry and logical message target conflicts.

use anyhow::{Result, anyhow, bail};
use arkret_models_collaboration::device_messages::{
    DeviceMessagesAckRequestBody, DeviceMessagesSendRequestBody,
};
use reqwest::StatusCode;
use serde_json::Value;

use crate::harness::{
    ArkretServer, device_message_send_request, encrypted_envelope, expect_api_error, expect_json,
};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, spawn_with_harness_account_authority,
};

/// CT-10 scenario probe — see module docs for the 10-step walk-through.
pub async fn to_device_offline_ordering_run() -> Result<()> {
    let server = spawn_with_harness_account_authority("to-device-offline-ordering", &[]).await?;

    // ── Setup: alice (sender), bob (recipient, single device).
    let alice_did = actor_did_for_service_did(server.service_did(), "offline-ordering-alice")?;
    let alice = server
        .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let alice_token = alice.expect_dev_bearer().to_owned();
    let bob_did = actor_did_for_service_did(server.service_did(), "bob-offline-ordering")?;
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000ba";
    let bob = server.demo_client(&bob_did, bob_device).await?;
    acknowledge_bootstrap_messages(&bob).await?;
    let bob_token = bob.expect_dev_bearer().to_owned();
    let expires_at = queue_expiry()?;
    // ── Step 2: alice sends msg 1 to bob's device.
    send_to_device(
        &server,
        &alice_token,
        DeviceMessageRequest {
            recipient: &bob_did,
            device_id: bob_device,
            device_message_id: "ak:device_message:0196419b-0000-7000-8000-00000000c101",
            idempotency_key: "ct10-msg-1",
            ciphertext: "ciphertext-msg-1",
            expect_delivery: true,
            expires_at,
        },
    )
    .await?;

    // ── Step 3: bob polls, receives msg 1. Keep cursor but do NOT ack.
    let first_poll = poll_to_device(&server, &bob_token, None).await?;
    let events1 = application_messages(&first_poll)?;
    if events1.len() != 1 {
        bail!("expected exactly 1 event in first poll, got {events1:?}");
    }
    assert_message_ciphertext(&events1[0], "ciphertext-msg-1")?;
    // The next poll starts at the queue beginning to prove msg 1 remains
    // unacknowledged. Passing after would also be read-only; it is not an ack.

    // ── Step 4-6: "disconnect": no polling, alice sends msg 2 then msg 3.
    send_to_device(
        &server,
        &alice_token,
        DeviceMessageRequest {
            recipient: &bob_did,
            device_id: bob_device,
            device_message_id: "ak:device_message:0196419b-0000-7000-8000-00000000c102",
            idempotency_key: "ct10-msg-2",
            ciphertext: "ciphertext-msg-2",
            expect_delivery: true,
            expires_at,
        },
    )
    .await?;
    send_to_device(
        &server,
        &alice_token,
        DeviceMessageRequest {
            recipient: &bob_did,
            device_id: bob_device,
            device_message_id: "ak:device_message:0196419b-0000-7000-8000-00000000c103",
            idempotency_key: "ct10-msg-3",
            ciphertext: "ciphertext-msg-3",
            expect_delivery: true,
            expires_at,
        },
    )
    .await?;

    // ── Step 7: bob reconnects, polls WITHOUT acking the step-3 cursor.
    // Soland's GET /_arkret/self/device_messages without `?after=` defaults to
    // ack_position=0, returning all queued events. msg 1 may still be in
    // the queue until explicit ack; msg 2 and 3 follow it.
    let reconnect = poll_to_device(&server, &bob_token, None).await?;
    let events_after = application_messages(&reconnect)?;

    let cipher_order: Vec<String> = events_after
        .iter()
        .map(|event| {
            event["content"]["ciphertext"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    if cipher_order != ["ciphertext-msg-1", "ciphertext-msg-2", "ciphertext-msg-3"] {
        bail!("expected msg-1 < msg-2 < msg-3 on reconnect, got order {cipher_order:?}");
    }

    // ── Step 8: ack the latest delivery token → next poll empty.
    let ack_token = reconnect["ack_token"]
        .as_str()
        .ok_or_else(|| anyhow!("reconnect poll missing ack_token: {reconnect}"))?
        .to_owned();
    ack_to_device(&server, &bob_token, &ack_token).await?;
    let drained = poll_to_device(&server, &bob_token, None).await?;
    let drained_events = application_messages(&drained)?;
    if !drained_events.is_empty() {
        bail!("expected empty event list after ack of latest cursor, got {drained_events:?}");
    }

    // ── Step 10: idempotency on resend — alice retries msg-2 with the
    // same logical ID and a NEW HTTP key; soland MUST NOT deliver a duplicate.
    send_to_device(
        &server,
        &alice_token,
        DeviceMessageRequest {
            recipient: &bob_did,
            device_id: bob_device,
            device_message_id: "ak:device_message:0196419b-0000-7000-8000-00000000c102",
            idempotency_key: "ct10-msg-2-replay",
            ciphertext: "ciphertext-msg-2",
            expect_delivery: true,
            expires_at,
        },
    )
    .await?;
    let after_replay = poll_to_device(&server, &bob_token, None).await?;
    let replay_events = application_messages(&after_replay)?;
    if !replay_events.is_empty() {
        bail!("logical message replay after ack MUST NOT re-deliver, got {replay_events:?}");
    }

    let conflicting = device_message_send_request(
        &bob_did,
        bob_device,
        "ak:device_message:0196419b-0000-7000-8000-00000000c102",
        "ak.mls.application",
        encrypted_envelope("ak.mls.application", "ciphertext-msg-2-conflict"),
        expires_at,
    )?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/device_messages"))
            .bearer_auth(&alice_token)
            .header("Idempotency-Key", "ct10-msg-2-conflict")
            .json(&conflicting),
        StatusCode::CONFLICT,
        "duplicate_conflict",
    )
    .await?;

    Ok(())
}

struct DeviceMessageRequest<'a> {
    recipient: &'a str,
    device_id: &'a str,
    device_message_id: &'a str,
    idempotency_key: &'a str,
    ciphertext: &'a str,
    expect_delivery: bool,
    expires_at: chrono::DateTime<chrono::Utc>,
}

async fn send_to_device(
    server: &ArkretServer,
    sender_token: &str,
    request: DeviceMessageRequest<'_>,
) -> Result<Value> {
    let DeviceMessageRequest {
        recipient,
        device_id,
        device_message_id,
        idempotency_key,
        ciphertext,
        expect_delivery,
        expires_at,
    } = request;
    let body = device_message_send_request(
        recipient,
        device_id,
        device_message_id,
        "ak.mls.application",
        encrypted_envelope("ak.mls.application", ciphertext),
        expires_at,
    )?;
    let response = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/device_messages"))
            .bearer_auth(sender_token)
            .header("Idempotency-Key", idempotency_key)
            .json(&body),
        StatusCode::OK,
    )
    .await?;
    if expect_delivery {
        let recipient_core_id = crate::harness::actor_core_id(recipient)?;
        if response["delivered"][&recipient_core_id][device_id]["status"] != "delivered" {
            bail!("send_to_device did not deliver to {recipient}/{device_id}: {response}");
        }
    }
    Ok(response)
}

async fn ack_to_device(
    server: &ArkretServer,
    recipient_token: &str,
    ack_token: &str,
) -> Result<()> {
    let ack: arkret_models_collaboration::device_messages::DeviceMessagesAckOutcome =
        serde_json::from_value(expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/device_messages/ack"))
            .bearer_auth(recipient_token)
            .json(
                &arkret_models_collaboration::device_messages::DeviceMessagesAckRequestBody {
                    ack_token: ack_token.to_owned(),
                },
            ),
        StatusCode::OK,
    )
    .await?)?;
    if ack.pruned_count != 3 {
        bail!("expected to-device ack to prune 3 messages, got {ack:?}");
    }
    Ok(())
}

async fn poll_to_device(
    server: &ArkretServer,
    recipient_token: &str,
    after: Option<&str>,
) -> Result<Value> {
    let mut req = server
        .http()
        .get(server.url("/_arkret/self/device_messages"))
        .bearer_auth(recipient_token);
    if let Some(cursor) = after {
        req = req.query(&[("after", cursor)]);
    }
    expect_json(req, StatusCode::OK).await
}

fn assert_message_ciphertext(event: &Value, expected: &str) -> Result<()> {
    let actual = event["content"]["ciphertext"]
        .as_str()
        .ok_or_else(|| anyhow!("event missing ciphertext: {event}"))?;
    if actual != expected {
        bail!("expected ciphertext {expected}, got {actual} (event {event})");
    }
    Ok(())
}

// Complement: csapi/to_device_test.go and federation_to_device_test.go.
// Arkret deliberately uses explicit acknowledgement instead of Matrix's
// implicit sync acknowledgement: client-sync §10.1 and device-lifecycle §7.
pub async fn device_message_pagination_is_read_only_and_ack_is_cumulative() -> Result<()> {
    let server = spawn_with_harness_account_authority("device-ack-pagination", &[]).await?;
    let did = actor_did_for_service_did(server.service_did(), "device-ack-owner")?;
    let device = "ak:device:01904100-0000-7000-8000-0000000000a1";
    let owner = server.demo_client(&did, device).await?;
    let token = owner.expect_dev_bearer();
    let mut ids = Vec::new();
    for index in 0..3 {
        let id = format!("ak:device_message:0196419b-0000-7000-8000-00000000d3{index:02}");
        send_exact_message(
            &owner,
            &queue_request(&did, device, &id)?,
            &format!("page-{index}"),
        )
        .await?;
        ids.push(id);
    }

    let first = expect_json(
        owner
            .get("/_arkret/self/device_messages")
            .query(&[("limit", 1)]),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(queue_ids(&first)?, ids[..1]);
    assert_eq!(first["has_more"], true);
    let old_ack = delivery_token(&first)?;
    let mut cursor = first["next_cursor"]
        .as_str()
        .ok_or_else(|| anyhow!("limited page omitted next_cursor"))?
        .to_owned();
    for (index, expected_id) in ids.iter().enumerate().skip(1) {
        let page = expect_json(
            owner
                .get("/_arkret/self/device_messages")
                .query(&[("limit", "1"), ("after", cursor.as_str())]),
            StatusCode::OK,
        )
        .await?;
        assert_eq!(queue_ids(&page)?, vec![expected_id.clone()]);
        assert_eq!(page["has_more"], index < 2);
        if index < 2 {
            cursor = page["next_cursor"]
                .as_str()
                .ok_or_else(|| anyhow!("nonterminal page omitted next_cursor"))?
                .to_owned();
        }
    }
    let all = poll_to_device(&server, token, None).await?;
    assert_eq!(
        queue_ids(&all)?,
        ids,
        "after must not delete unacknowledged messages"
    );
    let latest_ack = delivery_token(&all)?;
    assert_eq!(ack_count(&owner, &old_ack).await?, 1);
    assert_eq!(
        queue_ids(&poll_to_device(&server, token, None).await?)?,
        ids[1..]
    );
    assert_eq!(ack_count(&owner, &old_ack).await?, 0);

    let tail_id = "ak:device_message:0196419b-0000-7000-8000-00000000d399";
    send_exact_message(
        &owner,
        &queue_request(&did, device, tail_id)?,
        "tail-after-delivery",
    )
    .await?;
    assert_eq!(
        ack_count(&owner, &latest_ack).await?,
        2,
        "old delivery token must not acknowledge a later enqueue"
    );
    assert_eq!(
        ack_count(&owner, &old_ack).await?,
        0,
        "old ack must not regress the high-water mark"
    );
    let tail = poll_to_device(&server, token, None).await?;
    assert_eq!(queue_ids(&tail)?, vec![tail_id]);
    assert_eq!(ack_count(&owner, &delivery_token(&tail)?).await?, 1);
    assert_eq!(ack_count(&owner, &latest_ack).await?, 0);
    assert!(queue_ids(&poll_to_device(&server, token, None).await?)?.is_empty());
    Ok(())
}

pub async fn device_ack_rejects_cross_binding_without_pruning(same_account: bool) -> Result<()> {
    let server = spawn_with_harness_account_authority(
        if same_account {
            "device-ack-device-binding"
        } else {
            "device-ack-account-binding"
        },
        &[],
    )
    .await?;
    let did = actor_did_for_service_did(server.service_did(), "ack-recipient")?;
    let other_did = if same_account {
        did.clone()
    } else {
        actor_did_for_service_did(server.service_did(), "ack-other-account")?
    };
    let first_device = "ak:device:01904100-0000-7000-8000-0000000000a1";
    let other_device = "ak:device:01904100-0000-7000-8000-0000000000b1";
    let first = server.demo_client(&did, first_device).await?;
    let other = server.demo_client(&other_did, other_device).await?;
    acknowledge_bootstrap_messages(&first).await?;
    acknowledge_bootstrap_messages(&other).await?;
    let first_id = "ak:device_message:0196419b-0000-7000-8000-00000000d401";
    let other_id = "ak:device_message:0196419b-0000-7000-8000-00000000d402";
    send_exact_message(
        &first,
        &queue_request(&did, first_device, first_id)?,
        "first-device",
    )
    .await?;
    send_exact_message(
        &other,
        &queue_request(&other_did, other_device, other_id)?,
        "other-device",
    )
    .await?;
    let first_page = poll_to_device(&server, first.expect_dev_bearer(), None).await?;
    let other_page = poll_to_device(&server, other.expect_dev_bearer(), None).await?;
    assert_eq!(queue_ids(&first_page)?, vec![first_id]);
    assert_eq!(queue_ids(&other_page)?, vec![other_id]);
    let first_ack = delivery_token(&first_page)?;
    let denied = expect_json(
        other
            .post("/_arkret/self/device_messages/ack")
            .json(&DeviceMessagesAckRequestBody {
                ack_token: first_ack.clone(),
            }),
        StatusCode::BAD_REQUEST,
    )
    .await?;
    assert_eq!(denied["type"], "https://arkret.org/problems/param_invalid");
    assert_eq!(denied["reason_code"], "invalid_ack_token");
    assert_eq!(
        queue_ids(&poll_to_device(&server, first.expect_dev_bearer(), None).await?)?,
        vec![first_id]
    );
    assert_eq!(
        queue_ids(&poll_to_device(&server, other.expect_dev_bearer(), None).await?)?,
        vec![other_id]
    );
    assert_eq!(ack_count(&first, &first_ack).await?, 1);
    assert_eq!(ack_count(&other, &delivery_token(&other_page)?).await?, 1);
    Ok(())
}

pub async fn concurrent_device_message_retries_enqueue_once() -> Result<()> {
    let server =
        spawn_with_harness_account_authority("device-message-concurrent-replay", &[]).await?;
    let did = actor_did_for_service_did(server.service_did(), "device-concurrent")?;
    let device = "ak:device:01904100-0000-7000-8000-0000000000a1";
    let owner = server.demo_client(&did, device).await?;
    let id = "ak:device_message:0196419b-0000-7000-8000-00000000d501";
    let body = queue_request(&did, device, id)?;
    let (first, second) = tokio::join!(
        send_exact_message(&owner, &body, "concurrent"),
        send_exact_message(&owner, &body, "concurrent")
    );
    assert_eq!(
        first?, second?,
        "same HTTP key and body must replay the outcome"
    );
    let page = poll_to_device(&server, owner.expect_dev_bearer(), None).await?;
    assert_eq!(queue_ids(&page)?, vec![id]);
    assert_eq!(ack_count(&owner, &delivery_token(&page)?).await?, 1);
    send_exact_message(&owner, &body, "different-http-key-same-message").await?;
    assert!(
        queue_ids(&poll_to_device(&server, owner.expect_dev_bearer(), None).await?)?.is_empty(),
        "logical replay after ack must not redeliver"
    );
    Ok(())
}

pub async fn device_message_id_conflict_cannot_redirect_delivery() -> Result<()> {
    let server =
        spawn_with_harness_account_authority("device-message-target-conflict", &[]).await?;
    let did = actor_did_for_service_did(server.service_did(), "target-conflict")?;
    let first_device = "ak:device:01904100-0000-7000-8000-0000000000a1";
    let second_device = "ak:device:01904100-0000-7000-8000-0000000000b1";
    let first = server.demo_client(&did, first_device).await?;
    let second = server.demo_client(&did, second_device).await?;
    acknowledge_bootstrap_messages(&first).await?;
    acknowledge_bootstrap_messages(&second).await?;
    let id = "ak:device_message:0196419b-0000-7000-8000-00000000d601";
    let body = queue_request(&did, first_device, id)?;
    send_exact_message(&first, &body, "target-original").await?;
    let mut redirected = body.clone();
    let targets = redirected
        .messages
        .values_mut()
        .next()
        .ok_or_else(|| anyhow!("missing target map"))?;
    let target = targets
        .remove(&arkret_wire::DeviceId::new(first_device)?)
        .ok_or_else(|| anyhow!("missing first target"))?;
    targets.insert(arkret_wire::DeviceId::new(second_device)?, target);
    let denied = expect_json(
        first
            .post("/_arkret/self/device_messages")
            .header("Idempotency-Key", "target-conflict")
            .json(&redirected),
        StatusCode::CONFLICT,
    )
    .await?;
    assert_eq!(
        denied["type"],
        "https://arkret.org/problems/duplicate_conflict"
    );
    assert_eq!(denied["reason_code"], "device_message_id_conflict");
    assert_eq!(
        queue_ids(&poll_to_device(&server, first.expect_dev_bearer(), None).await?)?,
        vec![id]
    );
    assert!(
        queue_ids(&poll_to_device(&server, second.expect_dev_bearer(), None).await?)?.is_empty()
    );
    let sentinel = "ak:device_message:0196419b-0000-7000-8000-00000000d602";
    send_exact_message(
        &first,
        &queue_request(&did, second_device, sentinel)?,
        "target-positive",
    )
    .await?;
    assert_eq!(
        queue_ids(&poll_to_device(&server, second.expect_dev_bearer(), None).await?)?,
        vec![sentinel]
    );
    Ok(())
}

fn queue_request(recipient: &str, device: &str, id: &str) -> Result<DeviceMessagesSendRequestBody> {
    device_message_send_request(
        recipient,
        device,
        id,
        "ak.mls.application",
        encrypted_envelope("ak.mls.application", "b3BhcXVl"),
        queue_expiry()?,
    )
}

fn queue_expiry() -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp_millis(
        (chrono::Utc::now() + chrono::Duration::minutes(10)).timestamp_millis(),
    )
    .ok_or_else(|| anyhow!("expiry outside timestamp range"))
}

async fn send_exact_message(
    client: &crate::harness::TestActorClient,
    body: &DeviceMessagesSendRequestBody,
    key: &str,
) -> Result<Value> {
    let outcome = expect_json(
        client
            .post("/_arkret/self/device_messages")
            .header("Idempotency-Key", key)
            .json(body),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(outcome["unknown_devices"], serde_json::json!({}));
    for (recipient, targets) in &body.messages {
        for device in targets.keys() {
            assert_eq!(
                outcome["delivered"][recipient.as_str()][device.as_str()]["status"],
                "delivered",
                "valid target was not delivered: {outcome}"
            );
        }
    }
    Ok(outcome)
}

/// The application DeviceMessage envelopes of one queue page, in queue order.
/// Account bootstrap may queue actor-private updates; they are not the
/// messages under test.
fn application_messages(page: &Value) -> Result<Vec<Value>> {
    Ok(page["deliveries"]
        .as_array()
        .ok_or_else(|| anyhow!("device queue omitted deliveries: {page}"))?
        .iter()
        .filter(|delivery| delivery["delivery_kind"] == "device_message")
        .map(|delivery| delivery["device_message"].clone())
        .filter(|message| message["kind"] == "ak.mls.application")
        .collect())
}

fn queue_ids(page: &Value) -> Result<Vec<String>> {
    application_messages(page)?
        .iter()
        .map(|message| {
            message["device_message_id"]
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| anyhow!("message omitted device_message_id"))
        })
        .collect()
}

fn delivery_token(page: &Value) -> Result<String> {
    page["ack_token"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("nonempty queue omitted ack_token"))
}

async fn ack_count(client: &crate::harness::TestActorClient, token: &str) -> Result<u64> {
    let outcome = expect_json(
        client
            .post("/_arkret/self/device_messages/ack")
            .json(&DeviceMessagesAckRequestBody {
                ack_token: token.to_owned(),
            }),
        StatusCode::OK,
    )
    .await?;
    outcome["pruned_count"]
        .as_u64()
        .ok_or_else(|| anyhow!("ack omitted pruned_count"))
}

async fn acknowledge_bootstrap_messages(client: &crate::harness::TestActorClient) -> Result<()> {
    // Pairing can enqueue actor-private device updates before the queue under
    // test is seeded. Consume them through the same explicit ack contract.
    let page = expect_json(client.get("/_arkret/self/device_messages"), StatusCode::OK).await?;
    let count = page["deliveries"]
        .as_array()
        .ok_or_else(|| anyhow!("device queue omitted deliveries: {page}"))?
        .len();
    if count > 0 {
        assert_eq!(
            ack_count(client, &delivery_token(&page)?).await?,
            count as u64
        );
    }
    let drained = expect_json(client.get("/_arkret/self/device_messages"), StatusCode::OK).await?;
    assert_eq!(drained["deliveries"], serde_json::json!([]), "{drained}");
    Ok(())
}

/// `device-lifecycle.md` §7: an unacknowledged DeviceMessage persists until
/// the recipient endpoint's cumulative ACK cancels it. After the Station
/// process restarts over the same durable database, the recipient reads the
/// byte-identical closed envelope (including the queue-materialized
/// `sent_at`), the send replays its stored outcome without a second enqueue,
/// and the ACK token issued after the restart still prunes exactly it.
pub async fn device_message_survives_station_restart() -> Result<()> {
    let ephemeral = crate::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres_for(
        "COTEST_SOLAND_DATABASE_URL",
    )?
    .ok_or_else(|| anyhow!("device-message restart requires isolated PostgreSQL"))?;
    let keystore_dir = tempfile::tempdir()?;
    let keystore_path = keystore_dir
        .path()
        .join("soland.v1")
        .to_string_lossy()
        .into_owned();
    let keystore_env = [
        ("SOLAND_KEYSTORE_BACKEND", "encrypted_file"),
        ("SOLAND_KEYSTORE_PATH", keystore_path.as_str()),
        (
            "SOLAND_KEYSTORE_MASTER_KEY",
            "UlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlI=",
        ),
    ];
    let mut server =
        crate::scenarios::identity_test_support::spawn_with_harness_account_authority_at(
            "device-message-restart",
            &ephemeral.connect_url,
            &keystore_env,
        )
        .await?;
    let did = actor_did_for_service_did(server.service_did(), "device-restart-owner")?;
    let owner = server
        .register_client(
            &did,
            "device-restart-owner",
            "ak:device:01904100-0000-7000-8000-0000000000e1",
        )
        .await?;
    let queued_before = restart_application_messages(&owner).await?;
    anyhow::ensure!(
        queued_before.is_empty(),
        "a fresh endpoint starts without application messages: {queued_before:?}"
    );

    let id = "ak:device_message:0196419b-0000-7000-8000-00000000e701";
    let body = device_message_send_request(
        &owner.actor,
        &owner.device_id,
        id,
        "ak.mls.application",
        encrypted_envelope("ak.mls.application", "cmVzdGFydA"),
        queue_expiry()?,
    )?;
    let sent = restart_send(&owner, &body, "restart-send").await?;
    let before = restart_application_messages(&owner).await?;
    anyhow::ensure!(
        before.len() == 1 && before[0]["device_message_id"] == id,
        "the sent message is queued before restart: {before:?}"
    );

    server.restart_external_process().await?;

    let after = restart_application_messages(&owner).await?;
    anyhow::ensure!(
        after == before,
        "the restarted Station must serve the identical closed envelope:\nbefore={before:?}\nafter={after:?}"
    );
    let replay = restart_send(&owner, &body, "restart-send").await?;
    anyhow::ensure!(
        replay == sent,
        "an exact HTTP retry after restart replays the stored outcome: {sent} vs {replay}"
    );
    anyhow::ensure!(
        restart_application_messages(&owner).await? == before,
        "a replay after restart must not enqueue a second copy"
    );

    let page = expect_json(owner.get("/_arkret/self/device_messages"), StatusCode::OK).await?;
    let pruned = ack_count(&owner, &delivery_token(&page)?).await?;
    anyhow::ensure!(
        pruned >= 1,
        "the post-restart ACK must cancel the queued message"
    );
    anyhow::ensure!(
        restart_application_messages(&owner).await?.is_empty(),
        "the ACKed message is no longer served after restart"
    );
    Ok(())
}

async fn restart_send(
    client: &crate::harness::TestActorClient,
    body: &DeviceMessagesSendRequestBody,
    key: &str,
) -> Result<Value> {
    let outcome = expect_json(
        client
            .post("/_arkret/self/device_messages")
            .header("Idempotency-Key", key)
            .json(body),
        StatusCode::OK,
    )
    .await?;
    let typed: arkret_models_collaboration::device_messages::DeviceMessagesSendOutcome =
        serde_json::from_value(outcome.clone())?;
    anyhow::ensure!(
        typed.unknown_devices.is_empty(),
        "the owner's accepted device must be deliverable: {outcome}"
    );
    for (recipient, targets) in &body.messages {
        for (device, target) in targets {
            let row = typed
                .delivered
                .get(recipient)
                .and_then(|devices| devices.get(device))
                .ok_or_else(|| anyhow!("{recipient}/{device} was not delivered: {outcome}"))?;
            anyhow::ensure!(row.device_message_id == target.device_message_id);
        }
    }
    Ok(outcome)
}

/// The application DeviceMessage envelopes the endpoint's queue serves, in
/// queue order. Account bootstrap may queue actor-private updates; they are
/// not the messages under test.
async fn restart_application_messages(
    client: &crate::harness::TestActorClient,
) -> Result<Vec<Value>> {
    let page: arkret_models_collaboration::device_messages::DeviceMessagesGetOutcome =
        serde_json::from_value(
            expect_json(client.get("/_arkret/self/device_messages"), StatusCode::OK).await?,
        )?;
    let mut messages = Vec::new();
    for delivery in page.deliveries {
        if let arkret_models_collaboration::device_messages::RecipientDelivery::DeviceMessage {
            device_message,
        } = delivery
            && device_message.kind.as_str() == "ak.mls.application"
        {
            messages.push(serde_json::to_value(&device_message)?);
        }
    }
    Ok(messages)
}
