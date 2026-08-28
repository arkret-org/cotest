//! CT-10 — To-device queue offline ordering.
//!
//! Spec:
//!   - `arkret-spec/spec/v1/zh/sync/client-sync.md` §2 — `to_device` cursor / position progresses
//!     monotonically per (actor, device).
//!   - `arkret-spec/spec/v1/zh/sync/operations-sync.md` §2.1 — queued to-device messages preserve
//!     send order across disconnect / reconnect; cursor-acked eviction ensures no replay or skip.
//!
//! Scenario walk-through:
//!   1. Alice and Bob log in with verified dev devices.
//!   2. Alice sends message 1 to dev_bob_a (POST /_arkret/self/device_messages with
//!      `Idempotency-Key: msg-1`).
//!   3. Bob's device polls (GET /_arkret/self/device_messages) — receives msg 1. We retain the
//!      returned `next_cursor` cursor.
//!   4. "Disconnect": bob does NOT poll between steps 4 and 7.
//!   5. Alice sends message 2 (Idempotency-Key: msg-2).
//!   6. Alice sends message 3 (Idempotency-Key: msg-3).
//!   7. Bob "reconnects" by polling GET /_arkret/self/device_messages without acking the cursor
//!      from step 3 — should still see msg 2 and msg 3 in send order (positions strictly
//!      increasing).
//!   8. Bob acks the latest delivery token → next poll returns no messages.
//!   9. Assert: msg 1 < msg 2 < msg 3 in the returned message order.
//!   10. Also assert idempotency: re-sending msg-2 with the same Idempotency-Key delivers nothing
//!       new (defends against reconnect-time duplicate-fan-out at the sender side).
//!
//! ──────────────────────────────────────────────────────────────────────────
//! Status: real test, runs against the in-process soland harness.
//!
//! No external prerequisites — soland's `/_arkret/self/device_messages` POST and
//! GET endpoints are wired in dev mode and the harness typed bootstrap issues
//! per-device-id sessions, so multi-device wiring is straightforward.

use anyhow::{Result, anyhow, bail};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    ArkretServer, device_message_send_request, encrypted_envelope, expect_api_error, expect_json,
};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

/// CT-10 scenario probe — see module docs for the 10-step walk-through.
pub async fn to_device_offline_ordering_run() -> Result<()> {
    let server = ArkretServer::spawn("to-device-offline-ordering").await?;

    // ── Setup: alice (sender), bob (recipient, single device).
    let alice_did = actor_did_for_service_did(server.service_did(), "offline-ordering-alice")?;
    let alice = server
        .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let alice_token = alice.token.clone();
    let bob_did = actor_did_for_service_did(server.service_did(), "bob-offline-ordering")?;
    let bob_device = "ak:device:01904100-0000-7000-8000-0000000000ba";
    let bob = server.demo_client(&bob_did, bob_device).await?;
    let bob_token = bob.token.clone();
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
        },
    )
    .await?;

    // ── Step 3: bob polls, receives msg 1. Keep cursor but do NOT ack.
    let first_poll = poll_to_device(&server, &bob_token, None).await?;
    let events1 = first_poll["messages"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if events1.len() != 1 {
        bail!("expected exactly 1 event in first poll, got {events1:?}");
    }
    assert_message_ciphertext(&events1[0], "ciphertext-msg-1")?;
    // Cursor captured here would be `first_poll["next_cursor"]`, but we
    // intentionally do NOT pass it back on the reconnect poll — that is
    // what the spec calls "no premature ack on disconnect", protecting
    // against silent drops if the device crashes before persisting.

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
        },
    )
    .await?;

    // ── Step 7: bob reconnects, polls WITHOUT acking the step-3 cursor.
    // Soland's GET /_arkret/self/device_messages without `?after=` defaults to
    // ack_position=0, returning all queued events. msg 1 may still be in
    // the queue (un-acked); msg 2 and 3 are definitely there.
    let reconnect = poll_to_device(&server, &bob_token, None).await?;
    let events_after = reconnect["messages"]
        .as_array()
        .cloned()
        .unwrap_or_default();

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
    let drained_events = drained["messages"].as_array().cloned().unwrap_or_default();
    if !drained_events.is_empty() {
        bail!("expected empty event list after ack of latest cursor, got {drained_events:?}");
    }

    // ── Step 10: idempotency on resend — alice retries msg-2 with the
    // SAME Idempotency-Key; soland MUST NOT deliver a duplicate.
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
        },
    )
    .await?;
    let after_replay = poll_to_device(&server, &bob_token, None).await?;
    let replay_events = after_replay["messages"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !replay_events.is_empty() {
        bail!("logical message replay after ack MUST NOT re-deliver, got {replay_events:?}");
    }

    let conflicting = device_message_send_request(
        &bob_did,
        bob_device,
        "ak:device_message:0196419b-0000-7000-8000-00000000c102",
        "ak.mls.application",
        encrypted_envelope("ak.mls.application", "ciphertext-msg-2-conflict"),
        chrono::DateTime::parse_from_rfc3339("2026-12-31T00:00:00.000Z")?
            .with_timezone(&chrono::Utc),
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
    } = request;
    let body = device_message_send_request(
        recipient,
        device_id,
        device_message_id,
        "ak.mls.application",
        encrypted_envelope("ak.mls.application", ciphertext),
        chrono::DateTime::parse_from_rfc3339("2026-12-31T00:00:00.000Z")?
            .with_timezone(&chrono::Utc),
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
        let delivered = response["delivered"][&recipient_core_id]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if !delivered
            .iter()
            .any(|device| device.as_str() == Some(device_id))
        {
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
    let ack: arkret_models_collaboration::sync_frames::account_sync::DeviceMessagesAckOutcome =
        serde_json::from_value(expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/device_messages/ack"))
            .bearer_auth(recipient_token)
            .json(&serde_json::from_value::<
                arkret_models_collaboration::sync_frames::account_sync::DeviceMessagesAckRequestBody,
            >(json!({ "ack_token": ack_token }))?),
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
    from: Option<&str>,
) -> Result<Value> {
    let mut req = server
        .http()
        .get(server.url("/_arkret/self/device_messages"))
        .bearer_auth(recipient_token);
    if let Some(cursor) = from {
        req = req.query(&[("from", cursor)]);
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
