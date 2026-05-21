//! CT-10 — To-device queue offline ordering.
//!
//! Spec:
//!   - `contrix-spec/spec/v1/zh/sync/client-sync.md` §2 — `to_device`
//!     cursor / position progresses monotonically per (actor, device).
//!   - `contrix-spec/spec/v1/zh/sync/operations-sync.md` §2.1 — queued
//!     to-device messages preserve send order across disconnect /
//!     reconnect; cursor-acked eviction ensures no replay or skip.
//!
//! Scenario walk-through:
//!   1. Alice registers (dev_alice) and Bob registers (dev_bob_a).
//!   2. Alice sends message 1 to dev_bob_a (POST /api/v1/device_messages
//!      with `Idempotency-Key: msg-1`).
//!   3. Bob's device polls (GET /api/v1/device_messages) — receives msg 1.
//!      We retain the returned `next_cursor` cursor.
//!   4. "Disconnect": bob does NOT poll between steps 4 and 7.
//!   5. Alice sends message 2 (Idempotency-Key: msg-2).
//!   6. Alice sends message 3 (Idempotency-Key: msg-3).
//!   7. Bob "reconnects" by polling GET /api/v1/device_messages without
//!      acking the cursor from step 3 — should still see msg 2 and msg 3
//!      in send order (positions strictly increasing).
//!   8. Bob acks the latest cursor → next poll returns no events.
//!   9. Assert: msg 1 position < msg 2 position < msg 3 position
//!      (HLC / `to_device_position` monotonic).
//!   10. Also assert idempotency: re-sending msg-2 with the same
//!       Idempotency-Key delivers nothing new (defends against
//!       reconnect-time duplicate-fan-out at the sender side).
//!
//! ──────────────────────────────────────────────────────────────────────────
//! Status: real test, runs against the in-process soland harness.
//!
//! No external prerequisites — soland's `/api/v1/device_messages` POST and
//! GET endpoints are wired in dev mode and the harness already supports
//! `dev_login` with per-device-id session issuance, so multi-device wiring
//! is straightforward.

use anyhow::{Result, anyhow, bail};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{ContrixServer, dev_login, encrypted_envelope, expect_json, register_account};

/// CT-10 scenario probe — see module docs for the 10-step walk-through.
pub async fn to_device_offline_ordering_run() -> Result<()> {
    let server = ContrixServer::spawn("to-device-offline-ordering").await?;

    // ── Setup: alice (sender), bob (recipient, single device).
    let alice_token =
        register_account(&server, "did:web:alice.example", "@alice", "dev_alice").await?;
    let bob_token = register_account(&server, "did:web:bob.example", "@bob", "dev_bob_a").await?;
    // Sanity: alice can also log in on a separate device id so the
    // sender's session is a separate row from the recipient's. (Not
    // strictly required by the scenario, but mirrors the implementor's
    // hint of "two devices for alice and one for bob".)
    let _alice_token_b = dev_login(&server, "did:web:alice.example", "dev_alice_b").await?;

    let bob_did = "did:web:bob.example";
    let bob_device = "dev_bob_a";

    // ── Step 2: alice sends msg 1 to bob's device.
    send_to_device(
        &server,
        &alice_token,
        bob_did,
        bob_device,
        "ct10-msg-1",
        "ciphertext-msg-1",
    )
    .await?;

    // ── Step 3: bob polls, receives msg 1. Keep cursor but do NOT ack.
    let first_poll = poll_to_device(&server, &bob_token, None).await?;
    let events1 = first_poll["events"].as_array().cloned().unwrap_or_default();
    if events1.len() != 1 {
        bail!("expected exactly 1 event in first poll, got {events1:?}");
    }
    assert_message_ciphertext(&events1[0], "ciphertext-msg-1")?;
    let pos_1 = position_of(&events1[0])?;
    // Cursor captured here would be `first_poll["next_cursor"]`, but we
    // intentionally do NOT pass it back on the reconnect poll — that is
    // what the spec calls "no premature ack on disconnect", protecting
    // against silent drops if the device crashes before persisting.

    // ── Step 4-6: "disconnect": no polling, alice sends msg 2 then msg 3.
    send_to_device(
        &server,
        &alice_token,
        bob_did,
        bob_device,
        "ct10-msg-2",
        "ciphertext-msg-2",
    )
    .await?;
    send_to_device(
        &server,
        &alice_token,
        bob_did,
        bob_device,
        "ct10-msg-3",
        "ciphertext-msg-3",
    )
    .await?;

    // ── Step 7: bob reconnects, polls WITHOUT acking the step-3 cursor.
    // Soland's GET /api/v1/device_messages without `?from=` defaults to
    // ack_position=0, returning all queued events. msg 1 may still be in
    // the queue (un-acked); msg 2 and 3 are definitely there.
    let reconnect = poll_to_device(&server, &bob_token, None).await?;
    let events_after = reconnect["events"].as_array().cloned().unwrap_or_default();

    // We require msg-2 and msg-3 to be in order. msg-1 will also be
    // present (no ack happened). All three positions must be strictly
    // increasing — this is the §2 HLC monotonic invariant on the
    // device's to_device_position.
    let positions: Vec<i64> = events_after
        .iter()
        .map(position_of)
        .collect::<Result<Vec<_>>>()?;
    if !positions.windows(2).all(|w| w[0] < w[1]) {
        bail!(
            "expected strictly increasing to_device positions across queued events, got {positions:?}"
        );
    }

    let cipher_order: Vec<String> = events_after
        .iter()
        .map(|event| {
            event["content"]["content"]["ciphertext"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    let i1 = cipher_order
        .iter()
        .position(|c| c == "ciphertext-msg-1")
        .ok_or_else(|| anyhow!("msg-1 missing on reconnect poll: {cipher_order:?}"))?;
    let i2 = cipher_order
        .iter()
        .position(|c| c == "ciphertext-msg-2")
        .ok_or_else(|| anyhow!("msg-2 missing on reconnect poll: {cipher_order:?}"))?;
    let i3 = cipher_order
        .iter()
        .position(|c| c == "ciphertext-msg-3")
        .ok_or_else(|| anyhow!("msg-3 missing on reconnect poll: {cipher_order:?}"))?;
    if !(i1 < i2 && i2 < i3) {
        bail!("expected msg-1 < msg-2 < msg-3 on reconnect, got order {cipher_order:?}");
    }

    // ── Step 9: position of msg-1 from first poll must equal position of
    // msg-1 from reconnect (same record, same column).
    let pos_1_again = positions[i1];
    if pos_1 != pos_1_again {
        bail!("msg-1 position drifted across polls: first={pos_1} reconnect={pos_1_again}");
    }

    // ── Step 8: ack the latest cursor → next poll empty.
    let next_cursor = reconnect["next_cursor"]
        .as_str()
        .ok_or_else(|| anyhow!("reconnect poll missing next_cursor: {reconnect}"))?
        .to_owned();
    let drained = poll_to_device(&server, &bob_token, Some(&next_cursor)).await?;
    let drained_events = drained["events"].as_array().cloned().unwrap_or_default();
    if !drained_events.is_empty() {
        bail!("expected empty event list after ack of latest cursor, got {drained_events:?}");
    }

    // ── Step 10: idempotency on resend — alice retries msg-2 with the
    // SAME Idempotency-Key; soland MUST NOT deliver a duplicate.
    send_to_device(
        &server,
        &alice_token,
        bob_did,
        bob_device,
        "ct10-msg-2",
        "ciphertext-msg-2-redux", // intentionally different ciphertext
    )
    .await?;
    let after_replay = poll_to_device(&server, &bob_token, Some(&next_cursor)).await?;
    let replay_events = after_replay["events"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !replay_events.is_empty() {
        bail!(
            "duplicate send under same Idempotency-Key MUST NOT re-deliver, got {replay_events:?}"
        );
    }

    Ok(())
}

async fn send_to_device(
    server: &ContrixServer,
    sender_token: &str,
    recipient: &str,
    device_id: &str,
    idempotency_key: &str,
    ciphertext: &str,
) -> Result<Value> {
    let body = json!({
        "messages": {
            recipient: {
                device_id: {
                    "type": "cx.mls.application",
                    "content": encrypted_envelope("cx.mls.application", ciphertext),
                }
            }
        }
    });
    expect_json(
        server
            .http()
            .post(server.url("/api/v1/device_messages"))
            .bearer_auth(sender_token)
            .header("Idempotency-Key", idempotency_key)
            .json(&body),
        StatusCode::OK,
    )
    .await
}

async fn poll_to_device(
    server: &ContrixServer,
    recipient_token: &str,
    from: Option<&str>,
) -> Result<Value> {
    let mut req = server
        .http()
        .get(server.url("/api/v1/device_messages"))
        .bearer_auth(recipient_token);
    if let Some(cursor) = from {
        req = req.query(&[("from", cursor)]);
    }
    expect_json(req, StatusCode::OK).await
}

fn position_of(event: &Value) -> Result<i64> {
    event["position"]
        .as_i64()
        .ok_or_else(|| anyhow!("to-device event missing position: {event}"))
}

fn assert_message_ciphertext(event: &Value, expected: &str) -> Result<()> {
    let actual = event["content"]["content"]["ciphertext"]
        .as_str()
        .ok_or_else(|| anyhow!("event missing ciphertext: {event}"))?;
    if actual != expected {
        bail!("expected ciphertext {expected}, got {actual} (event {event})");
    }
    Ok(())
}
