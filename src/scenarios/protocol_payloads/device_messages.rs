//! Phase 2 — `/_arkret/self/device_messages` send / duplicate / list / describe.

use anyhow::{Context, Result};
use reqwest::StatusCode;

use crate::harness::{
    ArkretServer, device_message_send_request, encrypted_envelope, expect_api_error, expect_json,
};

const PROTOCOL_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";
const PROTOCOL_MESSAGE_ID: &str = "ak:device_message:0196419b-0000-7000-8000-00000000f201";
/// A device id the actor's account never authorized.
const UNKNOWN_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-0000000000a2";

pub async fn run(server: &ArkretServer, token: &str, actor_id: &str) -> Result<()> {
    send_application_message(server, token, actor_id).await?;
    duplicate_send_is_idempotent(server, token, actor_id).await?;
    list_delivered_keeps_ciphertext_only(server, token, actor_id).await?;
    one_invalid_expiry_rejects_the_whole_batch(server, token, actor_id).await?;
    unknown_device_row_carries_only_id_and_status(server, token, actor_id).await?;
    exact_retry_after_expiry_returns_original_result(server, token, actor_id).await?;
    Ok(())
}

async fn send_application_message(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
) -> Result<()> {
    let send: arkret_models_collaboration::device_messages::DeviceMessagesSendOutcome =
        serde_json::from_value(
            expect_json(
                server
                    .http()
                    .post(server.url("/_arkret/self/device_messages"))
                    .bearer_auth(token)
                    .header("Idempotency-Key", "protocol-device-txn")
                    .json(&device_message_send_request(
                        actor_id,
                        "ak:device:01904100-0000-7000-8000-0000000000a1",
                        "ak:device_message:0196419b-0000-7000-8000-00000000f201",
                        "ak.mls.application",
                        encrypted_envelope("ak.mls.application", "base64url-opaque-ciphertext"),
                        protocol_expiry()?,
                    )?),
                StatusCode::OK,
            )
            .await?,
        )?;
    assert_delivered_to(
        &send,
        actor_id,
        "ak:device:01904100-0000-7000-8000-0000000000a1",
        "ak:device_message:0196419b-0000-7000-8000-00000000f201",
    )?;
    Ok(())
}

async fn duplicate_send_is_idempotent(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
) -> Result<()> {
    let duplicate_send: arkret_models_collaboration::device_messages::DeviceMessagesSendOutcome =
        serde_json::from_value(
            expect_json(
                server
                    .http()
                    .post(server.url("/_arkret/self/device_messages"))
                    .bearer_auth(token)
                    .header("Idempotency-Key", "protocol-device-txn")
                    .json(&device_message_send_request(
                        actor_id,
                        "ak:device:01904100-0000-7000-8000-0000000000a1",
                        "ak:device_message:0196419b-0000-7000-8000-00000000f201",
                        "ak.mls.application",
                        encrypted_envelope("ak.mls.application", "base64url-opaque-ciphertext"),
                        protocol_expiry()?,
                    )?),
                StatusCode::OK,
            )
            .await?,
        )?;
    assert_delivered_to(
        &duplicate_send,
        actor_id,
        "ak:device:01904100-0000-7000-8000-0000000000a1",
        "ak:device_message:0196419b-0000-7000-8000-00000000f201",
    )?;
    Ok(())
}

async fn list_delivered_keeps_ciphertext_only(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
) -> Result<()> {
    use arkret_identifiers::{DeviceId, DeviceMessageId, Did, project_did_to_core_id};
    use arkret_models_collaboration::device_messages::{
        DeviceMessageSender, DeviceMessagesAckOutcome, DeviceMessagesGetOutcome, RecipientDelivery,
    };

    let device_id = DeviceId::new(PROTOCOL_DEVICE_ID.to_owned())?;
    let core_id = project_did_to_core_id(&Did::new(actor_id.to_owned())?)?;
    // The formal list outcome is closed: decoding it through the SDK type
    // rejects any legacy or repaired queue shape.
    let delivered: DeviceMessagesGetOutcome = serde_json::from_value(
        expect_json(
            server
                .http()
                .get(server.url("/_arkret/self/device_messages"))
                .bearer_auth(token),
            StatusCode::OK,
        )
        .await?,
    )?;
    anyhow::ensure!(
        delivered.deliveries.len() == 1,
        "the duplicate send must not enqueue a second delivery: {:?}",
        delivered.deliveries.len()
    );
    anyhow::ensure!(!delivered.has_more, "a single delivery has no further page");
    let RecipientDelivery::DeviceMessage { device_message } = &delivered.deliveries[0] else {
        anyhow::bail!("human device queue served a non-DeviceMessage delivery");
    };
    anyhow::ensure!(
        device_message.device_message_id == DeviceMessageId::new(PROTOCOL_MESSAGE_ID.to_owned())?,
        "queued envelope names a different device message"
    );
    anyhow::ensure!(
        device_message.recipient_account_id.principal_id == core_id
            && device_message.recipient_device_id == device_id,
        "queued envelope is addressed to another endpoint"
    );
    anyhow::ensure!(
        matches!(
            &device_message.sender,
            DeviceMessageSender::Account { sender_account_id, sender_device_id }
                if sender_account_id.principal_id == core_id && *sender_device_id == device_id
        ),
        "queued envelope does not carry the authenticated human-device sender"
    );
    anyhow::ensure!(
        device_message.sent_at <= chrono::Utc::now()
            && device_message.sent_at <= device_message.expires_at,
        "queue-materialized sent_at is not an enqueue time"
    );
    assert_eq!(
        device_message.content.get("ciphertext"),
        Some(&serde_json::json!("base64url-opaque-ciphertext"))
    );
    assert!(!device_message.content.contains_key("plaintext"));
    let ack_token = delivered
        .ack_token
        .context("a non-empty delivery page carries an ACK token")?;

    let ack: DeviceMessagesAckOutcome = serde_json::from_value(
        expect_json(
            server
                .http()
                .post(server.url("/_arkret/self/device_messages/ack"))
                .bearer_auth(token)
                .json(
                    &arkret_models_collaboration::device_messages::DeviceMessagesAckRequestBody {
                        ack_token,
                    },
                ),
            StatusCode::OK,
        )
        .await?,
    )?;
    anyhow::ensure!(
        ack.pruned_count == 1,
        "ACK must cancel exactly the delivered message"
    );
    let after_ack: DeviceMessagesGetOutcome = serde_json::from_value(
        expect_json(
            server
                .http()
                .get(server.url("/_arkret/self/device_messages"))
                .bearer_auth(token),
            StatusCode::OK,
        )
        .await?,
    )?;
    anyhow::ensure!(
        after_ack.deliveries.is_empty() && after_ack.ack_token.is_none(),
        "ACKed delivery is still served"
    );
    Ok(())
}

/// An expiry inside the default 24 hour enqueue TTL (`device-lifecycle.md`
/// §7), fixed per process so the duplicate send repeats the exact intent.
fn protocol_expiry() -> Result<chrono::DateTime<chrono::Utc>> {
    static EXPIRY: std::sync::OnceLock<i64> = std::sync::OnceLock::new();
    let millis = *EXPIRY
        .get_or_init(|| (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp_millis());
    chrono::DateTime::from_timestamp_millis(millis).context("expiry outside timestamp range")
}

/// `DeviceMessagesSendOutcome.delivered` is now keyed by `DeviceId` and carries a
/// `DeviceMessageDeliveredRow` rather than a bare device-id string, so the check
/// names the device it expects and reads the row's status back instead of
/// comparing position 0 against a literal.
fn assert_delivered_to(
    outcome: &arkret_models_collaboration::device_messages::DeviceMessagesSendOutcome,
    actor_id: &str,
    device_id: &str,
    device_message_id: &str,
) -> Result<()> {
    use arkret_identifiers::{DeviceId, DeviceMessageId, Did, project_did_to_core_id};
    use arkret_models_collaboration::device_messages::DeviceMessageDeliveredStatus;

    let core_id = project_did_to_core_id(&Did::new(actor_id.to_owned())?)?;
    let device_id = DeviceId::new(device_id.to_owned())?;
    let devices = outcome
        .delivered
        .get(&core_id)
        .ok_or_else(|| anyhow::anyhow!("send outcome delivered nothing to {core_id}"))?;
    let row = devices
        .get(&device_id)
        .ok_or_else(|| anyhow::anyhow!("send outcome delivered nothing to device {device_id}"))?;
    anyhow::ensure!(
        row.status == DeviceMessageDeliveredStatus::Delivered,
        "device message to {device_id} is not delivered"
    );
    anyhow::ensure!(
        row.device_message_id == DeviceMessageId::new(device_message_id.to_owned())?,
        "delivered row names a different device message than the one sent"
    );
    anyhow::ensure!(
        outcome.unknown_devices.is_empty(),
        "send outcome reported unknown devices"
    );
    Ok(())
}

/// `ak.vector.sync.device_message_send_admission.v1`: one target with an
/// expired `expires_at` fails the whole request with `param_invalid` and
/// enqueues nothing, not even the valid sibling.
async fn one_invalid_expiry_rejects_the_whole_batch(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
) -> Result<()> {
    let mut body = device_message_send_request(
        actor_id,
        PROTOCOL_DEVICE_ID,
        "ak:device_message:0196419b-0000-7000-8000-00000000f211",
        "ak.mls.application",
        encrypted_envelope("ak.mls.application", "base64url-opaque-ciphertext"),
        protocol_expiry()?,
    )?;
    let expired = device_message_send_request(
        actor_id,
        UNKNOWN_DEVICE_ID,
        "ak:device_message:0196419b-0000-7000-8000-00000000f212",
        "ak.mls.application",
        encrypted_envelope("ak.mls.application", "base64url-opaque-ciphertext"),
        canonical_millis(chrono::Utc::now() - chrono::Duration::hours(1))?,
    )?;
    for (principal, targets) in expired.messages {
        body.messages.entry(principal).or_default().extend(targets);
    }
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/device_messages"))
            .bearer_auth(token)
            .header("Idempotency-Key", "protocol-device-mixed-expiry")
            .json(&body),
        StatusCode::BAD_REQUEST,
        "param_invalid",
    )
    .await?;
    let queue = device_queue(server, token).await?;
    anyhow::ensure!(
        queue.deliveries.is_empty(),
        "a rejected mixed batch enqueued {} deliveries",
        queue.deliveries.len()
    );
    Ok(())
}

/// `unknown_devices` rows carry exactly `device_message_id` and `status`; the
/// retired `reason_code` must not appear.
async fn unknown_device_row_carries_only_id_and_status(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
) -> Result<()> {
    use arkret_identifiers::{Did, project_did_to_core_id};

    let device_message_id = "ak:device_message:0196419b-0000-7000-8000-00000000f221";
    let raw = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/device_messages"))
            .bearer_auth(token)
            .header("Idempotency-Key", "protocol-device-unknown-row")
            .json(&device_message_send_request(
                actor_id,
                UNKNOWN_DEVICE_ID,
                device_message_id,
                "ak.mls.application",
                encrypted_envelope("ak.mls.application", "base64url-opaque-ciphertext"),
                protocol_expiry()?,
            )?),
        StatusCode::OK,
    )
    .await?;
    let outcome: arkret_models_collaboration::device_messages::DeviceMessagesSendOutcome =
        serde_json::from_value(raw.clone())?;
    anyhow::ensure!(
        outcome.delivered.is_empty(),
        "an unknown device was delivered"
    );
    let core_id = project_did_to_core_id(&Did::new(actor_id.to_owned())?)?;
    let row = &raw["unknown_devices"][core_id.as_str()][UNKNOWN_DEVICE_ID];
    anyhow::ensure!(
        *row == serde_json::json!({"device_message_id": device_message_id, "status": "unknown"}),
        "unknown row must carry only device_message_id and status: {raw}"
    );
    Ok(())
}

/// The exact idempotency check precedes the expiry check, so the same intent
/// retried after `expires_at` returns the original result and enqueues nothing.
async fn exact_retry_after_expiry_returns_original_result(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
) -> Result<()> {
    let device_message_id = "ak:device_message:0196419b-0000-7000-8000-00000000f231";
    let expires_at = canonical_millis(chrono::Utc::now() + chrono::Duration::seconds(2))?;
    let body = device_message_send_request(
        actor_id,
        PROTOCOL_DEVICE_ID,
        device_message_id,
        "ak.mls.application",
        encrypted_envelope("ak.mls.application", "base64url-opaque-ciphertext"),
        expires_at,
    )?;
    let send = || {
        server
            .http()
            .post(server.url("/_arkret/self/device_messages"))
            .bearer_auth(token)
            .header("Idempotency-Key", "protocol-device-retry-after-expiry")
            .json(&body)
    };
    let original = expect_json(send(), StatusCode::OK).await?;
    let typed: arkret_models_collaboration::device_messages::DeviceMessagesSendOutcome =
        serde_json::from_value(original.clone())?;
    assert_delivered_to(&typed, actor_id, PROTOCOL_DEVICE_ID, device_message_id)?;

    let wait = (expires_at - chrono::Utc::now())
        .to_std()
        .unwrap_or_default()
        + std::time::Duration::from_millis(500);
    tokio::time::sleep(wait).await;
    anyhow::ensure!(
        chrono::Utc::now() > expires_at,
        "retry is not after expires_at"
    );

    let retry = expect_json(send(), StatusCode::OK).await?;
    anyhow::ensure!(
        retry == original,
        "exact retry after expires_at changed the result: {original} -> {retry}"
    );
    let queue = device_queue(server, token).await?;
    anyhow::ensure!(
        queue.deliveries.len() == 1,
        "exact retry enqueued a second delivery: {}",
        queue.deliveries.len()
    );
    let ack_token = queue
        .ack_token
        .context("a non-empty delivery page carries an ACK token")?;
    expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/device_messages/ack"))
            .bearer_auth(token)
            .json(
                &arkret_models_collaboration::device_messages::DeviceMessagesAckRequestBody {
                    ack_token,
                },
            ),
        StatusCode::OK,
    )
    .await?;
    Ok(())
}

async fn device_queue(
    server: &ArkretServer,
    token: &str,
) -> Result<arkret_models_collaboration::device_messages::DeviceMessagesGetOutcome> {
    Ok(serde_json::from_value(
        expect_json(
            server
                .http()
                .get(server.url("/_arkret/self/device_messages"))
                .bearer_auth(token),
            StatusCode::OK,
        )
        .await?,
    )?)
}

fn canonical_millis(at: chrono::DateTime<chrono::Utc>) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::from_timestamp_millis(at.timestamp_millis())
        .context("timestamp outside range")
}
