//! Phase 2 — `/_arkret/self/device_messages` send / duplicate / list / describe.

use anyhow::{Context, Result};
use reqwest::StatusCode;

use crate::harness::{ArkretServer, device_message_send_request, encrypted_envelope, expect_json};

const PROTOCOL_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";
const PROTOCOL_MESSAGE_ID: &str = "ak:device_message:0196419b-0000-7000-8000-00000000f201";

pub async fn run(server: &ArkretServer, token: &str, actor_id: &str) -> Result<()> {
    send_application_message(server, token, actor_id).await?;
    duplicate_send_is_idempotent(server, token, actor_id).await?;
    list_delivered_keeps_ciphertext_only(server, token, actor_id).await?;
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
                .json(&serde_json::json!({ "ack_token": ack_token })),
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
