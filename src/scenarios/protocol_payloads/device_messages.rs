//! Phase 2 — `/_arkret/self/device_messages` send / duplicate / list / describe
//! plus the `ak.secret.request` side channel.

use anyhow::Result;
use reqwest::StatusCode;

use crate::harness::{ArkretServer, device_message_send_request, encrypted_envelope, expect_json};

pub async fn run(server: &ArkretServer, token: &str, actor_id: &str) -> Result<()> {
    send_application_message(server, token, actor_id).await?;
    duplicate_send_is_idempotent(server, token, actor_id).await?;
    list_delivered_keeps_ciphertext_only(server, token).await?;
    send_verification_message(server, token, actor_id).await?;
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
                        chrono::DateTime::parse_from_rfc3339("2026-12-31T00:00:00.000Z")?
                            .with_timezone(&chrono::Utc),
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
        serde_json::from_value(expect_json(
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
                chrono::DateTime::parse_from_rfc3339("2026-12-31T00:00:00.000Z")?
                    .with_timezone(&chrono::Utc),
            )?),
        StatusCode::OK,
    )
    .await?)?;
    assert_delivered_to(
        &duplicate_send,
        actor_id,
        "ak:device:01904100-0000-7000-8000-0000000000a1",
        "ak:device_message:0196419b-0000-7000-8000-00000000f201",
    )?;
    Ok(())
}

async fn list_delivered_keeps_ciphertext_only(server: &ArkretServer, token: &str) -> Result<()> {
    let delivered = expect_json(
        server
            .http()
            .get(server.url("/_arkret/self/device_messages"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    let content = &delivered["messages"][0]["content"];
    assert_eq!(content["ciphertext"], "base64url-opaque-ciphertext");
    assert!(content.get("plaintext").is_none());
    Ok(())
}

async fn send_verification_message(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
) -> Result<()> {
    let verification_send: arkret_models_collaboration::device_messages::DeviceMessagesSendOutcome =
        serde_json::from_value(expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/device_messages"))
            .bearer_auth(token)
            .header("Idempotency-Key", "protocol-verification-txn")
            .json(&device_message_send_request(
                actor_id,
                "ak:device:01904100-0000-7000-8000-0000000000a1",
                "ak:device_message:0196419b-0000-7000-8000-00000000f202",
                "ak.secret.request",
                encrypted_envelope(
                    "ak.secret.request",
                    "base64url-opaque-verification-ciphertext",
                ),
                chrono::DateTime::parse_from_rfc3339("2026-12-31T00:00:00.000Z")?
                    .with_timezone(&chrono::Utc),
            )?),
        StatusCode::OK,
    )
    .await?)?;
    assert_delivered_to(
        &verification_send,
        actor_id,
        "ak:device:01904100-0000-7000-8000-0000000000a1",
        "ak:device_message:0196419b-0000-7000-8000-00000000f202",
    )?;
    Ok(())
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
    use arkret_models_collaboration::device_messages::DeviceMessageDeliveredStatus;
    use arkret_identifiers::{DeviceId, DeviceMessageId, Did, project_did_to_core_id};

    let core_id = project_did_to_core_id(&Did::new(actor_id.to_owned())?)?;
    let device_id = DeviceId::new(device_id.to_owned())?;
    let devices = outcome
        .delivered
        .get(&core_id)
        .ok_or_else(|| anyhow::anyhow!("send outcome delivered nothing to {core_id}"))?;
    let row = devices.get(&device_id).ok_or_else(|| {
        anyhow::anyhow!("send outcome delivered nothing to device {device_id}")
    })?;
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
