//! Phase 2 — `/_arkret/self/device_messages` send / duplicate / list / describe
//! plus the `ak.key.verification.request` side channel.

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
    let send = expect_json(
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
    .await?;
    assert_eq!(send["ok"], true);
    Ok(())
}

async fn duplicate_send_is_idempotent(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
) -> Result<()> {
    let duplicate_send = expect_json(
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
    .await?;
    assert_eq!(duplicate_send["ok"], true);
    let actor_core_id = crate::harness::actor_core_id(actor_id)?;
    assert_eq!(
        duplicate_send["delivered"][actor_core_id][0],
        "ak:device:01904100-0000-7000-8000-0000000000a1"
    );
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
    let verification_send = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/device_messages"))
            .bearer_auth(token)
            .header("Idempotency-Key", "protocol-verification-txn")
            .json(&device_message_send_request(
                actor_id,
                "ak:device:01904100-0000-7000-8000-0000000000a1",
                "ak:device_message:0196419b-0000-7000-8000-00000000f202",
                "ak.key.verification.request",
                encrypted_envelope(
                    "ak.key.verification.request",
                    "base64url-opaque-verification-ciphertext",
                ),
                chrono::DateTime::parse_from_rfc3339("2026-12-31T00:00:00.000Z")?
                    .with_timezone(&chrono::Utc),
            )?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(verification_send["ok"], true);
    Ok(())
}
