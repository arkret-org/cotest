//! Phase 2 — `/_cokret/self/device_messages` send / duplicate / list / describe
//! plus the `ck.key.verification.request` side channel.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{CokretServer, encrypted_envelope, expect_json};

pub async fn run(server: &CokretServer, token: &str) -> Result<()> {
    send_application_message(server, token).await?;
    duplicate_send_is_idempotent(server, token).await?;
    list_delivered_keeps_ciphertext_only(server, token).await?;
    describe_contract_is_stable(server, token).await?;
    send_verification_message(server, token).await?;
    Ok(())
}

async fn send_application_message(server: &CokretServer, token: &str) -> Result<()> {
    let send = expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/device_messages"))
            .bearer_auth(token)
            .header("Idempotency-Key", "protocol-device-txn")
            .json(&json!({
                "messages": {
                    "did:web:alice.example": {
                        "dev_alice": {
                            "type": "cx.mls.application",
                            "content": encrypted_envelope("cx.mls.application", "base64url-opaque-ciphertext")
                        }
                    }
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(send["ok"], true);
    Ok(())
}

async fn duplicate_send_is_idempotent(server: &CokretServer, token: &str) -> Result<()> {
    let duplicate_send = expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/device_messages"))
            .bearer_auth(token)
            .header("Idempotency-Key", "protocol-device-txn")
            .json(&json!({
                "messages": {
                    "did:web:alice.example": {
                        "dev_alice": {
                            "type": "cx.mls.application",
                            "content": encrypted_envelope("cx.mls.application", "base64url-opaque-ciphertext")
                        }
                    }
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(duplicate_send["delivered"].as_object().unwrap().len(), 0);
    Ok(())
}

async fn list_delivered_keeps_ciphertext_only(server: &CokretServer, token: &str) -> Result<()> {
    let delivered = expect_json(
        server
            .http()
            .get(server.url("/_cokret/self/device_messages"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    let content = &delivered["events"][0]["content"]["content"];
    assert_eq!(content["ciphertext"], "base64url-opaque-ciphertext");
    assert!(content.get("plaintext").is_none());
    Ok(())
}

async fn describe_contract_is_stable(server: &CokretServer, token: &str) -> Result<()> {
    let device_messages_describe = expect_json(
        server
            .http()
            .get(server.url("/_cokret/self/device_messages/describe"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        device_messages_describe["contract"],
        "cokret.rest.device_messages_describe.v1"
    );
    assert_eq!(
        device_messages_describe["schema"],
        "ck.schema.device_message.v1"
    );
    Ok(())
}

async fn send_verification_message(server: &CokretServer, token: &str) -> Result<()> {
    let verification_send = expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/device_messages"))
            .bearer_auth(token)
            .header("Idempotency-Key", "protocol-verification-txn")
            .json(&json!({
                "messages": {
                    "did:web:alice.example": {
                        "dev_alice": {
                            "type": "ck.key.verification.request",
                            "content": encrypted_envelope(
                                "ck.key.verification.request",
                                "base64url-opaque-verification-ciphertext"
                            )
                        }
                    }
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(verification_send["ok"], true);
    Ok(())
}
