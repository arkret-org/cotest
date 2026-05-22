//! Phase 9 — `/api/v1/push/{register-device,notify}`.
//!
//! Registers Alice's device with the push gateway, then dispatches a blind
//! wakeup to two devices to confirm the missing one is reported back in
//! `rejected`.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ContrixServer, expect_json};

pub async fn run(server: &ContrixServer, token: &str) -> Result<()> {
    register_device(server, token).await?;
    notify_blind_wakeup(server).await?;
    Ok(())
}

async fn register_device(server: &ContrixServer, token: &str) -> Result<()> {
    let push = expect_json(
        server
            .http()
            .post(server.url("/api/v1/push/register-device"))
            .bearer_auth(token)
            .json(&json!({
                "device_id": "dev_alice",
                "push_gateway": "https://push.example",
                "push_key": "opaque",
                "platform": "desktop",
                "app_id": "yougen"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push["ok"], true);
    Ok(())
}

async fn notify_blind_wakeup(server: &ContrixServer) -> Result<()> {
    let notify = expect_json(
        server
            .http()
            .post(server.url("/api/v1/push/notify"))
            .json(&json!({
                "notification": {
                    "type": "blind_wakeup",
                    "devices": [{"device_id": "dev_alice"}, {"device_id": "dev_missing"}]
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(notify["rejected"].as_array().unwrap().len(), 1);
    Ok(())
}
