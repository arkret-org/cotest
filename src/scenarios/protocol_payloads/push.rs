//! Phase 9 — `/_cokret/edge/push/{register-device,notify}`.
//!
//! Registers Alice's device with the push gateway, then dispatches a blind
//! wakeup to two devices to confirm the missing one is reported back in
//! `rejected`.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{CokretServer, expect_json};

pub async fn run(server: &CokretServer, token: &str) -> Result<()> {
    register_device(server, token).await?;
    notify_blind_wakeup(server).await?;
    Ok(())
}

async fn register_device(server: &CokretServer, token: &str) -> Result<()> {
    let push = expect_json(
        server
            .http()
            .post(server.url("/_cokret/edge/push/register-device"))
            .bearer_auth(token)
            .json(&json!({
                "device_id": "ck:device:01904100-0000-7000-8000-0000000000a1",
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

async fn notify_blind_wakeup(server: &CokretServer) -> Result<()> {
    let notify = expect_json(
        server
            .http()
            .post(server.url("/_cokret/edge/push/notify"))
            .json(&json!({
                "notification": {
                    "wakeup_kind": "message",
                    "devices": [{"device_id": "ck:device:01904100-0000-7000-8000-0000000000a1"}, {"device_id": "ck:device:01904100-0000-7000-8000-00000000dead"}]
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(notify["rejected"].as_array().unwrap().len(), 1);
    Ok(())
}
