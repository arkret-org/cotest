//! Phase 9 — `/_arkret/edge/push/{register-device,notify}`.
//!
//! Registers Alice's device with the push gateway, then dispatches a blind
//! wakeup to two devices to confirm the unregistered one comes back with a
//! `rejected` gateway_status while the registered one is accepted.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ArkretServer, expect_json};

pub async fn run(server: &ArkretServer, token: &str) -> Result<()> {
    let push_target_id = register_device(server, token).await?;
    notify_blind_wakeup(server, &push_target_id).await?;
    Ok(())
}

async fn register_device(server: &ArkretServer, token: &str) -> Result<String> {
    let push = expect_json(
        server
            .http()
            .post(server.url("/_arkret/edge/push/register-device"))
            .bearer_auth(token)
            .json(&serde_json::from_value::<
                arkret_models_integration::PushRegisterDeviceRequestBody,
            >(json!({
                "device_id": "ak:device:01904100-0000-7000-8000-0000000000a1",
                "push_gateway": "https://push.example",
                "push_key": "opaque",
                "platform": "desktop",
                "app_id": "inkson"
            }))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push["ok"], true);
    // The registration returns the device's derived push target pseudonym; the
    // blind wakeup routes by that target so the registered device is matched.
    Ok(push["registration_id"]
        .as_str()
        .expect("register-device must return a registration_id")
        .to_owned())
}

async fn notify_blind_wakeup(server: &ArkretServer, push_target_id: &str) -> Result<()> {
    let notify = expect_json(
        server
            .http()
            .post(server.url("/_arkret/edge/push/notify"))
            .json(&serde_json::from_value::<
                arkret_models_integration::PushNotifyRequestBody,
            >(json!({
                "notification": {
                    "push_target_id": push_target_id,
                    "wakeup_kind": "message",
                    "timing_profile_hint": "default",
                    "devices": [{"device_id": "ak:device:01904100-0000-7000-8000-0000000000a1"}, {"device_id": "ak:device:01904100-0000-7000-8000-00000000dead"}]
                }
            }))?),
        StatusCode::OK,
    )
    .await?;
    // `push_notify_outcome` reports one entry per requested device rather than
    // accepted / rejected buckets. The registered device is accepted; the
    // device that was never registered is rejected as `push_token_unknown`.
    assert_eq!(notify["push_target_id"], push_target_id);
    let outcomes = notify["outcomes"]
        .as_array()
        .expect("push notify must return per-device outcomes");
    assert_eq!(outcomes.len(), 2);
    let registered = outcomes
        .iter()
        .find(|outcome| outcome["device_id"] == "ak:device:01904100-0000-7000-8000-0000000000a1")
        .expect("registered device outcome");
    assert_eq!(registered["gateway_status"], "accepted");
    assert!(registered.get("reason_code").is_none());
    let unregistered = outcomes
        .iter()
        .find(|outcome| outcome["device_id"] == "ak:device:01904100-0000-7000-8000-00000000dead")
        .expect("unregistered device outcome");
    assert_eq!(unregistered["gateway_status"], "rejected");
    assert_eq!(unregistered["reason_code"], "push_token_unknown");
    Ok(())
}
