//! Phase 9 — `/_arkret/edge/push/{register-device,notify}`.
//!
//! Registers Alice's device with the push gateway, then dispatches a blind
//! wakeup to two devices to confirm the unregistered one comes back with a
//! `rejected` gateway_status while the registered one is accepted.

use anyhow::{Context, Result};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ArkretServer, expect_json};

pub async fn run(server: &ArkretServer, token: &str) -> Result<()> {
    let push_target_id = register_device(server, token).await?;
    notify_blind_wakeup(server, &push_target_id).await?;
    Ok(())
}

async fn register_device(server: &ArkretServer, token: &str) -> Result<arkret_wire::PushTargetId> {
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
    // push-notifications.md §3.1 requires the register-device response to
    // return the server-derived `push_target_id`; the harness uses that value
    // verbatim as the notify target and never re-spells it from the
    // gateway-local `registration_id`.
    let outcome: arkret_models_integration::PushRegisterDeviceOutcome =
        serde_json::from_value(push)
            .context("register-device response is not a PushRegisterDeviceOutcome")?;
    assert!(outcome.ok);
    Ok(outcome.push_target_id)
}

async fn notify_blind_wakeup(
    server: &ArkretServer,
    push_target_id: &arkret_wire::PushTargetId,
) -> Result<()> {
    let notify = expect_json(
        server
            .http()
            .post(server.url("/_arkret/edge/push/notify"))
            .json(&serde_json::from_value::<
                arkret_models_integration::PushNotifyRequestBody,
            >(json!({
                "notification": {
                    "push_target_id": push_target_id.as_str(),
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
    assert_eq!(notify["push_target_id"], push_target_id.as_str());
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
