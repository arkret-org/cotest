//! Phase 9 — `/_arkret/edge/push/{register-device,notify}`.
//!
//! Registers Alice's device with the push gateway, then dispatches a blind
//! wakeup to two devices to confirm the unregistered one comes back with a
//! `rejected` gateway_status while the registered one is accepted.

use anyhow::{Context, Result};
use arkret_models_integration::{
    PushDeviceRoute, PushKey, PushNotificationEnvelope, PushNotifyRequestBody,
    PushRegisterDeviceRequestBody, PushTimingProfileHint,
};
use arkret_wire::DeviceId;
use reqwest::StatusCode;

use crate::harness::{ArkretServer, expect_json};

const REGISTERED_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";
const UNREGISTERED_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-00000000dead";

fn push_device_route(device_id: &str) -> Result<PushDeviceRoute> {
    Ok(PushDeviceRoute {
        device_id: DeviceId::new(device_id)?,
        push_key: None,
        app_id: None,
        platform: None,
        target_route_token: None,
        visible_notification_opt_in: false,
    })
}

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
            .json(&PushRegisterDeviceRequestBody {
                device_id: DeviceId::new(REGISTERED_DEVICE_ID)?,
                push_gateway_url: "https://push.example".to_owned(),
                push_key: PushKey::new("opaque").map_err(anyhow::Error::msg)?,
                platform: Some("desktop".to_owned()),
                app_id: Some("inkson".to_owned()),
                display_name: None,
                recipient_id: None,
            }),
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
            .json(&PushNotifyRequestBody {
                notification: PushNotificationEnvelope {
                    push_target_id: Some(push_target_id.clone()),
                    wakeup_kind: Some("message".to_owned()),
                    timing_profile_hint: Some(PushTimingProfileHint::Default),
                    devices: vec![
                        push_device_route(REGISTERED_DEVICE_ID)?,
                        push_device_route(UNREGISTERED_DEVICE_ID)?,
                    ],
                    ..PushNotificationEnvelope::default()
                },
                event_kind: None,
                reason_code: None,
                audit_envelope: None,
            }),
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
