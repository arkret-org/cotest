//! Station-owned authenticated push registration against a Gateway URL the
//! Station has not onboarded.
//!
//! push-notifications.md §3.3: a bare `push_gateway_url` never establishes
//! trust. The Station resolves it only to a pre-onboarded canonical Gateway
//! origin and service DID and fails closed otherwise, so registering with an
//! arbitrary origin must be rejected with the operation's registered
//! `push_gateway_unreachable` and must install nothing. Because nothing was
//! installed, §3.2 unregistration of the same device is the idempotent 204.
//!
//! The onboarded-Gateway success path needs a live Gateway that publishes its
//! verifiable service resolution and role-scoped Describe; it belongs to the
//! joint `ak.vector.push.registration_handoff_lifecycle.v1` run, not to this
//! single-Station payload walk.

use anyhow::{Context, Result, ensure};
use arkret_models_integration::{
    PushKey, PushRegisterDeviceRequestBody, PushUnregisterDeviceRequestBody,
};
use arkret_wire::DeviceId;
use reqwest::StatusCode;

use crate::harness::{ArkretServer, expect_api_error, expect_response};

const REGISTERED_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";
const NOT_ONBOARDED_GATEWAY_URL: &str = "https://push.example";
const APP_ID: &str = "inkson";

pub async fn run(server: &ArkretServer, token: &str) -> Result<()> {
    // Retrying must not turn a refused registration into a half-installed one.
    for attempt in ["first", "retry"] {
        register_with_not_onboarded_gateway(server, token)
            .await
            .with_context(|| format!("{attempt} registration with a non-onboarded Gateway"))?;
    }
    unregister_is_idempotent_without_installation(server, token).await
}

async fn register_with_not_onboarded_gateway(server: &ArkretServer, token: &str) -> Result<()> {
    let problem = expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/edge/push/register-device"))
            .bearer_auth(token)
            .json(&PushRegisterDeviceRequestBody {
                device_id: DeviceId::new(REGISTERED_DEVICE_ID)?,
                push_gateway_url: NOT_ONBOARDED_GATEWAY_URL.to_owned(),
                push_key: PushKey::new("opaque").map_err(anyhow::Error::msg)?,
                platform: Some("desktop".to_owned()),
                app_id: Some(APP_ID.to_owned()),
                display_name: None,
                visible_notification_opt_in: false,
            }),
        StatusCode::SERVICE_UNAVAILABLE,
        "push_gateway_unreachable",
    )
    .await?;
    let rendered = serde_json::to_string(&problem)?;
    ensure!(
        !rendered.contains("opaque"),
        "a refused registration must not echo the provider route: {rendered}"
    );
    Ok(())
}

async fn unregister_is_idempotent_without_installation(
    server: &ArkretServer,
    token: &str,
) -> Result<()> {
    let response = expect_response(
        server
            .http()
            .post(server.url("/_arkret/edge/push/unregister-device"))
            .bearer_auth(token)
            .json(&PushUnregisterDeviceRequestBody {
                device_id: DeviceId::new(REGISTERED_DEVICE_ID)?,
                push_key: None,
                app_id: Some(APP_ID.to_owned()),
            }),
        StatusCode::NO_CONTENT,
    )
    .await?;
    ensure!(
        response.body.is_empty(),
        "unregister-device 204 must carry no entity body"
    );
    Ok(())
}
