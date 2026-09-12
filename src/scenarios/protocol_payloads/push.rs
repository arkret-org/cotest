//! Station-owned authenticated push registration. Gateway dispatch is exercised
//! separately with an authenticated source and a durable registration directory.

use anyhow::{Context, Result};
use arkret_models_integration::{PushKey, PushRegisterDeviceRequestBody};
use arkret_wire::DeviceId;
use reqwest::StatusCode;

use crate::harness::{ArkretServer, expect_json};

const REGISTERED_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";
pub async fn run(server: &ArkretServer, token: &str) -> Result<()> {
    register_device(server, token).await?;
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
                visible_notification_opt_in: false,
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
