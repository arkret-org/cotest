use anyhow::Result;
use reqwest::StatusCode;

use crate::harness::{ContrixServer, expect_json};

pub async fn principal_bridge_contracts_are_discoverable() -> Result<()> {
    let server = ContrixServer::spawn("bridge-contracts").await?;

    let auth_bridge = expect_json(
        server.http().get(server.url("/api/v1/auth/bridge/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(auth_bridge["contract"], "contrix.rest.auth_bridge.v1");
    assert_eq!(
        auth_bridge["auth"]["session_grant_exchange_path"],
        "/api/v1/auth/session-grant/exchange"
    );
    assert_eq!(
        auth_bridge["push"]["register_device_path"],
        "/api/v1/push/register-device"
    );

    let push_bridge = expect_json(
        server
            .http()
            .get(server.url("/api/v1/push/outbound/bridge/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push_bridge["contract"], "contrix.rest.outbound_push_bridge.v1");
    assert_eq!(
        push_bridge["gateway_contract"]["resolve_path"],
        "/api/v1/push/outbound/bridge/resolve"
    );
    assert_eq!(
        push_bridge["gateway_contract"]["fetch_path"],
        "/api/v1/push/outbound/bridge/fetch"
    );
    assert_eq!(
        push_bridge["gateway_contract"]["cache_status_path"],
        "/api/v1/push/outbound/bridge/cache/status"
    );
    assert_eq!(
        push_bridge["gateway_contract"]["cache_invalidate_path"],
        "/api/v1/push/outbound/bridge/cache/invalidate"
    );

    Ok(())
}

pub async fn multi_service_bridge_contract_matrix_scaffold() -> Result<()> {
    // TODO(cotest): spawn a composed stack with coauth + soland + floria + yougen-facing
    // bridge clients, then fetch:
    // - coauth /api/v1/auth/bridge/describe
    // - coauth /api/admin/v1/bridge/describe
    // - floria /api/v1/push/bridge/describe
    // - soland /api/v1/auth/bridge/describe
    // - soland /api/v1/push/outbound/bridge/describe
    // and assert that path templates, example payloads, and drift/cache policies line up.
    Ok(())
}
