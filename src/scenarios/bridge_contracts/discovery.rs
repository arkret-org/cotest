use anyhow::Result;
use reqwest::StatusCode;

use crate::harness::{CokretServer, expect_json};

pub async fn principal_bridge_contracts_are_discoverable() -> Result<()> {
    let server = CokretServer::spawn("bridge-contracts").await?;

    let integration = expect_json(
        server
            .http()
            .get(server.url("/_soland/self/integration/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        integration["contract"],
        "cokret.rest.integration_manifest.v1"
    );
    assert_eq!(integration["service"], "soland");
    assert_eq!(integration["service_kind"], "principal_server");
    assert_eq!(
        integration["dependencies"][0]["required_contract"],
        "oauth2.token_introspection.rfc7662"
    );
    assert_eq!(
        integration["surfaces"][0]["path"],
        "/_soland/gate/auth/bridge/describe"
    );
    assert!(integration["surfaces"].as_array().is_some_and(|surfaces| {
        surfaces.iter().any(|surface| {
            surface["name"] == "authz_describe" && surface["path"] == "/_soland/self/authz/describe"
        })
    }));
    assert!(integration["surfaces"].as_array().is_some_and(|surfaces| {
        surfaces.iter().any(|surface| {
            surface["name"] == "policies_describe"
                && surface["path"] == "/_soland/self/policies/describe"
        })
    }));
    assert_eq!(
        integration["examples"]["compose_strand"]["step_2"]["path"],
        "protected route"
    );
    assert_eq!(
        integration["examples"]["compose_strand"]["step_3"]["path"],
        "/_soland/edge/push/outbound/bridge/fetch"
    );

    let auth_bridge = expect_json(
        server
            .http()
            .get(server.url("/_soland/gate/auth/bridge/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(auth_bridge["contract"], "cokret.rest.principal_bridge.v1");
    assert_eq!(
        auth_bridge["auth"]["session_grant_exchange_path"],
        "/_cokret/gate/account/session-grants"
    );
    assert_eq!(
        auth_bridge["push"]["register_device_path"],
        "/_cokret/edge/push/register-device"
    );
    assert_eq!(
        auth_bridge["examples"]["session_grant_exchange_request"]["principal_id"],
        "did:web:alice.example"
    );
    assert_eq!(
        auth_bridge["examples"]["register_device_request"]["platform"],
        "web"
    );

    let push_bridge = expect_json(
        server
            .http()
            .get(server.url("/_soland/edge/push/outbound/bridge/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        push_bridge["contract"],
        "cokret.rest.outbound_push_bridge.v1"
    );
    assert_eq!(
        push_bridge["gateway_contract"]["resolve_path"],
        "/_soland/edge/push/outbound/bridge/resolve"
    );
    assert_eq!(
        push_bridge["gateway_contract"]["fetch_path"],
        "/_soland/edge/push/outbound/bridge/fetch"
    );
    assert_eq!(
        push_bridge["gateway_contract"]["cache_status_path"],
        "/_soland/edge/push/outbound/bridge/cache/status"
    );
    assert_eq!(
        push_bridge["gateway_contract"]["cache_invalidate_path"],
        "/_soland/edge/push/outbound/bridge/cache/invalidate"
    );
    assert_eq!(
        push_bridge["examples"]["resolve_request"]["push_gateway_url"],
        "https://floria.example/_cokret/edge/push/notify"
    );
    assert_eq!(
        push_bridge["examples"]["fetch_request"]["force_refresh"],
        true
    );

    Ok(())
}
