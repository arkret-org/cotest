use anyhow::Result;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{ContrixServer, expect_json};

#[derive(Debug)]
struct BridgeContractSnapshot {
    service: &'static str,
    surface: &'static str,
    contract: String,
    version: String,
    required_paths: Vec<String>,
    example_keys: Vec<String>,
    todo: &'static str,
}

#[derive(Debug)]
struct BridgeContractMatrixScaffold {
    rows: Vec<BridgeContractSnapshot>,
}

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
    assert_eq!(
        auth_bridge["examples"]["session_grant_exchange_request"]["principal_did"],
        "did:web:alice.example"
    );
    assert_eq!(
        auth_bridge["examples"]["register_device_request"]["platform"],
        "web"
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
    assert_eq!(
        push_bridge["examples"]["resolve_request"]["push_gateway_url"],
        "https://floria.example/api/v1/push/notify"
    );
    assert_eq!(
        push_bridge["examples"]["fetch_request"]["force_refresh"],
        true
    );

    Ok(())
}

pub async fn multi_service_bridge_contract_matrix_scaffold() -> Result<()> {
    let server = ContrixServer::spawn("bridge-matrix").await?;
    let principal_auth = expect_json(
        server.http().get(server.url("/api/v1/auth/bridge/describe")),
        StatusCode::OK,
    )
    .await?;
    let principal_push = expect_json(
        server
            .http()
            .get(server.url("/api/v1/push/outbound/bridge/describe")),
        StatusCode::OK,
    )
    .await?;

    let matrix = BridgeContractMatrixScaffold {
        rows: vec![
            snapshot_from_live(
                "soland",
                "principal_auth_bridge",
                &principal_auth,
                &[
                    "/api/v1/auth/dev-login",
                    "/api/v1/auth/session-grant/exchange",
                    "/api/v1/push/register-device",
                ],
                &[
                    "examples.session_grant_exchange_request",
                    "examples.register_device_request",
                    "examples.unregister_device_request",
                ],
            ),
            snapshot_from_live(
                "soland",
                "principal_outbound_push_bridge",
                &principal_push,
                &[
                    "/api/v1/push/outbound/bridge/resolve",
                    "/api/v1/push/outbound/bridge/fetch",
                    "/api/v1/push/outbound/bridge/cache/status",
                    "/api/v1/push/outbound/bridge/cache/invalidate",
                ],
                &[
                    "examples.resolve_request",
                    "examples.fetch_request",
                    "examples.notify_headers",
                ],
            ),
            snapshot_placeholder(
                "coauth",
                "auth_bridge",
                "contrix.rest.auth_bridge.v1",
                &[
                    "/api/v1/auth/bridge/describe",
                    "/api/v1/auth/oidc/browser-bridge/session",
                    "/api/v1/auth/oidc/exchange/describe",
                    "/api/v1/auth/oidc/exchange",
                ],
                &[
                    "oauth.browser_bridge_session_path",
                    "oauth.exchange_describe_path",
                    "oauth.exchange_path",
                ],
                "TODO(cotest): replace placeholder with live coauth process/container and assert full OIDC browser/exchange contract matrix",
            ),
            snapshot_placeholder(
                "coauth",
                "admin_bridge",
                "contrix.rest.coauth_admin_bridge.v1",
                &[
                    "/api/admin/v1/bridge/describe",
                    "/api/admin/v1/accounts/{account_id}/claims",
                    "/api/admin/v1/accounts/{account_id}/session-grants",
                    "/api/admin/v1/accounts/{account_id}/risk-action",
                ],
                &[
                    "risk_action_examples.proposal_request",
                    "risk_action_examples.approve_request",
                    "risk_action_examples.execute_request",
                ],
                "TODO(cotest): replace placeholder with live coauth admin bridge assertions once multi-service harness can spawn coauth",
            ),
            snapshot_placeholder(
                "floria",
                "push_bridge",
                "cx.push.bridge.describe",
                &[
                    "/api/v1/push/bridge/describe",
                    "/api/v1/push/notify",
                ],
                &[
                    "examples.notify_headers",
                    "examples.blind_wakeup_request",
                    "examples.plaintext_visible_service_request",
                ],
                "TODO(cotest): replace placeholder with live floria gateway and assert notify example/header compatibility against soland outbound bridge",
            ),
        ],
    };

    assert_eq!(matrix.rows.len(), 5);
    assert!(matrix.rows.iter().any(|row| {
        row.service == "soland" && row.surface == "principal_auth_bridge"
    }));
    assert!(matrix.rows.iter().any(|row| {
        row.service == "coauth" && row.surface == "auth_bridge"
    }));
    assert!(matrix.rows.iter().any(|row| {
        row.service == "floria" && row.surface == "push_bridge"
    }));
    assert!(matrix
        .rows
        .iter()
        .all(|row| !row.required_paths.is_empty() && !row.example_keys.is_empty()));

    Ok(())
}

fn snapshot_from_live(
    service: &'static str,
    surface: &'static str,
    body: &Value,
    required_paths: &[&str],
    example_keys: &[&str],
) -> BridgeContractSnapshot {
    BridgeContractSnapshot {
        service,
        surface,
        contract: body
            .get("contract")
            .and_then(Value::as_str)
            .unwrap_or("missing")
            .to_owned(),
        version: body
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("missing")
            .to_owned(),
        required_paths: required_paths.iter().map(|value| (*value).to_owned()).collect(),
        example_keys: example_keys.iter().map(|value| (*value).to_owned()).collect(),
        todo: "TODO(cotest): expand this live bridge row with cross-service semantic assertions once the composed stack harness lands",
    }
}

fn snapshot_placeholder(
    service: &'static str,
    surface: &'static str,
    contract: &'static str,
    required_paths: &[&str],
    example_keys: &[&str],
    todo: &'static str,
) -> BridgeContractSnapshot {
    let _placeholder_body = json!({
        "service": service,
        "surface": surface,
        "contract": contract,
        "required_paths": required_paths,
        "example_keys": example_keys,
    });
    BridgeContractSnapshot {
        service,
        surface,
        contract: contract.to_owned(),
        version: "2026-05-04-scaffold".to_owned(),
        required_paths: required_paths.iter().map(|value| (*value).to_owned()).collect(),
        example_keys: example_keys.iter().map(|value| (*value).to_owned()).collect(),
        todo,
    }
}
