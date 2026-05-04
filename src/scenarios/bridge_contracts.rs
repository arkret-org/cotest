use anyhow::Result;
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::env;

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

    let integration = expect_json(
        server.http().get(server.url("/api/v1/integration/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(integration["contract"], "contrix.rest.integration_manifest.v1");
    assert_eq!(integration["service"], "soland");
    assert_eq!(integration["service_kind"], "principal_server");
    assert_eq!(
        integration["dependencies"][0]["required_contract"],
        "contrix.rest.auth_bridge.v1"
    );
    assert_eq!(
        integration["surfaces"][0]["path"],
        "/api/v1/auth/bridge/describe"
    );
    assert_eq!(
        integration["examples"]["authz_protocol"]["authz_check_request"]["path"],
        "/api/v1/authz/check"
    );
    assert_eq!(
        integration["examples"]["authz_protocol"]["policy_upsert_request"]["path"],
        "/api/v1/policies"
    );
    assert_eq!(
        integration["examples"]["authz_protocol"]["policy_get_path"],
        "/api/v1/policies/{policy_id}"
    );

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
    let service_integration = expect_json(
        server.http().get(server.url("/api/v1/integration/describe")),
        StatusCode::OK,
    )
    .await?;
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
    let coauth_base_url = configured_external_service_base("COAUTH_BASE_URL");
    let floria_base_url = configured_external_service_base("FLORIA_BASE_URL");

    let coauth_service_integration = load_optional_live_contract(
        coauth_base_url.as_deref(),
        "/api/v1/integration/describe",
    )
    .await?;
    let coauth_auth_bridge = load_optional_live_contract(
        coauth_base_url.as_deref(),
        "/api/v1/auth/bridge/describe",
    )
    .await?;
    let coauth_recovery_bridge = load_optional_live_contract(
        coauth_base_url.as_deref(),
        "/api/v1/auth/recovery/describe",
    )
    .await?;
    let coauth_admin_bridge = load_optional_live_contract(
        coauth_base_url.as_deref(),
        "/api/admin/v1/bridge/describe",
    )
    .await?;
    let floria_service_integration = load_optional_live_contract(
        floria_base_url.as_deref(),
        "/api/v1/integration/describe",
    )
    .await?;
    let floria_push_bridge = load_optional_live_contract(
        floria_base_url.as_deref(),
        "/api/v1/push/bridge/describe",
    )
    .await?;

    let matrix = BridgeContractMatrixScaffold {
        rows: vec![
            snapshot_from_live(
                "soland",
                "service_integration_manifest",
                &service_integration,
                &[
                    "/api/v1/integration/describe",
                    "/api/v1/auth/bridge/describe",
                    "/api/v1/push/outbound/bridge/describe",
                ],
                &[
                    "dependencies.0.discovery_path",
                    "surfaces.0.path",
                    "surfaces.1.path",
                    "examples.authz_protocol.authz_check_request",
                    "examples.authz_protocol.policy_upsert_request",
                ],
            ),
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
            coauth_service_integration.map_or_else(
                || {
                    snapshot_placeholder(
                        "coauth",
                        "service_integration_manifest",
                        "contrix.rest.integration_manifest.v1",
                        &[
                            "/api/v1/integration/describe",
                            "/api/v1/auth/bridge/describe",
                            "/api/admin/v1/bridge/describe",
                        ],
                        &[
                            "dependencies.0.discovery_path",
                            "surfaces.0.path",
                            "surfaces.4.path",
                        ],
                        "TODO(cotest): point COAUTH_BASE_URL at a live coauth service to replace this placeholder row without waiting for a local multi-service harness.",
                    )
                },
                |body| {
                    snapshot_from_live(
                        "coauth",
                        "service_integration_manifest",
                        &body,
                        &[
                            "/api/v1/integration/describe",
                            "/api/v1/auth/bridge/describe",
                            "/api/admin/v1/bridge/describe",
                        ],
                        &[
                            "dependencies.0.discovery_path",
                            "surfaces.0.path",
                            "surfaces.4.path",
                        ],
                    )
                },
            ),
            coauth_auth_bridge.map_or_else(
                || {
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
                        "TODO(cotest): point COAUTH_BASE_URL at a live coauth service to replace this placeholder auth bridge row and assert the OIDC browser/exchange contract.",
                    )
                },
                |body| {
                    snapshot_from_live(
                        "coauth",
                        "auth_bridge",
                        &body,
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
                    )
                },
            ),
            coauth_recovery_bridge.map_or_else(
                || {
                    snapshot_placeholder(
                        "coauth",
                        "recovery_bridge",
                        "contrix.auth.recovery_bridge.v1",
                        &[
                            "/api/v1/auth/recovery/describe",
                            "/api/v1/auth/recovery/start",
                            "/api/v1/auth/recovery/{id}",
                            "/api/v1/auth/recovery/{id}/resend",
                            "/api/v1/recovery/contract-stack",
                            "/api/v1/device_messages/describe",
                            "/api/v1/keys/backups",
                            "/api/v1/keys/backups/describe",
                            "/api/v1/keys/backups/{backup_id}/restore/start",
                            "/api/v1/authz/describe",
                            "/api/v1/policies/describe",
                        ],
                        &[
                            "example_backup_payload",
                            "recovery_restore_examples.restore_start_request",
                            "recovery_restore_examples.restore_ticket_advance_request",
                            "verification_event_kinds",
                            "recovery_modes",
                        ],
                        "TODO(cotest): point COAUTH_BASE_URL at a live coauth service to replace this placeholder recovery bridge row and assert key-backup/device-message recovery contract compatibility.",
                    )
                },
                |body| {
                    snapshot_from_live(
                        "coauth",
                        "recovery_bridge",
                        &body,
                        &[
                            "/api/v1/auth/recovery/describe",
                            "/api/v1/auth/recovery/start",
                            "/api/v1/auth/recovery/{id}",
                            "/api/v1/auth/recovery/{id}/resend",
                            "/api/v1/recovery/contract-stack",
                            "/api/v1/device_messages/describe",
                            "/api/v1/keys/backups",
                            "/api/v1/keys/backups/describe",
                            "/api/v1/keys/backups/{backup_id}/restore/start",
                            "/api/v1/authz/describe",
                            "/api/v1/policies/describe",
                        ],
                        &[
                            "example_backup_payload",
                            "recovery_restore_examples.restore_start_request",
                            "recovery_restore_examples.restore_ticket_advance_request",
                            "verification_event_kinds",
                            "recovery_modes",
                        ],
                    )
                },
            ),
            BridgeContractSnapshot {
                service: "compose",
                surface: "recovery_authz_policy_alignment",
                contract: "contrix.contract_alignment.recovery_authz.v1".to_owned(),
                version: "2026-05-04-scaffold".to_owned(),
                required_paths: vec![
                    "/api/v1/auth/recovery/describe".to_owned(),
                    "/api/v1/recovery/contract-stack".to_owned(),
                    "/api/v1/device_messages/describe".to_owned(),
                    "/api/v1/keys/backups".to_owned(),
                    "/api/v1/keys/backups/describe".to_owned(),
                    "/api/v1/keys/backups/{backup_id}/restore/start".to_owned(),
                    "/api/v1/authz/describe".to_owned(),
                    "/api/v1/authz/check".to_owned(),
                    "/api/v1/policies/describe".to_owned(),
                    "/api/v1/policies".to_owned(),
                ],
                example_keys: vec![
                    "coauth.example_backup_payload".to_owned(),
                    "coauth.recovery_restore_examples.restore_start_request".to_owned(),
                    "coauth.recovery_restore_examples.restore_ticket_advance_request".to_owned(),
                    "coauth.recovery_authz_examples.authz_check_request".to_owned(),
                    "coauth.recovery_authz_examples.policy_upsert_request".to_owned(),
                    "soland.examples.authz_protocol.authz_check_request".to_owned(),
                    "soland.examples.authz_protocol.policy_upsert_request".to_owned(),
                    "soland.examples.key_backups.put_request".to_owned(),
                ],
                todo: "TODO(cotest): replace this synthetic alignment row with a live composed coauth + soland recovery restore flow once the stack harness can execute cross-service recovery/authz/policy handoff.",
            },
            coauth_admin_bridge.map_or_else(
                || {
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
                        "TODO(cotest): point COAUTH_BASE_URL at a live coauth service to replace this placeholder admin bridge row without waiting for a spawned coauth harness.",
                    )
                },
                |body| {
                    snapshot_from_live(
                        "coauth",
                        "admin_bridge",
                        &body,
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
                    )
                },
            ),
            floria_service_integration.map_or_else(
                || {
                    snapshot_placeholder(
                        "floria",
                        "service_integration_manifest",
                        "contrix.rest.integration_manifest.v1",
                        &[
                            "/api/v1/integration/describe",
                            "/api/v1/push/bridge/describe",
                            "/api/v1/push/notify",
                        ],
                        &[
                            "dependencies.0.discovery_path",
                            "surfaces.0.path",
                            "surfaces.1.path",
                        ],
                        "TODO(cotest): point FLORIA_BASE_URL at a live floria service to replace this placeholder row without waiting for a local push-gateway harness.",
                    )
                },
                |body| {
                    snapshot_from_live(
                        "floria",
                        "service_integration_manifest",
                        &body,
                        &[
                            "/api/v1/integration/describe",
                            "/api/v1/push/bridge/describe",
                            "/api/v1/push/notify",
                        ],
                        &[
                            "dependencies.0.discovery_path",
                            "surfaces.0.path",
                            "surfaces.1.path",
                        ],
                    )
                },
            ),
            floria_push_bridge.map_or_else(
                || {
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
                        "TODO(cotest): point FLORIA_BASE_URL at a live floria service to replace this placeholder gateway row and assert notify example/header compatibility against soland outbound bridge.",
                    )
                },
                |body| {
                    snapshot_from_live(
                        "floria",
                        "push_bridge",
                        &body,
                        &[
                            "/api/v1/push/bridge/describe",
                            "/api/v1/push/notify",
                        ],
                        &[
                            "examples.notify_headers",
                            "examples.blind_wakeup_request",
                            "examples.plaintext_visible_service_request",
                        ],
                    )
                },
            ),
        ],
    };

    assert_eq!(matrix.rows.len(), 10);
    assert!(matrix.rows.iter().any(|row| {
        row.service == "soland" && row.surface == "principal_auth_bridge"
    }));
    assert!(matrix.rows.iter().any(|row| {
        row.service == "soland" && row.surface == "service_integration_manifest"
    }));
    assert!(matrix.rows.iter().any(|row| {
        row.service == "coauth" && row.surface == "auth_bridge"
    }));
    assert!(matrix.rows.iter().any(|row| {
        row.service == "coauth" && row.surface == "recovery_bridge"
    }));
    assert!(matrix.rows.iter().any(|row| {
        row.service == "compose" && row.surface == "recovery_authz_policy_alignment"
    }));
    assert!(matrix.rows.iter().any(|row| {
        row.service == "coauth" && row.surface == "service_integration_manifest"
    }));
    assert!(matrix.rows.iter().any(|row| {
        row.service == "floria" && row.surface == "push_bridge"
    }));
    assert!(matrix.rows.iter().any(|row| {
        row.service == "floria" && row.surface == "service_integration_manifest"
    }));
    assert!(matrix
        .rows
        .iter()
        .all(|row| !row.required_paths.is_empty() && !row.example_keys.is_empty()));

    Ok(())
}

fn configured_external_service_base(env_key: &str) -> Option<String> {
    env::var(env_key)
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_owned())
        .filter(|value| !value.is_empty())
}

async fn load_optional_live_contract(
    base_url: Option<&str>,
    path: &str,
) -> Result<Option<Value>> {
    let Some(base_url) = base_url else {
        return Ok(None);
    };
    let url = format!("{base_url}{path}");
    let client = reqwest::Client::new();
    let body = expect_json(client.get(url), StatusCode::OK).await?;
    Ok(Some(body))
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
