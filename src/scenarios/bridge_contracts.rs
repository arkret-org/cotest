use anyhow::Result;
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::{
    env,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration as StdDuration,
};

use crate::harness::{ContrixServer, expect_json};

#[derive(Debug)]
#[allow(dead_code)]
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
        server
            .http()
            .get(server.url("/api/v1/integration/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        integration["contract"],
        "contrix.rest.integration_manifest.v1"
    );
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
    assert!(integration["surfaces"].as_array().is_some_and(|surfaces| {
        surfaces.iter().any(|surface| {
            surface["name"] == "authz_describe" && surface["path"] == "/api/v1/authz/describe"
        })
    }));
    assert!(integration["surfaces"].as_array().is_some_and(|surfaces| {
        surfaces.iter().any(|surface| {
            surface["name"] == "policies_describe" && surface["path"] == "/api/v1/policies/describe"
        })
    }));
    assert_eq!(
        integration["examples"]["compose_flow"]["step_2"]["path"],
        "/api/v1/auth/session-grant/exchange"
    );
    assert_eq!(
        integration["examples"]["compose_flow"]["step_3"]["path"],
        "/api/v1/push/outbound/bridge/fetch"
    );

    let auth_bridge = expect_json(
        server
            .http()
            .get(server.url("/api/v1/auth/bridge/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(auth_bridge["contract"], "contrix.rest.principal_bridge.v1");
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
    assert_eq!(
        push_bridge["contract"],
        "contrix.rest.outbound_push_bridge.v1"
    );
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
        server
            .http()
            .get(server.url("/api/v1/integration/describe")),
        StatusCode::OK,
    )
    .await?;
    let principal_auth = expect_json(
        server
            .http()
            .get(server.url("/api/v1/auth/bridge/describe")),
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

    let coauth_service_integration =
        load_optional_live_contract(coauth_base_url.as_deref(), "/api/v1/integration/describe")
            .await?;
    let coauth_auth_bridge =
        load_optional_live_contract(coauth_base_url.as_deref(), "/api/v1/auth/bridge/describe")
            .await?;
    let coauth_recovery_bridge =
        load_optional_live_contract(coauth_base_url.as_deref(), "/api/v1/auth/recovery/describe")
            .await?;
    let coauth_admin_bridge =
        load_optional_live_contract(coauth_base_url.as_deref(), "/api/admin/v1/bridge/describe")
            .await?;
    let floria_service_integration =
        load_optional_live_contract(floria_base_url.as_deref(), "/api/v1/integration/describe")
            .await?;
    let floria_push_bridge =
        load_optional_live_contract(floria_base_url.as_deref(), "/api/v1/push/bridge/describe")
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
                            "/api/v1/auth/recovery/principal-snapshot",
                            "/api/v1/auth/recovery/principal-cache/status",
                            "/api/v1/auth/recovery/principal-cache/refresh",
                            "/api/v1/auth/recovery/principal-cache/queue",
                            "/api/v1/auth/recovery/principal-cache/complete",
                            "/api/v1/auth/recovery/principal-cache/fail",
                            "/api/v1/auth/recovery/principal-cache/policy",
                            "/api/v1/auth/recovery/principal-cache/retry",
                            "/api/v1/auth/recovery/principal-cache/invalidate",
                            "/api/v1/auth/recovery/principal-cache/failures",
                            "/api/v1/auth/recovery/principal-cache/upstream",
                            "/api/v1/auth/recovery/principal-cache/upstream/probe",
                            "/api/v1/auth/recovery/principal-cache/upstream/bind",
                            "/api/v1/auth/recovery/start",
                            "/api/v1/auth/recovery/{id}",
                            "/api/v1/auth/recovery/{id}/resend",
                            "/api/v1/recovery/contract-stack",
                            "/api/v1/device_messages/describe",
                            "/api/v1/keys/backups",
                            "/api/v1/keys/backups/describe",
                            "/api/v1/keys/backups/restore-state/describe",
                            "/api/v1/keys/backups/restore-state/export",
                            "/api/v1/keys/backups/restore-state/import",
                            "/api/v1/keys/backups/restore-state/durability",
                            "/api/v1/keys/backups/restore-state/checkpoints",
                            "/api/v1/keys/backups/{backup_id}/restore/start",
                            "/api/v1/keys/backups/restore-tickets",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/resume",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/cancel",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/retry",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/status",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/submit",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/enqueue",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/start",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/complete",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/result",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/materialized-device-handoff",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/activity",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed",
                            "/api/v1/recovery/live-snapshot",
                            "/api/v1/recovery/discovery",
                            "/api/v1/recovery/readiness",
                            "/api/v1/authz/describe",
                            "/api/v1/policies/describe",
                        ],
                        &[
                            "example_backup_payload",
                            "recovery_principal_snapshot_path",
                            "recovery_principal_cache_status_path",
                            "recovery_principal_cache_refresh_path",
                            "recovery_principal_cache_queue_path",
                            "recovery_principal_cache_complete_path",
                            "recovery_principal_cache_fail_path",
                            "recovery_principal_cache_policy_path",
                            "recovery_principal_cache_retry_path",
                            "recovery_principal_cache_invalidate_path",
                            "recovery_principal_cache_failures_path",
                            "recovery_principal_cache_upstream_path",
                            "recovery_principal_cache_upstream_probe_path",
                            "recovery_principal_cache_upstream_bind_path",
                            "recovery_restore_examples.restore_start_request",
                            "recovery_restore_examples.restore_ticket_advance_request",
                            "principal_restore_ticket_collection_path",
                            "principal_restore_ticket_resume_path",
                            "principal_restore_ticket_cancel_path",
                            "principal_restore_ticket_retry_path",
                            "principal_restore_state_describe_path",
                            "principal_restore_state_export_path",
                            "principal_restore_state_import_path",
                            "principal_restore_state_durability_path",
                            "principal_restore_state_checkpoint_collection_path",
                            "principal_restore_approval_status_path",
                            "principal_restore_approval_submit_path",
                            "principal_restore_executor_status_path",
                            "principal_restore_executor_enqueue_path",
                            "principal_restore_executor_start_path",
                            "principal_restore_executor_complete_path",
                            "principal_restore_result_path",
                            "principal_restore_receipt_path",
                            "principal_restore_materialized_device_handoff_path",
                            "principal_restore_bundle_path",
                            "principal_restore_activity_path",
                            "principal_restore_timeline_path",
                            "principal_restore_audit_feed_path",
                            "principal_recovery_live_snapshot_path",
                            "principal_recovery_discovery_path",
                            "principal_recovery_readiness_path",
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
                            "/api/v1/auth/recovery/principal-snapshot",
                            "/api/v1/auth/recovery/principal-cache/status",
                            "/api/v1/auth/recovery/principal-cache/refresh",
                            "/api/v1/auth/recovery/principal-cache/queue",
                            "/api/v1/auth/recovery/principal-cache/complete",
                            "/api/v1/auth/recovery/principal-cache/fail",
                            "/api/v1/auth/recovery/principal-cache/policy",
                            "/api/v1/auth/recovery/principal-cache/retry",
                            "/api/v1/auth/recovery/principal-cache/invalidate",
                            "/api/v1/auth/recovery/principal-cache/failures",
                            "/api/v1/auth/recovery/principal-cache/upstream",
                            "/api/v1/auth/recovery/principal-cache/upstream/probe",
                            "/api/v1/auth/recovery/principal-cache/upstream/bind",
                            "/api/v1/auth/recovery/start",
                            "/api/v1/auth/recovery/{id}",
                            "/api/v1/auth/recovery/{id}/resend",
                            "/api/v1/recovery/contract-stack",
                            "/api/v1/device_messages/describe",
                            "/api/v1/keys/backups",
                            "/api/v1/keys/backups/describe",
                            "/api/v1/keys/backups/restore-state/describe",
                            "/api/v1/keys/backups/restore-state/export",
                            "/api/v1/keys/backups/restore-state/import",
                            "/api/v1/keys/backups/restore-state/durability",
                            "/api/v1/keys/backups/restore-state/checkpoints",
                            "/api/v1/keys/backups/{backup_id}/restore/start",
                            "/api/v1/keys/backups/restore-tickets",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/resume",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/cancel",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/retry",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/status",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/submit",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/enqueue",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/start",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/complete",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/result",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/materialized-device-handoff",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/activity",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline",
                            "/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed",
                            "/api/v1/recovery/live-snapshot",
                            "/api/v1/recovery/discovery",
                            "/api/v1/recovery/readiness",
                            "/api/v1/authz/describe",
                            "/api/v1/policies/describe",
                        ],
                        &[
                            "example_backup_payload",
                            "recovery_principal_snapshot_path",
                            "recovery_principal_cache_status_path",
                            "recovery_principal_cache_refresh_path",
                            "recovery_principal_cache_queue_path",
                            "recovery_principal_cache_complete_path",
                            "recovery_principal_cache_fail_path",
                            "recovery_principal_cache_policy_path",
                            "recovery_principal_cache_retry_path",
                            "recovery_principal_cache_invalidate_path",
                            "recovery_principal_cache_failures_path",
                            "recovery_principal_cache_upstream_path",
                            "recovery_principal_cache_upstream_probe_path",
                            "recovery_principal_cache_upstream_bind_path",
                            "recovery_restore_examples.restore_start_request",
                            "recovery_restore_examples.restore_ticket_advance_request",
                            "principal_restore_ticket_collection_path",
                            "principal_restore_ticket_resume_path",
                            "principal_restore_ticket_cancel_path",
                            "principal_restore_ticket_retry_path",
                            "principal_restore_state_describe_path",
                            "principal_restore_state_export_path",
                            "principal_restore_state_import_path",
                            "principal_restore_state_durability_path",
                            "principal_restore_state_checkpoint_collection_path",
                            "principal_restore_approval_status_path",
                            "principal_restore_approval_submit_path",
                            "principal_restore_executor_status_path",
                            "principal_restore_executor_enqueue_path",
                            "principal_restore_executor_start_path",
                            "principal_restore_executor_complete_path",
                            "principal_restore_result_path",
                            "principal_restore_receipt_path",
                            "principal_restore_materialized_device_handoff_path",
                            "principal_restore_bundle_path",
                            "principal_restore_activity_path",
                            "principal_restore_timeline_path",
                            "principal_restore_audit_feed_path",
                            "principal_recovery_live_snapshot_path",
                            "principal_recovery_discovery_path",
                            "principal_recovery_readiness_path",
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
                    "/api/v1/keys/backups/restore-state/describe".to_owned(),
                    "/api/v1/keys/backups/restore-state/export".to_owned(),
                    "/api/v1/keys/backups/restore-state/import".to_owned(),
                    "/api/v1/keys/backups/{backup_id}/restore/start".to_owned(),
                    "/api/v1/keys/backups/restore-tickets".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/resume".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/cancel".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/retry".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/status".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/approvals/submit".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/status".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/enqueue".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/start".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/executor/complete".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/result".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/materialized-device-handoff".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/bundle".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/activity".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed".to_owned(),
                    "/api/v1/recovery/live-snapshot".to_owned(),
                    "/api/v1/recovery/stack-bundle".to_owned(),
                    "/api/v1/recovery/discovery".to_owned(),
                    "/api/v1/recovery/readiness".to_owned(),
                    "/api/v1/authz/describe".to_owned(),
                    "/api/v1/authz/check".to_owned(),
                    "/api/v1/policies/describe".to_owned(),
                    "/api/v1/policies".to_owned(),
                ],
                example_keys: vec![
                    "coauth.example_backup_payload".to_owned(),
                    "coauth.recovery_principal_snapshot_path".to_owned(),
                    "coauth.recovery_principal_cache_status_path".to_owned(),
                    "coauth.recovery_principal_cache_refresh_path".to_owned(),
                    "coauth.recovery_principal_cache_queue_path".to_owned(),
                    "coauth.recovery_principal_cache_complete_path".to_owned(),
                    "coauth.recovery_principal_cache_fail_path".to_owned(),
                    "coauth.recovery_principal_cache_policy_path".to_owned(),
                    "coauth.recovery_principal_cache_retry_path".to_owned(),
                    "coauth.recovery_principal_cache_invalidate_path".to_owned(),
                    "coauth.recovery_principal_cache_failures_path".to_owned(),
                    "coauth.recovery_principal_cache_upstream_path".to_owned(),
                    "coauth.recovery_principal_cache_upstream_probe_path".to_owned(),
                    "coauth.recovery_principal_cache_upstream_bind_path".to_owned(),
                    "coauth.principal_restore_timeline_path".to_owned(),
                    "coauth.principal_restore_audit_feed_path".to_owned(),
                    "coauth.recovery_restore_examples.restore_start_request".to_owned(),
                    "coauth.recovery_restore_examples.restore_ticket_advance_request".to_owned(),
                    "coauth.principal_restore_ticket_collection_path".to_owned(),
                    "coauth.principal_restore_ticket_resume_path".to_owned(),
                    "coauth.principal_restore_ticket_cancel_path".to_owned(),
                    "coauth.principal_restore_ticket_retry_path".to_owned(),
                    "coauth.principal_restore_state_describe_path".to_owned(),
                    "coauth.principal_restore_state_export_path".to_owned(),
                    "coauth.principal_restore_state_import_path".to_owned(),
                    "coauth.principal_restore_state_durability_path".to_owned(),
                    "coauth.principal_restore_state_checkpoint_collection_path".to_owned(),
                    "coauth.principal_restore_approval_status_path".to_owned(),
                    "coauth.principal_restore_approval_submit_path".to_owned(),
                    "coauth.principal_restore_executor_status_path".to_owned(),
                    "coauth.principal_restore_executor_enqueue_path".to_owned(),
                    "coauth.principal_restore_executor_start_path".to_owned(),
                    "coauth.principal_restore_executor_complete_path".to_owned(),
                    "coauth.principal_restore_result_path".to_owned(),
                    "coauth.principal_restore_receipt_path".to_owned(),
                    "coauth.principal_restore_materialized_device_handoff_path".to_owned(),
                    "coauth.principal_restore_bundle_path".to_owned(),
                    "coauth.principal_restore_activity_path".to_owned(),
                    "coauth.principal_restore_timeline_path".to_owned(),
                    "coauth.principal_restore_audit_feed_path".to_owned(),
                    "coauth.principal_recovery_live_snapshot_path".to_owned(),
                    "coauth.principal_recovery_stack_bundle_path".to_owned(),
                    "coauth.principal_recovery_discovery_path".to_owned(),
                    "coauth.principal_recovery_readiness_path".to_owned(),
                    "coauth.recovery_authz_examples.authz_check_request".to_owned(),
                    "coauth.recovery_authz_examples.policy_upsert_request".to_owned(),
                    "soland.examples.authz_protocol.authz_check_request".to_owned(),
                    "soland.examples.authz_protocol.policy_upsert_request".to_owned(),
                    "soland.examples.key_backups.put_request".to_owned(),
                    "soland.examples.key_backups.restore_state_export_response_shape".to_owned(),
                    "soland.examples.key_backups.restore_state_import_request".to_owned(),
                    "soland.examples.key_backups.restore_executor_start_request".to_owned(),
                    "soland.examples.key_backups.restore_executor_complete_request".to_owned(),
                    "soland.examples.key_backups.restore_ticket_collection_response_shape".to_owned(),
                    "soland.examples.key_backups.restore_ticket_resume_request".to_owned(),
                    "soland.examples.key_backups.restore_ticket_cancel_request".to_owned(),
                    "soland.examples.key_backups.restore_ticket_retry_request".to_owned(),
                    "soland.examples.key_backups.restore_result_response_shape".to_owned(),
                    "soland.examples.key_backups.restore_receipt_response_shape".to_owned(),
                    "soland.examples.key_backups.restore_materialized_device_handoff_request".to_owned(),
                    "soland.examples.key_backups.restore_bundle_response_shape".to_owned(),
                    "soland.examples.key_backups.restore_activity_response_shape".to_owned(),
                    "soland.examples.key_backups.restore_timeline_response_shape".to_owned(),
                    "soland.examples.key_backups.restore_audit_feed_response_shape".to_owned(),
                    "soland.examples.key_backups.recovery_live_snapshot_response_shape".to_owned(),
                    "soland.examples.key_backups.restore_state_durability_response_shape".to_owned(),
                    "soland.examples.key_backups.restore_state_checkpoint_list_response_shape".to_owned(),
                    "soland.examples.key_backups.restore_state_checkpoint_create_request".to_owned(),
                    "soland.examples.recovery_stack_bundle.response_shape".to_owned(),
                ],
                todo: "TODO(cotest): replace this synthetic alignment row with a live composed coauth + soland recovery restore flow once the stack harness can execute cross-service recovery/authz/policy handoff.",
            },
            BridgeContractSnapshot {
                service: "compose",
                surface: "recovery_stack_manifest",
                contract: "contrix.compose.recovery_stack_manifest.v1".to_owned(),
                version: "2026-05-04-scaffold".to_owned(),
                required_paths: vec![
                    "/api/v1/auth/recovery/describe".to_owned(),
                    "/api/v1/auth/recovery/principal-snapshot".to_owned(),
                    "/api/v1/auth/recovery/principal-cache/status".to_owned(),
                    "/api/v1/auth/recovery/principal-cache/refresh".to_owned(),
                    "/api/v1/auth/recovery/principal-cache/policy".to_owned(),
                    "/api/v1/auth/recovery/principal-cache/retry".to_owned(),
                    "/api/v1/auth/recovery/principal-cache/invalidate".to_owned(),
                    "/api/v1/auth/recovery/principal-cache/failures".to_owned(),
                    "/api/v1/auth/recovery/principal-cache/upstream".to_owned(),
                    "/api/v1/auth/recovery/principal-cache/upstream/probe".to_owned(),
                    "/api/v1/auth/recovery/principal-cache/upstream/bind".to_owned(),
                    "/api/v1/recovery/contract-stack".to_owned(),
                    "/api/v1/recovery/discovery".to_owned(),
                    "/api/v1/recovery/readiness".to_owned(),
                    "/api/v1/recovery/live-snapshot".to_owned(),
                    "/api/v1/keys/backups/restore-state/durability".to_owned(),
                    "/api/v1/keys/backups/restore-state/checkpoints".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/activity".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline".to_owned(),
                    "/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed".to_owned(),
                ],
                example_keys: vec![
                    "coauth.recovery_principal_snapshot_path".to_owned(),
                    "coauth.recovery_principal_cache_status_path".to_owned(),
                    "coauth.recovery_principal_cache_refresh_path".to_owned(),
                    "coauth.recovery_principal_cache_policy_path".to_owned(),
                    "coauth.recovery_principal_cache_retry_path".to_owned(),
                    "coauth.recovery_principal_cache_invalidate_path".to_owned(),
                    "coauth.recovery_principal_cache_failures_path".to_owned(),
                    "coauth.recovery_principal_cache_upstream_path".to_owned(),
                    "coauth.recovery_principal_cache_upstream_probe_path".to_owned(),
                    "coauth.recovery_principal_cache_upstream_bind_path".to_owned(),
                    "coauth.principal_restore_state_durability_path".to_owned(),
                    "coauth.principal_restore_state_checkpoint_collection_path".to_owned(),
                    "coauth.principal_restore_activity_path".to_owned(),
                    "coauth.principal_restore_timeline_path".to_owned(),
                    "coauth.principal_restore_audit_feed_path".to_owned(),
                    "coauth.principal_recovery_live_snapshot_path".to_owned(),
                    "coauth.principal_recovery_discovery_path".to_owned(),
                    "coauth.principal_recovery_readiness_path".to_owned(),
                    "soland.examples.key_backups.restore_state_durability_response_shape".to_owned(),
                    "soland.examples.key_backups.restore_state_checkpoint_list_response_shape".to_owned(),
                    "soland.examples.key_backups.restore_state_checkpoint_create_request".to_owned(),
                    "soland.examples.key_backups.restore_activity_response_shape".to_owned(),
                    "soland.examples.key_backups.restore_timeline_response_shape".to_owned(),
                    "soland.examples.key_backups.restore_audit_feed_response_shape".to_owned(),
                    "soland.examples.key_backups.recovery_live_snapshot_response_shape".to_owned(),
                ],
                todo: "TODO(cotest): replace this synthetic compose manifest row with a live coauth + soland recovery-stack harness that exercises principal-cache refresh and recovery snapshot propagation.",
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

    assert!(matrix.rows.len() >= 10);
    assert!(
        matrix
            .rows
            .iter()
            .any(|row| { row.service == "soland" && row.surface == "principal_auth_bridge" })
    );
    assert!(
        matrix.rows.iter().any(|row| {
            row.service == "soland" && row.surface == "service_integration_manifest"
        })
    );
    assert!(
        matrix
            .rows
            .iter()
            .any(|row| { row.service == "coauth" && row.surface == "auth_bridge" })
    );
    assert!(
        matrix
            .rows
            .iter()
            .any(|row| { row.service == "coauth" && row.surface == "recovery_bridge" })
    );
    assert!(matrix.rows.iter().any(|row| {
        row.service == "compose" && row.surface == "recovery_authz_policy_alignment"
    }));
    assert!(
        matrix.rows.iter().any(|row| {
            row.service == "coauth" && row.surface == "service_integration_manifest"
        })
    );
    assert!(
        matrix
            .rows
            .iter()
            .any(|row| { row.service == "floria" && row.surface == "push_bridge" })
    );
    assert!(
        matrix.rows.iter().any(|row| {
            row.service == "floria" && row.surface == "service_integration_manifest"
        })
    );
    assert!(
        matrix
            .rows
            .iter()
            .all(|row| !row.required_paths.is_empty() && !row.example_keys.is_empty())
    );

    Ok(())
}

pub async fn starid_optional_resolver_profile_is_discoverable() -> Result<()> {
    let server = ContrixServer::spawn_with_env(
        "starid-optional",
        &[
            (
                "SERVERX_DID_RESOLVER_ALLOW_METHODS",
                "did:web,did:key,did:uuid,did:webvh",
            ),
            (
                "SERVERX_STARID_WEBVH_RESOLVER_URL",
                "http://starid.cotest.local",
            ),
        ],
    )
    .await?;

    let describe = expect_json(
        server.http().get(server.url("/api/v1/identity/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(describe["starid_profile"]["enabled"], true);
    assert_eq!(describe["starid_profile"]["method"], "did:webvh");
    assert_eq!(
        describe["starid_profile"]["profile"],
        "cx.identity.starid.webvh.optional.v1"
    );
    assert_eq!(
        describe["starid_profile"]["resolver_url"],
        "http://starid.cotest.local"
    );
    assert!(
        describe["resolver_policy"]["allow_methods"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str() == Some("webvh")),
        "did:webvh should be discoverable when the optional starid resolver is configured"
    );
    assert!(
        describe["todos"]
            .as_array()
            .is_some_and(|todos| !todos.is_empty()),
        "soland must keep explicit TODO markers until starid proof/trust-root validation lands"
    );

    Ok(())
}

pub async fn session_grant_exchange_uses_configured_coauth_introspection() -> Result<()> {
    let principal_did = "did:web:alice-session-grant.example";
    let device_id = "dev_web";
    let coauth = MockCoauthIntrospectionServer::spawn(principal_did, device_id)?;
    let _env = EnvOverride::set(&[
        (
            "SERVERX_SESSION_GRANT_INTROSPECTION_URL",
            Some(coauth.url()),
        ),
        (
            "SERVERX_SESSION_GRANT_INTROSPECTION_BEARER",
            Some("principal-token".to_owned()),
        ),
    ]);
    let server = ContrixServer::spawn("session-grant-exchange").await?;

    expect_json(
        server
            .http()
            .post(server.url("/api/v1/account/register"))
            .json(&json!({
                "did": principal_did,
                "handle": "@alice-session-grant",
                "display_name": "Alice Session Grant",
                "device_id": device_id
            })),
        StatusCode::CREATED,
    )
    .await?;

    let exchange = expect_json(
        server
            .http()
            .post(server.url("/api/v1/auth/session-grant/exchange"))
            .json(&json!({
                "grant_jwt": "coauth.session.jwt",
                "principal_did": principal_did,
                "device_id": device_id,
                "display_name": "yougen session-grant bridge",
                "introspection_proof": {
                    "challenge": "soland-bridge-challenge",
                    "proof_jwt": "client.session-key.proof.jwt"
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(exchange["actor"], principal_did);
    assert_eq!(exchange["device_id"], device_id);
    assert_eq!(exchange["token_type"], "Bearer");
    assert!(
        exchange["access_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );

    let authenticated = expect_json(
        server
            .http()
            .get(server.url("/api/v1/account/me"))
            .bearer_auth(exchange["access_token"].as_str().unwrap()),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(authenticated["did"], principal_did);

    let push = expect_json(
        server
            .http()
            .post(server.url("/api/v1/push/register-device"))
            .header("X-Contrix-Session-Grant", "coauth.session.jwt")
            .header("X-Contrix-Session-Grant-Challenge", "soland-push-challenge")
            .header(
                "X-Contrix-Session-Grant-Proof",
                "client.session-key.push-proof.jwt",
            )
            .json(&json!({
                "operation_id": "cx.push.register_device",
                "principal_did": principal_did,
                "device_id": device_id,
                "push_gateway": "https://floria.example/api/v1/push/notify",
                "push_key": "webpush:opaque-token",
                "platform": "web",
                "request_id": "cx:req:push-session-grant",
                "proof": {"kind": "push-register-proof-placeholder"}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push["ok"], true);
    assert_eq!(push["registration_id"], format!("cx:push:{device_id}"));

    let requests = coauth.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["grant_jwt"], "coauth.session.jwt");
    assert_eq!(requests[0]["audience"], server.service_did());
    assert_eq!(requests[0]["proof"]["challenge"], "soland-bridge-challenge");
    assert_eq!(requests[1]["grant_jwt"], "coauth.session.jwt");
    assert_eq!(requests[1]["audience"], server.service_did());
    assert_eq!(requests[1]["proof"]["challenge"], "soland-push-challenge");

    Ok(())
}

fn configured_external_service_base(env_key: &str) -> Option<String> {
    env::var(env_key)
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_owned())
        .filter(|value| !value.is_empty())
}

async fn load_optional_live_contract(base_url: Option<&str>, path: &str) -> Result<Option<Value>> {
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
        required_paths: required_paths
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        example_keys: example_keys
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
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
        required_paths: required_paths
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        example_keys: example_keys
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        todo,
    }
}

struct EnvOverride {
    previous: Vec<(&'static str, Option<String>)>,
}

impl EnvOverride {
    fn set(pairs: &[(&'static str, Option<String>)]) -> Self {
        let previous = pairs
            .iter()
            .map(|(key, _)| (*key, env::var(key).ok()))
            .collect();
        for (key, value) in pairs {
            unsafe {
                match value {
                    Some(value) => env::set_var(key, value),
                    None => env::remove_var(key),
                }
            }
        }
        Self { previous }
    }
}

impl Drop for EnvOverride {
    fn drop(&mut self) {
        for (key, value) in &self.previous {
            unsafe {
                match value {
                    Some(value) => env::set_var(key, value),
                    None => env::remove_var(key),
                }
            }
        }
    }
}

struct MockCoauthIntrospectionServer {
    url: String,
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<Value>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockCoauthIntrospectionServer {
    fn spawn(subject: &str, device_id: &str) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let url = format!("http://{addr}/api/v1/session-grants/introspect");
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread_stop = Arc::clone(&stop);
        let thread_requests = Arc::clone(&requests);
        let subject = subject.to_owned();
        let device_id = device_id.to_owned();
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let request_subject = subject.clone();
                        let request_device_id = device_id.clone();
                        let request_log = Arc::clone(&thread_requests);
                        thread::spawn(move || {
                            handle_mock_coauth_request(
                                stream,
                                &request_subject,
                                &request_device_id,
                                request_log,
                            );
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(StdDuration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            url,
            addr,
            stop,
            requests,
            handle: Some(handle),
        })
    }

    fn url(&self) -> String {
        self.url.clone()
    }

    fn requests(&self) -> Vec<Value> {
        self.requests.lock().expect("mock requests lock").clone()
    }
}

impl Drop for MockCoauthIntrospectionServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn handle_mock_coauth_request(
    mut stream: TcpStream,
    subject: &str,
    device_id: &str,
    requests: Arc<Mutex<Vec<Value>>>,
) {
    let Ok(request) = read_http_request(&mut stream) else {
        return;
    };
    let request_text = String::from_utf8_lossy(&request);
    if !request_text
        .to_ascii_lowercase()
        .contains("authorization: bearer principal-token")
    {
        write_http_response(&mut stream, 401, json!({"error": "unauthorized"}));
        return;
    }
    let body = parse_http_json_body(&request).unwrap_or_else(|| json!({}));
    requests
        .lock()
        .expect("mock requests lock")
        .push(body.clone());
    let audience = body
        .get("audience")
        .and_then(Value::as_str)
        .unwrap_or("did:web:missing-audience");
    write_http_response(
        &mut stream,
        200,
        json!({
            "active": true,
            "status": "active",
            "proof_required": true,
            "one_time_use_consumed": true,
            "grant": {
                "id": "01HZSESSIONGRANTMOCK000000000",
                "issuer": "did:web:coauth.cotest.local",
                "subject": subject,
                "service_account_id": "alice-session-grant",
                "device_id": device_id,
                "audience": audience,
                "scopes": ["urn:contrix:principal-server:session.bind"],
                "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
                "revoked_at": null,
                "revocation_ref": "cx:session:mock"
            }
        }),
    );
}

fn read_http_request(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(StdDuration::from_secs(2)))?;
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if http_request_complete(&request) {
            break;
        }
    }
    Ok(request)
}

fn http_request_complete(request: &[u8]) -> bool {
    let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let body_start = header_end + 4;
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    request.len() >= body_start + content_length
}

fn parse_http_json_body(request: &[u8]) -> Option<Value> {
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    let body = &request[header_end + 4..];
    serde_json::from_slice(body).ok()
}

fn write_http_response(stream: &mut TcpStream, status: u16, body: Value) {
    let body = body.to_string();
    let reason = if status == 200 { "OK" } else { "Unauthorized" };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.as_bytes().len()
    );
    let _ = stream.write_all(response.as_bytes());
}
