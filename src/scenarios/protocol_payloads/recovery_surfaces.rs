//! Phase 5 — recovery describe / live-snapshot / discovery / readiness /
//! stack-bundle plus the per-ticket timeline + audit-feed.
//!
//! Closes out the post-restore observability surfaces from the orchestrator's
//! point of view; subsequent state-store / authz checks live in
//! [`super::restore_state_store`].

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ContrixServer, expect_json};

const TICKET_BASE: &str = "/api/v1/keys/backups/restore-tickets/restore-ticket-backup-alice-01";

pub async fn run(server: &ContrixServer, token: &str) -> Result<()> {
    live_snapshot(server, token).await?;
    discovery(server, token).await?;
    readiness(server, token).await?;
    stack_bundle(server, token).await?;
    timeline(server, token).await?;
    audit_feed(server, token).await?;
    Ok(())
}

async fn live_snapshot(server: &ContrixServer, token: &str) -> Result<()> {
    let recovery_live_snapshot = expect_json(
        server
            .http()
            .get(server.url("/api/v1/recovery/live-snapshot"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        recovery_live_snapshot["contract"],
        "contrix.rest.recovery_live_snapshot.v1"
    );
    assert_eq!(
        recovery_live_snapshot["ticket_collection_path"],
        "/api/v1/keys/backups/restore-tickets"
    );
    assert_eq!(
        recovery_live_snapshot["discovery_path"],
        "/api/v1/recovery/discovery"
    );
    assert_eq!(
        recovery_live_snapshot["readiness_path"],
        "/api/v1/recovery/readiness"
    );
    Ok(())
}

async fn discovery(server: &ContrixServer, token: &str) -> Result<()> {
    let recovery_discovery = expect_json(
        server
            .http()
            .get(server.url("/api/v1/recovery/discovery"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        recovery_discovery["contract"],
        "contrix.rest.recovery_discovery.v1"
    );
    assert_eq!(
        recovery_discovery["recovery_readiness_path"],
        "/api/v1/recovery/readiness"
    );
    Ok(())
}

async fn readiness(server: &ContrixServer, token: &str) -> Result<()> {
    let recovery_readiness = expect_json(
        server
            .http()
            .get(server.url("/api/v1/recovery/readiness"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        recovery_readiness["contract"],
        "contrix.rest.recovery_readiness.v1"
    );
    assert_eq!(recovery_readiness["readiness_state"], "ready");
    assert_eq!(recovery_readiness["blocking_gaps"], json!([]));
    Ok(())
}

async fn stack_bundle(server: &ContrixServer, token: &str) -> Result<()> {
    let recovery_stack_bundle = expect_json(
        server
            .http()
            .get(server.url("/api/v1/recovery/stack-bundle"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        recovery_stack_bundle["contract"],
        "contrix.rest.recovery_stack_bundle.v1"
    );
    assert_eq!(
        recovery_stack_bundle["discovery_path"],
        "/api/v1/recovery/discovery"
    );
    assert_eq!(
        recovery_stack_bundle["readiness_path"],
        "/api/v1/recovery/readiness"
    );
    Ok(())
}

async fn timeline(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_timeline = expect_json(
        server
            .http()
            .get(server.url(&format!("{TICKET_BASE}/timeline")))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_timeline["contract"],
        "contrix.rest.key_backup_restore_timeline.v1"
    );
    Ok(())
}

async fn audit_feed(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_audit_feed = expect_json(
        server
            .http()
            .get(server.url(&format!("{TICKET_BASE}/audit-feed")))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_audit_feed["contract"],
        "contrix.rest.key_backup_restore_audit_feed.v1"
    );
    Ok(())
}
