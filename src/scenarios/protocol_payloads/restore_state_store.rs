//! Phase 6 — restore-state durability / checkpoints / retry / cancel /
//! export-import + closing authz / recovery contract-stack / policies
//! describe assertions.
//!
//! The export -> import handoff is the only intra-phase data flow: the export
//! body's `records` array is fed back into the import payload to verify a
//! round-trip restores the same ticket count.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ContrixServer, expect_json};

const TICKET_BASE: &str = "/api/v1/keys/backups/restore-tickets/restore-ticket-backup-alice-01";

pub async fn run(server: &ContrixServer, token: &str) -> Result<()> {
    durability(server, token).await?;
    checkpoint_collection(server, token).await?;
    create_checkpoint(server, token).await?;
    retry_ticket(server, token).await?;
    cancel_ticket(server, token).await?;
    export_then_import(server, token).await?;
    authz_describe(server, token).await?;
    recovery_contract_stack(server, token).await?;
    policies_describe(server, token).await?;
    Ok(())
}

async fn durability(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_state_durability = expect_json(
        server
            .http()
            .get(server.url("/api/v1/keys/backups/restore-state/durability"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_state_durability["contract"],
        "contrix.rest.key_backup_restore_state_durability.v1"
    );
    Ok(())
}

async fn checkpoint_collection(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_state_checkpoints = expect_json(
        server
            .http()
            .get(server.url("/api/v1/keys/backups/restore-state/checkpoints"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_state_checkpoints["contract"],
        "contrix.rest.key_backup_restore_state_checkpoint_collection.v1"
    );
    Ok(())
}

async fn create_checkpoint(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_state_checkpoint_create = expect_json(
        server
            .http()
            .post(server.url("/api/v1/keys/backups/restore-state/checkpoints"))
            .bearer_auth(token)
            .json(&json!({
                "checkpoint_mode": "manual_scaffold",
                "reason": "cotest_snapshot_before_retry"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_state_checkpoint_create["contract"],
        "contrix.rest.key_backup_restore_state_checkpoint_create.v1"
    );
    Ok(())
}

async fn retry_ticket(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_retry = expect_json(
        server
            .http()
            .post(server.url(&format!("{TICKET_BASE}/retry")))
            .bearer_auth(token)
            .json(&json!({
                "retry_mode": "reuse_backup_material",
                "note": "cotest scaffold retry"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_retry["contract"],
        "contrix.rest.key_backup_restore_ticket_retry.v1"
    );
    assert_eq!(restore_retry["state"], "retry_queued");
    Ok(())
}

async fn cancel_ticket(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_cancel = expect_json(
        server
            .http()
            .post(server.url(&format!("{TICKET_BASE}/cancel")))
            .bearer_auth(token)
            .json(&json!({
                "reason": "operator_cancelled",
                "note": "cotest scaffold cancel"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_cancel["contract"],
        "contrix.rest.key_backup_restore_ticket_cancel.v1"
    );
    assert_eq!(restore_cancel["state"], "cancelled");
    Ok(())
}

async fn export_then_import(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_state_export = expect_json(
        server
            .http()
            .get(server.url("/api/v1/keys/backups/restore-state/export"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_state_export["contract"],
        "contrix.rest.key_backup_restore_state_store_export.v1"
    );
    assert_eq!(restore_state_export["ticket_count"], 1);

    let restore_state_import = expect_json(
        server
            .http()
            .post(server.url("/api/v1/keys/backups/restore-state/import"))
            .bearer_auth(token)
            .json(&json!({
                "merge_mode": "replace_owned",
                "records": restore_state_export["records"].clone()
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_state_import["contract"],
        "contrix.rest.key_backup_restore_state_store_import.v1"
    );
    assert_eq!(restore_state_import["imported_ticket_count"], 1);
    Ok(())
}

async fn authz_describe(server: &ContrixServer, token: &str) -> Result<()> {
    let authz_describe = expect_json(
        server
            .http()
            .get(server.url("/api/v1/authz/describe"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(authz_describe["contract"], "contrix.rest.authz_describe.v1");
    assert_eq!(authz_describe["check_path"], "/api/v1/authz/check");
    Ok(())
}

async fn recovery_contract_stack(server: &ContrixServer, token: &str) -> Result<()> {
    let recovery_contract_stack = expect_json(
        server
            .http()
            .get(server.url("/api/v1/recovery/contract-stack"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        recovery_contract_stack["contract"],
        "contrix.rest.recovery_contract_stack.v1"
    );
    assert_eq!(
        recovery_contract_stack["device_messages_describe_path"],
        "/api/v1/device_messages/describe"
    );
    assert_eq!(
        recovery_contract_stack["restore_state_describe_path"],
        "/api/v1/keys/backups/restore-state/describe"
    );
    assert_eq!(
        recovery_contract_stack["restore_result_path"],
        "/api/v1/keys/backups/restore-tickets/{ticket_id}/result"
    );
    assert_eq!(
        recovery_contract_stack["restore_receipt_path"],
        "/api/v1/keys/backups/restore-tickets/{ticket_id}/receipt"
    );
    assert_eq!(
        recovery_contract_stack["restore_materialized_device_handoff_path"],
        "/api/v1/keys/backups/restore-tickets/{ticket_id}/materialized-device-handoff"
    );
    assert_eq!(
        recovery_contract_stack["restore_activity_path"],
        "/api/v1/keys/backups/restore-tickets/{ticket_id}/activity"
    );
    assert_eq!(
        recovery_contract_stack["recovery_live_snapshot_path"],
        "/api/v1/recovery/live-snapshot"
    );
    assert_eq!(
        recovery_contract_stack["restore_timeline_path"],
        "/api/v1/keys/backups/restore-tickets/{ticket_id}/timeline"
    );
    assert_eq!(
        recovery_contract_stack["restore_audit_feed_path"],
        "/api/v1/keys/backups/restore-tickets/{ticket_id}/audit-feed"
    );
    Ok(())
}

async fn policies_describe(server: &ContrixServer, token: &str) -> Result<()> {
    let policies_describe = expect_json(
        server
            .http()
            .get(server.url("/api/v1/policies/describe"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        policies_describe["contract"],
        "contrix.rest.policies_describe.v1"
    );
    assert_eq!(policies_describe["collection_path"], "/api/v1/policies");
    Ok(())
}
