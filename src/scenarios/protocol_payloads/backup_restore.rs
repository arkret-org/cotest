//! Phase 4 — backup restore ticket lifecycle from describe through bundle.
//!
//! Walks the linear progression: describe -> start -> ticket-collection ->
//! resume -> ticket-state -> advance -> approval-status -> approval-submit ->
//! executor (status / enqueue / start / complete) -> result -> receipt ->
//! handoff -> bundle -> activity. The tickets are addressed by the fixed
//! identifier `restore-ticket-backup-alice-01` derived from the seeded backup,
//! so no inter-helper state plumbing is required beyond `(server, token)`.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ContrixServer, expect_json};

const TICKET_BASE: &str = "/api/v1/keys/backups/restore-tickets/restore-ticket-backup-alice-01";

pub async fn run(server: &ContrixServer, token: &str) -> Result<()> {
    describe_restore_surfaces(server, token).await?;
    start_restore(server, token).await?;
    list_restore_tickets(server, token).await?;
    resume_restore_ticket(server, token).await?;
    fetch_restore_ticket(server, token).await?;
    advance_restore_ticket(server, token).await?;
    walk_approvals(server, token).await?;
    walk_executor(server, token).await?;
    fetch_result_and_receipt(server, token).await?;
    submit_handoff(server, token).await?;
    fetch_bundle_and_activity(server, token).await?;
    Ok(())
}

async fn describe_restore_surfaces(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_describe = expect_json(
        server
            .http()
            .get(server.url("/api/v1/keys/backups/backup-alice-01/restore/describe"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_describe["contract"],
        "contrix.rest.key_backup_restore_describe.v1"
    );
    assert_eq!(
        restore_describe["principal_authz_check_path"],
        "/api/v1/authz/check"
    );
    assert_eq!(
        restore_describe["principal_policy_collection_path"],
        "/api/v1/policies"
    );
    Ok(())
}

async fn start_restore(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_start = expect_json(
        server
            .http()
            .post(server.url("/api/v1/keys/backups/backup-alice-01/restore/start"))
            .bearer_auth(token)
            .json(&json!({
                "backup_id": "backup-alice-01",
                "actor": "did:web:alice.example",
                "device_id": "dev_alice",
                "verification_event_kind": "cx.key.verification.done"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_start["contract"],
        "contrix.rest.key_backup_restore_start.v1"
    );
    assert_eq!(restore_start["state"], "scaffold_started");
    assert_eq!(
        restore_start["restore_ticket_path"],
        "/api/v1/keys/backups/restore-tickets/restore-ticket-backup-alice-01"
    );
    Ok(())
}

async fn list_restore_tickets(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_ticket_collection = expect_json(
        server
            .http()
            .get(server.url("/api/v1/keys/backups/restore-tickets"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_ticket_collection["contract"],
        "contrix.rest.key_backup_restore_ticket_collection.v1"
    );
    assert_eq!(restore_ticket_collection["total_count"], 1);
    Ok(())
}

async fn resume_restore_ticket(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_resume = expect_json(
        server
            .http()
            .post(server.url(&format!("{TICKET_BASE}/resume")))
            .bearer_auth(token)
            .json(&json!({
                "resume_mode": "resume_from_current_state",
                "note": "cotest scaffold resume"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_resume["contract"],
        "contrix.rest.key_backup_restore_ticket_resume.v1"
    );
    assert_eq!(restore_resume["state"], "resumed");
    Ok(())
}

async fn fetch_restore_ticket(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_ticket = expect_json(
        server
            .http()
            .get(server.url(TICKET_BASE))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_ticket["contract"],
        "contrix.rest.key_backup_restore_ticket.v1"
    );
    assert_eq!(restore_ticket["lifecycle_state"], "resumed");
    Ok(())
}

async fn advance_restore_ticket(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_advance = expect_json(
        server
            .http()
            .post(server.url(&format!("{TICKET_BASE}/advance")))
            .bearer_auth(token)
            .json(&json!({
                "transition": "authz_checked",
                "note": "cotest scaffold advance"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_advance["contract"],
        "contrix.rest.key_backup_restore_ticket_advance.v1"
    );
    assert_eq!(restore_advance["state"], "policy_pending");
    Ok(())
}

async fn walk_approvals(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_approval_status = expect_json(
        server
            .http()
            .get(server.url(&format!("{TICKET_BASE}/approvals/status")))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_approval_status["contract"],
        "contrix.rest.key_backup_restore_approval_status.v1"
    );

    let restore_approval_submit = expect_json(
        server
            .http()
            .post(server.url(&format!("{TICKET_BASE}/approvals/submit")))
            .bearer_auth(token)
            .json(&json!({
                "approver": "did:web:guardian.example",
                "decision": "approve",
                "note": "cotest scaffold approval"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_approval_submit["contract"],
        "contrix.rest.key_backup_restore_approval_submit.v1"
    );
    Ok(())
}

async fn walk_executor(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_executor_status = expect_json(
        server
            .http()
            .get(server.url(&format!("{TICKET_BASE}/executor/status")))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_executor_status["contract"],
        "contrix.rest.key_backup_restore_executor_status.v1"
    );

    let restore_executor_enqueue = expect_json(
        server
            .http()
            .post(server.url(&format!("{TICKET_BASE}/executor/enqueue")))
            .bearer_auth(token)
            .json(&json!({
                "execution_mode": "scaffold_materialize",
                "requested_by": "did:web:alice.example",
                "note": "cotest scaffold enqueue"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_executor_enqueue["contract"],
        "contrix.rest.key_backup_restore_executor_enqueue.v1"
    );
    assert_eq!(restore_executor_enqueue["state"], "queued");

    let restore_executor_start = expect_json(
        server
            .http()
            .post(server.url(&format!("{TICKET_BASE}/executor/start")))
            .bearer_auth(token)
            .json(&json!({
                "worker_id": "restore-worker-01",
                "lease_kind": "scaffold_single_actor",
                "note": "cotest scaffold start"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_executor_start["contract"],
        "contrix.rest.key_backup_restore_executor_start.v1"
    );
    assert_eq!(restore_executor_start["state"], "running");

    let restore_executor_complete = expect_json(
        server
            .http()
            .post(server.url(&format!("{TICKET_BASE}/executor/complete")))
            .bearer_auth(token)
            .json(&json!({
                "result": "success",
                "materialized_device_id": "dev_alice_restored",
                "note": "cotest scaffold complete"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_executor_complete["contract"],
        "contrix.rest.key_backup_restore_executor_complete.v1"
    );
    assert_eq!(restore_executor_complete["ticket_state"], "completed");
    Ok(())
}

async fn fetch_result_and_receipt(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_result = expect_json(
        server
            .http()
            .get(server.url(&format!("{TICKET_BASE}/result")))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_result["contract"],
        "contrix.rest.key_backup_restore_result.v1"
    );
    assert_eq!(restore_result["result"], "success");

    let restore_receipt = expect_json(
        server
            .http()
            .get(server.url(&format!("{TICKET_BASE}/receipt")))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_receipt["contract"],
        "contrix.rest.key_backup_restore_receipt.v1"
    );
    assert_eq!(
        restore_receipt["materialized_device_id"],
        "dev_alice_restored"
    );
    Ok(())
}

async fn submit_handoff(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_handoff = expect_json(
        server
            .http()
            .post(server.url(&format!("{TICKET_BASE}/materialized-device-handoff")))
            .bearer_auth(token)
            .json(&json!({
                "target_device_id": "dev_alice_restored",
                "delivery_channel": "device_messages",
                "receipt_ack_mode": "scaffold_manual_ack",
                "note": "cotest scaffold handoff"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_handoff["contract"],
        "contrix.rest.key_backup_restore_materialized_device_handoff.v1"
    );
    assert_eq!(restore_handoff["handoff_state"], "submitted");
    Ok(())
}

async fn fetch_bundle_and_activity(server: &ContrixServer, token: &str) -> Result<()> {
    let restore_bundle = expect_json(
        server
            .http()
            .get(server.url(&format!("{TICKET_BASE}/bundle")))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_bundle["contract"],
        "contrix.rest.key_backup_restore_bundle.v1"
    );
    assert_eq!(restore_bundle["bundle_state"], "handoff_submitted");

    let restore_activity = expect_json(
        server
            .http()
            .get(server.url(&format!("{TICKET_BASE}/activity")))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_activity["contract"],
        "contrix.rest.key_backup_restore_activity.v1"
    );
    assert_eq!(
        restore_activity["recovery_live_snapshot_path"],
        "/api/v1/recovery/live-snapshot"
    );
    Ok(())
}
