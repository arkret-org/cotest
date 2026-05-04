use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    ContrixServer, dev_login, encrypted_envelope, expect_json, expect_status, expect_text,
    repo_message_operation, signed_commit,
};

pub async fn repo_keys_device_blob_push_and_moderation_surfaces_work() -> Result<()> {
    let server = ContrixServer::spawn("protocol-payloads").await?;
    let token = dev_login(&server, "did:web:alice.example", "dev_alice").await?;

    let operation = repo_message_operation(
        "cx:operation:adapter-01",
        "cx:event:adapter-01",
        "cx:space:adapter",
        "did:web:alice.example",
        "cx:thread:adapter",
        "hello",
    )?;
    let commit = signed_commit(
        "cx:commit:adapter-01",
        "did:web:alice.example",
        1,
        std::slice::from_ref(&operation),
        None,
    )?;
    let commit_digest = commit.commit_digest()?;

    let submit = expect_json(
        server
            .http()
            .post(server.url("/api/v1/repo/submit-commit"))
            .json(&json!({
                "repo_id": "did:web:alice.example",
                "expected_head": null,
                "operations": [operation.clone()],
                "commit": commit
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(submit["status"], "accepted");
    assert_eq!(submit["head_commit"], commit_digest);

    let repo_sync = expect_json(
        server
            .http()
            .post(server.url("/api/v1/repo/sync"))
            .json(&json!({"repo_id": "did:web:alice.example", "limit": 10})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        repo_sync["operations"][0]["operation_id"],
        "cx:operation:adapter-01"
    );

    let upload_keys = expect_json(
        server
            .http()
            .post(server.url("/api/v1/keys/upload"))
            .bearer_auth(&token)
            .json(&json!({
                "device_id": "dev_alice",
                "device_keys": {"alg": "mls-rfc9420", "key": "alice-device-key"},
                "principal_signing_keys": [{"kid": "did:web:alice.example#principal", "key": "principal-key"}],
                "recovery_keys": [{"kid": "did:web:alice.example#recovery", "key": "recovery-key"}],
                "session_keys": [{"kid": "did:web:alice.example#session", "key": "session-key"}],
                "agent_keys": [{"kid": "did:web:alice.example#agent", "key": "agent-key"}],
                "one_time_keys": [{"key_id": "otk1", "key": "one-time"}],
                "fallback_keys": {"signed_curve25519:fallback": {"key": "fallback-key"}},
                "mls_key_packages": [{"package_id": "mls-package-1", "key": "opaque-package"}],
                "backup_restore_keys": [{"kid": "did:web:alice.example#backup", "key": "backup-key"}],
                "device_signature": {"alg": "none"}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(upload_keys["one_time_key_counts"]["signed_curve25519"], 1);

    let query_keys = expect_json(
        server
            .http()
            .post(server.url("/api/v1/keys/query"))
            .bearer_auth(&token)
            .json(&json!({"device_keys": {"did:web:alice.example": ["dev_alice"]}})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        query_keys["device_keys"]["did:web:alice.example"]["dev_alice"]["device_keys"]["key"],
        "alice-device-key"
    );
    assert_eq!(
        query_keys["device_keys"]["did:web:alice.example"]["dev_alice"]["agent_keys"][0]["key"],
        "agent-key"
    );

    let claimed = expect_json(
        server
            .http()
            .post(server.url("/api/v1/keys/claim"))
            .bearer_auth(&token)
            .json(&json!({
                "one_time_keys": {
                    "did:web:alice.example": {"dev_alice": "signed_curve25519"}
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        claimed["one_time_keys"]["did:web:alice.example"]["dev_alice"]["key"],
        "one-time"
    );

    let send = expect_json(
        server
            .http()
            .put(server.url("/api/v1/device_messages/protocol-device-txn"))
            .bearer_auth(&token)
            .json(&json!({
                "messages": {
                    "did:web:alice.example": {
                        "dev_alice": {
                            "type": "cx.mls.application",
                            "content": encrypted_envelope("cx.mls.application", "base64url-opaque-ciphertext")
                        }
                    }
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(send["ok"], true);

    let duplicate_send = expect_json(
        server
            .http()
            .put(server.url("/api/v1/device_messages/protocol-device-txn"))
            .bearer_auth(&token)
            .json(&json!({
                "messages": {
                    "did:web:alice.example": {
                        "dev_alice": {
                            "type": "cx.mls.application",
                            "content": encrypted_envelope("cx.mls.application", "base64url-opaque-ciphertext")
                        }
                    }
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(duplicate_send["delivered"].as_object().unwrap().len(), 0);

    let delivered = expect_json(
        server
            .http()
            .get(server.url("/api/v1/device_messages"))
            .bearer_auth(&token),
        StatusCode::OK,
    )
    .await?;
    let content = &delivered["events"][0]["content"]["content"];
    assert_eq!(content["ciphertext"], "base64url-opaque-ciphertext");
    assert!(content.get("plaintext").is_none());

    let device_messages_describe = expect_json(
        server
            .http()
            .get(server.url("/api/v1/device_messages/describe"))
            .bearer_auth(&token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        device_messages_describe["contract"],
        "contrix.rest.device_messages_describe.v1"
    );
    assert_eq!(
        device_messages_describe["schema"],
        "cx.schema.device_message.v1"
    );

    let verification_send = expect_json(
        server
            .http()
            .put(server.url("/api/v1/device_messages/protocol-verification-txn"))
            .bearer_auth(&token)
            .json(&json!({
                "messages": {
                    "did:web:alice.example": {
                        "dev_alice": {
                            "type": "cx.key.verification.request",
                            "content": {
                                "transaction_id": "verify-sas-01",
                                "method": "sas",
                                "todo": "replace scaffold verification payload with signed device envelope"
                            }
                        }
                    }
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(verification_send["ok"], true);

    let backup_put = expect_json(
        server
            .http()
            .put(server.url("/api/v1/keys/backups/backup-alice-01"))
            .bearer_auth(&token)
            .json(&json!({
                "schema": "cx.schema.key_backup.v1",
                "backup_id": "backup-alice-01",
                "class": "mls_export",
                "encryption": {
                    "alg": "xchacha20poly1305",
                    "kdf": "argon2id"
                },
                "items": [
                    {
                        "kind": "mls_group_state",
                        "ref": "group:default",
                        "todo": "replace scaffold payload with encrypted export blob"
                    }
                ]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(backup_put["ok"], true);
    assert_eq!(backup_put["state"], "scaffold");

    let backup_list = expect_json(
        server
            .http()
            .get(server.url("/api/v1/keys/backups"))
            .bearer_auth(&token),
        StatusCode::OK,
    )
    .await?;
    assert!(backup_list["items"].as_array().unwrap().len() >= 1);

    let key_backups_describe = expect_json(
        server
            .http()
            .get(server.url("/api/v1/keys/backups/describe"))
            .bearer_auth(&token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        key_backups_describe["contract"],
        "contrix.rest.key_backups_describe.v1"
    );
    assert_eq!(key_backups_describe["schema"], "cx.schema.key_backup.v1");

    let backup_get = expect_json(
        server
            .http()
            .get(server.url("/api/v1/keys/backups/backup-alice-01"))
            .bearer_auth(&token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(backup_get["backup"]["schema"], "cx.schema.key_backup.v1");

    let restore_describe = expect_json(
        server
            .http()
            .get(server.url("/api/v1/keys/backups/backup-alice-01/restore/describe"))
            .bearer_auth(&token),
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

    let restore_start = expect_json(
        server
            .http()
            .post(server.url("/api/v1/keys/backups/backup-alice-01/restore/start"))
            .bearer_auth(&token)
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

    let restore_ticket = expect_json(
        server
            .http()
            .get(server.url("/api/v1/keys/backups/restore-tickets/restore-ticket-backup-alice-01"))
            .bearer_auth(&token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restore_ticket["contract"],
        "contrix.rest.key_backup_restore_ticket.v1"
    );
    assert_eq!(restore_ticket["lifecycle_state"], "authz_pending");

    let restore_advance = expect_json(
        server
            .http()
            .post(server.url("/api/v1/keys/backups/restore-tickets/restore-ticket-backup-alice-01/advance"))
            .bearer_auth(&token)
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

    let restore_approval_status = expect_json(
        server
            .http()
            .get(server.url("/api/v1/keys/backups/restore-tickets/restore-ticket-backup-alice-01/approvals/status"))
            .bearer_auth(&token),
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
            .post(server.url("/api/v1/keys/backups/restore-tickets/restore-ticket-backup-alice-01/approvals/submit"))
            .bearer_auth(&token)
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

    let restore_executor_status = expect_json(
        server
            .http()
            .get(server.url("/api/v1/keys/backups/restore-tickets/restore-ticket-backup-alice-01/executor/status"))
            .bearer_auth(&token),
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
            .post(server.url("/api/v1/keys/backups/restore-tickets/restore-ticket-backup-alice-01/executor/enqueue"))
            .bearer_auth(&token)
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

    let authz_describe = expect_json(
        server
            .http()
            .get(server.url("/api/v1/authz/describe"))
            .bearer_auth(&token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(authz_describe["contract"], "contrix.rest.authz_describe.v1");
    assert_eq!(authz_describe["check_path"], "/api/v1/authz/check");

    let recovery_contract_stack = expect_json(
        server
            .http()
            .get(server.url("/api/v1/recovery/contract-stack"))
            .bearer_auth(&token),
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

    let policies_describe = expect_json(
        server
            .http()
            .get(server.url("/api/v1/policies/describe"))
            .bearer_auth(&token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        policies_describe["contract"],
        "contrix.rest.policies_describe.v1"
    );
    assert_eq!(policies_describe["collection_path"], "/api/v1/policies");

    let backup_delete = expect_json(
        server
            .http()
            .delete(server.url("/api/v1/keys/backups/backup-alice-01"))
            .bearer_auth(&token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(backup_delete["ok"], true);

    expect_status(
        server
            .http()
            .post(server.url("/api/v1/blob/upload"))
            .bearer_auth(&token)
            .header(
                "x-contrix-sha256",
                "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            )
            .body("encrypted-bytes"),
        StatusCode::CONFLICT,
    )
    .await?;

    let blob = expect_json(
        server
            .http()
            .post(server.url("/api/v1/blob/upload"))
            .bearer_auth(&token)
            .header("content-type", "text/plain")
            .body("encrypted-bytes"),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(blob["size"], 15);
    assert!(
        blob["blob_ref"]
            .as_str()
            .unwrap()
            .starts_with("cx:blob:sha256:")
    );

    let range = expect_text(
        server
            .http()
            .get(server.url(&format!(
                "/api/v1/blob/get?blob_ref={}&purpose=message.attachment",
                blob["blob_ref"].as_str().unwrap()
            )))
            .bearer_auth(&token)
            .header("range", "bytes=0-8"),
        StatusCode::PARTIAL_CONTENT,
    )
    .await?;
    assert_eq!(range, "encrypted");

    let push = expect_json(
        server
            .http()
            .post(server.url("/api/v1/push/register-device"))
            .bearer_auth(&token)
            .json(&json!({
                "device_id": "dev_alice",
                "push_gateway": "https://push.example",
                "push_key": "opaque",
                "platform": "desktop",
                "app_id": "clientx"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push["ok"], true);

    let notify = expect_json(
        server
            .http()
            .post(server.url("/api/v1/push/notify"))
            .json(&json!({
                "notification": {
                    "type": "blind_wakeup",
                    "devices": [{"device_id": "dev_alice"}, {"device_id": "dev_missing"}]
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(notify["rejected"].as_array().unwrap().len(), 1);

    let report = expect_json(
        server
            .http()
            .post(server.url("/api/v1/moderation/report"))
            .bearer_auth(&token)
            .json(&json!({
                "space_id": "cx:space:01js0sp0000000000000000000",
                "target_ref": "cx:event:demo",
                "reason": "spam",
                "reporter": "did:web:alice.example"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(report["status"], "queued");

    Ok(())
}
