//! Phase 1 — repo submit/sync + key upload/query/claim setup.
//!
//! Walks Alice through pushing a single signed adapter commit, replaying it
//! via `/api/v1/repo/sync`, then uploading her full device-key bundle and
//! exercising `/api/v1/keys/{query,claim}` to confirm the upload is visible.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ContrixServer, expect_json, repo_message_operation, signed_commit};

pub async fn run(server: &ContrixServer, token: &str) -> Result<()> {
    submit_adapter_commit(server).await?;
    upload_and_inspect_keys(server, token).await?;
    Ok(())
}

async fn submit_adapter_commit(server: &ContrixServer) -> Result<()> {
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
    Ok(())
}

async fn upload_and_inspect_keys(server: &ContrixServer, token: &str) -> Result<()> {
    let upload_keys = expect_json(
        server
            .http()
            .post(server.url("/api/v1/keys/upload"))
            .bearer_auth(token)
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
            .bearer_auth(token)
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
            .bearer_auth(token)
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
    Ok(())
}
