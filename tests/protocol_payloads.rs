mod support;

use anyhow::Result;
use chrono::Utc;
use contrix_sdk::{Commit, CommitId, Did, Hash, Operation, OperationId, Proof, SpaceId};
use reqwest::StatusCode;
use serde_json::json;
use serial_test::serial;

use support::{ServerxInstance, dev_login, expect_json, expect_status};

#[tokio::test]
#[serial]
async fn repo_keys_device_blob_push_and_moderation_surfaces_work() -> Result<()> {
    let server = ServerxInstance::spawn("protocol-payloads").await?;
    let token = dev_login(&server, "did:web:alice.example", "dev_alice").await?;

    let operation = Operation::create(
        OperationId::new("cx:operation:protocol-payloadsdapter-01")?,
        SpaceId::new("cx:space:protocol-payloadsdapter")?,
        "message",
        json!({"body": "repo protocol hello"}),
    );
    let operation_digest = Hash::new(operation.operation_digest()?)?;
    let mut commit = Commit::new(
        CommitId::new("cx:commit:protocol-payloadsdapter-01")?,
        "did:web:alice.example",
        Did::new("did:web:alice.example")?,
        1,
    );
    commit.operations.push(operation_digest);
    commit.proofs.push(dummy_proof());
    let commit_digest = commit.commit_digest()?;

    let submit = expect_json(
        server
            .http()
            .post(server.url("/api/v1/repo/submit-commit"))
            .json(&json!({
                "repo_id": "did:web:alice.example",
                "expected_head": null,
                "operations": [operation],
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
        "cx:operation:protocol-payloadsdapter-01"
    );

    let upload_keys = expect_json(
        server
            .http()
            .post(server.url("/api/v1/keys/upload"))
            .bearer_auth(&token)
            .json(&json!({
                "device_id": "dev_alice",
                "device_keys": {"alg": "mls-rfc9420", "key": "alice-device-key"},
                "one_time_keys": [{"key_id": "otk1", "key": "one-time"}],
                "fallback_keys": {"signed_curve25519:fallback": {"key": "fallback-key"}},
                "mls_key_packages": [{"package_id": "mls-package-1", "key": "opaque-package"}],
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
                            "content": {
                                "algorithm": "mls-rfc9420",
                                "ciphertext": "base64url-opaque-ciphertext"
                            }
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
            .json(&json!({"messages": {}})),
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

    expect_status(
        server
            .http()
            .post(server.url("/api/v1/blob/upload"))
            .bearer_auth(&token)
            .header("x-contrix-sha256", "sha256:deadbeef")
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

    let range = server
        .http()
        .get(server.url(&format!(
            "/api/v1/blob/get?blob_ref={}",
            blob["blob_ref"].as_str().unwrap()
        )))
        .header("range", "bytes=0-8")
        .send()
        .await?;
    assert_eq!(range.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(range.text().await?, "encrypted");

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

fn dummy_proof() -> Proof {
    Proof {
        kind: "detached_jws".to_owned(),
        alg: "none".to_owned(),
        verification_method: "did:web:alice.example#dev".to_owned(),
        payload_hash: Hash::new(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap(),
        created_at: Utc::now(),
        domain: None,
        audience: None,
        jws: "dev-proof".to_owned(),
    }
}
