use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    ContrixServer, dev_login, encrypted_envelope, expect_api_error,
    expect_indistinguishable_api_errors, expect_json, expect_response, expect_text,
    register_account,
};

pub async fn key_upload_query_and_claim_edges_are_enforced() -> Result<()> {
    let server = ContrixServer::spawn("delivery-keys").await?;
    let token = dev_login(&server, "did:web:alice.example", "dev_alice").await?;

    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/keys/upload"))
            .json(&json!({"device_id": "dev_alice"})),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/keys/query"))
            .json(&json!({"device_keys": {}})),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/keys/upload"))
            .bearer_auth(&token)
            .json(&json!({
                "device_id": "dev_other",
                "device_keys": {},
                "one_time_keys": [],
                "fallback_keys": {},
                "mls_key_packages": [],
                "device_signature": {}
            })),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    expect_json(
        server
            .http()
            .post(server.url("/api/v1/keys/upload"))
            .bearer_auth(&token)
            .json(&json!({
                "device_id": "dev_alice",
                "device_keys": {"key": "alice-device"},
                "one_time_keys": [{"key_id": "otk1", "key": "single-use"}],
                "fallback_keys": {},
                "mls_key_packages": [],
                "device_signature": {"alg": "none"}
            })),
        StatusCode::OK,
    )
    .await?;

    let first_claim = expect_json(
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
        first_claim["one_time_keys"]["did:web:alice.example"]["dev_alice"]["key"],
        "single-use"
    );

    let second_claim = expect_json(
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
    assert!(
        second_claim["one_time_keys"]["did:web:alice.example"]
            .as_object()
            .unwrap()
            .is_empty()
    );

    Ok(())
}

pub async fn to_device_messages_are_idempotent_opaque_and_drained_once() -> Result<()> {
    let server = ContrixServer::spawn("device-delivery").await?;
    let token = dev_login(&server, "did:web:alice.example", "dev_alice").await?;

    expect_api_error(
        server
            .http()
            .put(server.url("/api/v1/device_messages/device-noauth"))
            .json(&json!({"messages": {}})),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .put(server.url("/api/v1/device_messages/device-bad-json"))
            .bearer_auth(&token)
            .header("content-type", "application/json")
            .body("{"),
        StatusCode::BAD_REQUEST,
        "bad_json",
    )
    .await?;

    let send = expect_json(
        server
            .http()
            .put(server.url("/api/v1/device_messages/device-idempotent-txn"))
            .bearer_auth(&token)
            .json(&json!({
                "messages": {
                    "did:web:alice.example": {
                        "dev_alice": {
                            "type": "cx.mls.application",
                            "content": encrypted_envelope("cx.mls.application", "opaque-to-device")
                        }
                    }
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(send["delivered"]["did:web:alice.example"][0], "dev_alice");

    let duplicate = expect_json(
        server
            .http()
            .put(server.url("/api/v1/device_messages/device-idempotent-txn"))
            .bearer_auth(&token)
            .json(&json!({
                "messages": {
                    "did:web:alice.example": {
                        "dev_alice": {
                            "type": "cx.mls.application",
                            "content": encrypted_envelope("cx.mls.application", "opaque-to-device")
                        }
                    }
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert!(duplicate["delivered"].as_object().unwrap().is_empty());

    let delivered = expect_json(
        server
            .http()
            .get(server.url("/api/v1/device_messages"))
            .bearer_auth(&token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        delivered["events"][0]["content"]["content"]["ciphertext"],
        "opaque-to-device"
    );
    assert!(
        delivered["events"][0]["content"]["content"]
            .get("plaintext")
            .is_none()
    );

    let drained = expect_json(
        server
            .http()
            .get(server.url("/api/v1/device_messages"))
            .bearer_auth(&token),
        StatusCode::OK,
    )
    .await?;
    assert!(drained["events"].as_array().unwrap().is_empty());

    Ok(())
}

pub async fn blob_integrity_head_range_and_missing_edges_work() -> Result<()> {
    let server = ContrixServer::spawn("blob-media").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client("did:web:bob-blob.example", "@bob-blob", "dev_bob")
        .await?;
    let carol = server
        .register_client("did:web:carol-blob.example", "@carol-blob", "dev_carol")
        .await?;
    let space_id = alice.create_space("Blob Access Space").await?;
    alice.add_member(&space_id, &bob).await?;

    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/blob/upload"))
            .body("no auth"),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/blob/upload"))
            .bearer_auth(&alice.token)
            .header(
                "x-contrix-sha256",
                "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            )
            .body("blob-bytes"),
        StatusCode::CONFLICT,
        "hash_mismatch",
    )
    .await?;

    let blob = expect_json(
        server
            .http()
            .post(server.url("/api/v1/blob/upload"))
            .bearer_auth(&alice.token)
            .header("x-contrix-space-id", &space_id)
            .header("content-type", "text/plain")
            .body("encrypted-bytes"),
        StatusCode::OK,
    )
    .await?;
    let blob_ref = blob["blob_ref"].as_str().unwrap();

    let head = expect_response(
        server
            .http()
            .head(server.url(&format!(
                "/api/v1/blob/get?blob_ref={blob_ref}&purpose=message.attachment"
            )))
            .bearer_auth(&bob.token),
        StatusCode::OK,
    )
    .await?;
    assert!(head.headers.get("digest").is_some());

    let range = expect_text(
        bob.get(&format!(
            "/api/v1/blob/get?blob_ref={blob_ref}&purpose=message.attachment"
        ))
        .header("range", "bytes=0-8"),
        StatusCode::PARTIAL_CONTENT,
    )
    .await?;
    assert_eq!(range, "encrypted");

    expect_api_error(
        bob.get(&format!(
            "/api/v1/blob/get?blob_ref={blob_ref}&purpose=message.attachment"
        ))
            .header("range", "bytes=99-100"),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .get(server.url(&format!(
                "/api/v1/blob/get?blob_ref={blob_ref}&purpose=message.attachment&access_token={}",
                alice.token
            ))),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    let _ = expect_indistinguishable_api_errors(
        carol.get(&format!(
            "/api/v1/blob/get?blob_ref={blob_ref}&purpose=message.attachment"
        )),
        carol.get("/api/v1/blob/get?blob_ref=cx:blob:sha256:missing&purpose=message.attachment"),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    Ok(())
}

pub async fn push_and_moderation_edges_are_enforced() -> Result<()> {
    let server = ContrixServer::spawn("push-moderation").await?;
    let alice = dev_login(&server, "did:web:alice.example", "dev_alice").await?;
    let bob = register_account(
        &server,
        "did:web:bob-delivery.example",
        "@bob-delivery",
        "dev_bob",
    )
    .await?;

    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/push/unregister-device"))
            .header("content-type", "application/json")
            .body("{"),
        StatusCode::BAD_REQUEST,
        "bad_json",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/push/notify"))
            .json(&json!({
                "notification": {
                    "devices": [{"device_id": "unknown-device"}],
                    "body": "plaintext leak"
                }
            })),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;
    let notify = expect_json(
        server
            .http()
            .post(server.url("/api/v1/push/notify"))
            .json(&json!({
                "notification": {"devices": [{"device_id": "unknown-device"}]}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(notify["rejected"].as_array().unwrap().len(), 1);

    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/moderation/report"))
            .json(&json!({
                "space_id": "cx:space:01js0sp0000000000000000000",
                "target_ref": "cx:event:demo",
                "reason": "spam",
                "reporter": "did:web:alice.example"
            })),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/moderation/report"))
            .bearer_auth(&alice)
            .json(&json!({
                "space_id": "cx:space:01js0sp0000000000000000000",
                "target_ref": "cx:event:demo",
                "reason": "spam",
                "reporter": "did:web:bob-delivery.example"
            })),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/moderation/report"))
            .bearer_auth(&bob)
            .json(&json!({
                "space_id": "cx:space:01js0sp0000000000000000000",
                "target_ref": "cx:event:demo",
                "reason": "spam",
                "reporter": "did:web:bob-delivery.example"
            })),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    Ok(())
}
