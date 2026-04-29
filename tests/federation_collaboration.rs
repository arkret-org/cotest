mod support;

use anyhow::Result;
use contrix_sdk::{Operation, OperationId, SpaceId};
use reqwest::StatusCode;
use serde_json::json;
use serial_test::serial;

use support::{ServerxInstance, dev_login, expect_json, register_account};

#[tokio::test]
#[serial]
async fn cross_server_collaboration_flow_works() -> Result<()> {
    let server_a = ServerxInstance::spawn("federation-a").await?;
    let server_b = ServerxInstance::spawn("federation-b").await?;
    let alice = dev_login(&server_a, "did:web:alice.example", "dev_alice").await?;
    let bob = register_account(&server_b, "did:web:bob-b.example", "@bob-b", "dev_bob_b").await?;

    let describe_a = expect_json(
        server_a.http().get(server_a.url("/api/v1/server/describe")),
        StatusCode::OK,
    )
    .await?;
    let describe_b = expect_json(
        server_b.http().get(server_b.url("/api/v1/server/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(describe_a["service_type"], "principal_server");
    assert_eq!(describe_b["service_type"], "principal_server");

    let bob_document = expect_json(
        server_a
            .http()
            .post(server_a.url("/api/v1/identity/resolve"))
            .json(&json!({"did": "did:web:bob-b.example"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(bob_document["did_document"]["id"], "did:web:bob-b.example");

    let verify_bob = expect_json(
        server_a
            .http()
            .post(server_a.url("/api/v1/federation/verify-actor"))
            .json(&json!({
                "actor_id": "did:web:bob-b.example",
                "signature": {"alg": "none"},
                "purpose": "cross-server-invite"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(verify_bob["valid"], true);

    let created_space = expect_json(
        server_a
            .http()
            .post(server_a.url("/api/v1/spaces"))
            .bearer_auth(&alice)
            .json(&json!({
                "title": "Federated Collaboration Space",
                "summary": "cross server collaboration",
                "public": false,
                "invitees": ["did:web:bob-b.example"]
            })),
        StatusCode::CREATED,
    )
    .await?;
    let space_id = created_space["space_id"].as_str().unwrap().to_owned();

    let alice_message = Operation::create(
        OperationId::new("cx:operation:federation-alice-message-01")?,
        SpaceId::new(space_id.clone())?,
        "message",
        json!({
            "event_id": "cx:event:federation-alice-01",
            "sender": "did:web:alice.example",
            "thread_id": "cx:thread:federation",
            "space_title": "Federated Collaboration Space",
            "space_summary": "cross server collaboration",
            "members": ["did:web:alice.example", "did:web:bob-b.example"],
            "content": {"body": "hello bob from server a"},
            "encrypted": false
        }),
    );
    let pushed_to_b = expect_json(
        server_b
            .http()
            .post(server_b.url("/api/v1/federation/push-operations"))
            .json(&json!({
                "origin": "did:web:federation-a.cotest.local",
                "destination": "did:web:federation-b.cotest.local",
                "space_id": space_id,
                "service_binding_ref": "cotest",
                "operations": [alice_message]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        pushed_to_b["accepted"][0],
        "cx:operation:federation-alice-message-01"
    );

    let pulled_on_b = expect_json(
        server_b.http().get(server_b.url(&format!(
            "/api/v1/federation/pull-operations?space_id={space_id}"
        ))),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        pulled_on_b["operations"][0]["operation_id"],
        "cx:operation:federation-alice-message-01"
    );

    let bob_sync = expect_json(
        server_b
            .http()
            .post(server_b.url("/api/v1/sync"))
            .bearer_auth(&bob)
            .json(&json!({})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        bob_sync["spaces"][&space_id]["timeline"]["events"][0]["content"]["body"],
        "hello bob from server a"
    );

    let bob_reply = Operation::create(
        OperationId::new("cx:operation:federation-bob-message-01")?,
        SpaceId::new(space_id.clone())?,
        "message",
        json!({
            "event_id": "cx:event:federation-bob-01",
            "sender": "did:web:bob-b.example",
            "thread_id": "cx:thread:federation",
            "space_title": "Federated Collaboration Space",
            "members": ["did:web:alice.example", "did:web:bob-b.example"],
            "content": {"body": "hello alice from server b"},
            "encrypted": false
        }),
    );
    let txn = expect_json(
        server_a
            .http()
            .put(server_a.url("/api/v1/federation/transactions/federation-b-to-a-01"))
            .json(&json!({
                "origin": "did:web:federation-b.cotest.local",
                "destination": "did:web:federation-a.cotest.local",
                "service_binding_ref": "cotest",
                "operations": [bob_reply]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(txn["accepted"][0], "cx:operation:federation-bob-message-01");

    let alice_thread = expect_json(
        server_a
            .http()
            .get(server_a.url("/api/v1/index/thread?thread_id=cx:thread:federation"))
            .bearer_auth(&alice),
        StatusCode::OK,
    )
    .await?;
    assert!(
        alice_thread["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["content"]["body"] == "hello alice from server b")
    );

    let key_upload = expect_json(
        server_b
            .http()
            .post(server_b.url("/api/v1/keys/upload"))
            .bearer_auth(&bob)
            .json(&json!({
                "device_id": "dev_bob_b",
                "device_keys": {"alg": "mls-rfc9420", "key": "bob-device-key"},
                "one_time_keys": [{"key_id": "bob-otk1", "key": "bob-one-time"}],
                "fallback_keys": {},
                "mls_key_packages": [{"package_id": "bob-mls-package", "key": "opaque"}],
                "device_signature": {"alg": "none"}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(key_upload["one_time_key_counts"]["signed_curve25519"], 1);

    let device_message = expect_json(
        server_b
            .http()
            .put(server_b.url("/api/v1/device_messages/federation-to-bob-01"))
            .bearer_auth(&bob)
            .json(&json!({
                "messages": {
                    "did:web:bob-b.example": {
                        "dev_bob_b": {
                            "type": "cx.mls.welcome",
                            "content": {"ciphertext": "opaque-cross-server-welcome"}
                        }
                    }
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(device_message["ok"], true);
    let received = expect_json(
        server_b
            .http()
            .get(server_b.url("/api/v1/device_messages"))
            .bearer_auth(&bob),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        received["events"][0]["content"]["content"]["ciphertext"],
        "opaque-cross-server-welcome"
    );

    let blob = expect_json(
        server_a
            .http()
            .post(server_a.url("/api/v1/blob/upload"))
            .bearer_auth(&alice)
            .header("content-type", "application/octet-stream")
            .body("federated-media"),
        StatusCode::OK,
    )
    .await?;
    let downloaded = server_a
        .http()
        .get(server_a.url(&format!(
            "/api/v1/blob/get?blob_ref={}",
            blob["blob_ref"].as_str().unwrap()
        )))
        .send()
        .await?;
    assert_eq!(downloaded.status(), StatusCode::OK);
    assert_eq!(downloaded.text().await?, "federated-media");

    let push = expect_json(
        server_b
            .http()
            .post(server_b.url("/api/v1/push/register-device"))
            .bearer_auth(&bob)
            .json(&json!({
                "device_id": "dev_bob_b",
                "push_gateway": "https://push.example",
                "push_key": "opaque",
                "platform": "desktop",
                "app_id": "clientx"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push["ok"], true);

    let report = expect_json(
        server_b
            .http()
            .post(server_b.url("/api/v1/moderation/report"))
            .bearer_auth(&bob)
            .json(&json!({
                "space_id": space_id,
                "target_ref": "cx:event:federation-alice-01",
                "reason": "spam",
                "reporter": "did:web:bob-b.example"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(report["status"], "queued");

    Ok(())
}
