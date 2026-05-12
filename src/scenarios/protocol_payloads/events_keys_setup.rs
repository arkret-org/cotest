//! Phase 1 — event submit + key upload/query/claim setup.
//!
//! Walks Alice through pushing a single signed event, then uploading her
//! device-key bundle and exercising `/api/v1/keys/{query,claim}` to confirm
//! the upload is visible.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::harness::{ContrixServer, expect_json};

pub async fn run(server: &ContrixServer, token: &str) -> Result<()> {
    submit_adapter_event(server, token).await?;
    upload_and_inspect_keys(server, token).await?;
    Ok(())
}

async fn submit_adapter_event(server: &ContrixServer, token: &str) -> Result<()> {
    let created_space = expect_json(
        server
            .http()
            .post(server.url("/api/v1/spaces"))
            .bearer_auth(token)
            .json(&json!({ "title": "Adapter Event Space" })),
        StatusCode::CREATED,
    )
    .await?;
    let space_id = created_space["space_id"]
        .as_str()
        .expect("space_id")
        .to_owned();
    let event = signed_message_event(
        "cx:event:0196419b-0000-7000-8000-000000000001",
        1,
        &space_id,
        "did:web:alice.example",
        "dev_alice",
        "cx:thread:adapter",
        "hello",
    )?;

    let submit = expect_json(
        server
            .http()
            .post(server.url("/api/v1/events"))
            .bearer_auth(token)
            .json(&event),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(submit["status"], "accepted");
    assert_eq!(
        submit["event_id"],
        "cx:event:0196419b-0000-7000-8000-000000000001"
    );

    Ok(())
}

fn signed_message_event(
    event_id: &str,
    actor_seq: u64,
    space_id: &str,
    actor_id: &str,
    _device_id: &str,
    thread_id: &str,
    body: &str,
) -> Result<Value> {
    let payload = json!({
        "event_id": event_id,
        "sender": actor_id,
        "thread_id": thread_id,
        "content": {"body": body, "msgtype": "m.text"},
        "encrypted": false
    });
    let mut event = json!({
        "event_id": event_id,
        "kind": "cx.message.create",
        "actor_id": actor_id,
        "actor_seq": actor_seq,
        "space_id": space_id,
        "created_at": "2026-05-02T00:00:00Z",
        "hlc": format!("01970e589d21-{actor_seq:08x}-a13f9c2e"),
        "prev_refs": [],
        "refs": [],
        "payload": payload,
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{actor_id}#cotest"),
            "payload_hash": "",
            "created_at": "2026-05-02T00:00:00Z",
            "jws": "a..b",
        }],
    });
    refresh_event_proof(&mut event)?;
    Ok(event)
}

fn canonical_event_digest(event: &Value) -> Result<String> {
    let mut canonical = event.clone();
    if let Value::Object(object) = &mut canonical {
        object.remove("proofs");
        object.remove("unsigned");
    }
    sha256_json(&canonical)
}

fn refresh_event_proof(event: &mut Value) -> Result<()> {
    let digest = canonical_event_digest(event)?;
    event["proofs"][0]["payload_hash"] = Value::String(digest);
    Ok(())
}

fn sha256_json(value: &Value) -> Result<String> {
    let bytes = serde_json::to_vec(value)?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

async fn upload_and_inspect_keys(server: &ContrixServer, token: &str) -> Result<()> {
    let upload_keys = expect_json(
        server
            .http()
            .post(server.url("/api/v1/keys/upload"))
            .bearer_auth(token)
            .json(&json!({
                "device_id": "dev_alice",
                "one_time_keys": {"signed_curve25519:otk1": {"key_id": "otk1", "key": "one-time"}},
                "fallback_keys": {"signed_curve25519:fallback": {"key": "fallback-key"}},
                "device_signature": {"alg": "EdDSA", "signature": "alice-device-signature"}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(upload_keys["one_time_key_counts"]["total"], 1);

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
        query_keys["device_keys"]["did:web:alice.example"]["dev_alice"]["device_signature"]["signature"],
        "alice-device-signature"
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
