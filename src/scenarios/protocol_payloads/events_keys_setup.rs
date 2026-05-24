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

const ADAPTER_REALM_ID: &str = "cx:realm:0196419b-0000-7000-8000-000000000101";
const ADAPTER_REALM_CREATE_EVENT_ID: &str = "cx:event:0196419b-0000-7000-8000-000000000100";
const ADAPTER_MESSAGE_EVENT_ID: &str = "cx:event:0196419b-0000-7000-8000-000000000001";

pub async fn run(server: &ContrixServer, token: &str) -> Result<()> {
    submit_adapter_event(server, token).await?;
    upload_and_inspect_keys(server, token).await?;
    Ok(())
}

async fn submit_adapter_event(server: &ContrixServer, token: &str) -> Result<()> {
    let space_id = create_adapter_realm(server, token).await?;
    let event = signed_message_event(
        ADAPTER_MESSAGE_EVENT_ID,
        2,
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
    assert_eq!(submit["event_id"], ADAPTER_MESSAGE_EVENT_ID);

    Ok(())
}

async fn create_adapter_realm(server: &ContrixServer, token: &str) -> Result<String> {
    let event = signed_realm_create_event(
        ADAPTER_REALM_CREATE_EVENT_ID,
        1,
        ADAPTER_REALM_ID,
        "did:web:alice.example",
        "Adapter Event Space",
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
    assert_eq!(submit["event_id"], ADAPTER_REALM_CREATE_EVENT_ID);

    Ok(ADAPTER_REALM_ID.to_owned())
}

fn signed_realm_create_event(
    event_id: &str,
    actor_seq: u64,
    realm_id: &str,
    actor_id: &str,
    title: &str,
) -> Result<Value> {
    let payload = json!({
        "object": {
            "id": realm_id,
            "schema": "cx.schema.realm.v1",
            "title": title,
            "summary": title,
            "trust_domain": "cx:trust_domain:protocol-payloads.cotest.local",
            "created_by_principal": actor_id,
            "schema_refs": ["cx.schema.realm.v1"],
            "default_discoverability": "public",
            "default_join_rule": "public",
            "history_visibility": "world_readable",
            "encryption_profile": "none",
            "security_class": "standard",
            "federation_policy": "open",
            "anchor_profile": "single_did",
            "digest_algorithm": "sha256",
            "anchorer": {
                "type": "single_did",
                "did": actor_id,
                "recovery_members": ["did:web:recovery-anchorer.cotest.local"],
                "controller_organization": "did:web:protocol-payloads.cotest.local",
                "recovery_controller_organizations": ["did:web:recovery-org.cotest.local"]
            },
            "created_at": "2026-05-02T00:00:00Z"
        }
    });
    let mut event = json!({
        "event_id": event_id,
        "kind": "cx.realm.create",
        "schema_id": "cx.schema.event.v1",
        "actor_id": actor_id,
        "actor_seq": actor_seq,
        "realm_id": realm_id,
        "created_at": "2026-05-02T00:00:00Z",
        "hlc": format!("01970e589d21-{:04x}-a13f9c2e", actor_seq & 0xffff),
        "prev_refs": [],
        "refs": [],
        "payload": payload,
        "unsigned": {
            "local_operation_idempotency_alias": format!(
                "cx:operation:{}",
                event_id.trim_start_matches("cx:event:")
            )
        },
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{actor_id}#cotest"),
            "payload_digest": "",
            "created_at": "2026-05-02T00:00:00Z",
            "jws": "a..b",
        }],
    });
    refresh_event_proof(&mut event)?;
    Ok(event)
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
        "flow_id": "cx:flow:0196419b-0000-7000-8000-000000000001",
        "track": "discussion",
        "thread_id": thread_id,
        "content": {
            "kind": "cx.content.text",
            "body": body,
            "format": "plain"
        },
        "encrypted": false
    });
    let mut event = json!({
        "event_id": event_id,
        "kind": "cx.message.create",
        "actor_id": actor_id,
        "actor_seq": actor_seq,
        "realm_id": space_id,
        "created_at": "2026-05-02T00:00:00Z",
        "hlc": format!("01970e589d21-{:04x}-a13f9c2e", actor_seq & 0xffff),
        "prev_refs": [],
        "refs": [],
        "payload": payload,
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{actor_id}#cotest"),
            "payload_digest": "",
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
    event["proofs"][0]["payload_digest"] = Value::String(digest);
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
                "one_time_keys": [{
                    "algorithm": "signed_curve25519",
                    "key_id": "otk1",
                    "key": "one-time"
                }],
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
