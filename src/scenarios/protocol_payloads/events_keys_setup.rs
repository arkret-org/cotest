//! Phase 1 — event submit + key upload/query/claim setup.
//!
//! Walks Alice through pushing a single signed event, then uploading her
//! device-key bundle and exercising `/_arkret/self/keys/{query,claim}` to confirm
//! the upload is visible.

use anyhow::Result;
use arkret::Did;
use arkret::auth::principal_control_realm_id;
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    CokretServer, expect_json, message_create_text_payload_for_strand, parse_strand_id,
    refresh_event_proof,
};
use crate::scenarios::federation_collaboration::signed_keys_upload_body;

const KEYS_ACTOR_DID: &str = "did:web:alice.example";
const KEYS_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";

const ADAPTER_REALM_ID: &str = "ak:realm:0196419b-0000-7000-8000-000000000101";
const ADAPTER_REALM_CREATE_EVENT_ID: &str = "ak:event:0196419b-0000-7000-8000-000000000100";
const ADAPTER_MESSAGE_EVENT_ID: &str = "ak:event:0196419b-0000-7000-8000-000000000001";

pub async fn run(server: &CokretServer, token: &str) -> Result<()> {
    // soland's keys/upload requires a verified, authorized device record whose
    // device_public_key the detached JWS is verified against. Authorize the
    // device FIRST, as actor_seq 0, so it precedes this phase's contiguous
    // actor-frontier (the adapter realm/message use seq 1/2) instead of
    // perturbing it.
    let device_key = SigningKey::from_bytes(&[0x7a; 32]);
    authorize_keys_device(server, token, &device_key).await?;
    submit_adapter_event(server, token).await?;
    upload_and_inspect_keys(server, token, &device_key).await?;
    Ok(())
}

async fn authorize_keys_device(
    server: &CokretServer,
    token: &str,
    device_key: &SigningKey,
) -> Result<()> {
    let principal = Did::new(KEYS_ACTOR_DID.to_owned())
        .map_err(|error| anyhow::anyhow!("invalid keys actor DID: {error}"))?;
    let control_realm = principal_control_realm_id(&principal);
    let mut event = json!({
        "event_id": "ak:event:0196419b-0000-7000-8000-00000000d0a0",
        "kind": "ck.device.authorize",
        "realm_id": control_realm,
        "actor_id": KEYS_ACTOR_DID,
        "actor_seq": 1,
        "created_at": "2026-05-02T00:00:00Z",
        "hlc": "01970e589d21-0001-a13f9c2e",
        "prev_refs": [],
        "refs": [],
        "payload": crate::scenarios::federation_collaboration::bootstrap_device_authorize_payload(
            KEYS_ACTOR_DID,
            KEYS_DEVICE_ID,
            device_key,
        )?,
        "unsigned": {
            "local_operation_idempotency_alias": "ak:operation:0196419b-0000-7000-8000-00000000d0a0"
        },
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{KEYS_ACTOR_DID}#cotest"),
            "event_digest": "",
            "created_at": "2026-05-02T00:00:00Z",
            "jws": "a..b",
        }],
    });
    refresh_event_proof(&mut event);
    let accepted = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(token)
            .json(&event),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(accepted["status"], "accepted");
    Ok(())
}

async fn submit_adapter_event(server: &CokretServer, token: &str) -> Result<()> {
    let realm_id = create_adapter_realm(server, token).await?;
    let event = signed_message_event(
        ADAPTER_MESSAGE_EVENT_ID,
        3,
        &realm_id,
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-0000000000a1",
        "ak:thread:adapter",
        "hello",
    )?;

    let submit = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(token)
            .json(&event),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(submit["status"], "accepted");
    assert_eq!(submit["accepted"][0], ADAPTER_MESSAGE_EVENT_ID);

    Ok(())
}

async fn create_adapter_realm(server: &CokretServer, token: &str) -> Result<String> {
    let event = signed_realm_create_event(
        ADAPTER_REALM_CREATE_EVENT_ID,
        2,
        ADAPTER_REALM_ID,
        "did:web:alice.example",
        "Adapter Event Space",
    )?;
    let submit = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(token)
            .json(&event),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(submit["status"], "accepted");
    assert_eq!(submit["accepted"][0], ADAPTER_REALM_CREATE_EVENT_ID);

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
            "schema": "ck.schema.realm.v1",
            "title": title,
            "summary": title,
            "trust_domain": "ak:trust_domain:protocol-payloads.cotest.local",
            "created_by": actor_id,
            "schema_refs": ["ck.schema.realm.v1"],
            "default_discoverability": "public",
            "default_join_rule": "public",
            "history_visibility": "world_readable",
            "encryption_profile": "none",
            "security_class": "standard",
            "federation_policy": "open",
            "notary_profile": "single_did",
            "digest_algorithm": "sha256",
            "notary": {
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
        "kind": "ck.realm.create",
        "realm_id": realm_id,
        "actor_id": actor_id,
        "actor_seq": actor_seq,
        "created_at": "2026-05-02T00:00:00Z",
        "hlc": format!("01970e589d21-{:04x}-a13f9c2e", actor_seq & 0xffff),
        "prev_refs": [],
        "refs": [],
        "payload": payload,
        "unsigned": {
            "local_operation_idempotency_alias": format!(
                "ak:operation:{}",
                event_id.trim_start_matches("ak:event:")
            )
        },
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{actor_id}#cotest"),
            "event_digest": "",
            "created_at": "2026-05-02T00:00:00Z",
            "jws": "a..b",
        }],
    });
    refresh_event_proof(&mut event);
    Ok(event)
}

fn signed_message_event(
    event_id: &str,
    actor_seq: u64,
    realm_id: &str,
    actor_id: &str,
    _device_id: &str,
    _thread_id: &str,
    body: &str,
) -> Result<Value> {
    let payload = message_create_text_payload_for_strand(
        parse_strand_id("ak:strand:0196419b-0000-7000-8000-000000000001")?,
        body,
    )?;
    let mut event = json!({
        "event_id": event_id,
        "kind": "ck.message.create",
        "realm_id": realm_id,
        "actor_id": actor_id,
        "actor_seq": actor_seq,
        "created_at": "2026-05-02T00:00:00Z",
        "hlc": format!("01970e589d21-{:04x}-a13f9c2e", actor_seq & 0xffff),
        "prev_refs": [],
        "refs": [],
        "payload": payload,
        "unsigned": {
            "local_operation_idempotency_alias": format!(
                "ak:operation:{}",
                event_id.trim_start_matches("ak:event:")
            )
        },
        "proofs": [{
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": format!("{actor_id}#cotest"),
            "event_digest": "",
            "created_at": "2026-05-02T00:00:00Z",
            "jws": "a..b",
        }],
    });
    refresh_event_proof(&mut event);
    Ok(event)
}

async fn upload_and_inspect_keys(
    server: &CokretServer,
    token: &str,
    device_key: &SigningKey,
) -> Result<()> {
    let upload_keys = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/keys/upload"))
            .bearer_auth(token)
            .json(&signed_keys_upload_body(
                KEYS_ACTOR_DID,
                KEYS_DEVICE_ID,
                device_key,
                json!({
                    "signed_curve25519:otk1": {
                        "algorithm": "signed_curve25519",
                        "key_id": "otk1",
                        "key": "one-time"
                    }
                }),
                json!({"signed_curve25519:fallback": {"key": "fallback-key"}}),
            )?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(upload_keys["one_time_key_counts"]["total"], 1);

    let query_keys = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/keys/query"))
            .bearer_auth(token)
            .json(&json!({"device_keys": {"did:web:alice.example": ["ak:device:01904100-0000-7000-8000-0000000000a1"]}})),
        StatusCode::OK,
    )
    .await?;
    // The stored device_signature is the authoritative detached-JWS bundle
    // (alg / kid / jws) the upload was verified with, not a stub `signature`.
    let queried_signature = &query_keys["device_keys"]["did:web:alice.example"]["ak:device:01904100-0000-7000-8000-0000000000a1"]
        ["algorithms"]["device_signature"];
    assert_eq!(queried_signature["alg"], "EdDSA");
    assert!(
        queried_signature["jws"].as_str().is_some(),
        "queried device_signature must carry the detached JWS: {queried_signature}"
    );

    let claimed = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/keys/claim"))
            .bearer_auth(token)
            .json(&json!({
                "one_time_keys": {
                    "did:web:alice.example": {"ak:device:01904100-0000-7000-8000-0000000000a1": "signed_curve25519"}
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        claimed["one_time_keys"]["did:web:alice.example"]["ak:device:01904100-0000-7000-8000-0000000000a1"]
            ["key"],
        "one-time"
    );
    Ok(())
}
