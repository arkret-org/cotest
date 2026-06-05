use anyhow::Result;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    CokretServer, TestActorClient, dev_login, encrypted_envelope, expect_api_error,
    expect_indistinguishable_api_errors, expect_json, expect_response, expect_text,
    refresh_event_proof, register_account,
};

const BLOB_REALM_ID: &str = "ck:realm:0196419b-0000-7000-8000-00000000d101";
const BLOB_REALM_CREATE_EVENT_ID: &str = "ck:event:0196419b-0000-7000-8000-00000000d100";
const BLOB_REALM_MEMBER_EVENT_ID: &str = "ck:event:0196419b-0000-7000-8000-00000000d102";

pub async fn key_upload_query_and_claim_edges_are_enforced() -> Result<()> {
    let server = CokretServer::spawn("delivery-keys").await?;
    let token = dev_login(&server, "did:web:alice.example", "dev_alice").await?;

    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/self/keys/upload"))
            .json(&json!({"device_id": "dev_alice"})),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/self/keys/query"))
            .json(&json!({"device_keys": {}})),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/self/keys/upload"))
            .bearer_auth(&token)
            .json(&json!({
                "device_id": "dev_other",
                "one_time_keys": [],
                "fallback_keys": {},
                "device_signature": {"alg": "EdDSA", "signature": "wrong-device"}
            })),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/keys/upload"))
            .bearer_auth(&token)
            .json(&json!({
                "device_id": "dev_alice",
                "one_time_keys": [{
                    "algorithm": "signed_curve25519",
                    "key_id": "otk1",
                    "key": "single-use"
                }],
                "fallback_keys": {},
                "device_signature": {"alg": "EdDSA", "signature": "alice-device"}
            })),
        StatusCode::OK,
    )
    .await?;

    let first_claim = expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/keys/claim"))
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
            .post(server.url("/_cokret/self/keys/claim"))
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
    let server = CokretServer::spawn("device-delivery").await?;
    let token = dev_login(&server, "did:web:alice.example", "dev_alice").await?;

    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/self/device_messages"))
            .header("Idempotency-Key", "device-noauth")
            .json(&json!({"messages": {}})),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/self/device_messages"))
            .bearer_auth(&token)
            .header("Idempotency-Key", "device-bad-json")
            .header("content-type", "application/json")
            .body("{"),
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await?;

    let send = expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/device_messages"))
            .bearer_auth(&token)
            .header("Idempotency-Key", "device-idempotent-txn")
            .json(&json!({
                "messages": {
                    "did:web:alice.example": {
                        "dev_alice": {
                            "type": "ck.mls.application",
                            "content": encrypted_envelope("ck.mls.application", "opaque-to-device")
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
            .post(server.url("/_cokret/self/device_messages"))
            .bearer_auth(&token)
            .header("Idempotency-Key", "device-idempotent-txn")
            .json(&json!({
                "messages": {
                    "did:web:alice.example": {
                        "dev_alice": {
                            "type": "ck.mls.application",
                            "content": encrypted_envelope("ck.mls.application", "opaque-to-device")
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
            .get(server.url("/_cokret/self/device_messages"))
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
            .get(server.url(&format!(
                "/_cokret/self/device_messages?from={}",
                delivered["next_cursor"].as_str().unwrap()
            )))
            .bearer_auth(&token),
        StatusCode::OK,
    )
    .await?;
    assert!(drained["events"].as_array().unwrap().is_empty());

    Ok(())
}

pub async fn blob_integrity_head_range_and_missing_edges_work() -> Result<()> {
    let server = CokretServer::spawn("blob-media").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client("did:web:bob-blob.example", "@bob-blob", "dev_bob")
        .await?;
    let carol = server
        .register_client("did:web:carol-blob.example", "@carol-blob", "dev_carol")
        .await?;
    let realm_id = create_blob_access_realm(&alice, &bob).await?;

    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/self/blob/upload"))
            .body("no auth"),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/self/blob/upload"))
            .bearer_auth(&alice.token)
            .header(
                "x-cokret-content-digest",
                "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            )
            .body("blob-bytes"),
        StatusCode::CONFLICT,
        "digest_mismatch",
    )
    .await?;

    let blob = expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/blob/upload"))
            .bearer_auth(&alice.token)
            .header("x-cokret-realm-id", &realm_id)
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
                "/_cokret/self/blob/get?blob_ref={blob_ref}&purpose=message.attachment"
            )))
            .bearer_auth(&bob.token),
        StatusCode::OK,
    )
    .await?;
    assert!(head.headers.get("digest").is_some());

    let range = expect_text(
        bob.get(&format!(
            "/_cokret/self/blob/get?blob_ref={blob_ref}&purpose=message.attachment"
        ))
        .header("range", "bytes=0-8"),
        StatusCode::PARTIAL_CONTENT,
    )
    .await?;
    assert_eq!(range, "encrypted");

    expect_api_error(
        bob.get(&format!(
            "/_cokret/self/blob/get?blob_ref={blob_ref}&purpose=message.attachment"
        ))
        .header("range", "bytes=99-100"),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;
    expect_api_error(
        server.http().get(server.url(&format!(
            "/_cokret/self/blob/get?blob_ref={blob_ref}&purpose=message.attachment&access_token={}",
            alice.token
        ))),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    let _ = expect_indistinguishable_api_errors(
        carol.get(&format!(
            "/_cokret/self/blob/get?blob_ref={blob_ref}&purpose=message.attachment"
        )),
        carol.get(
            "/_cokret/self/blob/get?blob_ref=ck:blob:sha256:missing&purpose=message.attachment",
        ),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    Ok(())
}

async fn create_blob_access_realm(
    alice: &TestActorClient,
    bob: &TestActorClient,
) -> Result<String> {
    let realm_create = signed_realm_create_event(
        BLOB_REALM_CREATE_EVENT_ID,
        1,
        BLOB_REALM_ID,
        &alice.actor,
        "Blob Access Space",
        alice.service_did(),
    )?;
    let create = expect_json(
        alice.post("/_cokret/self/events").json(&realm_create),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(create["status"], "accepted");

    let bob_member = signed_membership_event(
        BLOB_REALM_MEMBER_EVENT_ID,
        2,
        BLOB_REALM_ID,
        &alice.actor,
        &bob.actor,
        "join",
    )?;
    let member = expect_json(
        alice.post("/_cokret/self/events").json(&bob_member),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(member["status"], "accepted");

    Ok(BLOB_REALM_ID.to_owned())
}

fn signed_realm_create_event(
    event_id: &str,
    actor_seq: u64,
    realm_id: &str,
    actor_id: &str,
    title: &str,
    service_did: &str,
) -> Result<Value> {
    let payload = json!({
        "object": {
            "id": realm_id,
            "schema": "ck.schema.realm.v1",
            "title": title,
            "summary": title,
            "trust_domain": "ck:trust_domain:delivery-media.cotest.local",
            "created_by": actor_id,
            "schema_refs": ["ck.schema.realm.v1"],
            "default_discoverability": "public",
            "default_join_rule": "public",
            "history_visibility": "world_readable",
            "encryption_profile": "none",
            "security_class": "standard",
            "federation_policy": "open",
            "anchor_profile": "single_did",
            "digest_algorithm": "sha256",
            "plaintext_visible_services": [service_did],
            "anchorer": {
                "type": "single_did",
                "did": actor_id,
                "recovery_members": ["did:web:recovery-anchorer.cotest.local"],
                "controller_organization": "did:web:delivery-media.cotest.local",
                "recovery_controller_organizations": ["did:web:recovery-org.cotest.local"]
            },
            "created_at": "2026-05-02T00:00:00Z"
        }
    });
    signed_event(
        event_id,
        actor_seq,
        realm_id,
        actor_id,
        "ck.realm.create",
        payload,
    )
}

fn signed_membership_event(
    event_id: &str,
    actor_seq: u64,
    realm_id: &str,
    actor_id: &str,
    member_actor: &str,
    membership: &str,
) -> Result<Value> {
    let payload = json!({
        "actor_id": member_actor,
        "membership": membership,
        "delivery_status": "unroutable"
    });
    signed_event(
        event_id,
        actor_seq,
        realm_id,
        actor_id,
        "ck.member.state",
        payload,
    )
}

fn signed_event(
    event_id: &str,
    actor_seq: u64,
    realm_id: &str,
    actor_id: &str,
    kind: &str,
    payload: Value,
) -> Result<Value> {
    let mut event = json!({
        "event_id": event_id,
        "kind": kind,
        "realm_id": realm_id,
        "actor_id": actor_id,
        "actor_seq": actor_seq,
        "created_at": "2026-05-02T00:00:00Z",
        "hlc": format!("01970e589d21-{:04x}-a13f9c2e", actor_seq & 0xffff),
        "prev_refs": [],
        "refs": [],
        "payload": payload,
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

pub async fn push_and_moderation_edges_are_enforced() -> Result<()> {
    let server = CokretServer::spawn("push-moderation").await?;
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
            .post(server.url("/_cokret/edge/push/unregister-device"))
            .header("content-type", "application/json")
            .body("{"),
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/edge/push/notify"))
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
            .post(server.url("/_cokret/edge/push/notify"))
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
            .post(server.url("/_cokret/self/moderation/report"))
            .json(&json!({
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "target_ref": "ck:event:demo",
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
            .post(server.url("/_cokret/self/moderation/report"))
            .bearer_auth(&alice)
            .json(&json!({
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "target_ref": "ck:event:demo",
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
            .post(server.url("/_cokret/self/moderation/report"))
            .bearer_auth(&bob)
            .json(&json!({
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "target_ref": "ck:event:demo",
                "reason": "spam",
                "reporter": "did:web:bob-delivery.example"
            })),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    Ok(())
}
