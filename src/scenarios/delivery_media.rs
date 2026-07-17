use anyhow::Result;
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    ArkretServer, TestActorClient, dev_login, encrypted_envelope, expect_api_error,
    expect_indistinguishable_api_errors, expect_json, expect_response, expect_text,
    member_join_payload_value, refresh_event_proof, register_account,
};
use crate::scenarios::federation_collaboration::{
    actor_did_for_service, authorize_device_public_key, signed_keys_upload_body,
};

const BLOB_REALM_ID: &str = "ak:realm:0196419b-0000-7000-8000-00000000d101";
const BLOB_REALM_CREATE_EVENT_ID: &str = "ak:event:0196419b-0000-7000-8000-00000000d100";
const BLOB_REALM_MEMBER_EVENT_ID: &str = "ak:event:0196419b-0000-7000-8000-00000000d102";

pub async fn key_upload_query_and_claim_edges_are_enforced() -> Result<()> {
    let server = ArkretServer::spawn("delivery-keys").await?;
    let alice_did = actor_did_for_service(server.service_id(), "delivery-alice")?;
    let alice_device = "ak:device:01904100-0000-7000-8000-0000000000a1";
    let token = register_account(&server, &alice_did, "@delivery-alice", alice_device).await?;

    // soland binds keys/upload to the authoritative device key (the device must
    // be authorized, and the upload carries an Ed25519 signature over the
    // canonical body). Authorize Alice's device up front.
    let device_key = SigningKey::from_bytes(&[0x7a; 32]);
    authorize_device_public_key(&server, &token, &alice_did, alice_device, &device_key).await?;

    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/keys/upload"))
            .json(&signed_keys_upload_body(
                &alice_did,
                alice_device,
                &device_key,
                json!({}),
                json!({}),
            )?),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/keys/query"))
            .json(&json!({"device_keys": {}})),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    // Uploading keys for a device that is not the caller's bound device is
    // rejected: the body is validly signed by Alice's authorized device key, but
    // it claims a different device_id that Alice does not control.
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/keys/upload"))
            .bearer_auth(&token)
            .json(&signed_keys_upload_body(
                &alice_did,
                "ak:device:01904100-0000-7000-8000-0000000000f0",
                &device_key,
                json!({}),
                json!({}),
            )?),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/keys/upload"))
            .bearer_auth(&token)
            .json(&signed_keys_upload_body(
                &alice_did,
                alice_device,
                &device_key,
                json!({
                    "signed_curve25519:otk1": {
                        "algorithm": "signed_curve25519",
                        "key_id": "otk1",
                        "key": "single-use"
                    }
                }),
                json!({}),
            )?),
        StatusCode::OK,
    )
    .await?;

    let first_claim = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/keys/claim"))
            .bearer_auth(&token)
            .json(&json!({
                "one_time_keys": {
                    (&alice_did): {(alice_device): "signed_curve25519"}
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        first_claim["one_time_keys"][&alice_did][alice_device]["signed_curve25519"]["key"],
        "single-use"
    );

    let second_claim = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/keys/claim"))
            .bearer_auth(&token)
            .json(&json!({
                "one_time_keys": {
                    (&alice_did): {(alice_device): "signed_curve25519"}
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert!(
        second_claim["one_time_keys"][&alice_did]
            .as_object()
            .unwrap()
            .is_empty()
    );

    Ok(())
}

pub async fn to_device_messages_are_idempotent_opaque_and_drained_once() -> Result<()> {
    let server = ArkretServer::spawn("device-delivery").await?;
    let token = dev_login(
        &server,
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-0000000000a1",
    )
    .await?;

    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/device_messages"))
            .header("Idempotency-Key", "device-noauth")
            .json(&json!({"messages": {}})),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/device_messages"))
            .bearer_auth(&token)
            .header("Idempotency-Key", "device-bad-json")
            .header("content-type", "application/json")
            .body("{"),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    let send = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/device_messages"))
            .bearer_auth(&token)
            .header("Idempotency-Key", "device-idempotent-txn")
            .json(&json!({
                "messages": {
                    "did:web:alice.example": {
                        "ak:device:01904100-0000-7000-8000-0000000000a1": {
                            "kind": "ak.mls.application",
                            "content": encrypted_envelope("ak.mls.application", "opaque-to-device"),
                            "expires_at": "2026-12-31T00:00:00Z"
                        }
                    }
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        send["delivered"]["did:web:alice.example"][0],
        "ak:device:01904100-0000-7000-8000-0000000000a1"
    );

    let duplicate = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/device_messages"))
            .bearer_auth(&token)
            .header("Idempotency-Key", "device-idempotent-txn")
            .json(&json!({
                "messages": {
                    "did:web:alice.example": {
                        "ak:device:01904100-0000-7000-8000-0000000000a1": {
                            "kind": "ak.mls.application",
                            "content": encrypted_envelope("ak.mls.application", "opaque-to-device"),
                            "expires_at": "2026-12-31T00:00:00Z"
                        }
                    }
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert!(
        duplicate["delivered"]
            .as_object()
            .is_none_or(serde_json::Map::is_empty)
    );

    let delivered = expect_json(
        server
            .http()
            .get(server.url("/_arkret/self/device_messages"))
            .bearer_auth(&token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        delivered["messages"][0]["content"]["ciphertext"],
        "opaque-to-device"
    );
    assert!(
        delivered["messages"][0]["content"]
            .get("plaintext")
            .is_none()
    );

    let drained = expect_json(
        server
            .http()
            .get(server.url(&format!(
                "/_arkret/self/device_messages?after={}",
                delivered["next_cursor"].as_str().unwrap()
            )))
            .bearer_auth(&token),
        StatusCode::OK,
    )
    .await?;
    assert!(drained["messages"].as_array().unwrap().is_empty());

    Ok(())
}

/// Build a spec-shaped multipart/form-data blob upload body. soland requires
/// blob uploads to be `multipart/form-data` with a single `content` file part
/// and a `size_bytes` field matching the part size (blob.rs upload parser).
pub(crate) fn blob_upload_form(bytes: &[u8], media_type: &str) -> Result<reqwest::multipart::Form> {
    let part = reqwest::multipart::Part::bytes(bytes.to_vec())
        .file_name("blob.bin")
        .mime_str(media_type)?;
    Ok(reqwest::multipart::Form::new()
        .text("size_bytes", bytes.len().to_string())
        .part("content", part))
}

pub async fn blob_integrity_head_range_and_missing_edges_work() -> Result<()> {
    let server = ArkretServer::spawn("blob-media").await?;
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let bob = server
        .register_client(
            "did:web:bob-blob.example",
            "@bob-blob",
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;
    let carol = server
        .register_client(
            "did:web:carol-blob.example",
            "@carol-blob",
            "ak:device:01904100-0000-7000-8000-000000000ca0",
        )
        .await?;
    let realm_id = create_blob_access_realm(&alice, &bob).await?;

    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/blob/upload"))
            .body("no auth"),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/blob/upload"))
            .bearer_auth(&alice.token)
            .header(
                "x-arkret-content-digest",
                "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            )
            .multipart(blob_upload_form(b"blob-bytes", "text/plain")?),
        StatusCode::CONFLICT,
        "digest_mismatch",
    )
    .await?;

    let blob = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/blob/upload"))
            .bearer_auth(&alice.token)
            .header("x-arkret-realm-id", &realm_id)
            .multipart(blob_upload_form(b"encrypted-bytes", "text/plain")?),
        StatusCode::OK,
    )
    .await?;
    let blob_ref = blob["blob_ref"].as_str().unwrap();

    let head = expect_response(
        server
            .http()
            .head(server.url(&format!(
                "/_arkret/self/blob/get?blob_ref={blob_ref}&purpose=message.attachment"
            )))
            .bearer_auth(&bob.token),
        StatusCode::OK,
    )
    .await?;
    assert!(head.headers.get("digest").is_some());

    let range = expect_text(
        bob.get(&format!(
            "/_arkret/self/blob/get?blob_ref={blob_ref}&purpose=message.attachment"
        ))
        .header("range", "bytes=0-8"),
        StatusCode::PARTIAL_CONTENT,
    )
    .await?;
    assert_eq!(range, "encrypted");

    expect_api_error(
        bob.get(&format!(
            "/_arkret/self/blob/get?blob_ref={blob_ref}&purpose=message.attachment"
        ))
        .header("range", "bytes=99-100"),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;
    expect_api_error(
        server.http().get(server.url(&format!(
            "/_arkret/self/blob/get?blob_ref={blob_ref}&purpose=message.attachment&access_token={}",
            alice.token
        ))),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    let _ = expect_indistinguishable_api_errors(
        carol.get(&format!(
            "/_arkret/self/blob/get?blob_ref={blob_ref}&purpose=message.attachment"
        )),
        carol.get(
            "/_arkret/self/blob/get?blob_ref=ak:blob:sha256:missing&purpose=message.attachment",
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
        alice.service_id(),
    )?;
    let create = expect_json(
        alice.post("/_arkret/self/events").json(&realm_create),
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
        alice.post("/_arkret/self/events").json(&bob_member),
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
    service_id: &str,
) -> Result<Value> {
    let payload = json!({
        "object": {
            "id": realm_id,
            "schema": "ak.schema.realm.v1",
            "title": title,
            "summary": title,
            "trust_domain": "ak:trust_domain:delivery-media.cotest.local",
            "created_by": actor_id,
            "schema_refs": ["ak.schema.realm.v1"],
            "default_discoverability": "public",
            "default_join_rule": "public",
            "history_visibility": "world_readable",
            "encryption_profile": "none",
            "security_class": "standard",
            "federation_policy": "open",
            "notary_profile": "single_did",
            "digest_algorithm": "sha256",
            "plaintext_visible_services": [service_id],
            "notary": {
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
        "ak.realm.create",
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
    let payload = match membership {
        "join" => member_join_payload_value(realm_id, member_actor)?,
        other => anyhow::bail!("unsupported signed membership fixture state: {other}"),
    };
    signed_event(
        event_id,
        actor_seq,
        realm_id,
        actor_id,
        "ak.member.state",
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
    let server = ArkretServer::spawn("push-moderation").await?;
    let alice = dev_login(
        &server,
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-0000000000a1",
    )
    .await?;
    let bob = register_account(
        &server,
        "did:web:bob-delivery.example",
        "@bob-delivery",
        "ak:device:01904100-0000-7000-8000-0000000000b0",
    )
    .await?;

    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/edge/push/unregister-device"))
            .header("content-type", "application/json")
            .body("{"),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;
    // Blind-wakeup minimization: the push notification envelope is metadata-only
    // and `deny_unknown_fields`, so it structurally cannot carry a plaintext
    // `content` field — a push that tries to violates the declared schema and
    // is rejected as `schema_violation` (422) before any rule evaluation.
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/edge/push/notify"))
            .json(&json!({
                "notification": {
                    "devices": [{"device_id": "ak:device:01904100-0000-7000-8000-0000000000ff"}],
                    "content": {"body": "plaintext leak"}
                }
            })),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;
    let notify = expect_json(
        server
            .http()
            .post(server.url("/_arkret/edge/push/notify"))
            .json(&json!({
                "notification": {
                    "push_target_id": "ak:pseudonym:push:aaaaaaaaaaaaaaaaaaaaaa",
                    "devices": [{"device_id": "ak:device:01904100-0000-7000-8000-0000000000ff"}]
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(notify["rejected"].as_array().unwrap().len(), 1);

    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/moderation/report"))
            .json(&json!({
                "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000",
                "target_ref": "ak:event:0196419b-0000-7000-8000-000000000001",
                "report_reason_code": "spam",
                "reporter": "did:web:alice.example"
            })),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/moderation/report"))
            .bearer_auth(&alice)
            .json(&json!({
                "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000",
                "target_ref": "ak:event:0196419b-0000-7000-8000-000000000001",
                "report_reason_code": "spam",
                "reporter": "did:web:bob-delivery.example"
            })),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/moderation/report"))
            .bearer_auth(&bob)
            .json(&json!({
                "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000000",
                "target_ref": "ak:event:0196419b-0000-7000-8000-000000000001",
                "report_reason_code": "spam",
                "reporter": "did:web:bob-delivery.example"
            })),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    Ok(())
}
