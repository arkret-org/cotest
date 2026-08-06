use anyhow::{Result, anyhow};
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    ArkretServer, TestActorClient, dev_login, device_message_send_request, encrypted_envelope,
    expect_api_error, expect_indistinguishable_api_errors, expect_json, expect_response,
    expect_text, register_account,
};
use crate::scenarios::identity_test_support::{
    actor_did_for_service, authorize_device_public_key, signed_keys_upload_body,
};

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
            .json(&serde_json::from_value::<
                arkret_models_crypto::KeysQueryRequestBody,
            >(json!({"device_keys": {}}))?),
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
            .json(&serde_json::from_value::<
                arkret_models_crypto::KeysClaimRequestBody,
            >(json!({
                "one_time_keys": {
                    (&alice_did): {(alice_device): "signed_curve25519"}
                }
            }))?),
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
            .json(&serde_json::from_value::<
                arkret_models_crypto::KeysClaimRequestBody,
            >(json!({
                "one_time_keys": {
                    (&alice_did): {(alice_device): "signed_curve25519"}
                }
            }))?),
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
            .json(&serde_json::from_value::<
                arkret_models_collaboration::sync_frames::account_sync::DeviceMessagesSendRequestBody,
            >(json!({"messages": {}}))?),
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

    let expires_at = chrono::DateTime::parse_from_rfc3339("2026-12-31T00:00:00.000Z")?
        .with_timezone(&chrono::Utc);
    let request = device_message_send_request(
        "did:web:alice.example",
        "ak:device:01904100-0000-7000-8000-0000000000a1",
        "ak:device_message:0196419b-0000-7000-8000-00000000d201",
        "ak.mls.application",
        encrypted_envelope("ak.mls.application", "opaque-to-device"),
        expires_at,
    )?;
    let send = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/device_messages"))
            .bearer_auth(&token)
            .header("Idempotency-Key", "device-idempotent-txn")
            .json(&request),
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
            .json(&request),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        duplicate, send,
        "request replay must return the stored outcome"
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

    let ack = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/device_messages/ack"))
            .bearer_auth(&token)
            .json(&serde_json::from_value::<
                arkret_models_collaboration::sync_frames::account_sync::DeviceMessagesAckRequestBody,
            >(json!({
                "ack_token": delivered["ack_token"].as_str().unwrap()
            }))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(ack["ok"], true);

    let drained = expect_json(
        server
            .http()
            .get(server.url("/_arkret/self/device_messages"))
            .bearer_auth(&token),
        StatusCode::OK,
    )
    .await?;
    assert!(
        drained["messages"].as_array().unwrap().is_empty(),
        "acknowledged messages were delivered again: first={delivered}, next={drained}"
    );

    let message_replay = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/device_messages"))
            .bearer_auth(&token)
            .header("Idempotency-Key", "device-logical-replay-txn")
            .json(&request),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(message_replay, send);
    let after_message_replay = expect_json(
        server
            .http()
            .get(server.url("/_arkret/self/device_messages"))
            .bearer_auth(&token),
        StatusCode::OK,
    )
    .await?;
    assert!(
        after_message_replay["messages"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let mut conflicting_request = request;
    conflicting_request
        .messages
        .values_mut()
        .next()
        .and_then(|devices| devices.values_mut().next())
        .expect("typed request contains one target")
        .content
        .insert("ciphertext".to_owned(), json!("different-opaque-bytes"));
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/device_messages"))
            .bearer_auth(&token)
            .header("Idempotency-Key", "device-logical-conflict-txn")
            .json(&conflicting_request),
        StatusCode::CONFLICT,
        "duplicate_conflict",
    )
    .await?;

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
    let create = alice
        .create_realm_with(json!({
            "title": "Blob Access Space",
            "public": true,
            "discoverability": "public",
            "join_rule": "public",
            "history_visibility": "world_readable",
            "plaintext_visible_services": [alice.service_id()]
        }))
        .await?;
    // The Realm id is derived from the genesis Event, so it can only be read
    // back from the create response.
    let realm_id = create["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow!("Realm create response has no realm_id"))?
        .to_owned();

    let member = alice.add_member(&realm_id, bob).await?;
    assert_eq!(member["status"], "accepted");

    Ok(realm_id)
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
    let push_baseline =
        serde_json::from_value::<arkret_models_integration::PushNotifyRequestBody>(json!({
            "notification": {
                "push_target_id": "ak:pseudonym:push:aaaaaaaaaaaaaaaaaaaaaa",
                "wakeup_kind": "message",
                "timing_profile_hint": "default",
                "devices": [{"device_id": "ak:device:01904100-0000-7000-8000-0000000000ff"}]
            }
        }))?;
    let plaintext_push = crate::harness::wire_negative_from_sdk(&push_baseline, |body| {
        body["notification"]["content"] = json!({"body": "plaintext leak"});
    })?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/edge/push/notify"))
            .json(&plaintext_push),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;
    let notify = expect_json(
        server
            .http()
            .post(server.url("/_arkret/edge/push/notify"))
            .json(&serde_json::from_value::<
                arkret_models_integration::PushNotifyRequestBody,
            >(json!({
                "notification": {
                    "push_target_id": "ak:pseudonym:push:aaaaaaaaaaaaaaaaaaaaaa",
                    "wakeup_kind": "message",
                    "timing_profile_hint": "default",
                    "devices": [{"device_id": "ak:device:01904100-0000-7000-8000-0000000000ff"}]
                }
            }))?),
        StatusCode::OK,
    )
    .await?;
    // `push_notify_outcome` is one per-device outcome list, not accepted /
    // rejected buckets. This device was never registered, so it comes back with
    // a `rejected` gateway_status and the `push_token_unknown` reason code
    // (`push_target_unknown` is reserved for a registered device whose
    // registration does not accept the requested push target).
    let outcomes = notify["outcomes"]
        .as_array()
        .expect("push notify must return per-device outcomes");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0]["gateway_status"], "rejected");
    assert_eq!(outcomes[0]["reason_code"], "push_token_unknown");

    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/moderation/report"))
            .json(&serde_json::from_value::<
                arkret_models_collaboration::governance::moderation::ModerationReportRequestBody,
            >(json!({
                "realm_id": "ak:realm:0196419b-0000-8000-8000-000000000000",
                "target_ref": "ak:event:0196419b-0000-8000-8000-000000000001",
                "report_reason_code": "spam",
                "reporter": "did:web:alice.example"
            }))?),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/moderation/report"))
            .bearer_auth(&alice)
            .json(&serde_json::from_value::<
                arkret_models_collaboration::governance::moderation::ModerationReportRequestBody,
            >(json!({
                "realm_id": "ak:realm:0196419b-0000-8000-8000-000000000000",
                "target_ref": "ak:event:0196419b-0000-8000-8000-000000000001",
                "report_reason_code": "spam",
                "reporter": "did:web:bob-delivery.example"
            }))?),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/self/moderation/report"))
            .bearer_auth(&bob)
            .json(&serde_json::from_value::<
                arkret_models_collaboration::governance::moderation::ModerationReportRequestBody,
            >(json!({
                "realm_id": "ak:realm:0196419b-0000-8000-8000-000000000000",
                "target_ref": "ak:event:0196419b-0000-8000-8000-000000000001",
                "report_reason_code": "spam",
                "reporter": "did:web:bob-delivery.example"
            }))?),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    Ok(())
}
