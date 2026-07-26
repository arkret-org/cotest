//! Phase 1 — event submit + key upload/query/claim setup.
//!
//! Walks Alice through pushing a single signed event, then uploading her
//! device-key bundle and exercising `/_arkret/self/keys/{query,claim}` to confirm
//! the upload is visible.

use anyhow::Result;
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    ArkretServer, expect_json, message_create_text_payload_for_strand, parse_strand_id,
    realm_bootstrap_event_batch, submit_event_with_signing_seed_and_verification_method,
};
use crate::scenarios::federation_collaboration::{
    TEST_PRINCIPAL_SIGNING_KEY_SEED, authorize_device_public_key, signed_keys_upload_body,
};

const KEYS_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";

const ADAPTER_REALM_ID: &str = "ak:realm:0196419b-0000-7000-8000-000000000101";

pub async fn run(server: &ArkretServer, token: &str, actor_id: &str) -> Result<String> {
    // keys/upload verifies its typed request signature against the accepted
    // device projection. Publish the principal/self-signing hierarchy before
    // authorizing the device; the adapter realm/message then continue at actor
    // sequence 3/4.
    let device_key = SigningKey::from_bytes(&[0x7a; 32]);
    authorize_device_public_key(server, token, actor_id, KEYS_DEVICE_ID, &device_key).await?;
    let message_event_id = submit_adapter_event(server, token, actor_id).await?;
    upload_and_inspect_keys(server, token, actor_id, &device_key).await?;
    Ok(message_event_id)
}

async fn submit_adapter_event(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
) -> Result<String> {
    let realm_id = create_adapter_realm(server, token, actor_id).await?;
    let submit = submit_event_with_signing_seed_and_verification_method(
        server,
        token,
        actor_id,
        &realm_id,
        "ak.message.create",
        message_create_text_payload_for_strand(
            parse_strand_id("ak:strand:0196419b-0000-7000-8000-000000000001")?,
            "hello",
        )?,
        StatusCode::OK,
        TEST_PRINCIPAL_SIGNING_KEY_SEED,
        &format!("{actor_id}#cotest-principal-signing-key"),
    )
    .await?;
    assert_eq!(submit["status"], "accepted");
    submit["event_id"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow::anyhow!("accepted adapter message lacks event_id: {submit}"))
}

async fn create_adapter_realm(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
) -> Result<String> {
    let events = realm_bootstrap_event_batch(
        actor_id,
        ADAPTER_REALM_ID,
        adapter_realm_payload(ADAPTER_REALM_ID, actor_id, "Adapter Event Space"),
    )?;
    let submit = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(token)
            .json(&json!({"events": events})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(submit["status"], "accepted");
    assert_eq!(submit["accepted"].as_array().map(Vec::len), Some(2));

    Ok(ADAPTER_REALM_ID.to_owned())
}

fn adapter_realm_payload(realm_id: &str, actor_id: &str, title: &str) -> Value {
    json!({
        "object": {
            "id": realm_id,
            "schema": "ak.schema.realm.v1",
            "title": title,
            "summary": title,
            "trust_domain": "ak:trust_domain:protocol-payloads.cotest.local",
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
            "notary": {
                "kind": "single_did",
                "did": actor_id,
                "recovery_members": ["did:web:recovery-anchorer.cotest.local"],
                "controller_organization": "did:web:protocol-payloads.cotest.local",
                "recovery_controller_organizations": ["did:web:recovery-org.cotest.local"]
            },
            "created_at": "2026-05-02T00:00:00.000Z"
        }
    })
}

async fn upload_and_inspect_keys(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
    device_key: &SigningKey,
) -> Result<()> {
    let upload_keys = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/keys/upload"))
            .bearer_auth(token)
            .json(&signed_keys_upload_body(
                actor_id,
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
            .json(&json!({"device_keys": {(actor_id): [KEYS_DEVICE_ID]}})),
        StatusCode::OK,
    )
    .await?;
    // Query returns the accepted device directory projection and cross-signing
    // link. The upload request signature authorizes the mutation; it is not a
    // prekey algorithm entry and therefore is not echoed under `algorithms`.
    let queried_device = &query_keys["device_keys"][actor_id][KEYS_DEVICE_ID];
    assert_eq!(queried_device["device_status"], "active");
    assert!(
        queried_device["device_signing_key"]
            .as_str()
            .is_some_and(|key| key.starts_with("did:key:z6Mk")),
        "query must expose the authoritative active device signing key: {queried_device}"
    );
    assert_eq!(
        queried_device["cross_signing_binding"]["verification_method"],
        format!("{actor_id}#ak_self_signing_v1")
    );

    let claimed = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/keys/claim"))
            .bearer_auth(token)
            .json(&json!({
                "one_time_keys": {
                    (actor_id): {(KEYS_DEVICE_ID): "signed_curve25519"}
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        claimed["one_time_keys"][actor_id][KEYS_DEVICE_ID]["signed_curve25519"]["key"],
        "one-time"
    );
    Ok(())
}
