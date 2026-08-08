//! Phase 1 — event submit + key upload/query/claim setup.
//!
//! Walks Alice through pushing a single signed event, then uploading her
//! device-key bundle and exercising `/_arkret/self/keys/{query,claim}` to confirm
//! the upload is visible.

use anyhow::Result;
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    ArkretServer, expect_json, message_create_text_payload_for_strand, parse_strand_id,
};
use crate::scenarios::identity_test_support::{
    authorize_device_public_key, signed_keys_upload_body,
};

const KEYS_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";

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
    let actor = server.client_with_token(actor_id, KEYS_DEVICE_ID, token.to_owned())?;
    let realm_id = actor
        .create_realm_with(json!({
            "title": "Adapter Event Space",
            "summary": "Adapter Event Space",
            "public": true,
            "plaintext_visible_services": [server.service_id()]
        }))
        .await?["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("adapter Realm create omitted realm_id"))?
        .to_owned();
    let submit = actor
        .submit_event(
            &realm_id,
            "ak.message.create",
            message_create_text_payload_for_strand(
                parse_strand_id("ak:strand:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-")?,
                "hello",
            )?,
        )
        .await?;
    assert_eq!(submit["status"], "accepted");
    submit["event_id"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow::anyhow!("accepted adapter message lacks event_id: {submit}"))
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
            .json(&serde_json::from_value::<
                arkret_models_crypto::KeysQueryRequestBody,
            >(
                json!({"device_keys": {(actor_id): [KEYS_DEVICE_ID]}})
            )?),
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

    let claimed = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/keys/claim"))
            .bearer_auth(token)
            .json(&serde_json::from_value::<
                arkret_models_crypto::KeysClaimRequestBody,
            >(json!({
                "one_time_keys": {
                    (actor_id): {(KEYS_DEVICE_ID): "signed_curve25519"}
                }
            }))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        claimed["one_time_keys"][actor_id][KEYS_DEVICE_ID]["signed_curve25519"]["key"],
        "one-time"
    );
    Ok(())
}
