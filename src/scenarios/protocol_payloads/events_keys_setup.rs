//! Phase 1 — event submit + key upload/query/claim setup.
//!
//! Walks Alice through pushing a single signed event, then uploading her
//! device-key bundle and exercising `/_arkret/self/keys/{query,claim}` to confirm
//! the upload is visible.

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    ArkretServer, TestActorClient, expect_json, message_create_text_payload_for_strand,
    parse_strand_id,
};
use crate::scenarios::identity_test_support::signed_keys_upload_body;

const KEYS_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";

pub async fn run(
    server: &ArkretServer,
    client: &TestActorClient,
) -> Result<(TestActorClient, String, String)> {
    // The bootstrap already authorized the founding device; sign the upload
    // with its provisioned key.
    let device_key = client
        .principal
        .as_ref()
        .context("client carries its provisioned principal")?
        .device_signing_key
        .clone();
    let (actor, realm_id, message_event_id) =
        submit_adapter_event(server, &client.token, &client.actor).await?;
    upload_and_inspect_keys(server, &client.token, &client.actor, &device_key).await?;
    Ok((actor, realm_id, message_event_id))
}

async fn submit_adapter_event(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
) -> Result<(TestActorClient, String, String)> {
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
    let event_id = crate::harness::submitted_event_id(&submit)?;
    Ok((actor, realm_id, event_id.to_string()))
}

async fn upload_and_inspect_keys(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
    device_key: &SigningKey,
) -> Result<()> {
    let actor_core_id = crate::harness::actor_core_id(actor_id)?;
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

    let query_keys_value = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/keys/query"))
            .bearer_auth(token)
            .json(&arkret_models_crypto::KeysQueryRequestBody {
                device_keys: std::collections::BTreeMap::from([(
                    arkret_identifiers::DidCoreId::new(actor_core_id.clone())?,
                    vec![arkret_identifiers::DeviceId::new(KEYS_DEVICE_ID)?],
                )]),
                timeout_ms: None,
            }),
        StatusCode::OK,
    )
    .await?;
    let query_keys: arkret_models_crypto::KeysQueryOutcome =
        serde_json::from_value(query_keys_value)
            .context("keys/query response is not the closed SDK outcome")?;
    // Query returns the accepted device projection. Device identity, signing
    // material and generation live only inside the service attestation; the
    // row itself carries just prekeys, trust algorithms and that attestation.
    // The upload request signature authorizes the mutation; it is not a prekey
    // algorithm entry and therefore is not echoed under `algorithms`.
    let principal_id = arkret_identifiers::DidCoreId::new(actor_core_id.clone())?;
    let device_id = arkret_identifiers::DeviceId::new(KEYS_DEVICE_ID.to_owned())?;
    let queried_record = query_keys
        .device_keys
        .get(&principal_id)
        .and_then(|devices| devices.get(&device_id))
        .context("keys/query omitted the requested device record")?;
    queried_record.validate_attestation_binding(&principal_id, &device_id)?;
    let generation = query_keys
        .device_generations
        .get(&principal_id)
        .context("keys/query omitted the principal generation fence")?;
    assert!(
        queried_record.is_usable_in_generation(Some(generation)),
        "attested device must match the active response generation fence"
    );
    let queried_device = serde_json::to_value(queried_record)?;
    for retired_mirror in [
        "principal_id",
        "station_id",
        "device_id",
        "device_status",
        "device_signing_key_did",
        "hpke_key",
        "device_authorize_event_id",
        "authorized_generation_ref",
        "attested_at",
        "expires_at",
    ] {
        assert!(
            queried_device.get(retired_mirror).is_none(),
            "keys/query row repeated attested identity field {retired_mirror}: {queried_device}"
        );
    }
    let attestation = &queried_device["device_projection_attestation"];
    assert_eq!(attestation["attestation"]["device_status"], "active");
    assert!(
        attestation["attestation"]["device_signing_key_did"]
            .as_str()
            .is_some_and(|key| key.starts_with("did:key:z6Mk")),
        "query must expose the authoritative active device signing key: {queried_device}"
    );
    // `device-lifecycle.md` §8.2 — a returned row is complete and attested, and
    // the attestation covers this exact projection. That is the whole
    // verification closure of this cross-principal surface: PCR genesis
    // receipts, authorization chains and Seals MUST NOT appear here.
    assert_eq!(
        attestation["attestation"]["authorized_generation_ref"],
        serde_json::to_value(generation.current_device_generation_ref)?,
        "attestation generation must equal the response fence: {queried_device}"
    );
    assert!(
        attestation["proof"]["verification_method"]
            .as_str()
            .is_some_and(|method| method.contains('#')),
        "attestation proof must name a verification method: {attestation}"
    );
    assert_eq!(
        attestation["proof"]["created_at"], attestation["attestation"]["attested_at"],
        "proof timestamp must equal the attested instant: {attestation}"
    );
    for forbidden in [
        "principal_genesis_receipt",
        "authorization_chain",
        "seal",
        "seal_ref",
    ] {
        assert!(
            queried_device.get(forbidden).is_none(),
            "keys/query MUST NOT carry PCR material ({forbidden}): {queried_device}"
        );
    }
    // The typed DTO is the contract: a row that is not complete and attested
    // fails to decode rather than being consumed as a partial projection.
    let claimed = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/keys/claim"))
            .bearer_auth(token)
            .json(&arkret_models_crypto::KeysClaimRequestBody {
                one_time_keys: std::collections::BTreeMap::from([(
                    arkret_identifiers::DidCoreId::new(actor_core_id.clone())?,
                    std::collections::BTreeMap::from([(
                        arkret_identifiers::DeviceId::new(KEYS_DEVICE_ID)?,
                        arkret_wire::NonEmptyString::new("signed_curve25519")
                            .map_err(anyhow::Error::msg)?,
                    )]),
                )]),
            }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        claimed["one_time_keys"][&actor_core_id][KEYS_DEVICE_ID]["signed_curve25519"]["key"],
        "one-time"
    );
    Ok(())
}
