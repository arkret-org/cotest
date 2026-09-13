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
        submit_adapter_event(server, client.expect_dev_bearer(), &client.actor).await?;
    upload_and_inspect_keys(
        server,
        client.expect_dev_bearer(),
        &client.actor,
        &device_key,
    )
    .await?;
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
                device_keys: vec![arkret_models_crypto::QueryAccountDeviceSelector {
                    account_id: arkret_wire::AccountId::new(
                        arkret_identifiers::DidCoreId::new(actor_core_id.clone())?,
                        server.service_id().clone(),
                    ),
                    device_ids: vec![arkret_identifiers::DeviceId::new(KEYS_DEVICE_ID)?],
                }],
                timeout_ms: None,
            }),
        StatusCode::OK,
    )
    .await?;
    let query_keys: arkret_models_crypto::KeysQueryOutcome =
        serde_json::from_value(query_keys_value.clone())
            .context("keys/query response is not the closed SDK outcome")?;
    // `device-lifecycle.md` §8.2 — this is the client-facing self surface. The
    // client's own authenticated Station verified the origin Station's
    // attestation and projects the verified values, so the row carries prekeys,
    // trust algorithms, the `signer_evidence_ref` the client actually uses and
    // the closed `device_projection` — never the origin proof or the wrapper
    // whose only job was to verify it. The upload request signature authorizes
    // the mutation; it is not a prekey algorithm entry and therefore is not
    // echoed under `algorithms`.
    let account_id = arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new(actor_core_id.clone())?,
        server.service_id().clone(),
    );
    let device_id = arkret_identifiers::DeviceId::new(KEYS_DEVICE_ID.to_owned())?;
    let queried_record = query_keys
        .devices_for(&account_id)
        .and_then(|devices| devices.get(&device_id))
        .context("keys/query omitted the requested device record")?;
    let generation = query_keys
        .generation_for(&account_id)
        .context("keys/query omitted the principal generation fence")?;
    let queried_device = serde_json::to_value(queried_record)?;
    let row_members = queried_device
        .as_object()
        .context("keys/query row must be an object")?
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        row_members,
        std::collections::BTreeSet::from([
            "algorithms".to_owned(),
            "device_projection".to_owned(),
            "signer_evidence_ref".to_owned(),
            "trust_algorithms".to_owned(),
        ]),
        "self keys/query row is not the closed client-facing shape: {queried_device}"
    );
    assert!(
        queried_device["signer_evidence_ref"]
            .as_str()
            .is_some_and(|value| !value.is_empty()),
        "self row must keep the exact signer evidence reference it uses: {queried_device}"
    );
    let projection = &queried_device["device_projection"];
    let projection_members = projection
        .as_object()
        .context("device_projection must be an object")?
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        projection_members,
        std::collections::BTreeSet::from([
            "attested_at".to_owned(),
            "authorization_window".to_owned(),
            "authorized_generation_ref".to_owned(),
            "device_authorize_event_id".to_owned(),
            "device_signing_key_did".to_owned(),
            "device_status".to_owned(),
            "expires_at".to_owned(),
            "hpke_key".to_owned(),
        ]),
        "device_projection is not the closed eight-member verified projection: {projection}"
    );
    assert_eq!(projection["device_status"], "active");
    assert!(
        projection["device_signing_key_did"]
            .as_str()
            .is_some_and(|key| key.starts_with("did:key:z6Mk")),
        "query must expose the authoritative active device signing key: {queried_device}"
    );
    // The projected generation is the response fence: the returning Station
    // matched the verified attestation against this exact account and device
    // before projecting it, so the client never re-derives that binding.
    assert_eq!(
        projection["authorized_generation_ref"],
        serde_json::to_value(generation.current_device_generation_ref)?,
        "projected generation must equal the response fence: {queried_device}"
    );
    // §8.2 — `account_id` and `device_id` are the entry and map keys, not
    // projection members, and the self face carries no origin proof shell: PCR
    // genesis receipts, authorization chains and Seals MUST NOT appear either.
    for forbidden in [
        "account_id",
        "device_id",
        "principal_id",
        "station_id",
        "proof",
        "attestation",
        "device_projection_attestation",
    ] {
        assert!(
            projection.get(forbidden).is_none(),
            "verified device projection leaked {forbidden}: {projection}"
        );
    }
    for forbidden in [
        "device_projection_attestation",
        "attestation",
        "proof",
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
        "principal_genesis_receipt",
        "authorization_chain",
        "seal",
        "seal_ref",
    ] {
        assert!(
            queried_device.get(forbidden).is_none(),
            "self keys/query row MUST NOT carry {forbidden}: {queried_device}"
        );
    }
    // Negative: the closed self outcome rejects an origin proof shell outright.
    // A Station MUST NOT hand the client an attested peer row, and a client
    // MUST NOT accept one as a verified self projection — so re-decoding the
    // very response we just accepted, with the peer-face member grafted back
    // onto the row, must fail rather than ignore the extra member.
    for shell in ["device_projection_attestation", "proof"] {
        let mut forged = query_keys_value.clone();
        forged["device_keys"][0]["device_keys"][KEYS_DEVICE_ID]
            .as_object_mut()
            .context("forged self row object")?
            .insert(
                shell.to_owned(),
                serde_json::json!({
                    "attestation": projection.clone(),
                    "proof": {
                        "verification_method": "did:web:origin.example#service-key",
                        "created_at": projection["attested_at"].clone(),
                        "jws": "ZXhhbXBsZQ"
                    }
                }),
            );
        assert!(
            serde_json::from_value::<arkret_models_crypto::KeysQueryOutcome>(forged).is_err(),
            "self keys/query outcome accepted an origin proof shell member `{shell}`"
        );
    }
    // The typed DTO is the contract: a row that is not the closed verified
    // projection fails to decode rather than being consumed as a partial one.
    let claimed = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/keys/claim"))
            .bearer_auth(token)
            .json(&arkret_models_crypto::KeysClaimRequestBody {
                one_time_keys: vec![arkret_models_crypto::AccountDeviceAlgorithmEntry {
                    account_id: account_id.clone(),
                    device_algorithms: std::collections::BTreeMap::from([(
                        arkret_identifiers::DeviceId::new(KEYS_DEVICE_ID)?,
                        arkret_wire::NonEmptyString::new("signed_curve25519")
                            .map_err(anyhow::Error::msg)?,
                    )]),
                }],
            }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        claimed["one_time_keys"][0]["device_keys"][KEYS_DEVICE_ID]["signed_curve25519"]["key"],
        "one-time"
    );
    Ok(())
}
