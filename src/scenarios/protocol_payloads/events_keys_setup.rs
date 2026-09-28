//! Phase 1 — event submit + key upload/query/claim setup.
//!
//! Walks Alice through pushing a single signed event, then uploading her
//! device-key bundle and exercising `/_arkret/self/keys/{query,claim}` to confirm
//! the upload is visible.

use anyhow::{Context, Result};
use arkret_models_identity::account::{
    AccountDataDeleteRequestBody, AccountDataReplaceRequestBody,
};
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
    dev_client: &TestActorClient,
    event_client: &TestActorClient,
) -> Result<(TestActorClient, String, String)> {
    // The bootstrap already authorized the founding device; sign the upload
    // with its provisioned key.
    let device_key = dev_client
        .principal
        .as_ref()
        .context("client carries its provisioned principal")?
        .device_signing_key
        .clone();
    let (actor, realm_id, message_event_id) = submit_adapter_event(server, event_client).await?;
    upload_and_inspect_keys(
        server,
        dev_client.expect_dev_bearer(),
        &dev_client.actor,
        &device_key,
    )
    .await?;
    Ok((actor, realm_id, message_event_id))
}

async fn submit_adapter_event(
    server: &ArkretServer,
    event_client: &TestActorClient,
) -> Result<(TestActorClient, String, String)> {
    let actor = event_client.clone();
    let created = actor
        .create_realm_with(json!({
            "title": "Adapter Event Space",
            "summary": "Adapter Event Space",
            "public": true,
            "plaintext_visible_services": [server.service_id()]
        }))
        .await?;
    let realm_id = created["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("adapter Realm create omitted realm_id"))?
        .to_owned();
    let strand_id = created["default_strand_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("adapter Realm create omitted default_strand_id"))?;
    let submit = actor
        .submit_event(
            &realm_id,
            "ak.message.create",
            message_create_text_payload_for_strand(parse_strand_id(strand_id)?, "hello")?,
        )
        .await?;
    assert_eq!(submit["status"], "committed");
    let event_id = crate::harness::submitted_event_id(&submit)?;
    advance_read_cursor_to(server, &actor, &realm_id, &event_id.to_string()).await?;
    account_data_round_trip(server, &actor).await?;
    actor_private_push_route_round_trip(server, &actor).await?;
    Ok((actor, realm_id, event_id.to_string()))
}

/// `ak.self.account_data.resource.replace.v1` / `.delete.v1` admit the
/// holder-signed `ak.account_data.set` as an actor-private Event on the
/// holder's PCR: the revision CAS applies once, a byte-identical retry returns
/// the value it wrote, a stale write is `cas_conflict`, and the tombstone
/// hides the key (actor-private-effects.md section 3.1).
async fn account_data_round_trip(server: &ArkretServer, actor: &TestActorClient) -> Result<()> {
    let principal = actor
        .principal
        .as_ref()
        .context("event client carries its provisioned principal")?;
    let pcr_realm_id = principal.pcr_realm_id.to_string();
    let actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new(crate::harness::actor_core_id(&actor.actor)?)?,
        server.service_id().clone(),
    ));
    let key = arkret_wire::AccountDataKey::PUSH_RULES;
    let path = format!("/_arkret/self/account_data/{key}");
    let sealed = |value: serde_json::Value, nonce: u8| {
        arkret_crypto::account_data_crypto::seal_account_data_value_with_nonce(
            &[7; 32],
            &actor_id,
            key,
            &value,
            [nonce; 24],
        )
    };
    let first_value = serde_json::to_value(sealed(json!({"enabled": true}), 9)?)?;
    let set = actor
        .author_event(
            &pcr_realm_id,
            "ak.account_data.set",
            json!({"key": key, "expected_server_revision": 0, "body": first_value}),
        )
        .await?;
    let body = AccountDataReplaceRequestBody {
        set_event: arkret_wire::EventAdmissionSubmission::new(set),
    };
    let created = expect_json(actor.put(&path).json(&body), StatusCode::CREATED)
        .await
        .context("account data create")?;
    assert_eq!(created["revision"], 1, "{created}");
    assert_eq!(created["content"], first_value, "{created}");
    let replay = expect_json(actor.put(&path).json(&body), StatusCode::OK)
        .await
        .context("exact account data retry")?;
    assert_eq!(replay["revision"], 1, "{replay}");
    assert_eq!(replay["content"], first_value, "{replay}");

    let stale = actor
        .author_event(
            &pcr_realm_id,
            "ak.account_data.set",
            json!({"key": key, "expected_server_revision": 0, "body": sealed(json!({"enabled": false}), 8)?}),
        )
        .await?;
    crate::harness::expect_api_error(
        actor.put(&path).json(&AccountDataReplaceRequestBody {
            set_event: arkret_wire::EventAdmissionSubmission::new(stale),
        }),
        StatusCode::CONFLICT,
        "cas_conflict",
    )
    .await
    .context("stale account data write")?;
    let read = expect_json(actor.get(&path), StatusCode::OK).await?;
    assert_eq!(read["revision"], 1, "{read}");

    let tombstone = actor
        .author_event(
            &pcr_realm_id,
            "ak.account_data.set",
            json!({"key": key, "expected_server_revision": 1, "tombstone": true}),
        )
        .await?;
    let deleted = expect_json(
        actor.delete(&path).json(&AccountDataDeleteRequestBody {
            set_event: arkret_wire::EventAdmissionSubmission::new(tombstone),
        }),
        StatusCode::OK,
    )
    .await
    .context("account data tombstone")?;
    assert_eq!(deleted["revision"], 2, "{deleted}");
    crate::harness::expect_api_error(actor.get(&path), StatusCode::NOT_FOUND, "not_found")
        .await
        .context("tombstoned account data read")?;
    Ok(())
}

/// `ak.self.actor_private_events.command.submit.v1` with the owner-signed
/// `ak.device.push_route` (actor-private-effects.md §2.1, §3.3): the route
/// revision CAS applies once and returns `{event_kind, accepted_event_id,
/// revision}`, a byte-identical retry returns the first outcome, a stale
/// revision is `cas_conflict`, an owner on another Station is `param_invalid`,
/// and the shared self Event submit refuses the kind as
/// `unsupported_event_kind`. None of these writes produce a RealmCommit.
async fn actor_private_push_route_round_trip(
    server: &ArkretServer,
    actor: &TestActorClient,
) -> Result<()> {
    const PATH: &str = "/_arkret/self/actor-private-events";
    let principal = actor
        .principal
        .as_ref()
        .context("event client carries its provisioned principal")?;
    let pcr_realm_id = principal.pcr_realm_id.to_string();
    let account_id = arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new(crate::harness::actor_core_id(&actor.actor)?)?,
        server.service_id().clone(),
    );
    let route = |account_id: &arkret_wire::AccountId, expected: u64, revoked: bool| {
        if revoked {
            json!({
                "account_id": account_id,
                "device_id": actor.device_id,
                "push_route": "apns_main",
                "revoked": true,
                "expected_server_revision": expected,
            })
        } else {
            json!({
                "account_id": account_id,
                "device_id": actor.device_id,
                "push_route": "apns_main",
                "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
                "push_gateway_id": "ak:did_core:web:gateway.example",
                "encryption_key": "base64url-public-key",
                "capabilities": ["chat"],
                "expected_server_revision": expected,
            })
        }
    };
    let create = actor
        .author_event(
            &pcr_realm_id,
            "ak.device.push_route",
            route(&account_id, 0, false),
        )
        .await?;
    let body = arkret_wire::ActorPrivateEventSubmitRequestBody::new(create.clone());
    let first = expect_json(actor.post(PATH).json(&body), StatusCode::OK)
        .await
        .context("push route create")?;
    assert_eq!(
        first,
        json!({
            "event_kind": "ak.device.push_route",
            "accepted_event_id": create.event_id,
            "revision": 1,
        }),
        "{first}"
    );
    let replay = expect_json(actor.post(PATH).json(&body), StatusCode::OK)
        .await
        .context("exact push route retry")?;
    assert_eq!(replay, first, "exact retry must return the first outcome");

    let stale = actor
        .author_event(
            &pcr_realm_id,
            "ak.device.push_route",
            route(&account_id, 0, true),
        )
        .await?;
    crate::harness::expect_api_error(
        actor
            .post(PATH)
            .json(&arkret_wire::ActorPrivateEventSubmitRequestBody::new(stale)),
        StatusCode::CONFLICT,
        "cas_conflict",
    )
    .await
    .context("stale push route revision")?;

    let foreign_owner = arkret_wire::AccountId::new(
        account_id.principal_id.clone(),
        arkret_identifiers::DidCoreId::new("ak:did_core:web:other-station.example")?,
    );
    let foreign = actor
        .author_event(
            &pcr_realm_id,
            "ak.device.push_route",
            route(&foreign_owner, 1, true),
        )
        .await?;
    crate::harness::expect_api_error(
        actor
            .post(PATH)
            .json(&arkret_wire::ActorPrivateEventSubmitRequestBody::new(
                foreign,
            )),
        StatusCode::BAD_REQUEST,
        "param_invalid",
    )
    .await
    .context("push route owned by another Station")?;

    let revoke = actor
        .author_event(
            &pcr_realm_id,
            "ak.device.push_route",
            route(&account_id, 1, true),
        )
        .await?;
    let revoked = expect_json(
        actor
            .post(PATH)
            .json(&arkret_wire::ActorPrivateEventSubmitRequestBody::new(
                revoke.clone(),
            )),
        StatusCode::OK,
    )
    .await
    .context("push route revoke")?;
    assert_eq!(revoked["revision"], 2, "{revoked}");
    assert_eq!(
        revoked["accepted_event_id"],
        json!(revoke.event_id),
        "{revoked}"
    );

    // The shared self Event submit never admits an actor-private kind.
    let shared = actor
        .author_event(
            &pcr_realm_id,
            "ak.device.push_route",
            route(&account_id, 2, false),
        )
        .await?;
    crate::harness::expect_api_error(
        actor
            .post("/_arkret/self/events")
            .json(&arkret_wire::EventAdmissionSubmission::new(shared)),
        StatusCode::NOT_IMPLEMENTED,
        "unsupported_event_kind",
    )
    .await
    .context("actor-private kind on the shared self Event submit")?;
    Ok(())
}

/// `ak.self.read_cursor.command.advance.v1` on the committed Message: the
/// actor-private winner is stored at the owner's Station, a byte-identical
/// retry returns the first outcome, and the list reads the durable winner
/// with `updated_at` from the advance envelope (read-receipts.md §6.1, §6.6).
async fn advance_read_cursor_to(
    server: &ArkretServer,
    actor: &TestActorClient,
    realm_id: &str,
    message_event_id: &str,
) -> Result<()> {
    let actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_identifiers::DidCoreId::new(crate::harness::actor_core_id(&actor.actor)?)?,
        server.service_id().clone(),
    ));
    let event = actor
        .author_event(
            realm_id,
            "ak.read_cursor.advance",
            json!({
                "schema": "ak.schema.read_cursor.v1",
                "actor_id": actor_id,
                "device_id": actor.device_id,
                "realm_id": realm_id,
                "read_scope": {"kind": "realm"},
                "position": {
                    "event_id": message_event_id,
                    "hlc": "019041000000-0001-1dae0001"
                }
            }),
        )
        .await?;
    let created_at = arkret_canonical::format_timestamp_canonical(event.created_at);
    let body = arkret_models_collaboration::objects::read_receipts::ReadCursorAdvanceRequestBody {
        advance_event: arkret_wire::EventAdmissionSubmission::new(event),
    };
    let first = expect_json(
        actor.post("/_arkret/self/read-cursors").json(&body),
        StatusCode::OK,
    )
    .await
    .context("read cursor advance")?;
    assert_eq!(first["position"]["event_id"], message_event_id, "{first}");
    assert_eq!(first["device_id"], actor.device_id.as_str(), "{first}");
    assert_eq!(first["updated_at"], created_at.as_str(), "{first}");
    let replay = expect_json(
        actor.post("/_arkret/self/read-cursors").json(&body),
        StatusCode::OK,
    )
    .await
    .context("exact read cursor advance retry")?;
    assert_eq!(replay, first, "exact retry must return the first outcome");
    let listed = actor.read_cursors(realm_id).await?;
    assert_eq!(listed["markers"], json!([first]), "{listed}");
    Ok(())
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
