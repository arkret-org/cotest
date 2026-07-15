use anyhow::Result;
use chrono::{Duration as ChronoDuration, Timelike, Utc};
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    ArkretServer, TestActorClient, attach_ephemeral_proof, ephemeral_proof_placeholder,
    expect_api_error, expect_json,
};
use crate::scenarios::federation_collaboration::{
    actor_did_for_service, authorize_device_public_key,
};

pub async fn typing_and_push_rules_strand_work() -> Result<()> {
    let server = ArkretServer::spawn("typing-push-rules").await?;
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let bob_actor = actor_did_for_service(server.service_id(), "bob-typing")?;
    let bob = server
        .register_client(
            &bob_actor,
            "@bob-typing",
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;
    let carol = server
        .register_client(
            "did:web:carol-typing.example",
            "@carol-typing",
            "ak:device:01904100-0000-7000-8000-000000000ca0",
        )
        .await?;
    let bob_device_key = SigningKey::from_bytes(&[0xb0; 32]);
    authorize_device_public_key(
        &server,
        &bob.token,
        &bob.actor,
        &bob.device_id,
        &bob_device_key,
    )
    .await?;
    let carol_device_key = SigningKey::from_bytes(&[0xca; 32]);

    let realm_id = alice.create_realm("Typing And Push Realm").await?;
    alice.add_member(&realm_id, &bob).await?;
    let strand_id = default_strand_id(&alice, &realm_id).await?;

    expect_api_error(
        carol.post("/_arkret/self/ephemeral").json(&typing_envelope(
            &carol.actor,
            "ak:device:01904100-0000-7000-8000-000000000ca0",
            &realm_id,
            &strand_id,
            &carol_device_key,
            true,
        )),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let typing = expect_json(
        bob.post("/_arkret/self/ephemeral").json(&typing_envelope(
            &bob.actor,
            "ak:device:01904100-0000-7000-8000-0000000000b0",
            &realm_id,
            &strand_id,
            &bob_device_key,
            true,
        )),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(typing["accepted"], true);
    assert_eq!(typing["kind"], "ak.typing");

    let sync_with_typing = alice.sync().await?;
    let ephemeral = sync_with_typing["realms"][&realm_id]["ephemeral"]["events"]
        .as_array()
        .expect("realm ephemeral container exposes typed events");
    assert_eq!(ephemeral.len(), 1);
    assert_eq!(ephemeral[0]["kind"], "ak.typing");
    assert_eq!(ephemeral[0]["payload"]["strand_id"], strand_id);
    assert_eq!(ephemeral[0]["payload"]["typing"], true);
    assert_eq!(ephemeral[0]["actor_id"], bob.actor);

    let stopped = expect_json(
        bob.post("/_arkret/self/ephemeral").json(&typing_envelope(
            &bob.actor,
            "ak:device:01904100-0000-7000-8000-0000000000b0",
            &realm_id,
            &strand_id,
            &bob_device_key,
            false,
        )),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(stopped["accepted"], true);

    let sync_without_typing = alice.sync().await?;
    assert!(
        sync_without_typing["realms"][&realm_id]["ephemeral"]["events"]
            .as_array()
            .expect("realm ephemeral container exposes typed events")
            .is_empty()
    );

    let initial_sync = bob.sync().await?;
    assert!(
        account_data_entry(&initial_sync, "ak.push_rules").is_none(),
        "initial account subscribe must not include ak.push_rules: {initial_sync}"
    );

    // `ak.push_rules` is private account_data: soland requires the content to be
    // a schema-valid encrypted envelope (the plaintext rules never leave the
    // client). Seal a real `AccountDataEncryptedValue` with the SDK so the
    // envelope matches the typed model soland validates; the zero-knowledge
    // account_data store round-trips it unchanged.
    let push_rules_carrier = serde_json::to_value(
        arkret::account_data_crypto::seal_account_data_value_with_nonce(
            &[7u8; 32],
            bob.actor.as_str(),
            "ak.push_rules",
            &json!({"rules": [], "muted_realms": []}),
            [9u8; 24],
        )?,
    )?;
    let rules_written = bob
        .submit_event(
            &realm_id,
            "ak.account_data.set",
            json!({
                "key": "ak.push_rules",
                "owner": bob.actor.as_str(),
                "body": push_rules_carrier.clone(),
                "updated_at": "2026-05-02T00:00:00Z"
            }),
        )
        .await?;
    assert_eq!(rules_written["status"], "accepted");

    let listed_sync = bob.sync().await?;
    let listed_rules =
        account_data_entry(&listed_sync, "ak.push_rules").expect("ak.push_rules account_data row");
    assert_eq!(
        listed_rules["payload"]["body"], push_rules_carrier,
        "push_rules must round-trip as an encrypted account-data envelope unchanged: {listed_rules}"
    );

    let deleted_rules = bob
        .submit_event(
            &realm_id,
            "ak.account_data.set",
            json!({
                "key": "ak.push_rules",
                "owner": bob.actor.as_str(),
                "tombstone": true,
                "updated_at": "2026-05-02T00:00:01Z"
            }),
        )
        .await?;
    assert_eq!(deleted_rules["status"], "accepted");

    let final_sync = bob.sync().await?;
    assert!(
        account_data_entry(&final_sync, "ak.push_rules").is_none(),
        "tombstoned ak.push_rules must not appear in account subscribe: {final_sync}"
    );

    Ok(())
}

fn account_data_entry<'a>(sync: &'a Value, data_type: &str) -> Option<&'a Value> {
    sync["account_data"]["events"]
        .as_array()
        .and_then(|events| {
            events
                .iter()
                .find(|event| event["payload"]["key"] == data_type)
        })
}

/// Author the realm's conversation Strand (the message/typing envelope derives
/// `strand_id` from the realm id), then return the default Strand exposed by the
/// realm-scoped projection. soland does NOT auto-create a Strand on realm
/// create, and the ephemeral/typing scope resolves through the projected Strand,
/// so it must exist before typing into it.
async fn default_strand_id(client: &TestActorClient, realm_id: &str) -> Result<String> {
    let strand_id = realm_id.replace("ak:realm:", "ak:strand:");
    let created = client
        .submit_event(
            realm_id,
            "ak.strand.create",
            json!({
                "object": {
                    "id": strand_id,
                    "schema": "ak.schema.strand.v1",
                    "realm_id": realm_id,
                    "tracks": {"discussion": {"enabled": true, "is_primary": true}},
                    "created_by": client.actor,
                    "created_at": "2026-05-02T00:00:00Z"
                }
            }),
        )
        .await?;
    assert_eq!(
        created["status"], "accepted",
        "strand create must be accepted"
    );

    // The typing/ephemeral scope resolves through the realm-scoped Strand
    // projection, so confirm the Strand we just authored is visible there and
    // return its id. We deliberately do NOT require it to be the realm's
    // `default` Strand: soland only marks `is_default` once a Realm publishes a
    // `ak.realm.set_default_strand` pointer, which this typing scenario neither
    // needs nor exercises.
    let realm_path_id = encode_path_segment(realm_id);
    let strands = expect_json(
        client.get(&format!("/_arkret/self/realms/{realm_path_id}/strands")),
        StatusCode::OK,
    )
    .await?;
    let projected = strands["strands"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|row| row["strand_id"].as_str() == Some(strand_id.as_str()))
        })
        .and_then(|row| row["strand_id"].as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            anyhow::anyhow!("strand projection did not expose the authored strand: {strands}")
        })?;
    Ok(projected)
}

fn encode_path_segment(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

/// ephemeral-envelope.schema.json: every broadcast ephemeral kind carries
/// `device_id` and a detached-JWS `proof` (`{actor_id}#{device_id}`, digest
/// over the canonical envelope without `proof`). Built on the typed SDK
/// `EphemeralEnvelope` so a malformed envelope fails at construction.
fn typing_envelope(
    actor_id: &str,
    device_id: &str,
    realm_id: &str,
    strand_id: &str,
    signing_key: &SigningKey,
    typing: bool,
) -> arkret_core::EphemeralEnvelope {
    let sent_at = Utc::now()
        .with_nanosecond(0)
        .expect("zeroing nanos is valid");
    let expires_at = sent_at + ChronoDuration::seconds(30);
    let mut envelope = arkret_core::EphemeralEnvelope::new(
        "ak.typing",
        arkret_core::RealmId::new(realm_id.to_owned()).expect("test realm id is typed"),
        arkret_core::Did::new(actor_id.to_owned()).expect("test actor DID is typed"),
        arkret_core::DeviceId::new(device_id.to_owned()).expect("test device id is typed"),
        sent_at,
        expires_at,
        std::collections::BTreeMap::from([
            ("strand_id".to_owned(), json!(strand_id)),
            // ephemeral-envelope.schema.json ak.typing branch: optional, const
            // "discussion" in v1; omitted resolves to "discussion".
            ("track_name".to_owned(), json!("discussion")),
            ("typing".to_owned(), json!(typing)),
        ]),
        ephemeral_proof_placeholder(actor_id, device_id, sent_at),
    )
    .expect("typing envelope is well-formed");
    attach_ephemeral_proof(&mut envelope, signing_key);
    envelope
}
