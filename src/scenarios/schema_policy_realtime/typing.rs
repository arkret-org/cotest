use anyhow::Result;
use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use crate::scenarios::identity_test_support::{
    actor_did_for_service_full_id, authorize_device_public_key,
    spawn_with_harness_account_authority,
};

pub async fn typing_and_push_rules_strand_work() -> Result<()> {
    let server = spawn_with_harness_account_authority("typing-push-rules", &[]).await?;
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let bob_actor = actor_did_for_service_full_id(server.service_full_id(), "bob-typing")?;
    let bob = server
        .register_client(
            &bob_actor,
            "@bob-typing",
            "ak:device:01904100-0000-7000-8000-0000000000b0",
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

    let realm_id = alice.create_realm("Typing And Push Realm").await?;
    alice.add_member(&realm_id, &bob).await?;

    // Typing is a Signal, not a sync frame: `zh/sync/signal.md` §1 keeps the
    // exact payload type and its Strand target inside `encrypted_payload`, so
    // the account-subscribe stream carries no typing bucket to assert on and
    // the service cannot see `typing`/`strand_id` at all. The receiver-side
    // contract lives in `conformance::presence_signal`; the send-side
    // capability gate is a soland admission concern on
    // `POST /_arkret/self/signal`.

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
                "expected_revision": 0,
                "body": push_rules_carrier.clone(),
                "updated_at": "2026-05-02T00:00:00.000Z"
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
                "expected_revision": 1,
                "tombstone": true,
                "updated_at": "2026-05-02T00:00:01.000Z"
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

fn account_data_entry<'a>(sync: &'a Value, account_data_key: &str) -> Option<&'a Value> {
    sync["account_data"]["events"]
        .as_array()
        .and_then(|events| {
            events
                .iter()
                .find(|event| event["payload"]["key"] == account_data_key)
        })
}
