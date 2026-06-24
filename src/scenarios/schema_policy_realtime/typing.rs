use anyhow::Result;
use chrono::{Duration as ChronoDuration, Utc};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{CokretServer, TestActorClient, expect_api_error, expect_json};

pub async fn typing_and_push_rules_strand_work() -> Result<()> {
    let server = CokretServer::spawn("typing-push-rules").await?;
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let bob = server
        .register_client(
            "did:web:bob-typing.example",
            "@bob-typing",
            "ck:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;
    let carol = server
        .register_client(
            "did:web:carol-typing.example",
            "@carol-typing",
            "ck:device:01904100-0000-7000-8000-000000000ca0",
        )
        .await?;

    let realm_id = alice.create_realm("Typing And Push Realm").await?;
    alice.add_member(&realm_id, &bob).await?;
    let strand_id = default_strand_id(&alice, &realm_id).await?;

    expect_api_error(
        carol.post("/_cokret/self/ephemeral").json(&typing_envelope(
            &carol.actor,
            &realm_id,
            &strand_id,
            true,
        )),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let typing = expect_json(
        bob.post("/_cokret/self/ephemeral")
            .json(&typing_envelope(&bob.actor, &realm_id, &strand_id, true)),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(typing["accepted"], true);
    assert_eq!(typing["kind"], "ck.typing");

    let sync_with_typing = alice.sync().await?;
    let ephemeral = sync_with_typing["realms"][&realm_id]["ephemeral"]
        .as_array()
        .unwrap();
    assert_eq!(ephemeral.len(), 1);
    assert_eq!(ephemeral[0]["type"], "ck.typing");
    assert_eq!(ephemeral[0]["strand_id"], strand_id);
    assert!(
        ephemeral[0]["actors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|actor| actor["actor"] == bob.actor)
    );

    let stopped = expect_json(
        bob.post("/_cokret/self/ephemeral")
            .json(&typing_envelope(&bob.actor, &realm_id, &strand_id, false)),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(stopped["accepted"], true);

    let sync_without_typing = alice.sync().await?;
    assert!(
        sync_without_typing["realms"][&realm_id]["ephemeral"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let initial_sync = bob.sync().await?;
    assert!(
        account_data_entry(&initial_sync, "ck.push_rules").is_none(),
        "initial account subscribe must not include ck.push_rules: {initial_sync}"
    );

    let rules_written = bob
        .submit_event(
            &realm_id,
            "ck.account_data.set",
            json!({
                "key": "ck.push_rules",
                "owner": bob.actor.as_str(),
                "body": {
                    "rules": [
                        {"rule_id": "global.default"},
                        {
                            "rule_id": "global.mute.messages",
                            "actions": ["dont_notify"],
                            "conditions": [{"field": "notification.type", "equals": "message"}]
                        }
                    ]
                },
                "updated_at": "2026-05-02T00:00:00Z"
            }),
        )
        .await?;
    assert_eq!(rules_written["status"], "accepted");

    let listed_sync = bob.sync().await?;
    let listed_rules =
        account_data_entry(&listed_sync, "ck.push_rules").expect("ck.push_rules account_data row");
    let rules = listed_rules["content"]["rules"].as_array().unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0]["rule_id"], "global.default");
    assert_eq!(rules[1]["actions"][0], "dont_notify");

    let deleted_rules = bob
        .submit_event(
            &realm_id,
            "ck.account_data.set",
            json!({
                "key": "ck.push_rules",
                "owner": bob.actor.as_str(),
                "tombstone": true,
                "updated_at": "2026-05-02T00:00:01Z"
            }),
        )
        .await?;
    assert_eq!(deleted_rules["status"], "accepted");

    let final_sync = bob.sync().await?;
    assert!(
        account_data_entry(&final_sync, "ck.push_rules").is_none(),
        "tombstoned ck.push_rules must not appear in account subscribe: {final_sync}"
    );

    Ok(())
}

fn account_data_entry<'a>(sync: &'a Value, data_type: &str) -> Option<&'a Value> {
    sync["account_data"]["events"]
        .as_array()
        .and_then(|events| events.iter().find(|event| event["data_type"] == data_type))
}

async fn default_strand_id(client: &TestActorClient, realm_id: &str) -> Result<String> {
    // soland does NOT auto-create a default Strand on realm create; the Realm's
    // `default_strand_id` pointer is only set by `ck.realm.set_default_strand`,
    // which requires the named Strand to already exist (and the Strand-list
    // projection only carries an `is_default` row once that pointer is set).
    // Author the Strand as the realm owner, then point the Realm default at it.
    let strand_id = realm_id.replace("ck:realm:", "ck:strand:");
    let created = client
        .submit_event(
            realm_id,
            "ck.strand.create",
            json!({
                "object": {
                    "id": strand_id,
                    "schema": "ck.schema.strand.v1",
                    "realm_id": realm_id,
                    "tracks": {"discussion": {"enabled": true, "is_primary": true}},
                    "created_by": client.actor,
                    "created_at": "2026-05-02T00:00:00Z"
                }
            }),
        )
        .await?;
    assert_eq!(created["status"], "accepted", "strand create must be accepted");
    let defaulted = client
        .submit_event(
            realm_id,
            "ck.realm.set_default_strand",
            json!({
                "strand_id": strand_id,
                "expected_default_strand_id": Value::Null
            }),
        )
        .await?;
    assert_eq!(
        defaulted["status"], "accepted",
        "set_default_strand must be accepted"
    );
    Ok(strand_id)
}

fn typing_envelope(actor_id: &str, realm_id: &str, strand_id: &str, typing: bool) -> Value {
    let sent_at = Utc::now();
    let expires_at = sent_at + ChronoDuration::seconds(30);
    json!({
        "kind": "ck.typing",
        "realm_id": realm_id,
        "actor_id": actor_id,
        "sent_at": sent_at,
        "expires_at": expires_at,
        "payload": {
            "strand_id": strand_id,
            "typing": typing
        }
    })
}
