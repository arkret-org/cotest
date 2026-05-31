use anyhow::Result;
use chrono::{Duration as ChronoDuration, Utc};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{ContrixServer, expect_api_error, expect_json};

pub async fn typing_and_push_rules_flow_work() -> Result<()> {
    let server = ContrixServer::spawn("typing-push-rules").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client("did:web:bob-typing.example", "@bob-typing", "dev_bob")
        .await?;
    let carol = server
        .register_client("did:web:carol-typing.example", "@carol-typing", "dev_carol")
        .await?;

    let space_id = alice.create_space("Typing And Push Space").await?;
    alice.add_member(&space_id, &bob).await?;

    expect_api_error(
        carol
            .post("/api/v1/ephemeral")
            .json(&typing_envelope(&carol.actor, &space_id, true)),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let typing = expect_json(
        bob.post("/api/v1/ephemeral")
            .json(&typing_envelope(&bob.actor, &space_id, true)),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(typing["accepted"], true);
    assert_eq!(typing["kind"], "cx.typing");

    let sync_with_typing = alice.sync().await?;
    let ephemeral = sync_with_typing["realms"][&space_id]["ephemeral"]
        .as_array()
        .unwrap();
    assert_eq!(ephemeral.len(), 1);
    assert_eq!(ephemeral[0]["type"], "cx.typing");
    assert_eq!(ephemeral[0]["scope_id"], "cx:thread:typing");
    assert!(
        ephemeral[0]["actors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|actor| actor["actor"] == bob.actor)
    );

    let stopped = expect_json(
        bob.post("/api/v1/ephemeral")
            .json(&typing_envelope(&bob.actor, &space_id, false)),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(stopped["accepted"], true);

    let sync_without_typing = alice.sync().await?;
    assert!(
        sync_without_typing["realms"][&space_id]["ephemeral"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let initial_rules = expect_json(bob.get("/api/v1/push/rules"), StatusCode::OK).await?;
    assert!(initial_rules["rules"].as_array().unwrap().is_empty());

    let default_rule = expect_json(
        bob.post("/api/v1/push/rules").json(&json!({
            "rule_id": "global.default"
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(default_rule["rule"]["actions"][0], "notify");

    let mute_rule = expect_json(
        bob.post("/api/v1/push/rules").json(&json!({
            "rule_id": "global.mute.messages",
            "actions": ["dont_notify"],
            "conditions": [{"field": "notification.type", "equals": "message"}]
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(mute_rule["rule"]["actions"][0], "dont_notify");

    let listed_rules = expect_json(bob.get("/api/v1/push/rules"), StatusCode::OK).await?;
    assert_eq!(listed_rules["rules"].as_array().unwrap().len(), 2);

    expect_api_error(
        bob.post("/api/v1/push/rules").json(&json!({
            "rule_id": "global.invalid",
            "actions": ["explode"]
        })),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    let deleted_mute = expect_json(
        bob.delete("/api/v1/push/rules/global.mute.messages"),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(deleted_mute["ok"], true);

    let deleted_default = expect_json(
        bob.delete("/api/v1/push/rules/global.default"),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(deleted_default["ok"], true);

    let final_rules = expect_json(bob.get("/api/v1/push/rules"), StatusCode::OK).await?;
    assert!(final_rules["rules"].as_array().unwrap().is_empty());

    Ok(())
}

fn typing_envelope(actor_id: &str, realm_id: &str, typing: bool) -> Value {
    let sent_at = Utc::now();
    let expires_at = sent_at + ChronoDuration::seconds(30);
    json!({
        "kind": "cx.typing",
        "realm_id": realm_id,
        "actor_id": actor_id,
        "sent_at": sent_at,
        "expires_at": expires_at,
        "payload": {
            "scope_id": "cx:thread:typing",
            "typing": typing
        }
    })
}
