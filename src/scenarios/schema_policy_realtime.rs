use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ContrixServer, expect_api_error, expect_json};

const REQUEST_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

pub async fn schema_registry_lifecycle_and_visibility_work() -> Result<()> {
    let server = ContrixServer::spawn("schema-registry").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client("did:web:bob-schema.example", "@bob-schema", "dev_bob")
        .await?;
    let schema_id = "com.example.schema.widget.v1";

    let builtins = expect_json(
        server
            .http()
            .get(server.url("/api/v1/schemas?kind=entity&limit=20")),
        StatusCode::OK,
    )
    .await?;
    assert!(
        builtins["schemas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|schema| schema["schema_id"] == "cx.schema.entity.generic.v1")
    );

    let registered = expect_json(
        alice.post("/api/v1/schemas").json(&json!({
            "schema_id": schema_id,
            "kind": "entity",
            "version": "1",
            "name": "Widget schema",
            "definition": {
                "$id": schema_id,
                "type": "object",
                "properties": {
                    "status": {"type": "string"}
                }
            }
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(registered["schema_id"], schema_id);
    assert_eq!(registered["owner"], alice.actor);

    let fetched = expect_json(
        server
            .http()
            .get(server.url(&format!("/api/v1/schemas/{schema_id}"))),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(fetched["name"], "Widget schema");

    expect_api_error(
        alice.post("/api/v1/schemas").json(&json!({
            "schema_id": "com.example.schema.invalid.v1",
            "kind": "entity",
            "version": "1",
            "definition": {
                "$id": "com.example.schema.other.v1"
            }
        })),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    expect_api_error(
        bob.post("/api/v1/schemas").json(&json!({
            "schema_id": schema_id,
            "kind": "entity",
            "version": "2",
            "definition": {
                "$id": schema_id,
                "type": "object"
            }
        })),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let deactivated = expect_json(
        alice.post("/api/v1/schemas").json(&json!({
            "schema_id": schema_id,
            "kind": "entity",
            "version": "2",
            "name": "Widget schema",
            "active": false,
            "definition": {
                "$id": schema_id,
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "version": {"type": "integer"}
                }
            }
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(deactivated["active"], false);
    assert_eq!(deactivated["version"], "2");

    expect_api_error(
        server
            .http()
            .get(server.url(&format!("/api/v1/schemas/{schema_id}"))),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    let active_list = expect_json(
        server
            .http()
            .get(server.url("/api/v1/schemas?kind=entity&limit=200")),
        StatusCode::OK,
    )
    .await?;
    assert!(
        active_list["schemas"]
            .as_array()
            .unwrap()
            .iter()
            .all(|schema| schema["schema_id"] != schema_id)
    );

    let inactive_list = expect_json(
        server
            .http()
            .get(server.url("/api/v1/schemas?kind=entity&include_inactive=true&limit=200")),
        StatusCode::OK,
    )
    .await?;
    assert!(
        inactive_list["schemas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|schema| schema["schema_id"] == schema_id && schema["active"] == false)
    );

    expect_api_error(
        bob.delete(&format!("/api/v1/schemas/{schema_id}")),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let deleted = expect_json(
        alice.delete(&format!("/api/v1/schemas/{schema_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(deleted["ok"], true);

    expect_api_error(
        server
            .http()
            .get(server.url(&format!("/api/v1/schemas/{schema_id}"))),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    Ok(())
}

pub async fn policy_documents_shape_decisions_and_ownership_work() -> Result<()> {
    let server = ContrixServer::spawn("policy-documents").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client("did:web:bob-policy.example", "@bob-policy", "dev_bob")
        .await?;

    let space_id = alice.create_space("Policy Document Space").await?;
    alice.add_member(&space_id, &bob).await?;

    let initial = expect_json(alice.get("/api/v1/policies"), StatusCode::OK).await?;
    assert!(initial["policies"].as_array().unwrap().is_empty());

    let policy = expect_json(
        alice.post("/api/v1/policies").json(&json!({
            "scope": space_id,
            "subject_ref": bob.actor,
            "policy_type": "message.send",
            "effect": "deny",
            "actions": ["message.send"],
            "resource": {"kind": "space", "space_id": space_id},
            "obligations": [{"kind": "audit", "channel": "mod-log"}]
        })),
        StatusCode::OK,
    )
    .await?;
    let policy_id = policy["policy_id"].as_str().unwrap().to_owned();
    assert!(policy_id.starts_with("cx:policy:"));
    assert_eq!(policy["owner"], alice.actor);

    let listed = expect_json(
        alice.get(&format!("/api/v1/policies?scope={space_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(listed["policies"].as_array().unwrap().len(), 1);
    assert_eq!(listed["policies"][0]["policy_id"], policy_id);

    let fetched = expect_json(
        alice.get(&format!("/api/v1/policies/{policy_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(fetched["payload"]["effect"], "deny");

    expect_api_error(
        bob.get(&format!("/api/v1/policies/{policy_id}")),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    let denied = expect_json(
        server
            .http()
            .post(server.url("/contrix/v1/check"))
            .json(&json!({
                "request_id": "cx:req:policy-deny",
                "request_canonical_hash": REQUEST_HASH,
                "action": "message.send",
                "actor": bob.actor,
                "space_id": space_id,
                "source": {"kind": "space", "space_id": space_id}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(denied["decision"], "deny");
    assert_eq!(denied["reason_code"], "policy_denied");
    assert_eq!(denied["obligations"].as_array().unwrap().len(), 1);

    let inactive = expect_json(
        alice.post("/api/v1/policies").json(&json!({
            "policy_id": policy_id,
            "scope": space_id,
            "subject_ref": bob.actor,
            "policy_type": "message.send",
            "effect": "deny",
            "actions": ["message.send"],
            "resource": {"kind": "space", "space_id": space_id},
            "obligations": [{"kind": "audit", "channel": "mod-log"}],
            "active": false
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(inactive["active"], false);

    let allowed = expect_json(
        server
            .http()
            .post(server.url("/contrix/v1/check"))
            .json(&json!({
                "request_id": "cx:req:policy-allow",
                "request_canonical_hash": REQUEST_HASH,
                "action": "message.send",
                "actor": bob.actor,
                "space_id": space_id,
                "source": {"kind": "space", "space_id": space_id}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(allowed["decision"], "allow");
    assert_eq!(allowed["reason_code"], "ok");

    let hidden_in_default_list = expect_json(alice.get("/api/v1/policies"), StatusCode::OK).await?;
    assert!(
        hidden_in_default_list["policies"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let visible_with_inactive = expect_json(
        alice.get("/api/v1/policies?include_inactive=true"),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        visible_with_inactive["policies"].as_array().unwrap().len(),
        1
    );
    assert_eq!(visible_with_inactive["policies"][0]["active"], false);

    expect_api_error(
        bob.delete(&format!("/api/v1/policies/{policy_id}")),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let deleted = expect_json(
        alice.delete(&format!("/api/v1/policies/{policy_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(deleted["ok"], true);

    expect_api_error(
        alice.get(&format!("/api/v1/policies/{policy_id}")),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    Ok(())
}

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
        carol.post("/api/v1/sync/typing").json(&json!({
            "space_id": space_id,
            "typing": true
        })),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let typing = expect_json(
        bob.post("/api/v1/sync/typing").json(&json!({
            "space_id": space_id,
            "scope_id": "cx:thread:typing",
            "typing": true,
            "timeout_ms": 4000
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(typing["ok"], true);
    assert_eq!(typing["typing"], true);

    let sync_with_typing = expect_json(
        alice.post("/api/v1/sync").json(&json!({"profile": "chat"})),
        StatusCode::OK,
    )
    .await?;
    let ephemeral = sync_with_typing["spaces"][&space_id]["ephemeral"]
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
        bob.post("/api/v1/sync/typing").json(&json!({
            "space_id": space_id,
            "scope_id": "cx:thread:typing",
            "typing": false
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(stopped["typing"], false);

    let sync_without_typing = expect_json(
        alice.post("/api/v1/sync").json(&json!({"profile": "chat"})),
        StatusCode::OK,
    )
    .await?;
    assert!(
        sync_without_typing["spaces"][&space_id]["ephemeral"]
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
            "conditions": {"notification.type": "message"}
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

pub async fn webrtc_session_signal_flow_and_guards_work() -> Result<()> {
    let server = ContrixServer::spawn("webrtc-signaling").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client("did:web:bob-webrtc.example", "@bob-webrtc", "dev_bob")
        .await?;
    let carol = server
        .register_client("did:web:carol-webrtc.example", "@carol-webrtc", "dev_carol")
        .await?;
    let dave = server
        .register_client("did:web:dave-webrtc.example", "@dave-webrtc", "dev_dave")
        .await?;

    let space_id = alice.create_space("Webrtc Space").await?;
    for member in [&bob, &carol] {
        alice.add_member(&space_id, member).await?;
    }

    expect_api_error(
        dave.post("/api/v1/webrtc/sessions").json(&json!({
            "space_id": space_id,
            "participants": [bob.actor]
        })),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let session = expect_json(
        alice.post("/api/v1/webrtc/sessions").json(&json!({
            "space_id": space_id,
            "participants": [bob.actor],
            "ttl_ms": 90_000
        })),
        StatusCode::OK,
    )
    .await?;
    let session_id = session["session_id"].as_str().unwrap().to_owned();
    assert!(session_id.starts_with("cx:webrtc:"));
    assert_eq!(session["participants"].as_array().unwrap().len(), 2);

    expect_api_error(
        carol.get(&format!("/api/v1/webrtc/sessions/{session_id}/signals")),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let initial = expect_json(
        bob.get(&format!("/api/v1/webrtc/sessions/{session_id}/signals")),
        StatusCode::OK,
    )
    .await?;
    assert!(initial["events"].as_array().unwrap().is_empty());

    expect_api_error(
        bob.post(&format!("/api/v1/webrtc/sessions/{session_id}/signals"))
            .json(&json!({
                "message_type": "offer",
                "payload": {"sdp": "v=0"},
                "proofs": [{"actor": alice.actor, "sig": "not-bob"}]
            })),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    let offer = expect_json(
        bob.post(&format!("/api/v1/webrtc/sessions/{session_id}/signals"))
            .json(&json!({
                "message_type": "offer",
                "payload": {"sdp": "v=0"},
                "proofs": [{"actor": bob.actor, "sig": "signed-by-bob"}]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(offer["seq"], 1);
    assert_eq!(offer["next_cursor"], "1");

    let offer_events = expect_json(
        alice.get(&format!(
            "/api/v1/webrtc/sessions/{session_id}/signals?since=0&limit=1"
        )),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(offer_events["limited"], false);
    assert_eq!(offer_events["events"].as_array().unwrap().len(), 1);
    assert_eq!(offer_events["events"][0]["type"], "offer");
    assert_eq!(offer_events["events"][0]["sender"], bob.actor);

    let answer = expect_json(
        alice
            .post(&format!("/api/v1/webrtc/sessions/{session_id}/signals"))
            .json(&json!({
                "message_type": "answer",
                "payload": {"sdp": "v=0-answer"},
                "proofs": [{"kid": format!("{}#dev", alice.actor), "sig": "signed-by-alice"}]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(answer["seq"], 2);

    let answer_events = expect_json(
        bob.get(&format!(
            "/api/v1/webrtc/sessions/{session_id}/signals?since=1"
        )),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(answer_events["events"].as_array().unwrap().len(), 1);
    assert_eq!(answer_events["events"][0]["type"], "answer");
    assert_eq!(answer_events["events"][0]["sender"], alice.actor);

    let closed = expect_json(
        alice.delete(&format!("/api/v1/webrtc/sessions/{session_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(closed["ok"], true);

    expect_api_error(
        bob.get(&format!("/api/v1/webrtc/sessions/{session_id}/signals")),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    Ok(())
}
