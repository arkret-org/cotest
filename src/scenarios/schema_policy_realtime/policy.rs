use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ContrixServer, expect_api_error, expect_json};

const REQUEST_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
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
            "policy_type": "cx.message.create",
            "effect": "deny",
            "actions": ["cx.message.create"],
            "resource": {"kind": "space", "realm_id": space_id},
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
                "request_id": "cx:request:policy-deny",
                "request_canonical_digest": REQUEST_HASH,
                "action": "cx.message.create",
                "actor": bob.actor,
                "realm_id": space_id,
                "source": {"kind": "space", "realm_id": space_id}
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
            "policy_type": "cx.message.create",
            "effect": "deny",
            "actions": ["cx.message.create"],
            "resource": {"kind": "space", "realm_id": space_id},
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
                "request_id": "cx:request:policy-allow",
                "request_canonical_digest": REQUEST_HASH,
                "action": "cx.message.create",
                "actor": bob.actor,
                "realm_id": space_id,
                "source": {"kind": "space", "realm_id": space_id}
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
