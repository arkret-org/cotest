use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{CokretServer, expect_api_error, expect_json};

const REQUEST_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
pub async fn policy_documents_shape_decisions_and_ownership_work() -> Result<()> {
    let server = CokretServer::spawn("policy-documents").await?;
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let bob = server
        .register_client(
            "did:web:bob-policy.example",
            "@bob-policy",
            "ck:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;

    let realm_id = alice.create_realm("Policy Document Realm").await?;
    alice.add_member(&realm_id, &bob).await?;

    let initial = expect_json(alice.get("/_cokret/self/policies"), StatusCode::OK).await?;
    assert!(initial["policies"].as_array().unwrap().is_empty());

    let policy = expect_json(
        alice.post("/_cokret/self/policies").json(&json!({
            "scope": realm_id,
            "subject_ref": bob.actor,
            "policy_type": "ck.message.create",
            "effect": "deny",
            "actions": ["ck.message.create"],
            "resource": {"kind": "realm", "realm_id": realm_id},
            "obligations": [{"kind": "audit", "channel": "mod-log"}]
        })),
        StatusCode::OK,
    )
    .await?;
    let policy_id = policy["policy_id"].as_str().unwrap().to_owned();
    assert!(policy_id.starts_with("ck:policy:"));
    assert_eq!(policy["owner"], alice.actor);

    let listed = expect_json(
        alice.get(&format!("/_cokret/self/policies?scope={realm_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(listed["policies"].as_array().unwrap().len(), 1);
    assert_eq!(listed["policies"][0]["policy_id"], policy_id);

    let fetched = expect_json(
        alice.get(&format!("/_cokret/self/policies/{policy_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(fetched["payload"]["effect"], "deny");

    expect_api_error(
        bob.get(&format!("/_cokret/self/policies/{policy_id}")),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    let denied = expect_json(
        bob.post("/_cokret/self/policy/check").json(&json!({
            "request_id": "ck:request:policy-deny",
            "request_canonical_digest": REQUEST_HASH,
            "action": "ck.message.create",
            "actor_id": bob.actor,
            "realm_id": realm_id,
            "source": {"kind": "realm", "realm_id": realm_id}
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(denied["decision"], "deny");
    assert_eq!(denied["reason_code"], "policy_denied");
    assert_eq!(denied["obligations"].as_array().unwrap().len(), 1);

    let inactive = expect_json(
        alice.post("/_cokret/self/policies").json(&json!({
            "policy_id": policy_id,
            "scope": realm_id,
            "subject_ref": bob.actor,
            "policy_type": "ck.message.create",
            "effect": "deny",
            "actions": ["ck.message.create"],
            "resource": {"kind": "realm", "realm_id": realm_id},
            "obligations": [{"kind": "audit", "channel": "mod-log"}],
            "active": false
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(inactive["active"], false);

    let allowed = expect_json(
        bob.post("/_cokret/self/policy/check").json(&json!({
            "request_id": "ck:request:policy-allow",
            "request_canonical_digest": REQUEST_HASH,
            "action": "ck.message.create",
            "actor_id": bob.actor,
            "realm_id": realm_id,
            "source": {"kind": "realm", "realm_id": realm_id}
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(allowed["decision"], "require_review");
    assert_eq!(allowed["reason_code"], "review_required");

    let hidden_in_default_list =
        expect_json(alice.get("/_cokret/self/policies"), StatusCode::OK).await?;
    assert!(
        hidden_in_default_list["policies"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let visible_with_inactive = expect_json(
        alice.get("/_cokret/self/policies?include_inactive=true"),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        visible_with_inactive["policies"].as_array().unwrap().len(),
        1
    );
    assert_eq!(visible_with_inactive["policies"][0]["active"], false);

    expect_api_error(
        bob.delete(&format!("/_cokret/self/policies/{policy_id}")),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let deleted = expect_json(
        alice.delete(&format!("/_cokret/self/policies/{policy_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(deleted["ok"], true);

    expect_api_error(
        alice.get(&format!("/_cokret/self/policies/{policy_id}")),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    Ok(())
}
