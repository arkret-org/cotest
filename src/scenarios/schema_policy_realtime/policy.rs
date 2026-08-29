use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ArkretServer, actor_core_id, expect_api_error, expect_json};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

pub async fn policy_documents_shape_decisions_and_ownership_work() -> Result<()> {
    let server = ArkretServer::spawn("policy-documents").await?;
    let alice_actor = actor_did_for_service_did(server.service_did(), "alice-policy")?;
    let alice = server
        .demo_client(
            &alice_actor,
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let bob_actor = actor_did_for_service_did(server.service_did(), "bob-policy")?;
    let bob = server
        .register_client(
            &bob_actor,
            "@bob-policy",
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;

    let realm_id = alice.create_realm("Policy Document Realm").await?;
    alice.add_member(&realm_id, &bob).await?;
    let alice_core = actor_core_id(&alice.actor)?;

    let initial = expect_json(alice.get("/_soland/self/policies"), StatusCode::OK).await?;
    assert!(initial["policies"].as_array().unwrap().is_empty());

    let policy = expect_json(
        alice
            .post("/_soland/self/policies")
            .json(&crate::harness::NonProtocolTestBody::new(json!({
                "scope": realm_id,
                "subject_ref": bob.actor,
                "policy_kind": "ak.message.create",
                // Rule effects use the closed
                // allow/deny/quarantine/require_review set.
                "effect": "deny",
                "actions": ["ak.message.create"],
                // Realm-scoped resource: soland matches resource.kind against the
                // request source.service_kind, so constrain on realm_id only.
                "resource": {"realm_id": realm_id},
                "obligations": [{"kind": "audit", "channel": "mod-log"}]
            }))),
        StatusCode::OK,
    )
    .await?;
    let policy_id = policy["policy_id"].as_str().unwrap().to_owned();
    assert!(policy_id.starts_with("ak:policy:"));
    assert_eq!(policy["owner"], alice_core);

    // Negative vector: `hard_deny` is an authorization decision verb, not a
    // registered stored rule effect.
    expect_api_error(
        alice
            .post("/_soland/self/policies")
            .json(&crate::harness::NonProtocolTestBody::new(json!({
                "scope": realm_id,
                "subject_ref": bob.actor,
                "policy_kind": "ak.message.create",
                "effect": "hard_deny",
                "actions": ["ak.message.create"],
                "resource": {"kind": "realm", "realm_id": realm_id}
            }))),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;

    let listed = expect_json(
        alice.get(&format!("/_soland/self/policies?scope={realm_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(listed["policies"].as_array().unwrap().len(), 1);
    assert_eq!(listed["policies"][0]["policy_id"], policy_id);

    let fetched = expect_json(
        alice.get(&format!("/_soland/self/policies/{policy_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(fetched["payload"]["effect"], "deny");

    expect_api_error(
        bob.get(&format!("/_soland/self/policies/{policy_id}")),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    let inactive = expect_json(
        alice
            .post("/_soland/self/policies")
            .json(&crate::harness::NonProtocolTestBody::new(json!({
                "policy_id": policy_id,
                "scope": realm_id,
                "subject_ref": bob.actor,
                "policy_kind": "ak.message.create",
                "effect": "deny",
                "actions": ["ak.message.create"],
                "resource": {"kind": "realm", "realm_id": realm_id},
                "obligations": [{"kind": "audit", "channel": "mod-log"}],
                "active": false
            }))),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(inactive["active"], false);

    let hidden_in_default_list =
        expect_json(alice.get("/_soland/self/policies"), StatusCode::OK).await?;
    assert!(
        hidden_in_default_list["policies"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let visible_with_inactive = expect_json(
        alice.get("/_soland/self/policies?include_inactive=true"),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        visible_with_inactive["policies"].as_array().unwrap().len(),
        1
    );
    assert_eq!(visible_with_inactive["policies"][0]["active"], false);

    expect_api_error(
        bob.delete(&format!("/_soland/self/policies/{policy_id}")),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let deleted = expect_json(
        alice.delete(&format!("/_soland/self/policies/{policy_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(deleted["ok"], true);

    expect_api_error(
        alice.get(&format!("/_soland/self/policies/{policy_id}")),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    Ok(())
}
