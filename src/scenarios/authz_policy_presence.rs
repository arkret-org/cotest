use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    CokretServer, expect_account_subscribe_delta, expect_api_error, expect_audit_action,
    expect_json, expect_status,
};

pub async fn authz_grant_lifecycle_and_audit_work() -> Result<()> {
    let server = CokretServer::spawn("authz-grants").await?;
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-a11ce0000001",
        )
        .await?;
    let _presence_realm = alice.create_realm("Presence Policy Realm").await?;
    let bob = server
        .register_client(
            "did:web:bob-authz.example",
            "@bob-authz",
            "ck:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;
    let realm_id = alice.create_realm("Grant Lifecycle Realm").await?;

    let denied_before_grant = expect_json(
        alice.post("/_cokret/self/authz/check").json(&json!({
            "actor_id": bob.actor,
            "action": "ck.realm.admin",
            "resource": {"kind": "realm", "realm_id": realm_id}
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(denied_before_grant["decision"], "hard_deny");
    assert_eq!(denied_before_grant["reason_code"], "capability_denied");

    let manage_grant = expect_json(
        alice.post("/_soland/self/authz/grants").json(&json!({
            "realm_id": realm_id,
            "subject": bob.actor,
            "resource": "*",
            "actions": ["ck.realm.admin"],
            "constraints": []
        })),
        StatusCode::OK,
    )
    .await?;
    let manage_grant_id = manage_grant["grant_id"].as_str().unwrap().to_owned();

    let effective_grants = expect_json(
        alice.get("/_cokret/self/authz/effective-grants").query(&[
            ("subject", bob.actor.as_str()),
            ("realm_id", realm_id.as_str()),
        ]),
        StatusCode::OK,
    )
    .await?;
    assert!(effective_grants["state_digest"].is_string());
    assert!(!effective_grants["grants"].as_array().unwrap().is_empty());

    let allowed_after_grant = expect_json(
        alice.post("/_cokret/self/authz/check").json(&json!({
            "actor_id": bob.actor,
            "action": "ck.realm.admin",
            "resource": {"kind": "realm", "realm_id": realm_id}
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(allowed_after_grant["decision"], "allow");
    assert_eq!(
        allowed_after_grant["matched_grants"][0]["grant_id"],
        manage_grant_id
    );

    alice.add_member(&realm_id, &bob).await?;
    let member_send = expect_json(
        alice.post("/_cokret/self/authz/check").json(&json!({
            "actor_id": bob.actor,
            "action": "ck.message.create",
            "resource": {"kind": "realm", "realm_id": realm_id}
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(member_send["decision"], "allow");

    let revoked_manage = expect_json(
        alice.delete(&format!("/_soland/self/authz/grants/{manage_grant_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(revoked_manage["revoked"], true);

    let denied_after_revoke = expect_json(
        alice.post("/_cokret/self/authz/check").json(&json!({
            "actor_id": bob.actor,
            "action": "ck.realm.admin",
            "resource": {"kind": "realm", "realm_id": realm_id}
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(denied_after_revoke["decision"], "hard_deny");
    assert_eq!(denied_after_revoke["reason_code"], "capability_denied");

    let audit = expect_json(
        alice.get("/_soland/self/audit/events?limit=20"),
        StatusCode::OK,
    )
    .await?;
    let _ = expect_audit_action(&audit, "authz.grant.create")?;
    let _ = expect_audit_action(&audit, "authz.grant.revoke")?;

    Ok(())
}

pub async fn presence_push_policy_and_ice_contracts_work() -> Result<()> {
    let server = CokretServer::spawn("presence-policy").await?;
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-a11ce0000001",
        )
        .await?;

    expect_status(
        server
            .http()
            .get(server.url("/_cokret/self/account/subscribe?catchup=true&set_presence=online")),
        StatusCode::UNAUTHORIZED,
    )
    .await?;

    let presence_sync = expect_account_subscribe_delta(
        alice.get("/_cokret/self/account/subscribe?catchup=true&set_presence=unavailable"),
        StatusCode::OK,
    )
    .await?;
    assert!(presence_sync["cursor"].is_string());

    let presence_events = presence_sync["presence"]["events"]
        .as_array()
        .expect("account subscribe presence events array");
    let alice_presence = presence_events
        .iter()
        .find(|event| {
            event["actor_id"] == "did:web:alice.example"
                || event["user_id"] == "did:web:alice.example"
        })
        .expect("alice presence in account subscribe baseline");
    assert_eq!(alice_presence["status"], "unavailable");

    let push_registration = expect_json(
        alice
            .post("/_cokret/edge/push/register-device")
            .json(&json!({
                "device_id": alice.device_id.as_str(),
                "push_gateway": "https://push.example",
                "push_key": "opaque",
                "platform": "desktop",
                "app_id": "yougen"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push_registration["ok"], true);

    let push_unregister = expect_json(
        alice
            .post("/_cokret/edge/push/unregister-device")
            .json(&json!({
                "device_id": alice.device_id.as_str(),
                "push_key": "opaque",
                "app_id": "yougen"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push_unregister["ok"], true);

    let policy_realm_id = alice.create_realm("Presence Policy Check Realm").await?;
    let policy_document = expect_json(
        alice.post("/_cokret/self/policies").json(&json!({
            "policy_id": "ck:policy:presence-policy-allow",
            "scope": policy_realm_id,
            "subject_ref": alice.actor,
            "policy_type": "ck.message.create",
            "resource": {"kind": "realm", "realm_id": policy_realm_id},
            "effect": "allow",
            "actions": ["ck.message.create"],
            "obligations": []
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(policy_document["active"], true);

    let allow_policy = expect_json(
        alice
            .post("/_cokret/self/policy/check")
            .json(&json!({
                "request_id": "req-allow",
                "realm_id": policy_realm_id,
                "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "action": "ck.message.create",
                "actor_id": "did:web:alice.example",
                "source": {"service": "soland"}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(allow_policy["decision"], "allow");
    assert_eq!(allow_policy["reason_code"], "policy_allowed");

    let review_policy = expect_json(
        alice
            .post("/_cokret/self/policy/check")
            .json(&json!({
                "request_id": "req-review",
                "realm_id": policy_realm_id,
                "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "action": "ck.realm.destroy",
                "actor_id": "did:web:alice.example",
                "source": {"service": "soland"}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(review_policy["decision"], "require_review");
    assert_eq!(review_policy["reason_code"], "review_required");

    expect_api_error(
        alice
            .post("/_cokret/self/policy/check")
            .json(&json!({
                "request_id": "req-invalid",
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "action": "ck.message.create",
                "actor_id": "alice",
                "source": {"service": "soland"}
            })),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    let ice = expect_json(
        alice.post("/_cokret/self/rtc/ice-config").json(&json!({
            "realm_id": policy_realm_id,
            "call_id": "ck:call:01964137-0000-7000-8000-000000000001",
            "actor_id": alice.actor.as_str(),
            "device_id": alice.device_id.as_str(),
            "mode": "p2p"
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(ice["actor_id"], alice.actor);
    assert!(ice["ice_servers"].is_array());
    assert!(ice["signature"].is_object());

    Ok(())
}
