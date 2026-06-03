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
    let bob = server
        .register_client("did:web:bob-authz.example", "@bob-authz", "dev_bob")
        .await?;
    let space_id = alice.create_realm("Grant Lifecycle Space").await?;

    let denied_before_grant = expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/authz/check"))
            .json(&json!({
                "actor": bob.actor,
                "action": "manage_space",
                "resource": {"kind": "space", "realm_id": space_id}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(denied_before_grant["allowed"], false);
    assert_eq!(denied_before_grant["reason_code"], "capability_denied");

    let manage_grant = expect_json(
        alice.post("/_cokret/self/authz/grants").json(&json!({
            "space_id": space_id,
            "subject": bob.actor,
            "resource": "*",
            "actions": ["manage_space"],
            "constraints": []
        })),
        StatusCode::OK,
    )
    .await?;
    let manage_grant_id = manage_grant["grant_id"].as_str().unwrap().to_owned();

    let effective_grants = expect_json(
        server
            .http()
            .get(server.url("/_cokret/self/authz/effective-grants"))
            .query(&[
                ("subject", bob.actor.as_str()),
                ("space_id", space_id.as_str()),
            ]),
        StatusCode::OK,
    )
    .await?;
    assert!(effective_grants["state_digest"].is_string());
    assert!(!effective_grants["grants"].as_array().unwrap().is_empty());

    let allowed_after_grant = expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/authz/check"))
            .json(&json!({
                "actor": bob.actor,
                "action": "manage_space",
                "resource": {"kind": "space", "realm_id": space_id}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(allowed_after_grant["allowed"], true);
    assert_eq!(
        allowed_after_grant["grants"][0]["grant_id"],
        manage_grant_id
    );

    alice.add_member(&space_id, &bob).await?;
    let member_send = expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/authz/check"))
            .json(&json!({
                "actor": bob.actor,
                "action": "send",
                "resource": {"kind": "space", "realm_id": space_id}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(member_send["allowed"], true);

    let deny_send_grant = expect_json(
        alice.post("/_cokret/self/authz/grants").json(&json!({
            "space_id": space_id,
            "subject": bob.actor,
            "resource": "*",
            "actions": ["send"],
            "constraints": [{"constraint_type": "decision", "decision": "deny"}]
        })),
        StatusCode::OK,
    )
    .await?;
    let deny_send_grant_id = deny_send_grant["grant_id"].as_str().unwrap().to_owned();

    let denied_send = expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/authz/check"))
            .json(&json!({
                "actor": bob.actor,
                "action": "send",
                "resource": {"kind": "space", "realm_id": space_id}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(denied_send["allowed"], false);
    assert_eq!(denied_send["reason_code"], "explicit_deny");

    let revoked_deny = expect_json(
        alice.delete(&format!("/_cokret/self/authz/grants/{deny_send_grant_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(revoked_deny["revoked"], true);

    let send_after_revoke = expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/authz/check"))
            .json(&json!({
                "actor": bob.actor,
                "action": "send",
                "resource": {"kind": "space", "realm_id": space_id}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(send_after_revoke["allowed"], true);

    let revoked_manage = expect_json(
        alice.delete(&format!("/_cokret/self/authz/grants/{manage_grant_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(revoked_manage["revoked"], true);

    let denied_after_revoke = expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/authz/check"))
            .json(&json!({
                "actor": bob.actor,
                "action": "manage_space",
                "resource": {"kind": "space", "realm_id": space_id}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(denied_after_revoke["allowed"], false);
    assert_eq!(denied_after_revoke["reason_code"], "capability_denied");

    let audit = expect_json(
        alice.get("/_cokret/self/audit/events?limit=20"),
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

    let profile = expect_json(
        server
            .http()
            .get(server.url("/_cokret/self/profile/presence?did=did:web:alice.example")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(profile["actor"], "did:web:alice.example");
    assert_eq!(profile["presence"]["status"], "unavailable");

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

    let allow_policy = expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/policy/check"))
            .json(&json!({
                "request_id": "req-allow",
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "action": "ck.message.create",
                "actor": "did:web:alice.example",
                "source": {"service": "soland"}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(allow_policy["decision"], "allow");
    assert_eq!(allow_policy["reason_code"], "ok");

    let review_policy = expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/policy/check"))
            .json(&json!({
                "request_id": "req-review",
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "action": "space.delete",
                "actor": "did:web:alice.example",
                "source": {"service": "soland"}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(review_policy["decision"], "require_review");
    assert_eq!(review_policy["reason_code"], "review_required");

    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/self/policy/check"))
            .json(&json!({
                "request_id": "req-invalid",
                "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
                "request_canonical_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "action": "ck.message.create",
                "actor": "alice",
                "source": {"service": "soland"}
            })),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    let ice = expect_json(
        alice.post("/_cokret/self/rtc/ice-config").json(&json!({
            "realm_id": "ck:realm:0196419b-0000-7000-8000-000000000000",
            "call_id": "ck:call:01964137-0000-7000-8000-000000000001",
            "actor_id": alice.actor.as_str(),
            "device_id": alice.device_id.as_str()
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(ice["actor_id"], alice.actor);
    assert!(ice["ice_servers"].is_array());
    assert!(ice["signature"].is_object());

    Ok(())
}
