use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    ContrixServer, expect_api_error, expect_audit_action, expect_json, expect_status,
};

pub async fn authz_grant_lifecycle_and_audit_work() -> Result<()> {
    let server = ContrixServer::spawn("authz-grants").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client("did:web:bob-authz.example", "@bob-authz", "dev_bob")
        .await?;
    let space_id = alice.create_space("Grant Lifecycle Space").await?;

    let denied_before_grant = expect_json(
        server
            .http()
            .post(server.url("/api/v1/authz/check"))
            .json(&json!({
                "actor": bob.actor,
                "action": "manage_space",
                "resource": {"kind": "space", "space_id": space_id}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(denied_before_grant["allowed"], false);
    assert_eq!(denied_before_grant["reason_code"], "capability_denied");

    let manage_grant = expect_json(
        alice.post("/api/v1/authz/grants").json(&json!({
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
            .get(server.url("/api/v1/authz/effective-grants"))
            .query(&[
                ("subject", bob.actor.as_str()),
                ("space_id", space_id.as_str()),
            ]),
        StatusCode::OK,
    )
    .await?;
    assert!(effective_grants["state_hash"].is_string());
    assert!(!effective_grants["grants"].as_array().unwrap().is_empty());

    let allowed_after_grant = expect_json(
        server
            .http()
            .post(server.url("/api/v1/authz/check"))
            .json(&json!({
                "actor": bob.actor,
                "action": "manage_space",
                "resource": {"kind": "space", "space_id": space_id}
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
            .post(server.url("/api/v1/authz/check"))
            .json(&json!({
                "actor": bob.actor,
                "action": "send",
                "resource": {"kind": "space", "space_id": space_id}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(member_send["allowed"], true);

    let deny_send_grant = expect_json(
        alice.post("/api/v1/authz/grants").json(&json!({
            "space_id": space_id,
            "subject": bob.actor,
            "resource": "*",
            "actions": ["send"],
            "constraints": [{"type": "decision", "decision": "deny"}]
        })),
        StatusCode::OK,
    )
    .await?;
    let deny_send_grant_id = deny_send_grant["grant_id"].as_str().unwrap().to_owned();

    let denied_send = expect_json(
        server
            .http()
            .post(server.url("/api/v1/authz/check"))
            .json(&json!({
                "actor": bob.actor,
                "action": "send",
                "resource": {"kind": "space", "space_id": space_id}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(denied_send["allowed"], false);
    assert_eq!(denied_send["reason_code"], "explicit_deny");

    let revoked_deny = expect_json(
        alice.delete(&format!("/api/v1/authz/grants/{deny_send_grant_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(revoked_deny["revoked"], true);

    let send_after_revoke = expect_json(
        server
            .http()
            .post(server.url("/api/v1/authz/check"))
            .json(&json!({
                "actor": bob.actor,
                "action": "send",
                "resource": {"kind": "space", "space_id": space_id}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(send_after_revoke["allowed"], true);

    let revoked_manage = expect_json(
        alice.delete(&format!("/api/v1/authz/grants/{manage_grant_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(revoked_manage["revoked"], true);

    let denied_after_revoke = expect_json(
        server
            .http()
            .post(server.url("/api/v1/authz/check"))
            .json(&json!({
                "actor": bob.actor,
                "action": "manage_space",
                "resource": {"kind": "space", "space_id": space_id}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(denied_after_revoke["allowed"], false);
    assert_eq!(denied_after_revoke["reason_code"], "capability_denied");

    let audit = expect_json(alice.get("/api/v1/audit/events?limit=20"), StatusCode::OK).await?;
    let _ = expect_audit_action(&audit, "authz.grant.create")?;
    let _ = expect_audit_action(&audit, "authz.grant.revoke")?;

    Ok(())
}

pub async fn presence_push_policy_and_ice_contracts_work() -> Result<()> {
    let server = ContrixServer::spawn("presence-policy").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;

    expect_status(
        server
            .http()
            .post(server.url("/api/v1/sync"))
            .json(&json!({"set_presence": "online"})),
        StatusCode::UNAUTHORIZED,
    )
    .await?;

    let presence_sync = expect_json(
        alice
            .post("/api/v1/sync")
            .json(&json!({"set_presence": "unavailable"})),
        StatusCode::OK,
    )
    .await?;
    assert!(presence_sync["next_batch"].is_string());

    let profile = expect_json(
        server
            .http()
            .get(server.url("/api/v1/profile/presence?did=did:web:alice.example")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(profile["actor"], "did:web:alice.example");
    assert_eq!(profile["presence"]["status"], "unavailable");

    let push_registration = expect_json(
        alice.post("/api/v1/push/register-device").json(&json!({
            "device_id": "dev_alice",
            "push_gateway": "https://push.example",
            "push_key": "opaque",
            "platform": "desktop",
            "app_id": "clientx"
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push_registration["ok"], true);

    let push_unregister = expect_json(
        server
            .http()
            .post(server.url("/api/v1/push/unregister-device"))
            .json(&json!({
                "device_id": "dev_alice",
                "push_key": "opaque",
                "app_id": "clientx"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push_unregister["ok"], true);

    let allow_policy = expect_json(
        server
            .http()
            .post(server.url("/contrix/v1/check"))
            .json(&json!({
                "request_id": "req-allow",
                "space_id": "cx:space:01js0sp0000000000000000000",
                "request_canonical_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "action": "message.send",
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
            .post(server.url("/contrix/v1/check"))
            .json(&json!({
                "request_id": "req-review",
                "space_id": "cx:space:01js0sp0000000000000000000",
                "request_canonical_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
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
            .post(server.url("/contrix/v1/check"))
            .json(&json!({
                "request_id": "req-invalid",
                "space_id": "cx:space:01js0sp0000000000000000000",
                "request_canonical_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                "action": "message.send",
                "actor": "alice",
                "source": {"service": "soland"}
            })),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    let ice = expect_json(
        server
            .http()
            .post(server.url("/contrix/v1/ice-config"))
            .json(&json!({})),
        StatusCode::OK,
    )
    .await?;
    assert!(
        ice["service_did"]
            .as_str()
            .is_some_and(|service_did| !service_did.is_empty())
    );
    assert!(ice["ice_servers"].is_array());

    Ok(())
}
