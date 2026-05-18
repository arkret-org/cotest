use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ContrixServer, expect_json};
use crate::scenarios::_helpers::bridge::{EnvOverride, MockCoauthIntrospectionServer};

pub async fn session_grant_exchange_uses_configured_coauth_introspection() -> Result<()> {
    let principal_did = "did:web:alice-session-grant.example";
    let device_id = "dev_web";
    let coauth = MockCoauthIntrospectionServer::spawn(principal_did, device_id)?;
    let _env = EnvOverride::set(&[
        ("SOLAND_SESSION_GRANT_INTROSPECTION_URL", Some(coauth.url())),
        (
            "SOLAND_SESSION_GRANT_INTROSPECTION_BEARER",
            Some("principal-token".to_owned()),
        ),
    ]);
    let server = ContrixServer::spawn("session-grant-exchange").await?;

    expect_json(
        server
            .http()
            .post(server.url("/api/v1/account/register"))
            .json(&json!({
                "did": principal_did,
                "handle": "@alice-session-grant",
                "display_name": "Alice Session Grant",
                "device_id": device_id
            })),
        StatusCode::CREATED,
    )
    .await?;

    let exchange = expect_json(
        server
            .http()
            .post(server.url("/api/v1/auth/session-grant/exchange"))
            .json(&json!({
                "grant_jwt": "coauth.session.jwt",
                "principal_did": principal_did,
                "device_id": device_id,
                "display_name": "yougen session-grant bridge",
                "introspection_proof": {
                    "challenge": "soland-bridge-challenge",
                    "proof_jwt": "client.session-key.proof.jwt"
                }
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(exchange["actor"], principal_did);
    assert_eq!(exchange["device_id"], device_id);
    assert_eq!(exchange["token_type"], "Bearer");
    assert!(
        exchange["access_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );

    let authenticated = expect_json(
        server
            .http()
            .get(server.url("/api/v1/account/me"))
            .bearer_auth(exchange["access_token"].as_str().unwrap()),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(authenticated["did"], principal_did);

    let push = expect_json(
        server
            .http()
            .post(server.url("/api/v1/push/register-device"))
            .header("X-Contrix-Session-Grant", "coauth.session.jwt")
            .header("X-Contrix-Session-Grant-Challenge", "soland-push-challenge")
            .header(
                "X-Contrix-Session-Grant-Proof",
                "client.session-key.push-proof.jwt",
            )
            .json(&json!({
                "operation_id": "cx.push.register_device",
                "principal_did": principal_did,
                "device_id": device_id,
                "push_gateway": "https://floria.example/api/v1/push/notify",
                "push_key": "webpush:opaque-token",
                "platform": "web",
                "request_id": "cx:req:push-session-grant",
                "proof": {"kind": "push-register-proof-placeholder"}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(push["ok"], true);
    assert_eq!(push["registration_id"], format!("cx:push:{device_id}"));

    let requests = coauth.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["grant_jwt"], "coauth.session.jwt");
    assert_eq!(requests[0]["audience"], server.service_did());
    assert_eq!(requests[0]["proof"]["challenge"], "soland-bridge-challenge");
    assert_eq!(requests[1]["grant_jwt"], "coauth.session.jwt");
    assert_eq!(requests[1]["audience"], server.service_did());
    assert_eq!(requests[1]["proof"]["challenge"], "soland-push-challenge");

    Ok(())
}
