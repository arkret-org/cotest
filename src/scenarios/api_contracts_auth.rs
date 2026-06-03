use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::fixtures::TestScaffold;
use crate::harness::{CokretServer, expect_api_error, expect_json, expect_status};

pub async fn framework_errors_and_invalid_json_use_contrix_envelopes() -> Result<()> {
    // CT-12: scaffold-driven, parallel-safe.
    let scaffold = TestScaffold::fresh("api-errors").await?;
    let server = scaffold.server();

    let missing = expect_api_error(
        server.http().get(server.url("/api/v1/missing")),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;
    assert!(missing["request_id"].as_str().is_some());

    expect_api_error(
        server.http().post(server.url("/api/v1/server/describe")),
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/account/register"))
            .header("content-type", "application/json")
            .body("{"),
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await?;

    Ok(())
}

pub async fn account_auth_and_session_edges_are_enforced() -> Result<()> {
    let server = CokretServer::spawn("account-auth").await?;

    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/account/register"))
            .json(&json!({"did": "bad", "handle": "@bad", "device_id": "dev_bad"})),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    let registered = expect_json(
        server
            .http()
            .post(server.url("/api/v1/account/register"))
            .json(&json!({
                "did": "did:web:alice-auth.example",
                "handle": "@alice-auth",
                "display_name": "alice-auth",
                "device_id": "dev_alice"
            })),
        StatusCode::CREATED,
    )
    .await?;
    assert_eq!(registered["did"], "did:web:alice-auth.example");

    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/account/register"))
            .json(&json!({
                "did": "did:web:alice-auth.example",
                "handle": "@alice-auth",
                "display_name": "alice-auth",
                "device_id": "dev_alice2"
            })),
        StatusCode::CONFLICT,
        "duplicate_conflict",
    )
    .await?;

    let login = expect_json(
        server
            .http()
            .post(server.url("/api/v1/auth/dev-login"))
            .json(&json!({
                "actor": "did:web:alice-auth.example",
                "device_id": "dev_alice",
                "display_name": "Alice"
            })),
        StatusCode::OK,
    )
    .await?;
    let token = login["access_token"].as_str().unwrap();

    let me = expect_json(
        server
            .http()
            .get(server.url("/api/v1/account/me"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(me["did"], "did:web:alice-auth.example");

    expect_api_error(
        server.http().get(server.url("/api/v1/account/me")),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;

    let logout = expect_json(
        server
            .http()
            .post(server.url("/api/v1/auth/logout"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(logout["revoked"], true);

    expect_status(
        server
            .http()
            .get(server.url("/api/v1/account/me"))
            .bearer_auth(token),
        StatusCode::UNAUTHORIZED,
    )
    .await?;

    Ok(())
}

pub async fn contact_edges_are_rejected() -> Result<()> {
    let server = CokretServer::spawn("contact-edges").await?;
    let alice = expect_json(
        server
            .http()
            .post(server.url("/api/v1/account/register"))
            .json(&json!({
                "did": "did:web:alice-contact.example",
                "handle": "@alice-contact",
                "display_name": "Alice",
                "device_id": "dev_alice"
            })),
        StatusCode::CREATED,
    )
    .await?;
    assert_eq!(alice["did"], "did:web:alice-contact.example");

    let alice = expect_json(
        server
            .http()
            .post(server.url("/api/v1/auth/dev-login"))
            .json(&json!({
                "actor": "did:web:alice-contact.example",
                "device_id": "dev_alice",
                "display_name": "Alice"
            })),
        StatusCode::OK,
    )
    .await?;
    let alice_token = alice["access_token"].as_str().unwrap();

    let bob = expect_json(
        server
            .http()
            .post(server.url("/api/v1/account/register"))
            .json(&json!({
                "did": "did:web:bob-contact.example",
                "handle": "@bob-contact",
                "display_name": "Bob",
                "device_id": "dev_bob"
            })),
        StatusCode::CREATED,
    )
    .await?;
    assert_eq!(bob["did"], "did:web:bob-contact.example");

    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/contacts/request"))
            .bearer_auth(alice_token)
            .json(&json!({"target": "did:web:alice-contact.example"})),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/contacts/request"))
            .bearer_auth(alice_token)
            .json(&json!({"target": "did:web:missing-contact.example"})),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    let requested = expect_json(
        server
            .http()
            .post(server.url("/api/v1/contacts/request"))
            .bearer_auth(alice_token)
            .json(&json!({"target": "did:web:bob-contact.example"})),
        StatusCode::CREATED,
    )
    .await?;
    assert_eq!(requested["status"], "pending");

    let duplicate = expect_json(
        server
            .http()
            .post(server.url("/api/v1/contacts/request"))
            .bearer_auth(alice_token)
            .json(&json!({"target": "did:web:bob-contact.example"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(duplicate["status"], "pending");
    assert_eq!(duplicate["requester"], "did:web:alice-contact.example");
    assert_eq!(duplicate["target"], "did:web:bob-contact.example");

    Ok(())
}
