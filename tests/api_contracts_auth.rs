mod support;

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;
use serial_test::serial;

use support::{ServerxInstance, dev_login, expect_api_error, expect_json, register_account};

#[tokio::test]
#[serial]
async fn framework_errors_and_invalid_json_use_contrix_envelopes() -> Result<()> {
    let server = ServerxInstance::spawn("contract-errors").await?;

    expect_api_error(
        server.http().get(server.url("/api/v1/not-a-real-endpoint")),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
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
        "bad_json",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/identity/resolve"))
            .json(&json!({"did": "alice"})),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    Ok(())
}

#[tokio::test]
#[serial]
async fn account_auth_and_session_edges_are_enforced() -> Result<()> {
    let server = ServerxInstance::spawn("account-auth").await?;

    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/account/register"))
            .json(&json!({"did": "alice", "handle": "@alice"})),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/account/register"))
            .json(&json!({"did": "did:web:badhandle.example", "handle": "$bad"})),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    let normalized = expect_json(
        server
            .http()
            .post(server.url("/api/v1/account/register"))
            .json(&json!({
                "did": "did:web:upper.example",
                "handle": "UPPER",
                "device_id": "dev_upper"
            })),
        StatusCode::CREATED,
    )
    .await?;
    assert_eq!(normalized["handle"], "@upper");

    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/account/register"))
            .json(&json!({
                "did": "did:web:upper.example",
                "handle": "@upper2",
                "device_id": "dev_upper2"
            })),
        StatusCode::CONFLICT,
        "duplicate_conflict",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/auth/dev-login"))
            .json(&json!({"actor": "did:web:missing.example", "device_id": "dev_missing"})),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/auth/dev-login"))
            .json(&json!({"actor": "did:web:alice.example", "device_id": "bad-device"})),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    let token = dev_login(&server, "did:web:alice.example", "dev_alice").await?;
    expect_api_error(
        server.http().get(server.url("/api/v1/account/me")),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .get(server.url("/api/v1/account/me"))
            .bearer_auth("definitely-invalid"),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .get(server.url("/api/v1/account/me?access_token=query-leak"))
            .bearer_auth(token),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;

    Ok(())
}

#[tokio::test]
#[serial]
async fn contact_edges_are_rejected() -> Result<()> {
    let server = ServerxInstance::spawn("contact-edges").await?;
    let alice = dev_login(&server, "did:web:alice.example", "dev_alice").await?;
    let bob = register_account(
        &server,
        "did:web:bob-contact.example",
        "@bob-contact",
        "dev_bob",
    )
    .await?;

    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/contacts/request"))
            .bearer_auth(&alice)
            .json(&json!({"target": "did:web:alice.example"})),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/contacts/request"))
            .bearer_auth(&alice)
            .json(&json!({"target": "did:web:nope.example"})),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    let request = expect_json(
        server
            .http()
            .post(server.url("/api/v1/contacts/request"))
            .bearer_auth(&alice)
            .json(&json!({"target": "did:web:bob-contact.example"})),
        StatusCode::CREATED,
    )
    .await?;
    assert_eq!(request["status"], "pending");

    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/contacts/request"))
            .bearer_auth(&alice)
            .json(&json!({"target": "did:web:bob-contact.example"})),
        StatusCode::CONFLICT,
        "duplicate_conflict",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/contacts/respond"))
            .bearer_auth(&bob)
            .json(&json!({"requester": "did:web:alice.example", "action": "maybe"})),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/contacts/respond"))
            .bearer_auth(&bob)
            .json(&json!({"requester": "did:web:missing.example", "action": "accept"})),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    Ok(())
}
