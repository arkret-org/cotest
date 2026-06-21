use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::fixtures::TestScaffold;
use crate::harness::{CokretServer, expect_api_error, expect_json, expect_status};

pub async fn framework_errors_and_invalid_json_use_cokret_envelopes() -> Result<()> {
    // CT-12: scaffold-driven, parallel-safe.
    let scaffold = TestScaffold::fresh("api-errors").await?;
    let server = scaffold.server();

    let missing = expect_api_error(
        server.http().get(server.url("/_cokret/self/missing")),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;
    assert!(missing["request_id"].as_str().is_some());

    expect_api_error(
        server.http().post(server.url("/_cokret/describe")),
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/gate/account/register"))
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
            .post(server.url("/_cokret/gate/account/register"))
            .json(&json!({"principal_id": "bad", "device_id": "ck:device:01904100-0000-7000-8000-000000000bad"})),
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await?;

    let registered = expect_json(
        server
            .http()
            .post(server.url("/_cokret/gate/account/register"))
            .json(&json!({
                "principal_id": "did:web:alice-auth.example",
                "display_name": "alice-auth",
                "device_id": "ck:device:01904100-0000-7000-8000-0000000000a1"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(registered["principal_id"], "did:web:alice-auth.example");

    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/gate/account/register"))
            .json(&json!({
                "principal_id": "did:web:alice-auth.example",
                "display_name": "alice-auth",
                "device_id": "ck:device:01904100-0000-7000-8000-0000000000a2"
            })),
        StatusCode::CONFLICT,
        "duplicate_conflict",
    )
    .await?;

    let login = expect_json(
        server
            .http()
            .post(server.url("/_soland/gate/auth/dev-login"))
            .json(&json!({
                "actor": "did:web:alice-auth.example",
                "device_id": "ck:device:01904100-0000-7000-8000-0000000000a1",
                "display_name": "Alice"
            })),
        StatusCode::OK,
    )
    .await?;
    let token = login["session_credential"].as_str().unwrap();

    let me = expect_json(
        server
            .http()
            .get(server.url("/_cokret/self/account/viewer"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(me["principal_id"], "did:web:alice-auth.example");

    expect_api_error(
        server
            .http()
            .get(server.url("/_cokret/self/account/viewer")),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;

    let logout = expect_json(
        server
            .http()
            .post(server.url("/_cokret/gate/account/session-grants/revoke"))
            .bearer_auth(token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(logout["revoked_count"], 1);

    expect_status(
        server
            .http()
            .get(server.url("/_cokret/self/account/viewer"))
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
            .post(server.url("/_cokret/gate/account/register"))
            .json(&json!({
                "principal_id": "did:web:alice-contact.example",
                "display_name": "Alice",
                "device_id": "ck:device:01904100-0000-7000-8000-0000000000a1"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(alice["principal_id"], "did:web:alice-contact.example");

    let alice = expect_json(
        server
            .http()
            .post(server.url("/_soland/gate/auth/dev-login"))
            .json(&json!({
                "actor": "did:web:alice-contact.example",
                "device_id": "ck:device:01904100-0000-7000-8000-0000000000a1",
                "display_name": "Alice"
            })),
        StatusCode::OK,
    )
    .await?;
    let alice_token = alice["session_credential"].as_str().unwrap();

    let bob = expect_json(
        server
            .http()
            .post(server.url("/_cokret/gate/account/register"))
            .json(&json!({
                "principal_id": "did:web:bob-contact.example",
                "display_name": "Bob",
                "device_id": "ck:device:01904100-0000-7000-8000-0000000000b0"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(bob["principal_id"], "did:web:bob-contact.example");

    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/self/contacts/request"))
            .bearer_auth(alice_token)
            .json(&json!({"target": "did:web:alice-contact.example"})),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/_cokret/self/contacts/request"))
            .bearer_auth(alice_token)
            .json(&json!({"target": "did:web:missing-contact.example"})),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    let requested = expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/contacts/request"))
            .bearer_auth(alice_token)
            .json(&json!({"target": "did:web:bob-contact.example"})),
        StatusCode::CREATED,
    )
    .await?;
    assert_eq!(requested["state"], "pending_outgoing");

    let duplicate = expect_json(
        server
            .http()
            .post(server.url("/_cokret/self/contacts/request"))
            .bearer_auth(alice_token)
            .json(&json!({"target": "did:web:bob-contact.example"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(duplicate["state"], "pending_outgoing");

    Ok(())
}
