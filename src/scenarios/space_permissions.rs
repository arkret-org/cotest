use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    ContrixServer, add_member, create_space, dev_login, event_envelope, expect_api_error,
    expect_json, register_account, send_message,
};

pub async fn space_creation_and_owner_only_mutations_are_enforced() -> Result<()> {
    // CT-12: scaffold-driven, parallel-safe.
    let scaffold = crate::fixtures::TestScaffold::fresh("space-permissions").await?;
    let server = scaffold.server();
    let alice = dev_login(server, "did:web:alice.example", "dev_alice").await?;
    let bob = register_account(
        server,
        "did:web:bob-space.example",
        "@bob-space",
        "dev_bob",
    )
    .await?;

    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/spaces"))
            .json(&json!({"title": "No Auth"})),
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/spaces"))
            .bearer_auth(&alice)
            .json(&json!({"title": "   "})),
        StatusCode::BAD_REQUEST,
        "missing_param",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/spaces"))
            .bearer_auth(&alice)
            .json(&json!({"title": "Bad Invitee", "invitees": ["not-a-did"]})),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    let space_id = create_space(server, &alice, "Permission Space").await?;
    expect_api_error(
        server
            .http()
            .post(server.url(&format!("/api/v1/spaces/{space_id}/members")))
            .bearer_auth(&bob)
            .json(&json!({"member": "did:web:bob-space.example"})),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .delete(server.url(&format!(
                "/api/v1/spaces/{space_id}/members/did:web:alice.example"
            )))
            .bearer_auth(&alice),
        StatusCode::CONFLICT,
        "conflict",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .delete(server.url(&format!("/api/v1/spaces/{space_id}")))
            .bearer_auth(&bob),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    Ok(())
}

pub async fn private_visibility_non_member_send_and_deleted_space_edges() -> Result<()> {
    let server = ContrixServer::spawn("space-visibility").await?;
    let alice = dev_login(&server, "did:web:alice.example", "dev_alice").await?;
    let bob = register_account(
        &server,
        "did:web:bob-visible.example",
        "@bob-visible",
        "dev_bob",
    )
    .await?;
    let space_id = create_space(&server, &alice, "Private Space").await?;

    let anonymous_search = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/search-realms"))
            .json(&json!({"query": "Private Space"})),
        StatusCode::OK,
    )
    .await?;
    assert!(anonymous_search["results"].as_array().unwrap().is_empty());

    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/events"))
            .bearer_auth(&bob)
            .json(&event_envelope(
                "did:web:bob-visible.example",
                &space_id,
                "cx.message.create",
                json!({
                    "body": "not a member",
                    "content": {"body": "not a member"},
                    "thread_id": "cx:thread:space-denied",
                }),
            )),
        StatusCode::FORBIDDEN,
        "policy_denied",
    )
    .await?;

    add_member(&server, &alice, &space_id, "did:web:bob-visible.example").await?;
    send_message(
        &server,
        &bob,
        "did:web:bob-visible.example",
        &space_id,
        "cx:thread:space",
        "member can send",
    )
    .await?;

    expect_json(
        server
            .http()
            .delete(server.url(&format!("/api/v1/spaces/{space_id}")))
            .bearer_auth(&alice),
        StatusCode::OK,
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/events"))
            .bearer_auth(&alice)
            .json(&event_envelope(
                "did:web:alice.example",
                &space_id,
                "cx.message.create",
                json!({
                    "body": "after delete",
                    "content": {"body": "after delete"},
                    "thread_id": "cx:thread:space",
                }),
            )),
        StatusCode::FORBIDDEN,
        "policy_denied",
    )
    .await?;

    Ok(())
}
