use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ContrixServer, expect_api_error, expect_json, expect_status};

const DEMO_SPACE_ID: &str = "cx:space:0196419b-0000-7000-8000-000000000000";
pub async fn discovery_and_index_demo_projection_shapes_work() -> Result<()> {
    let server = ContrixServer::spawn("discovery-index").await?;

    let sync_describe = expect_json(
        server.http().get(server.url("/api/v1/sync/describe")),
        StatusCode::OK,
    )
    .await?;
    for profile in ["board", "chat", "topic"] {
        assert!(
            sync_describe["supported_sync_profiles"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == profile),
            "missing supported sync profile {profile}"
        );
    }

    expect_status(
        server
            .http()
            .post(server.url("/api/v1/sync"))
            .json(&json!({"profile": "invalid"})),
        StatusCode::BAD_REQUEST,
    )
    .await?;

    let chat_sync = expect_json(
        server
            .http()
            .post(server.url("/api/v1/sync"))
            .json(&json!({"profile": "chat"})),
        StatusCode::OK,
    )
    .await?;
    assert!(
        chat_sync["spaces"]
            .as_object()
            .unwrap()
            .contains_key(DEMO_SPACE_ID)
    );

    let directory = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/search-spaces"))
            .json(&json!({"query": "demo", "limit": 10})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(directory["results"].as_array().unwrap().len(), 1);

    let resolved_space = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/resolve-space"))
            .json(&json!({"space_id": DEMO_SPACE_ID})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(resolved_space["space_preview"]["space_id"], DEMO_SPACE_ID);

    let organizations = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/search-organizations"))
            .json(&json!({"query": "contrix", "limit": 10})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        organizations["results"][0]["organization_id"],
        "cx:org:demo"
    );

    let organization = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/resolve-organization"))
            .json(&json!({"organization_id": "cx:org:demo"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(organization["organization"]["handle"], "@contrix-demo");
    assert_eq!(organization["spaces"].as_array().unwrap().len(), 1);

    let actors = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/search-actors"))
            .json(&json!({"query": "alice"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(actors["results"][0]["did"], "did:web:alice.example");

    let users = expect_json(
        server
            .http()
            .get(server.url("/api/v1/directory/search-users?q=alice")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(users["results"][0]["handle"], "@alice");

    let handle = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/resolve-handle"))
            .json(&json!({"handle": "alice"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(handle["did"], "did:web:alice.example");

    expect_api_error(
        server
            .http()
            .get(server.url("/api/v1/directory/search-users?limit=0")),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    let entity = expect_json(
        server
            .http()
            .get(server.url(&format!("/api/v1/index/entity?entity_id={DEMO_SPACE_ID}"))),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(entity["entity"]["kind"], "space");

    let index = expect_json(
        server
            .http()
            .post(server.url("/api/v1/index/query"))
            .json(&json!({"space_ids": [DEMO_SPACE_ID]})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(index["results"].as_array().unwrap().len(), 1);

    let thread = expect_json(
        server
            .http()
            .get(server.url("/api/v1/index/thread?thread_id=cx:thread:demo")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(thread["thread"]["thread_id"], "cx:thread:demo");
    assert!(thread["events"].as_array().unwrap().is_empty());

    let notifications = expect_json(
        server
            .http()
            .get(server.url("/api/v1/index/notifications?actor=did:web:alice.example")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(notifications["unread_count"], 0);

    let inbox = expect_json(
        server.http().get(server.url("/api/v1/index/inbox")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(inbox["rooms"].as_array().unwrap().len(), 1);

    let search = expect_json(
        server
            .http()
            .post(server.url("/api/v1/index/search"))
            .json(&json!({"query": "demo", "entity_types": ["space"], "limit": 5})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(search["results"].as_array().unwrap().len(), 1);

    let hierarchy = expect_json(
        server.http().get(server.url(&format!(
            "/api/v1/index/space-hierarchy?root_space_id={DEMO_SPACE_ID}"
        ))),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(hierarchy["root_space_id"], DEMO_SPACE_ID);

    Ok(())
}
