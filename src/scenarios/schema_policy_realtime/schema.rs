use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ContrixServer, expect_api_error, expect_json};

pub async fn schema_registry_lifecycle_and_visibility_work() -> Result<()> {
    let server = ContrixServer::spawn("schema-registry").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client("did:web:bob-schema.example", "@bob-schema", "dev_bob")
        .await?;
    let schema_id = "com.example.schema.widget.v1";

    let builtins = expect_json(
        server
            .http()
            .get(server.url("/api/v1/schemas?kind=flow&limit=20")),
        StatusCode::OK,
    )
    .await?;
    assert!(
        builtins["schemas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|schema| schema["schema_id"] == "cx.schema.flow.v1")
    );

    let registered = expect_json(
        alice.post("/api/v1/schemas").json(&json!({
            "schema_id": schema_id,
            "kind": "morph",
            "version": "1",
            "name": "Widget schema",
            "definition": {
                "$id": schema_id,
                "type": "object",
                "properties": {
                    "status": {"type": "string"}
                }
            }
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(registered["schema_id"], schema_id);
    assert_eq!(registered["owner"], alice.actor);

    let fetched = expect_json(
        server
            .http()
            .get(server.url(&format!("/api/v1/schemas/{schema_id}"))),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(fetched["name"], "Widget schema");

    expect_api_error(
        alice.post("/api/v1/schemas").json(&json!({
            "schema_id": "com.example.schema.invalid.v1",
            "kind": "morph",
            "version": "1",
            "definition": {
                "$id": "com.example.schema.other.v1"
            }
        })),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    expect_api_error(
        bob.post("/api/v1/schemas").json(&json!({
            "schema_id": schema_id,
            "kind": "morph",
            "version": "2",
            "definition": {
                "$id": schema_id,
                "type": "object"
            }
        })),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let deactivated = expect_json(
        alice.post("/api/v1/schemas").json(&json!({
            "schema_id": schema_id,
            "kind": "morph",
            "version": "2",
            "name": "Widget schema",
            "active": false,
            "definition": {
                "$id": schema_id,
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "version": {"type": "integer"}
                }
            }
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(deactivated["active"], false);
    assert_eq!(deactivated["version"], "2");

    expect_api_error(
        server
            .http()
            .get(server.url(&format!("/api/v1/schemas/{schema_id}"))),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    let active_list = expect_json(
        server
            .http()
            .get(server.url("/api/v1/schemas?kind=morph&limit=200")),
        StatusCode::OK,
    )
    .await?;
    assert!(
        active_list["schemas"]
            .as_array()
            .unwrap()
            .iter()
            .all(|schema| schema["schema_id"] != schema_id)
    );

    let inactive_list = expect_json(
        server
            .http()
            .get(server.url("/api/v1/schemas?kind=morph&include_inactive=true&limit=200")),
        StatusCode::OK,
    )
    .await?;
    assert!(
        inactive_list["schemas"]
            .as_array()
            .unwrap()
            .iter()
            .any(|schema| schema["schema_id"] == schema_id && schema["active"] == false)
    );

    expect_api_error(
        bob.delete(&format!("/api/v1/schemas/{schema_id}")),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    let deleted = expect_json(
        alice.delete(&format!("/api/v1/schemas/{schema_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(deleted["ok"], true);

    expect_api_error(
        server
            .http()
            .get(server.url(&format!("/api/v1/schemas/{schema_id}"))),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    Ok(())
}
