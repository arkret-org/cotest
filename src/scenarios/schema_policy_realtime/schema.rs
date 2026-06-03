use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{CokretServer, expect_api_error};

pub async fn schema_registry_lifecycle_and_visibility_work() -> Result<()> {
    let server = CokretServer::spawn("schema-registry").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let schema_id = "com.example.schema.widget.v1";

    expect_api_error(
        server
            .http()
            .get(server.url("/api/v1/schemas?kind=flow&limit=20")),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    expect_api_error(
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
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    expect_api_error(
        server
            .http()
            .get(server.url(&format!("/api/v1/schemas/{schema_id}"))),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    expect_api_error(
        alice.delete(&format!("/api/v1/schemas/{schema_id}")),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    Ok(())
}
