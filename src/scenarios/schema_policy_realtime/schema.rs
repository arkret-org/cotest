use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ArkretServer, NonProtocolTestBody, expect_api_error};

pub async fn schema_registry_lifecycle_and_visibility_work() -> Result<()> {
    let server = ArkretServer::spawn("schema-registry").await?;
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let schema_id = "com.example.schema.widget.v1";

    expect_api_error(
        server
            .http()
            .get(server.url("/_arkret/self/schemas?kind=strand&limit=20")),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    expect_api_error(
        alice
            .post("/_arkret/self/schemas")
            .json(&NonProtocolTestBody::new(json!({
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
            }))),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    expect_api_error(
        server
            .http()
            .get(server.url(&format!("/_arkret/self/schemas/{schema_id}"))),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    expect_api_error(
        alice.delete(&format!("/_arkret/self/schemas/{schema_id}")),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    Ok(())
}
