use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{TestServerGroup, expect_json};

pub async fn two_sut_instances_are_isolated_and_federation_ready() -> Result<()> {
    let group = TestServerGroup::multi("federation-ready", 2).await?;
    assert_eq!(group.len(), 2);

    let server_a = group.server(0);
    let server_b = group.server(1);

    let describe_a = expect_json(
        server_a.http().get(server_a.url("/api/v1/server/describe")),
        StatusCode::OK,
    )
    .await?;
    let describe_b = expect_json(
        server_b.http().get(server_b.url("/api/v1/server/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_ne!(server_a.service_did(), server_b.service_did());
    assert_eq!(describe_a["service_type"], "principal_server");
    assert_eq!(describe_b["service_type"], "principal_server");

    let resolve = expect_json(
        server_a
            .http()
            .post(server_a.url("/api/v1/identity/resolve"))
            .json(&json!({"did": "did:web:alice.example"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(resolve["did_document"]["id"], "did:web:alice.example");

    Ok(())
}
