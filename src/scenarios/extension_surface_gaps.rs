use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{TestServerGroup, expect_api_error, expect_json};

pub async fn applet_lifecycle_surfaces_are_not_advertised_until_routes_exist() -> Result<()> {
    let group = TestServerGroup::single("extension-surface-applet").await?;
    let server = group.server(0);
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let space_id = alice.create_space("Applet Surface Space").await?;

    let describe = expect_json(
        server.http().get(server.url("/api/v1/server/describe")),
        StatusCode::OK,
    )
    .await?;
    let advertised = describe["supported_operations"]
        .as_array()
        .expect("supported_operations is an array")
        .iter()
        .filter_map(|operation| operation.as_str())
        .collect::<Vec<_>>();
    assert!(
        !advertised
            .iter()
            .any(|operation| operation.contains("applet"))
    );

    expect_api_error(
        alice
            .post(&format!("/api/v1/spaces/{space_id}/applets"))
            .json(&json!({
                "applet_id": "cx:applet:board",
                "manifest": {"name": "Board"}
            })),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    Ok(())
}

pub async fn agent_lifecycle_surfaces_are_not_advertised_until_routes_exist() -> Result<()> {
    let group = TestServerGroup::single("extension-surface-agent").await?;
    let server = group.server(0);
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let space_id = alice.create_space("Agent Surface Space").await?;

    let describe = expect_json(
        server.http().get(server.url("/api/v1/server/describe")),
        StatusCode::OK,
    )
    .await?;
    let advertised = describe["supported_operations"]
        .as_array()
        .expect("supported_operations is an array")
        .iter()
        .filter_map(|operation| operation.as_str())
        .collect::<Vec<_>>();
    assert!(
        !advertised
            .iter()
            .any(|operation| operation.contains("agent"))
    );

    expect_api_error(
        alice
            .post(&format!("/api/v1/spaces/{space_id}/agents"))
            .json(&json!({
                "agent_id": "did:web:agent.example",
                "display_name": "Planner"
            })),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    Ok(())
}
