mod support;

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;
use serial_test::serial;

use support::{TestServerGroup, expect_api_error, expect_json};

#[tokio::test]
#[serial]
async fn applet_and_agent_lifecycle_surfaces_are_not_advertised_until_routes_exist() -> Result<()> {
    let group = TestServerGroup::single("extension-surface").await?;
    let server = group.server(0);
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let space_id = alice.create_space("Extension Surface Space").await?;

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
    assert!(
        !advertised
            .iter()
            .any(|operation| operation.contains("agent"))
    );

    expect_api_error(
        alice
            .post(&format!("/api/v1/spaces/{space_id}/applets"))
            .json(&json!({
                "applet_id": "cx:applet:board",
                "manifest": {"name": "Board"}
            })),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    expect_api_error(
        alice
            .post(&format!("/api/v1/spaces/{space_id}/agents"))
            .json(&json!({
                "agent_id": "did:web:agent.example",
                "display_name": "Planner"
            })),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    Ok(())
}
