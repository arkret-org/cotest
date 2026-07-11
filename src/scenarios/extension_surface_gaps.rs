use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{TestServerGroup, expect_api_error, expect_json};

pub async fn applet_lifecycle_surfaces_are_not_advertised_until_routes_exist() -> Result<()> {
    let group = TestServerGroup::single("extension-surface-applet").await?;
    let server = group.server(0);
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let realm_id = alice.create_realm("Applet Surface Realm").await?;

    let describe = expect_json(
        server.http().get(server.url("/_arkret/describe")),
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
            .post(&format!("/_arkret/self/realms/{realm_id}/applets"))
            .json(&json!({
                "applet_id": "ak:applet:board",
                "manifest": {"name": "Board"}
            })),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    Ok(())
}

pub async fn agent_lifecycle_surfaces_are_advertised_when_routes_exist() -> Result<()> {
    let group = TestServerGroup::single("extension-surface-agent").await?;
    let server = group.server(0);
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let realm_id = alice.create_realm("Agent Surface Realm").await?;

    let describe = expect_json(
        server.http().get(server.url("/_arkret/describe")),
        StatusCode::OK,
    )
    .await?;
    let advertised = describe["supported_operations"]
        .as_array()
        .expect("supported_operations is an array")
        .iter()
        .filter_map(|operation| operation.as_str())
        .collect::<Vec<_>>();
    for required in [
        "ak.self.agent.command.provision",
        "ak.self.agent.query.list",
        "ak.self.agent.resource.get",
        "ak.self.agent.command.pause",
        "ak.self.agent.command.resume",
        "ak.self.agent.command.deactivate",
        "ak.self.agent.command.rotate_key",
        "ak.self.agent.grant.command.attach",
        "ak.self.agent.grant.resource.delete",
        "ak.self.agent.sidecar_thread.command.ensure",
    ] {
        assert!(
            advertised.contains(&required),
            "missing advertised agent operation {required}; advertised={advertised:#?}"
        );
    }

    let empty_list = expect_json(alice.get("/_arkret/self/agents"), StatusCode::OK).await?;
    assert!(empty_list["agents"].as_array().unwrap().is_empty());

    let provisioned = expect_json(
        alice.post("/_arkret/self/agents").json(&json!({
            "display_name": "Planner",
            "slug": "planner"
        })),
        StatusCode::CREATED,
    )
    .await?;
    // did:webvh-only red line: soland mints the agent principal as
    // `did:webvh:<scid>:<host>:webvh:agent:<uuid>` (never did:web).
    let agent_id = provisioned["agent_id"].as_str().unwrap_or_default();
    assert!(
        agent_id.starts_with("did:webvh:") && agent_id.contains(":webvh:agent:"),
        "agent_id must be a did:webvh agent DID, got: {agent_id}"
    );

    expect_api_error(
        alice
            .post(&format!("/_arkret/self/realms/{realm_id}/agents"))
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
