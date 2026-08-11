use anyhow::Result;
use arkret::{
    AgentKeyScope, AgentKeyScopeResource, AgentKeyScopeResourceKind, AgentProvisionRequestBody,
    DidFullId, Hash, PrincipalAuthorityInstance, project_full_id_to_core_id,
};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{NonProtocolTestBody, TestServerGroup, expect_api_error, expect_json};

pub async fn applet_lifecycle_surfaces_are_advertised_when_routes_exist() -> Result<()> {
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
    for required in [
        "ak.edge.applet.read.ping",
        "ak.edge.applet.read.describe",
        "ak.self.applet.install.command.preview",
        "ak.self.applet.command.install",
        "ak.self.applet.command.revoke",
        "ak.self.applet.ghost.command.provision",
    ] {
        assert!(
            advertised.contains(&required),
            "missing advertised applet operation {required}; advertised={advertised:#?}"
        );
    }
    let ping = expect_json(
        server.http().get(server.url("/_arkret/edge/applet/ping")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(ping["ok"], true);
    let applet_describe = expect_json(
        server
            .http()
            .get(server.url("/_arkret/edge/applet/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(applet_describe["contract"], "ak.applet.v1");

    expect_api_error(
        alice
            .post(&format!("/_arkret/self/realms/{realm_id}/applets"))
            .json(&NonProtocolTestBody::new(json!({
                "applet_id": "ak:applet:board",
                "manifest": {"name": "Board"}
            }))),
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
        "ak.self.agent.read.list",
        "ak.self.agent.resource.get",
        "ak.self.agent.command.pause",
        "ak.self.agent.command.resume",
        "ak.self.agent.command.deactivate",
        "ak.self.agent.command.renew_pairing",
        "ak.self.agent.grant.command.attach",
        "ak.self.agent.grant.resource.delete",
        "ak.self.agent.sidecar.command.ensure",
    ] {
        assert!(
            advertised.contains(&required),
            "missing advertised agent operation {required}; advertised={advertised:#?}"
        );
    }

    let empty_list = expect_json(alice.get("/_arkret/self/agents"), StatusCode::OK).await?;
    assert!(empty_list["agents"].as_array().unwrap().is_empty());

    let requested_operation = "ak.self.events.command.submit";
    let controller_full_id = DidFullId::new(alice.actor.clone())?;
    let controller_authority_instance = PrincipalAuthorityInstance::new(
        project_full_id_to_core_id(&controller_full_id)?,
        arkret::DidCoreId::new(alice.service_id().to_owned())?,
        arkret::RealmId::new(realm_id.clone())?,
        Hash::new(format!("sha256:{}", "2".repeat(64)))?,
    )?;
    let provision = AgentProvisionRequestBody::Prepare {
        operation_id: arkret::ProtocolOperationId::new(
            "ak:operation:extension-surface-agent-provision",
        )
        .expect("fixture operation id"),
        idempotency_key: arkret::IdempotencyKey::new("extension-surface-agent-provision")
            .expect("fixture idempotency key"),
        full_id: DidFullId::new("did:webvh:z6mkfixtureagent:agent.example")
            .expect("fixture managed Agent full id"),
        controller_authority_instance,
        slug: "planner".to_owned(),
        requested_scope: AgentKeyScope {
            actions: vec![
                requested_operation.to_owned(),
                "ak.message.create".to_owned(),
            ],
            resources: vec![AgentKeyScopeResource {
                kind: AgentKeyScopeResourceKind::Operation,
                realm_id: None,
                resource_ref: None,
                schema_ref: None,
                operation: Some(requested_operation.to_owned()),
                service_id: None,
            }],
            constraints: Vec::new(),
        },
        pairing_ttl_ms: None,
    };
    expect_api_error(
        alice.post("/_arkret/self/agents").json(&provision),
        StatusCode::PRECONDITION_FAILED,
        "failed_precondition",
    )
    .await?;

    expect_api_error(
        alice
            .post(&format!("/_arkret/self/realms/{realm_id}/agents"))
            .json(&NonProtocolTestBody::new(json!({
                "agent_id": "did:web:agent.example",
                "display_name": "Planner"
            }))),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    Ok(())
}
