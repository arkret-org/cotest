use anyhow::Result;
use arkret::{
    AgentKeyScope, AgentKeyScopeResource, AgentKeyScopeResourceKind, AgentProvisionRequestBody,
    DidFullId, PrincipalAuthorityKey, project_full_id_to_core_id,
};
use arkret_models_discovery::ServiceDescribe;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{NonProtocolTestBody, TestServerGroup, expect_api_error, expect_json};
use crate::scenarios::identity_test_support::actor_did_for_service_full_id;

pub async fn applet_lifecycle_surfaces_are_advertised_when_routes_exist() -> Result<()> {
    let group = TestServerGroup::single("extension-surface-applet").await?;
    let server = group.server(0);
    let alice_did = actor_did_for_service_full_id(server.service_full_id(), "alice-applet")?;
    let alice = server
        .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let realm_id = alice.create_realm("Applet Surface Realm").await?;

    let describe = expect_json(
        server.http().get(server.url("/_arkret/describe")),
        StatusCode::OK,
    )
    .await?;
    let advertised = describe["supported_operation_bundles"]
        .as_array()
        .expect("supported_operation_bundles is an array")
        .iter()
        .filter_map(Value::as_str)
        .filter_map(arkret_wire::operation_bundle_descriptor)
        .flat_map(|bundle| bundle.members)
        .map(|binding| binding.operation_id.as_str())
        .collect::<Vec<_>>();
    for required in [
        "ak.edge.applet.read.ping.v1",
        "ak.edge.applet.read.describe.v1",
        "ak.self.applet.install.command.preview.v1",
        "ak.self.applet.command.install.v1",
        "ak.self.applet.command.revoke.v1",
        "ak.self.applet.ghost.command.provision.v1",
    ] {
        assert!(
            advertised.contains(&required),
            "missing advertised applet operation {required}; advertised={advertised:#?}"
        );
    }
    let ping: arkret_models_integration::AppletPingOutcome = serde_json::from_value(
        expect_json(
            server.http().get(server.url("/_arkret/edge/applet/ping")),
            StatusCode::OK,
        )
        .await?,
    )?;
    assert_eq!(ping.service_id, server.service_id().clone());
    assert_eq!(ping.protocol_version, "1.0");
    let applet_describe: ServiceDescribe = serde_json::from_value(
        expect_json(
            server
                .http()
                .get(server.url("/_arkret/edge/applet/describe")),
            StatusCode::OK,
        )
        .await?,
    )?;
    applet_describe.validate()?;
    assert!(
        applet_describe
            .supports_operation(arkret_wire::ServiceOperationId::EdgeAppletReadDescribeV1)
    );

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
    let alice_did = actor_did_for_service_full_id(server.service_full_id(), "alice-agent")?;
    let alice = server
        .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let realm_id = alice.create_realm("Agent Surface Realm").await?;

    let describe = expect_json(
        server.http().get(server.url("/_arkret/describe")),
        StatusCode::OK,
    )
    .await?;
    let advertised = describe["supported_operation_bundles"]
        .as_array()
        .expect("supported_operation_bundles is an array")
        .iter()
        .filter_map(Value::as_str)
        .filter_map(arkret_wire::operation_bundle_descriptor)
        .flat_map(|bundle| bundle.members)
        .map(|binding| binding.operation_id.as_str())
        .collect::<Vec<_>>();
    for required in [
        "ak.self.agent.command.provision.v1",
        "ak.self.agent.read.list.v1",
        "ak.self.agent.resource.get.v1",
        "ak.self.agent.command.pause.v1",
        "ak.self.agent.command.resume.v1",
        "ak.self.agent.command.deactivate.v1",
        "ak.self.agent.command.renew_pairing.v1",
        "ak.self.agent.grant.command.attach.v1",
        "ak.self.agent.grant.resource.delete.v1",
        "ak.self.agent.sidecar.command.ensure.v1",
    ] {
        assert!(
            advertised.contains(&required),
            "missing advertised agent operation {required}; advertised={advertised:#?}"
        );
    }

    let empty_list = expect_json(alice.get("/_arkret/self/agents"), StatusCode::OK).await?;
    assert!(empty_list["agents"].as_array().unwrap().is_empty());

    let requested_operation = "ak.self.events.command.submit.v1";
    let controller_full_id = DidFullId::new(alice.actor.clone())?;
    let controller_authority = PrincipalAuthorityKey::new(
        project_full_id_to_core_id(&controller_full_id)?,
        arkret::DidCoreId::new(alice.service_id().to_owned())?,
    );
    let provision = AgentProvisionRequestBody::Prepare {
        operation_id: arkret::ProtocolOperationId::new(
            "ak:operation:extension-surface-agent-provision",
        )
        .expect("fixture operation id"),
        idempotency_key: arkret::IdempotencyKey::new("extension-surface-agent-provision")
            .expect("fixture idempotency key"),
        full_id: DidFullId::new("did:webvh:z6mkfixtureagent:agent.example")
            .expect("fixture managed Agent full id"),
        controller_authority,
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
