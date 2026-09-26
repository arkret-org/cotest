use anyhow::Result;
use arkret::{
    AgentKeyScope, AgentKeyScopeResource, AgentKeyScopeResourceKind, AgentProvisionRequestBody, Did,
};
use arkret_models_collaboration::agent_operations::{
    AgentProvisionPreparePhase, AgentProvisionPrepareRequestBody,
};
use arkret_models_collaboration::device_pairing::{
    DevicePairingNonce, DevicePairingResolveRequestBody, DevicePairingStageOutcome,
    DevicePairingStageRequestBody, DevicePairingState, DevicePairingStatusOutcome,
    DevicePairingStatusRequestBody,
};
use arkret_models_collaboration::governance::agent_artifacts::PublicKey;
use arkret_models_discovery::ServiceDescribe;
use arkret_wire::{Base64UrlString, NonEmptyString};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{NonProtocolTestBody, TestServerGroup, expect_api_error, expect_json};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

pub async fn applet_lifecycle_surfaces_are_advertised_when_routes_exist() -> Result<()> {
    let group = TestServerGroup::single("extension-surface-applet").await?;
    let server = group.server(0);
    let alice_did = actor_did_for_service_did(server.service_did(), "alice-applet")?;
    let alice = server
        .standard_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
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
    let alice_did = actor_did_for_service_did(server.service_did(), "alice-agent")?;
    let alice = server
        .standard_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
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
        "ak.self.agent.sidecar.command.ensure.v1",
    ] {
        assert!(
            advertised.contains(&required),
            "missing advertised agent operation {required}; advertised={advertised:#?}"
        );
    }

    let empty_list: arkret_models_collaboration::agent_operations::AgentList =
        serde_json::from_value(
            expect_json(alice.get("/_arkret/self/agents"), StatusCode::OK).await?,
        )?;
    assert!(empty_list.agents.is_empty() && !empty_list.has_more);

    let requested_operation = "ak.self.events.command.submit.v1";
    let provision = AgentProvisionRequestBody::Prepare(AgentProvisionPrepareRequestBody {
        phase: AgentProvisionPreparePhase::Prepare,
        operation_id: arkret::ProtocolOperationId::new(
            "ak:operation:extension-surface-agent-provision",
        )
        .expect("fixture operation id"),
        idempotency_key: arkret::IdempotencyKey::new("extension-surface-agent-provision")
            .expect("fixture idempotency key"),
        did: Did::new("did:webvh:z6mkfixtureagent:agent.example").expect("fixture Agent DID"),
        controller_station_id: arkret::DidCoreId::new(alice.service_id().to_owned())?,
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
    });
    let provision_error = expect_api_error(
        alice.post("/_arkret/self/agents").json(&provision),
        StatusCode::CONFLICT,
        "failed_precondition",
    )
    .await?;
    assert_eq!(
        provision_error
            .extensions
            .get("reason_code")
            .and_then(Value::as_str),
        Some("agent_provision_scope_migration_required")
    );

    expect_api_error(
        alice
            .post(&format!("/_arkret/self/realms/{realm_id}/agents"))
            .json(&NonProtocolTestBody::new(json!({
                "agent_id": "ak:did_core:web:agent.example",
                "display_name": "Planner"
            }))),
        StatusCode::NOT_FOUND,
        "unrecognized_endpoint",
    )
    .await?;

    Ok(())
}

pub async fn device_pairing_handoff_bundle_selects_all_canonical_routes() -> Result<()> {
    let group = TestServerGroup::single("extension-surface-device-pairing").await?;
    let server = group.server(0);
    let describe = expect_json(
        server.http().get(server.url("/_arkret/describe")),
        StatusCode::OK,
    )
    .await?;
    assert!(
        describe["supported_operation_bundles"]
            .as_array()
            .expect("supported_operation_bundles is an array")
            .iter()
            .any(|bundle| {
                bundle.as_str() == Some("ak.operation_bundle.station.device_pairing_handoff.v1")
            }),
        "Station must advertise the registered device-pairing handoff bundle"
    );

    let stage: DevicePairingStageOutcome = serde_json::from_value(
        expect_json(
            server
                .http()
                .post(server.url("/_arkret/open/device-pairing/requests"))
                .json(&DevicePairingStageRequestBody {
                    new_device_pubkey: PublicKey {
                        kty: NonEmptyString::new("OKP").map_err(anyhow::Error::msg)?,
                        kid: NonEmptyString::new("ak:device:01994100-0000-7000-8000-0000000000d1")
                            .map_err(anyhow::Error::msg)?,
                        algorithm: NonEmptyString::new("Ed25519").map_err(anyhow::Error::msg)?,
                        key: Base64UrlString::new(URL_SAFE_NO_PAD.encode([7_u8; 32]))
                            .map_err(anyhow::Error::msg)?,
                        key_digest: None,
                    },
                    client_nonce: DevicePairingNonce::new(URL_SAFE_NO_PAD.encode([9_u8; 16]))
                        .map_err(anyhow::Error::msg)?,
                    display_name: None,
                    device_metadata: None,
                }),
            StatusCode::OK,
        )
        .await?,
    )?;
    let request_id = stage.device_pairing_request_id.clone();
    let pairing_code = stage.pairing_code.clone();
    let token = URL_SAFE_NO_PAD.encode(arkret_canonical::canonical_json_bytes(&json!({
        "c": pairing_code.as_str(),
        "r": request_id.as_str()
    }))?);

    // `device-lifecycle.md` 2.1.1: stage is account-less and lands in `staged`.
    // Resolve, code claim and `pair_device` all require `ready_for_claim`, so a
    // record that has not been finalized is indistinguishable from one that
    // never existed. Anything that resolves here would mean the anonymous stage
    // call alone produced a claimable pairing.
    expect_api_error(
        server
            .http()
            .post(server.url("/_arkret/open/device-pairing/resolve"))
            .json(&DevicePairingResolveRequestBody {
                pairing_token: NonEmptyString::new(token).map_err(anyhow::Error::msg)?,
            }),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    // `status` is the one surface that keeps answering for a staged record: its
    // query credential is the request id plus the pairing code, which only the
    // candidate device that minted them holds.
    let status: DevicePairingStatusOutcome = serde_json::from_value(
        expect_json(
            server
                .http()
                .post(server.url("/_arkret/open/device-pairing/requests/status"))
                .json(&DevicePairingStatusRequestBody {
                    device_pairing_request_id: request_id,
                    pairing_code,
                }),
            StatusCode::OK,
        )
        .await?,
    )?;
    assert_eq!(status.state, DevicePairingState::Staged);
    assert!(
        status.device_id.is_none() && status.authorized_event_ref.is_none(),
        "a staged record exposes no device identity and no authorization"
    );
    Ok(())
}
