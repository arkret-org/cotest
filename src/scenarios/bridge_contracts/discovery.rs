use anyhow::Result;
use reqwest::StatusCode;

use crate::harness::{ArkretServer, expect_json};

pub async fn principal_bridge_contracts_are_discoverable() -> Result<()> {
    let server = ArkretServer::spawn("bridge-contracts").await?;

    let describe = expect_json(
        server.http().get(server.url("/_arkret/describe")),
        StatusCode::OK,
    )
    .await?;
    let oidc = describe["auth_metadata"]["methods"]
        .as_array()
        .and_then(|methods| methods.iter().find(|method| method["method"] == "oidc"))
        .expect("configured Station must advertise OIDC");
    assert_eq!(
        oidc["grant_exchange"],
        serde_json::json!({
            "kind": "account_handoff"
        })
    );
    assert!(oidc.get("proof_kind").is_none());

    let integration = expect_json(
        server
            .http()
            .get(server.url("/_soland/self/integration/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        integration["contract"],
        "arkret.rest.integration_manifest.v1"
    );
    assert_eq!(integration["service"], "soland");
    assert_eq!(integration["service_kind"], "station");
    assert_eq!(
        integration["dependencies"][0]["required_contract"],
        // The private integration manifest discovers the configured peer
        // through its canonical service description operation.
        arkret_wire::ServiceOperationId::SERVER_READ_DESCRIBE_V1
    );
    assert_eq!(
        integration["surfaces"][0]["path"],
        "/_soland/gate/auth/bridge/describe"
    );
    assert!(integration["surfaces"].as_array().is_some_and(|surfaces| {
        surfaces.iter().any(|surface| {
            surface["name"] == "push_register_device"
                && surface["path"] == "/_arkret/edge/push/register-device"
        })
    }));
    assert!(integration["surfaces"].as_array().is_some_and(|surfaces| {
        surfaces.iter().any(|surface| {
            surface["name"] == "agent_runtime_attestation"
                && surface["path"] == "/_arkret/gate/account/agent-key-pair"
        })
    }));
    assert_eq!(
        integration["examples"]["compose_strand"]["step_2"]["path"],
        "protected route"
    );
    assert_eq!(
        integration["examples"]["compose_strand"]["step_3"]["path"],
        "/_arkret/edge/push/register-device"
    );

    let auth_bridge = expect_json(
        server
            .http()
            .get(server.url("/_soland/gate/auth/bridge/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(auth_bridge["contract"], "arkret.rest.principal_bridge.v1");
    assert_eq!(
        auth_bridge["auth"]["session_grant_issuance_path"],
        "/_arkret/gate/account/session-grants"
    );
    assert_eq!(
        auth_bridge["auth"]["session_grant_presentation"],
        "Authorization: DPoP <ak.session.grant> with a DPoP proof on /_arkret/self/*"
    );
    assert_eq!(
        auth_bridge["push"]["register_device_path"],
        "/_arkret/edge/push/register-device"
    );
    assert_eq!(
        auth_bridge["examples"]["session_grant_issue_request"]["principal_id"],
        "ak:did_core:web:alice.example"
    );
    assert_eq!(
        auth_bridge["examples"]["register_device_request"]["platform"],
        "web"
    );

    Ok(())
}
