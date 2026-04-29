mod support;

use anyhow::Result;
use contrix_sdk::{Operation, OperationId, SpaceId};
use reqwest::StatusCode;
use serde_json::json;
use serial_test::serial;

use support::{ServerxInstance, dev_login, expect_api_error, expect_json};

#[tokio::test]
#[serial]
async fn federation_endpoints_reject_invalid_input_shapes() -> Result<()> {
    let server = ServerxInstance::spawn("federation-invalid").await?;

    expect_api_error(
        server
            .http()
            .put(server.url("/api/v1/federation/transactions/federation-bad"))
            .header("content-type", "application/json")
            .body("{"),
        StatusCode::BAD_REQUEST,
        "bad_json",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/federation/push-operations"))
            .json(&json!({"operations": []})),
        StatusCode::BAD_REQUEST,
        "bad_json",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .get(server.url("/api/v1/federation/pull-operations")),
        StatusCode::BAD_REQUEST,
        "missing_param",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .get(server.url("/api/v1/federation/pull-operations?space_id=bad")),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .get(server.url("/api/v1/federation/space-members")),
        StatusCode::BAD_REQUEST,
        "missing_param",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/federation/verify-actor"))
            .header("content-type", "application/json")
            .body("{"),
        StatusCode::BAD_REQUEST,
        "bad_json",
    )
    .await?;

    let verified = expect_json(
        server
            .http()
            .post(server.url("/api/v1/federation/verify-actor"))
            .json(&json!({
                "actor_id": "did:web:remote.example",
                "signature": {"alg": "none"},
                "purpose": "federation-contract"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(verified["valid"], true);

    Ok(())
}

#[tokio::test]
#[serial]
async fn federation_push_pull_cursor_and_member_projection_work() -> Result<()> {
    let server = ServerxInstance::spawn("federation-pull").await?;
    let space_id = "cx:space:federation-contract";
    let op1 = federated_message_operation(
        "cx:operation:federation-contract-01",
        space_id,
        "did:web:remote.example",
        "federation one",
    )?;
    let op2 = federated_message_operation(
        "cx:operation:federation-contract-02",
        space_id,
        "did:web:remote.example",
        "federation two",
    )?;

    let first_push = expect_json(
        server
            .http()
            .post(server.url("/api/v1/federation/push-operations"))
            .json(&json!({
                "origin": "did:web:remote-server.example",
                "destination": "did:web:federation-pull.cotest.local",
                "space_id": space_id,
                "service_binding_ref": "cotest",
                "operations": [op1, op2]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(first_push["accepted"].as_array().unwrap().len(), 2);

    let duplicate_push = expect_json(
        server
            .http()
            .post(server.url("/api/v1/federation/push-operations"))
            .json(&json!({
                "origin": "did:web:remote-server.example",
                "destination": "did:web:federation-pull.cotest.local",
                "space_id": space_id,
                "service_binding_ref": "cotest",
                "operations": [federated_message_operation(
                    "cx:operation:federation-contract-01",
                    space_id,
                    "did:web:remote.example",
                    "federation one"
                )?]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        duplicate_push["accepted"][0],
        "cx:operation:federation-contract-01"
    );

    let pulled = expect_json(
        server.http().get(server.url(&format!(
            "/api/v1/federation/pull-operations?space_id={space_id}"
        ))),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(pulled["operations"].as_array().unwrap().len(), 2);

    let after_first = expect_json(
        server.http().get(server.url(&format!(
            "/api/v1/federation/pull-operations?space_id={space_id}&after_cursor=cx:operation:federation-contract-01"
        ))),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        after_first["operations"][0]["operation_id"],
        "cx:operation:federation-contract-02"
    );

    let members = expect_json(
        server.http().get(server.url(&format!(
            "/api/v1/federation/space-members?space_id={space_id}"
        ))),
        StatusCode::OK,
    )
    .await?;
    assert!(
        members["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member["principal_id"] == "did:web:alice.example")
    );
    assert!(
        members["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member["principal_id"] == "did:web:remote.example")
    );

    Ok(())
}

#[tokio::test]
#[serial]
async fn federation_remote_operations_project_to_sync_and_index() -> Result<()> {
    let server = ServerxInstance::spawn("federation-project").await?;
    let alice = dev_login(&server, "did:web:alice.example", "dev_alice").await?;
    let space_id = "cx:space:federation-project";
    let operation = federated_message_operation(
        "cx:operation:federation-project-01",
        space_id,
        "did:web:remote.example",
        "searchable federated payload",
    )?;

    let txn = expect_json(
        server
            .http()
            .put(server.url("/api/v1/federation/transactions/federation-project-txn"))
            .json(&json!({
                "origin": "did:web:remote-server.example",
                "destination": "did:web:federation-project.cotest.local",
                "service_binding_ref": "cotest",
                "operations": [operation]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(txn["accepted"][0], "cx:operation:federation-project-01");

    let sync = expect_json(
        server
            .http()
            .post(server.url("/api/v1/sync"))
            .bearer_auth(&alice)
            .json(&json!({})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        sync["spaces"][space_id]["timeline"]["events"][0]["content"]["body"],
        "searchable federated payload"
    );

    let search = expect_json(
        server
            .http()
            .post(server.url("/api/v1/index/search"))
            .bearer_auth(&alice)
            .json(&json!({
                "query": "searchable federated",
                "space_ids": [space_id],
                "entity_types": ["message"]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        search["results"][0]["event_id"],
        "cx:event:federation-project-01"
    );

    Ok(())
}

fn federated_message_operation(
    operation_id: &str,
    space_id: &str,
    sender: &str,
    body: &str,
) -> Result<Operation> {
    Ok(Operation::create(
        OperationId::new(operation_id.to_owned())?,
        SpaceId::new(space_id.to_owned())?,
        "message",
        json!({
            "event_id": operation_id.replace("cx:operation:", "cx:event:"),
            "sender": sender,
            "thread_id": "cx:thread:federation-contract",
            "space_title": "Federation Contract Space",
            "members": ["did:web:alice.example", sender],
            "content": {"body": body},
            "encrypted": false
        }),
    ))
}
