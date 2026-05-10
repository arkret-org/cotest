use anyhow::Result;
use contrix_core::{Operation, OperationId, SpaceId};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ContrixServer, dev_login, expect_api_error, expect_json};

pub async fn federation_endpoints_reject_invalid_input_shapes() -> Result<()> {
    let server = ContrixServer::spawn("federation-invalid").await?;

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

    let legacy_transaction_operation = Operation::create(
        OperationId::new("cx:operation:federation-txn-legacy-contract")?,
        SpaceId::new("cx:space:federation-invalid")?,
        "cx.message.create",
        json!({
            "event_id": "cx:event:federation-txn-legacy-contract",
            "sender": "did:web:remote.example",
            "flow_id": "cx:card:legacy-card",
            "body": "legacy typed id"
        }),
    );
    let legacy_transaction = expect_json(
        server
            .http()
            .put(server.url("/api/v1/federation/transactions/federation-legacy-contract"))
            .json(&json!({
                "origin": "did:web:remote.example",
                "destination": server.service_did(),
                "service_binding_ref": "did:web:remote.example#soland",
                "operations": [legacy_transaction_operation]
            })),
        StatusCode::OK,
    )
    .await?;
    assert!(
        legacy_transaction["accepted"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        legacy_transaction["rejected"][0]["operation_id"],
        "cx:operation:federation-txn-legacy-contract"
    );
    assert_eq!(
        legacy_transaction["rejected"][0]["reason"],
        "invalid_semantics"
    );
    assert_eq!(
        legacy_transaction["rejected"][0]["message"],
        "removed legacy subject/room/card contract is forbidden on the active v1 wire"
    );

    Ok(())
}

pub async fn federation_replay_snapshot_and_redaction_contracts_work() -> Result<()> {
    let server = ContrixServer::spawn("federation-replay").await?;
    let operation = Operation::create(
        OperationId::new("cx:operation:federation-replay")?,
        SpaceId::new("cx:space:federation")?,
        "cx.message.create",
        json!({
            "event_id": "cx:event:federation-replay",
            "sender": "did:web:remote.example",
            "thread_id": "cx:thread:federation",
            "body": "from federation"
        }),
    );

    let first_push = expect_json(
        server
            .http()
            .post(server.url("/api/v1/federation/push-operations"))
            .json(&json!({
                "origin": "did:web:remote.example",
                "destination": server.service_did(),
                "space_id": "cx:space:federation",
                "service_binding_ref": "did:web:remote.example#soland",
                "operations": [operation.clone()]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(first_push["accepted"][0], "cx:operation:federation-replay");
    assert!(first_push["rejected"].as_array().unwrap().is_empty());

    let pulled = expect_json(
        server
            .http()
            .get(server.url("/api/v1/federation/pull-operations?space_id=cx:space:federation")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        pulled["operations"][0]["operation_id"],
        "cx:operation:federation-replay"
    );

    let bootstrap = expect_json(
        server.http().get(server.url(
            "/api/v1/federation/pull-operations?space_id=cx:space:federation&snapshot_bootstrap=true",
        )),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        bootstrap["snapshot_bootstrap"]["manifest"]["space_id"],
        "cx:space:federation"
    );
    assert!(
        bootstrap["snapshot_bootstrap"]["state_hash"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );

    let replay = expect_json(
        server
            .http()
            .post(server.url("/api/v1/federation/push-operations"))
            .json(&json!({
                "origin": "did:web:remote.example",
                "destination": server.service_did(),
                "space_id": "cx:space:federation",
                "service_binding_ref": "did:web:remote.example#soland",
                "operations": [operation]
            })),
        StatusCode::OK,
    )
    .await?;
    assert!(replay["accepted"].as_array().unwrap().is_empty());
    assert_eq!(
        replay["rejected"][0]["operation_id"],
        "cx:operation:federation-replay"
    );
    assert_eq!(replay["rejected"][0]["reason"], "replay");

    let invalid_operation = Operation::create(
        OperationId::new("cx:operation:federation-invalid-envelope")?,
        SpaceId::new("cx:space:federation")?,
        "cx.message.create",
        json!({
            "event_id": "cx:event:federation-invalid-envelope",
            "sender": "did:web:remote.example",
            "encrypted": true,
            "content": {"ciphertext": "missing-envelope-fields"}
        }),
    );
    let invalid_push = expect_json(
        server
            .http()
            .post(server.url("/api/v1/federation/push-operations"))
            .json(&json!({
                "origin": "did:web:remote.example",
                "destination": server.service_did(),
                "space_id": "cx:space:federation",
                "service_binding_ref": "did:web:remote.example#soland",
                "operations": [invalid_operation]
            })),
        StatusCode::OK,
    )
    .await?;
    assert!(invalid_push["accepted"].as_array().unwrap().is_empty());
    assert_eq!(invalid_push["rejected"][0]["reason"], "invalid_semantics");

    let legacy_operation = Operation::create(
        OperationId::new("cx:operation:federation-legacy-contract")?,
        SpaceId::new("cx:space:federation")?,
        "cx.message.create",
        json!({
            "event_id": "cx:event:federation-legacy-contract",
            "sender": "did:web:remote.example",
            "room_id": "!legacy:example.com",
            "body": "legacy contract field"
        }),
    );
    let legacy_push = expect_json(
        server
            .http()
            .post(server.url("/api/v1/federation/push-operations"))
            .json(&json!({
                "origin": "did:web:remote.example",
                "destination": server.service_did(),
                "space_id": "cx:space:federation",
                "service_binding_ref": "did:web:remote.example#soland",
                "operations": [legacy_operation]
            })),
        StatusCode::OK,
    )
    .await?;
    assert!(legacy_push["accepted"].as_array().unwrap().is_empty());
    assert_eq!(
        legacy_push["rejected"][0]["operation_id"],
        "cx:operation:federation-legacy-contract"
    );
    assert_eq!(legacy_push["rejected"][0]["reason"], "invalid_semantics");
    assert_eq!(
        legacy_push["rejected"][0]["message"],
        "removed legacy subject/room/card contract is forbidden on the active v1 wire"
    );

    let redaction = Operation::create(
        OperationId::new("cx:operation:federation-redaction")?,
        SpaceId::new("cx:space:federation")?,
        "cx.message.redact",
        json!({
            "event_id": "cx:event:federation-redaction",
            "target_event_id": "cx:event:federation-replay"
        }),
    );
    let redaction_push = expect_json(
        server
            .http()
            .post(server.url("/api/v1/federation/push-operations"))
            .json(&json!({
                "origin": "did:web:remote.example",
                "destination": server.service_did(),
                "space_id": "cx:space:federation",
                "service_binding_ref": "did:web:remote.example#soland",
                "operations": [redaction]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        redaction_push["accepted"][0],
        "cx:operation:federation-redaction"
    );

    let redacted_pull = expect_json(
        server
            .http()
            .get(server.url("/api/v1/federation/pull-operations?space_id=cx:space:federation")),
        StatusCode::OK,
    )
    .await?;
    assert!(redacted_pull["operations"].as_array().unwrap().is_empty());

    Ok(())
}

pub async fn federation_remote_operations_project_to_sync_and_index() -> Result<()> {
    let server = ContrixServer::spawn("federation-project").await?;
    let alice = dev_login(&server, "did:web:alice.example", "dev_alice").await?;
    let space_id = "cx:space:federation-project";
    let operation = Operation::create(
        OperationId::new("cx:operation:federation-project-01")?,
        SpaceId::new(space_id.to_owned())?,
        "cx.message.create",
        json!({
            "event_id": "cx:event:federation-project-01",
            "sender": "did:web:remote.example",
            "thread_id": "cx:thread:federation-contract",
            "space_title": "Federation Contract Space",
            "members": ["did:web:alice.example", "did:web:remote.example"],
            "content": {"body": "searchable federated payload"},
            "encrypted": false,
            "plaintext_visible_services": [server.service_did()]
        }),
    );

    let txn = expect_json(
        server
            .http()
            .put(server.url("/api/v1/federation/transactions/federation-project-txn"))
            .json(&json!({
                "origin": "did:web:remote-server.example",
                "destination": server.service_did(),
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
