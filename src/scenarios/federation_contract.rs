use anyhow::Result;
use contrix_core::{Operation, OperationId, RealmId};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    ContrixServer, dev_login, expect_account_subscribe_delta, expect_api_error, expect_json,
};

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

    Ok(())
}

pub async fn federation_replay_snapshot_and_redaction_contracts_work() -> Result<()> {
    let server = ContrixServer::spawn("federation-replay").await?;
    let operation = Operation::create(
        OperationId::new("cx:operation:federation-replay")?,
        RealmId::new("cx:realm:federation")?,
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
                "realm_id": "cx:realm:federation",
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
            .get(server.url("/api/v1/federation/pull-operations?space_id=cx:realm:federation")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        pulled["operations"][0]["operation_id"],
        "cx:operation:federation-replay"
    );

    let bootstrap = expect_json(
        server.http().get(server.url(
            "/api/v1/federation/pull-operations?space_id=cx:realm:federation&snapshot_bootstrap=true",
        )),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        bootstrap["snapshot_bootstrap"]["manifest"]["realm_id"],
        "cx:realm:federation"
    );
    assert!(
        bootstrap["snapshot_bootstrap"]["state_digest"]
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
                "realm_id": "cx:realm:federation",
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
        RealmId::new("cx:realm:federation")?,
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
                "realm_id": "cx:realm:federation",
                "service_binding_ref": "did:web:remote.example#soland",
                "operations": [invalid_operation]
            })),
        StatusCode::OK,
    )
    .await?;
    assert!(invalid_push["accepted"].as_array().unwrap().is_empty());
    assert_eq!(invalid_push["rejected"][0]["reason"], "invalid_semantics");

    let redaction = Operation::create(
        OperationId::new("cx:operation:federation-redaction")?,
        RealmId::new("cx:realm:federation")?,
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
                "realm_id": "cx:realm:federation",
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
            .get(server.url("/api/v1/federation/pull-operations?space_id=cx:realm:federation")),
        StatusCode::OK,
    )
    .await?;
    assert!(redacted_pull["operations"].as_array().unwrap().is_empty());

    Ok(())
}

pub async fn federation_remote_operations_project_to_sync_and_index() -> Result<()> {
    let server = ContrixServer::spawn("federation-project").await?;
    let alice = dev_login(&server, "did:web:alice.example", "dev_alice").await?;
    let realm_id = "cx:realm:federation-project";
    let operation = Operation::create(
        OperationId::new("cx:operation:federation-project-01")?,
        RealmId::new(realm_id.to_owned())?,
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

    let sync = expect_account_subscribe_delta(
        server
            .http()
            .get(server.url("/api/v1/account/subscribe?catchup=true"))
            .bearer_auth(&alice),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        sync["spaces"][realm_id]["timeline"]["events"][0]["content"]["body"],
        "searchable federated payload"
    );

    Ok(())
}
