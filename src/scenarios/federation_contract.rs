use anyhow::{Context, Result, anyhow};
use contrix_core::{Operation, OperationId, RealmId, canonical::canonical_sha256};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{ContrixServer, dev_login, expect_api_error, expect_json, expect_response};

fn with_round4_federation_headers(
    builder: reqwest::RequestBuilder,
    server: &ContrixServer,
    body: &Value,
) -> Result<reqwest::RequestBuilder> {
    let request_canonical_digest = canonical_sha256(body)?;
    let destination_trust_domain = format!(
        "cx:trust_domain:{}",
        server.service_did().trim_start_matches("did:web:")
    );
    Ok(builder
        .header("Source-Trust-Domain", "cx:trust_domain:peer.example")
        .header("Destination-Trust-Domain", destination_trust_domain)
        .header("Request-Canonical-Digest", request_canonical_digest))
}

fn account_delta_from_text(ndjson: &str) -> Result<Value> {
    for line in ndjson
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let frame: Value = serde_json::from_str(line)
            .with_context(|| format!("invalid subscribe frame: {line}"))?;
        if frame.get("kind").and_then(Value::as_str) == Some("delta") {
            return Ok(frame.get("payload").cloned().unwrap_or(frame));
        }
    }
    Err(anyhow!(
        "account subscribe response did not include a delta frame"
    ))
}

pub async fn federation_endpoints_reject_invalid_input_shapes() -> Result<()> {
    let server = ContrixServer::spawn("federation-invalid").await?;

    expect_api_error(
        server
            .http()
            .put(server.url("/api/v1/federation/transactions/federation-bad"))
            .header("content-type", "application/json")
            .body("{"),
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/federation/push-operations"))
            .json(&json!({"operations": []})),
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .get(server.url("/api/v1/federation/pull-operations")),
        StatusCode::BAD_REQUEST,
        "bad_request",
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
        "bad_request",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/federation/verify-actor"))
            .header("content-type", "application/json")
            .body("{"),
        StatusCode::BAD_REQUEST,
        "bad_request",
    )
    .await?;

    let verify_actor_body = json!({
        "actor_id": "did:web:remote.example",
        "signature": {"alg": "none"},
        "purpose": "federation-contract"
    });
    let verified = expect_json(
        with_round4_federation_headers(
            server
                .http()
                .post(server.url("/api/v1/federation/verify-actor"))
                .json(&verify_actor_body),
            &server,
            &verify_actor_body,
        )?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(verified["valid"], true);

    Ok(())
}

pub async fn federation_replay_snapshot_and_redaction_contracts_work() -> Result<()> {
    let server = ContrixServer::spawn("federation-replay").await?;
    let realm_id = "cx:realm:0196419b-0000-7000-8000-00000000fed0";
    let space_id = "cx:space:0196419b-0000-7000-8000-00000000fed0";
    let replay_operation_id = "cx:operation:0196419b-0000-7000-8000-00000000f001";
    let replay_event_id = "cx:event:0196419b-0000-7000-8000-00000000f101";
    let invalid_operation_id = "cx:operation:0196419b-0000-7000-8000-00000000f002";
    let invalid_event_id = "cx:event:0196419b-0000-7000-8000-00000000f102";
    let redaction_operation_id = "cx:operation:0196419b-0000-7000-8000-00000000f003";
    let redaction_event_id = "cx:event:0196419b-0000-7000-8000-00000000f103";

    let operation = Operation::create(
        OperationId::new(replay_operation_id)?,
        RealmId::new(realm_id)?,
        "cx.message.create",
        json!({
            "event_id": replay_event_id,
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
                "space_id": space_id,
                "service_binding_ref": "did:web:remote.example#soland",
                "operations": [operation.clone()]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(first_push["accepted"][0], replay_operation_id);
    assert!(first_push["rejected"].as_array().unwrap().is_empty());

    let pulled = expect_json(
        server.http().get(server.url(&format!(
            "/api/v1/federation/pull-operations?space_id={space_id}"
        ))),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(pulled["operations"][0]["operation_id"], replay_operation_id);

    let bootstrap = expect_json(
        server.http().get(server.url(&format!(
            "/api/v1/federation/pull-operations?space_id={space_id}&snapshot_bootstrap=true"
        ))),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        bootstrap["snapshot_bootstrap"]["manifest"]["space_id"],
        space_id
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
                "space_id": space_id,
                "service_binding_ref": "did:web:remote.example#soland",
                "operations": [operation]
            })),
        StatusCode::OK,
    )
    .await?;
    assert!(replay["accepted"].as_array().unwrap().is_empty());
    assert_eq!(replay["rejected"][0]["operation_id"], replay_operation_id);
    assert_eq!(replay["rejected"][0]["reason"], "replay");

    let invalid_operation = Operation::create(
        OperationId::new(invalid_operation_id)?,
        RealmId::new(realm_id)?,
        "cx.message.create",
        json!({
            "event_id": invalid_event_id,
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
                "space_id": space_id,
                "service_binding_ref": "did:web:remote.example#soland",
                "operations": [invalid_operation]
            })),
        StatusCode::OK,
    )
    .await?;
    assert!(invalid_push["accepted"].as_array().unwrap().is_empty());
    assert_eq!(invalid_push["rejected"][0]["reason"], "invalid_semantics");

    let redaction = Operation::create(
        OperationId::new(redaction_operation_id)?,
        RealmId::new(realm_id)?,
        "cx.message.redact",
        json!({
            "event_id": redaction_event_id,
            "target_event_id": replay_event_id
        }),
    );
    let redaction_push = expect_json(
        server
            .http()
            .post(server.url("/api/v1/federation/push-operations"))
            .json(&json!({
                "origin": "did:web:remote.example",
                "destination": server.service_did(),
                "space_id": space_id,
                "service_binding_ref": "did:web:remote.example#soland",
                "operations": [redaction]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(redaction_push["accepted"][0], redaction_operation_id);

    let redacted_pull = expect_json(
        server.http().get(server.url(&format!(
            "/api/v1/federation/pull-operations?space_id={space_id}"
        ))),
        StatusCode::OK,
    )
    .await?;
    assert!(redacted_pull["operations"].as_array().unwrap().is_empty());

    Ok(())
}

pub async fn federation_remote_operations_project_to_sync_and_index() -> Result<()> {
    let server = ContrixServer::spawn("federation-project").await?;
    let alice = dev_login(&server, "did:web:alice.example", "dev_alice").await?;
    let realm_id = "cx:realm:0196419b-0000-7000-8000-00000000fe20";
    let operation_id = "cx:operation:0196419b-0000-7000-8000-00000000fe21";
    let event_id = "cx:event:0196419b-0000-7000-8000-00000000fe22";
    let operation = Operation::create(
        OperationId::new(operation_id)?,
        RealmId::new(realm_id.to_owned())?,
        "cx.message.create",
        json!({
            "event_id": event_id,
            "sender": "did:web:alice.example",
            "thread_id": "cx:thread:federation-contract",
            "space_title": "Federation Contract Space",
            "discoverability": "public",
            "history_visibility": "world_readable",
            "members": ["did:web:alice.example", "did:web:remote.example"],
            "content": {
                "kind": "cx.content.text",
                "body": "searchable federated payload",
                "format": "plain"
            },
            "actor_id": "did:web:alice.example",
            "membership": "join",
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
    if txn["accepted"][0] != operation_id {
        return Err(anyhow!(
            "federation project message operation was not accepted: {}",
            serde_json::to_string_pretty(&txn)?
        ));
    }

    let sync_response = expect_response(
        server
            .http()
            .get(server.url("/api/v1/account/subscribe?catchup=true"))
            .bearer_auth(&alice)
            .header("accept", "application/x-ndjson"),
        StatusCode::OK,
    )
    .await?;
    let sync = account_delta_from_text(&sync_response.text())?;
    let synced_body = &sync["realms"][realm_id]["timeline"]["events"][0]["content"]["body"];
    if synced_body != "searchable federated payload" {
        return Err(anyhow!(
            "federated realm sync did not expose projected message body: {}",
            serde_json::to_string_pretty(&sync["realms"][realm_id])?
        ));
    }

    Ok(())
}
