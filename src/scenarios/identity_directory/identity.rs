use anyhow::{Context, Result};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ArkretServer, expect_json};
use crate::scenarios::identity_test_support::prepare_actor_inception_for_service;

pub async fn identity_surface_and_receipts_work() -> Result<()> {
    let server = ArkretServer::spawn("identity-surface").await?;

    let describe = expect_json(
        server
            .http()
            .get(server.url("/_arkret/root/identity/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(describe["protocol_version"], "1.0");

    let resolved = expect_json(
        server
            .http()
            .post(server.url("/_arkret/root/identity/resolve"))
            .json(&serde_json::from_value::<
                arkret_models_identity::identity::IdentityResolveRequestBody,
            >(json!({"did": "did:web:alice.example"}))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(resolved["did_document"]["id"], "did:web:alice.example");

    let document = expect_json(
        server
            .http()
            .get(server.url("/_arkret/root/identity/document?did=did:web:alice.example")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(document["did_document"]["id"], "did:web:alice.example");

    let log = expect_json(
        server
            .http()
            .get(server.url("/_arkret/root/identity/log?did=did:web:alice.example")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(log["did"], "did:web:alice.example");
    assert_eq!(log["method"], "did:web");
    assert_eq!(log["native_history"], false);
    assert!(log["entries"].as_array().is_some_and(Vec::is_empty));
    assert_eq!(log["has_more"], false);

    let prepared = prepare_actor_inception_for_service(server.service_id(), "identity-alice")?;
    let actor_id = prepared.did.clone();
    let submitted = expect_json(
        server
            .http()
            .post(server.url("/_arkret/root/identity/submit-did-operation"))
            .json(&prepared.submit_body),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(submitted["status"], "accepted");
    assert_eq!(submitted["did"], actor_id);
    assert_eq!(submitted["seq"], 1);

    let resolved_after_submit = expect_json(
        server
            .http()
            .post(server.url("/_arkret/root/identity/resolve"))
            .json(&serde_json::from_value::<
                arkret_models_identity::identity::IdentityResolveRequestBody,
            >(json!({"did": actor_id}))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        resolved_after_submit["key_log_head"],
        submitted["head_event_digest"]
    );
    assert_eq!(resolved_after_submit["seq"], 1);
    assert_eq!(resolved_after_submit["did_document"]["id"], actor_id);

    let log_after_submit = expect_json(
        server
            .http()
            .get(server.url("/_arkret/root/identity/log"))
            .query(&[("did", actor_id.as_str())]),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(log_after_submit["did"], actor_id);
    assert_eq!(log_after_submit["method"], "did:webvh");
    assert_eq!(log_after_submit["native_history"], true);
    assert_eq!(log_after_submit["entries"].as_array().unwrap().len(), 1);
    assert_eq!(log_after_submit["entries"][0], prepared.log_entry);

    let submitted_head = submitted["head_event_digest"]
        .as_str()
        .context("accepted DID operation response is missing head_event_digest")?;
    let receipts = expect_json(
        server
            .http()
            .get(server.url("/_arkret/root/identity/receipts"))
            .query(&[("did", actor_id.as_str()), ("head", submitted_head)]),
        StatusCode::OK,
    )
    .await?;
    assert!(
        receipts.get("threshold_met").is_none(),
        "registry that cannot evaluate witness policy must omit threshold_met: {receipts}"
    );
    assert!(
        receipts["receipts"].as_array().is_some_and(Vec::is_empty),
        "registry without a witness must return an empty receipt set: {receipts}"
    );

    Ok(())
}
