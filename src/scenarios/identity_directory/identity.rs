use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{CokretServer, expect_json};

pub async fn identity_surface_and_receipts_work() -> Result<()> {
    let server = CokretServer::spawn("identity-surface").await?;

    let describe = expect_json(
        server
            .http()
            .get(server.url("/_cokret/root/identity/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(describe["protocol_version"], "1.0");

    let resolved = expect_json(
        server
            .http()
            .post(server.url("/_cokret/root/identity/resolve"))
            .json(&json!({"did": "did:web:alice.example"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        resolved["did_document"]["document"]["id"],
        "did:web:alice.example"
    );

    let document = expect_json(
        server
            .http()
            .get(server.url("/_cokret/root/identity/document?did=did:web:alice.example")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        document["did_document"]["document"]["id"],
        "did:web:alice.example"
    );

    let log = expect_json(
        server
            .http()
            .get(server.url("/_cokret/root/identity/log?did=did:web:alice.example")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(log["has_more"], false);

    let submitted = expect_json(
        server
            .http()
            .post(server.url("/_cokret/root/identity/submit-did-operation"))
            .json(&json!({
                "did": "did:web:alice.example",
                "did_method": "did:web",
                "seq": 1,
                "operation": {
                    "type": "replace",
                    "state": {
                        "id": "did:web:alice.example",
                        "verificationMethod": [{
                            "id": "did:web:alice.example#key-1",
                            "type": "JsonWebKey2020",
                            "controller": "did:web:alice.example",
                            "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "dev"}
                        }],
                        "authentication": ["did:web:alice.example#key-1"],
                        "service": [{
                            "id": "#soland",
                            "type": "CokretPrincipalServer",
                            "serviceEndpoint": "https://alice.example"
                        }]
                    }
                },
                "proofs": [{
                    "kind": "detached_jws",
                    "alg": "EdDSA",
                    "verification_method": "did:web:alice.example#key-1",
                    "event_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "created_at": "2026-05-02T00:00:00Z",
                    "jws": "a..b"
                }]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(submitted["status"], "accepted");
    assert_eq!(submitted["seq"], 1);

    let resolved_after_submit = expect_json(
        server
            .http()
            .post(server.url("/_cokret/root/identity/resolve"))
            .json(&json!({"did": "did:web:alice.example"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        resolved_after_submit["key_log_head"],
        submitted["head_event_digest"]
    );
    assert_eq!(resolved_after_submit["seq"], 1);
    assert_eq!(
        resolved_after_submit["did_document"]["document"]["authentication"][0],
        "did:web:alice.example#key-1"
    );

    let log_after_submit = expect_json(
        server
            .http()
            .get(server.url("/_cokret/root/identity/log?did=did:web:alice.example")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(log_after_submit["events"].as_array().unwrap().len(), 1);
    assert_eq!(log_after_submit["events"][0]["seq"], 1);

    let receipts = expect_json(
        server
            .http()
            .get(server.url("/_cokret/root/identity/receipts?did=did:web:alice.example")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(receipts["threshold_met"], true);
    assert_eq!(
        receipts["receipts"][0]["head_event_digest"],
        submitted["head_event_digest"]
    );

    Ok(())
}
