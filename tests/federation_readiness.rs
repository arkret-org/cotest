mod support;

use anyhow::Result;
use contrix_sdk::{Client, Operation, OperationId, SpaceId};
use reqwest::StatusCode;
use serde_json::json;
use serial_test::serial;

use support::{ServerxInstance, expect_json, expect_status, register_account};

#[tokio::test]
#[serial]
async fn two_serverx_instances_are_isolated_and_federation_ready() -> Result<()> {
    let server_a = ServerxInstance::spawn("federation-ready-a").await?;
    let server_b = ServerxInstance::spawn("federation-ready-b").await?;

    let client_a = Client::builder(server_a.base_url())
        .allow_insecure_localhost()
        .build()?;
    let client_b = Client::builder(server_b.base_url())
        .allow_insecure_localhost()
        .build()?;

    let describe_a = client_a.describe().await?;
    let describe_b = client_b.describe().await?;
    assert_eq!(describe_a.service_type, "principal_server");
    assert_eq!(describe_b.service_type, "principal_server");
    for required in [
        "cx.federation.transaction",
        "cx.federation.push_operations",
        "cx.federation.pull_operations",
        "cx.federation.space_members",
        "cx.federation.verify_actor",
    ] {
        assert!(
            describe_a
                .supported_operations
                .iter()
                .any(|op| op == required),
            "missing supported operation {required}"
        );
    }

    let _alice_a = register_account(
        &server_a,
        "did:web:alice-a.example",
        "@alice-a",
        "dev_alice_a",
    )
    .await?;
    let bob_b = register_account(&server_b, "did:web:bob-b.example", "@bob-b", "dev_bob_b").await?;

    let search_a = expect_json(
        server_a
            .http()
            .get(server_a.url("/api/v1/directory/search-users?q=bob-b")),
        StatusCode::OK,
    )
    .await?;
    assert!(search_a["results"].as_array().unwrap().is_empty());

    let search_b_as_bob = expect_json(
        server_b
            .http()
            .get(server_b.url("/api/v1/directory/search-users?q=bob-b"))
            .bearer_auth(&bob_b),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        search_b_as_bob["results"][0]["did"],
        "did:web:bob-b.example"
    );

    let operation = Operation::create(
        OperationId::new("cx:operation:federation-ready-01")?,
        SpaceId::new("cx:space:federation-ready")?,
        "message",
        json!({
            "sender": "did:web:bob-b.example",
            "members": ["did:web:alice-a.example", "did:web:bob-b.example"],
            "body": "hello federation readiness"
        }),
    );

    let pushed = expect_json(
        server_a
            .http()
            .post(server_a.url("/api/v1/federation/push-operations"))
            .json(&json!({
                "origin": "did:web:federation-ready-b.cotest.local",
                "destination": "did:web:federation-ready-a.cotest.local",
                "space_id": "cx:space:federation-ready",
                "service_binding_ref": "cotest",
                "operations": [operation]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(pushed["accepted"][0], "cx:operation:federation-ready-01");

    let pulled = expect_json(
        server_a.http().get(
            server_a.url("/api/v1/federation/pull-operations?space_id=cx:space:federation-ready"),
        ),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        pulled["operations"][0]["operation_id"],
        "cx:operation:federation-ready-01"
    );

    expect_status(
        server_a
            .http()
            .post(server_a.url("/api/v1/federation/verify-actor"))
            .json(&json!({
                "actor_id": "did:web:bob-b.example",
                "signature": {"alg": "none"},
                "purpose": "federation-readiness"
            })),
        StatusCode::OK,
    )
    .await?;

    Ok(())
}
