mod support;

use anyhow::Result;
use contrix_sdk::Client;
use reqwest::StatusCode;
use serial_test::serial;

use support::{ServerxInstance, expect_json, expect_status};

#[tokio::test]
#[serial]
async fn serverx_process_exposes_core_service_surface() -> Result<()> {
    let server = ServerxInstance::spawn("service-surface").await?;

    let health = expect_json(server.http().get(server.url("/health")), StatusCode::OK).await?;
    assert_eq!(health["ok"], true);
    assert_eq!(health["service"], "serverx");

    let sdk = Client::builder(server.base_url())
        .allow_insecure_localhost()
        .build()?;
    let description = sdk.describe().await?;
    assert_eq!(description.protocol_version, "1.0");
    assert_eq!(description.service_type, "principal_server");

    for required in [
        "cx.repo.submit_commit",
        "cx.sync.client_sync",
        "cx.directory.search_spaces",
        "cx.index.query",
        "cx.authz.check",
        "cx.policy.check",
        "cx.moderation.report",
    ] {
        assert!(
            description
                .supported_operations
                .iter()
                .any(|op| op == required),
            "missing supported operation {required}"
        );
    }

    let sync = expect_json(
        server.http().get(server.url("/api/v1/sync/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(sync["service_did"], "did:web:serverx.local");

    let directory = expect_json(
        server.http().get(server.url("/api/v1/directory/describe")),
        StatusCode::OK,
    )
    .await?;
    assert!(
        directory["resource_types"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );

    let index = expect_json(
        server.http().get(server.url("/api/v1/index/describe")),
        StatusCode::OK,
    )
    .await?;
    assert!(
        index["query_features"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );

    expect_status(
        server.http().post(server.url("/api/v1/server/describe")),
        StatusCode::METHOD_NOT_ALLOWED,
    )
    .await?;

    Ok(())
}
