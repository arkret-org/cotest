use anyhow::Result;
use reqwest::StatusCode;

use crate::harness::{ContrixServer, expect_json, expect_status};

pub async fn server_exposes_core_service_surface() -> Result<()> {
    let server = ContrixServer::spawn("service-surface").await?;

    let health = expect_json(server.http().get(server.url("/health")), StatusCode::OK).await?;
    assert_eq!(health["ok"], true);
    assert!(
        health["service"]
            .as_str()
            .is_some_and(|service| !service.is_empty())
    );

    let sdk = server.sdk()?;
    let description = sdk.describe().await?;
    assert_eq!(description.protocol_version, "1.0");
    assert_eq!(description.service_type, "principal_server");

    for required in [
        "cx.repo.submit_commit",
        // C17 (spec 2026-05-08): cx.sync.client_sync → cx.sync.account
        "cx.sync.account",
        "cx.sync.typing",
        "cx.directory.search_spaces",
        "cx.index.query",
        "cx.authz.check",
        "cx.schemas.register",
        "cx.push.rules",
        "cx.webrtc.create_session",
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
    assert!(
        sync["service_did"]
            .as_str()
            .is_some_and(|service_did| !service_did.is_empty())
    );

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
