use anyhow::Result;
use reqwest::StatusCode;

use crate::fixtures::TestScaffold;
use crate::harness::{expect_json, expect_status};

pub async fn server_exposes_core_service_surface() -> Result<()> {
    // CT-12: TestScaffold::fresh — server is the same per-process
    // isolated `ContrixServer` the scenario used before. The scaffold
    // adds a process-unique suffix to `service-surface` so two
    // copies of this scenario (e.g. under `--test-threads > 1`) get
    // distinct service DIDs and on-disk artifact names.
    let scaffold = TestScaffold::fresh("service-surface").await?;
    let server = scaffold.server();

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

    let server_describe = expect_json(
        server.http().get(server.url("/api/v1/server/describe")),
        StatusCode::OK,
    )
    .await?;
    crate::conformance::validate_server_profile_claims(&server_describe)?;

    for required in [
        "cx.account.subscribe",
        "cx.directory.search_realms",
        "cx.authz.check",
        "cx.ephemeral.send",
        "cx.push.register_device",
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
    let local_extensions =
        server_describe["limits"]["profile_status"]["local_extension_operations"]
            .as_array()
            .expect("local extension operation list");
    for extension in [
        "cx.extension.soland.index.query",
        "cx.extension.soland.push.rules",
        "cx.extension.soland.webrtc.create_session",
    ] {
        assert!(
            local_extensions.iter().any(|op| op == extension),
            "missing local extension operation {extension}"
        );
    }

    let sync = expect_json(
        server.http().get(server.url("/api/v1/account/describe")),
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
