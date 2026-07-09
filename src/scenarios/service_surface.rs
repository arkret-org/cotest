use anyhow::Result;
use reqwest::StatusCode;

use crate::fixtures::TestScaffold;
use crate::harness::{expect_json, expect_status};

pub async fn server_exposes_core_service_surface() -> Result<()> {
    // CT-12: TestScaffold::fresh — server is the same per-process
    // isolated `CokretServer` the scenario used before. The scaffold
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
        server.http().get(server.url("/_arkret/describe")),
        StatusCode::OK,
    )
    .await?;
    crate::conformance::validate_server_profile_claims(&server_describe)?;

    for required in [
        "ck.self.account.stream.subscribe",
        "ck.find.directory.query.search_realms",
        "ck.self.authz.query.check",
        "ck.self.ephemeral.command.send",
        "ck.edge.push.command.register_device",
        "ck.self.keys.backups.resource.replace",
        "ck.self.keys.backups.query.list",
        "ck.self.call.media.exchange.issue_token",
        "ck.self.media.query.ice_config",
        "ck.self.policy.query.check",
        "ck.self.moderation.command.report",
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
        server
            .http()
            .get(server.url("/_arkret/self/account/describe")),
        StatusCode::OK,
    )
    .await?;
    assert!(
        sync["service_did"]
            .as_str()
            .is_some_and(|service_did| !service_did.is_empty())
    );

    let directory = expect_json(
        server
            .http()
            .get(server.url("/_arkret/find/directory/describe")),
        StatusCode::OK,
    )
    .await?;
    assert!(
        directory["resource_types"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );

    expect_status(
        server.http().post(server.url("/_arkret/describe")),
        StatusCode::METHOD_NOT_ALLOWED,
    )
    .await?;

    Ok(())
}
