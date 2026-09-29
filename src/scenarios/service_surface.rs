use anyhow::Result;
use reqwest::StatusCode;

use crate::fixtures::TestScaffold;
use crate::harness::{expect_json, expect_status};

pub async fn server_exposes_core_service_surface() -> Result<()> {
    // CT-12: TestScaffold::fresh — server is the same per-process
    // isolated `ArkretServer` the scenario used before. The scaffold
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
    assert_eq!(description.protocol_version.as_str(), "1.0");
    assert_eq!(description.service_kind, arkret_wire::ServiceKind::Station);

    let server_describe = expect_json(
        server.http().get(server.url("/_arkret/describe")),
        StatusCode::OK,
    )
    .await?;
    crate::conformance::validate_server_profile_claims(&server_describe)?;

    for required in [
        "ak.self.account.stream.subscribe.v1",
        "ak.self.authz.read.check.v1",
        "ak.self.signal.command.send.v1",
        "ak.edge.push.command.register_device.v1",
        "ak.self.keys.backups.resource.replace.v1",
        "ak.self.keys.backups.read.list.v1",
        "ak.self.call.media.exchange.issue_token.v1",
        "ak.self.media.read.ice_config.v1",
        "ak.self.moderation.command.report.v1",
    ] {
        assert!(
            description.supports_operation(
                arkret_wire::ServiceOperationId::from_wire(required)
                    .expect("required operation must be registered")
            ),
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
        sync["service_id"]
            .as_str()
            .is_some_and(|service_id| !service_id.is_empty())
    );

    let directory = expect_json(
        server
            .http()
            .get(server.url("/_arkret/find/directory/describe")),
        StatusCode::OK,
    )
    .await?;
    assert!(
        directory["resource_kinds"]
            .as_array()
            .is_some_and(|items| !items.is_empty())
    );
    let directory_description: arkret_models_discovery::ServiceDescribe =
        serde_json::from_value(directory)?;
    assert_eq!(
        directory_description.service_kind,
        arkret_wire::ServiceKind::DirectoryService
    );
    assert!(
        directory_description
            .supports_operation(arkret_wire::ServiceOperationId::FindDirectoryReadSearchRealmsV1)
    );

    expect_status(
        server.http().post(server.url("/_arkret/describe")),
        StatusCode::METHOD_NOT_ALLOWED,
    )
    .await?;

    Ok(())
}

/// Advertised JSON bundle members the live Station does not mount. Each is a
/// false Describe claim (`service-surface.md` §3: only bundles the deployment
/// really implements may be advertised, and a frozen bundle cannot drop a
/// member). The set mirrors Soland's own ratchet and may only shrink.
const KNOWN_ADVERTISED_UNMOUNTED: &[arkret_wire::ServiceOperationId] =
    &[arkret_wire::ServiceOperationId::EdgeAppletManagedActorCommandAuthorV1];

/// Advertised Station members served by the Account Authority of the same
/// Station TCB. The deployment gateway routes pairing and issuer-ledger
/// revocation to Coauth, so a bare Soland process does not mount them. The
/// exact hard-logout route remains on Soland. Mirrors Soland's own exemption;
/// these are not false Describe claims.
const SERVED_BY_ACCOUNT_AUTHORITY: &[arkret_wire::ServiceOperationId] = &[
    arkret_wire::ServiceOperationId::GateAccountCommandPairDeviceV1,
    arkret_wire::ServiceOperationId::GateAccountCommandRevokeSessionV1,
];

/// How the live router answered one unauthenticated, selector-carrying probe.
#[derive(Debug, PartialEq, Eq)]
enum ProbeOutcome {
    /// Dispatched to a handler (any refusal after the selector gate).
    Dispatched,
    /// No route: `unrecognized_endpoint` or `method_not_allowed`.
    Unmounted,
    /// Routed, but the selector refused the advertised operation id.
    SelectorRefused,
}

async fn probe_operation(
    server: &crate::harness::ArkretServer,
    operation: arkret_wire::ServiceOperationId,
) -> Result<ProbeOutcome> {
    let descriptor = operation.descriptor();
    // Concrete placeholder segments; the probe carries no credential, so a
    // mounted handler refuses it (auth, peer signature or closed schema)
    // before any state is read or written.
    let path = descriptor
        .http_path
        .split('/')
        .map(|segment| {
            if segment.starts_with('{') {
                "cotest-probe"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/");
    let method = reqwest::Method::from_bytes(descriptor.http_method.as_bytes())?;
    // The raw client: the probe names its own exact selector instead of the
    // path-derived one the selecting wrapper would add.
    let http = server.http();
    let raw: &reqwest::Client = &http;
    let mut request = raw
        .request(method.clone(), server.url(&path))
        .header(arkret_http_client::HEADER_OPERATION, operation.as_str());
    if !matches!(method.as_str(), "GET" | "HEAD" | "DELETE") {
        request = request
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body("{}");
    }
    let response = request.send().await?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    let code = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|problem| {
            problem["type"]
                .as_str()
                .and_then(|kind| kind.rsplit('/').next())
                .map(str::to_owned)
        })
        .unwrap_or_default();
    Ok(match code.as_str() {
        "unrecognized_endpoint" | "method_not_allowed" => ProbeOutcome::Unmounted,
        "unsupported_operation_version" | "operation_selector_required" => {
            ProbeOutcome::SelectorRefused
        }
        _ if status == StatusCode::NOT_FOUND && body.is_empty() => ProbeOutcome::Unmounted,
        _ => ProbeOutcome::Dispatched,
    })
}

/// Live Describe versus mounted routes: every JSON member of every advertised
/// bundle is dispatched by the fresh Station (outside the shrinking known
/// set), and the http_core peer stream scan and delivery-status read are
/// among them.
pub async fn advertised_operations_are_mounted_and_selectable() -> Result<()> {
    let scaffold = TestScaffold::fresh("advertised-mounted").await?;
    let server = scaffold.server();
    let description = server.sdk()?.describe().await?;
    description.validate()?;

    let mut unmounted = Vec::new();
    let mut refused = Vec::new();
    let mut probed = std::collections::BTreeSet::new();
    for bundle_id in &description.supported_operation_bundles {
        let bundle = arkret_wire::operation_bundle_descriptor(bundle_id).ok_or_else(|| {
            anyhow::anyhow!("Describe advertises unregistered bundle {bundle_id}")
        })?;
        for member in bundle.members {
            if member.binding_kind != arkret_wire::BindingKind::HttpJson
                || SERVED_BY_ACCOUNT_AUTHORITY.contains(&member.operation_id)
                || !probed.insert(member.operation_id)
            {
                continue;
            }
            match probe_operation(server, member.operation_id).await? {
                ProbeOutcome::Dispatched => {}
                ProbeOutcome::Unmounted => unmounted.push(member.operation_id),
                ProbeOutcome::SelectorRefused => refused.push(member.operation_id),
            }
        }
    }
    unmounted.sort_by_key(|operation| operation.as_str());
    let mut known = KNOWN_ADVERTISED_UNMOUNTED.to_vec();
    known.sort_by_key(|operation| operation.as_str());
    anyhow::ensure!(
        refused.is_empty(),
        "advertised operations refused by the live selector: {refused:?}"
    );
    anyhow::ensure!(
        unmounted == known,
        "advertised but unmounted operations changed: {unmounted:?}"
    );
    anyhow::ensure!(
        probed.contains(&arkret_wire::ServiceOperationId::PeerCommittedEventReadScanV1)
            && !unmounted.contains(&arkret_wire::ServiceOperationId::PeerCommittedEventReadScanV1),
        "the advertised peer stream scan must be mounted"
    );

    // The delivery-status read is a member of the advertised
    // `http_core_current` bundle, so it was probed above and must be mounted.
    let delivery_status = arkret_wire::ServiceOperationId::SelfEventsReadDeliveryStatusV1;
    anyhow::ensure!(
        description.supports_operation(delivery_status)
            && probed.contains(&delivery_status)
            && !unmounted.contains(&delivery_status),
        "the advertised delivery-status read must be mounted and selectable"
    );
    Ok(())
}
