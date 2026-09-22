use anyhow::{Context, Result};
use arkret_wire::{
    BindingKind, OperationBindingPair, ServiceOperationId, operation_bundle_descriptor,
};
use reqwest::{Client, StatusCode};
use serde_json::Value as JsonValue;

use crate::scenarios::_helpers::external_binary::{TEABAY_SPEC, try_spawn};

enum DirectoryTarget {
    Attached(String),
    Spawned(crate::scenarios::_helpers::external_binary::SpawnedExternalProcess),
}

impl DirectoryTarget {
    fn base_url(&self) -> &str {
        match self {
            Self::Attached(base_url) => base_url,
            Self::Spawned(process) => &process.base_url,
        }
    }

    fn url(&self, path: &str) -> String {
        let base = self.base_url().trim_end_matches('/');
        if path.starts_with('/') {
            format!("{base}{path}")
        } else {
            format!("{base}/{path}")
        }
    }

    fn is_spawned(&self) -> bool {
        matches!(self, Self::Spawned(_))
    }
}

pub async fn teabay_directory_service_profile_is_discoverable() -> Result<()> {
    assert_current_v1_registry_contract()?;

    let Some(directory) = directory_target().await? else {
        eprintln!(
            "skipping teabay Directory cotest: set TEABAY_BASE_URL or build teabay and set DATABASE_URL"
        );
        return Ok(());
    };
    let http = Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let health = get_json(&http, directory.url("/health")).await?;
    assert_eq!(health["ok"], true);

    let describe = get_json_with_operation(
        &http,
        directory.url("/_arkret/find/directory/describe"),
        ServiceOperationId::FIND_DIRECTORY_READ_DESCRIBE_V1,
    )
    .await?;
    assert!(
        describe["service_id"]
            .as_str()
            .is_some_and(|service_id| !service_id.is_empty())
    );
    if directory.is_spawned() {
        assert_eq!(
            describe["service_id"],
            "ak:did_core:web:teabay.cotest.local"
        );
    }
    assert_array_exact(
        &describe,
        "supported_profiles",
        &["ak.profile.directory_service.v1"],
    );
    assert_array_exact(
        &describe,
        "supported_operation_bundles",
        &[
            "ak.operation_bundle.directory_service.describe.v1",
            "ak.operation_bundle.directory_service.public_read.v1",
        ],
    );
    assert_array_exact(&describe, "resource_kinds", &["realm"]);
    assert!(describe.get("accepted_resource_kinds").is_none());
    assert!(describe.get("ingest_modes").is_none());
    assert!(describe.get("x_teabay_limitations").is_none());

    let openapi = get_json(&http, directory.url("/.well-known/arkret/openapi.json")).await?;
    for (path, method, operation_id) in [
        (
            "/_arkret/find/directory/describe",
            "get",
            ServiceOperationId::FIND_DIRECTORY_READ_DESCRIBE_V1,
        ),
        (
            "/_arkret/find/directory/search-realms",
            "post",
            ServiceOperationId::FIND_DIRECTORY_READ_SEARCH_REALMS_V1,
        ),
        (
            "/_arkret/find/directory/resolve-realm",
            "post",
            ServiceOperationId::FIND_DIRECTORY_READ_RESOLVE_REALM_V1,
        ),
    ] {
        assert_eq!(
            openapi["paths"][path][method]["operationId"], operation_id,
            "OpenAPI operation mismatch for {path}"
        );
    }
    let mut directory_paths = openapi["paths"]
        .as_object()
        .context("OpenAPI paths must be an object")?
        .keys()
        .filter(|path| path.starts_with("/_arkret/find/directory/"))
        .map(String::as_str)
        .collect::<Vec<_>>();
    directory_paths.sort_unstable();
    assert_eq!(
        directory_paths,
        vec![
            "/_arkret/find/directory/describe",
            "/_arkret/find/directory/resolve-realm",
            "/_arkret/find/directory/search-realms",
        ]
    );

    for retired_command in ["announce", "withdraw"] {
        let response = http
            .post(directory.url(&format!("/_arkret/find/directory/{retired_command}")))
            .header(
                "Arkret-Operation",
                format!("ak.find.directory.command.{retired_command}.v1"),
            )
            .json(&serde_json::json!({}))
            .send()
            .await?;
        assert!(
            matches!(
                response.status(),
                StatusCode::NOT_FOUND
                    | StatusCode::METHOD_NOT_ALLOWED
                    | StatusCode::UNPROCESSABLE_ENTITY
            ),
            "retired Directory {retired_command} unexpectedly reachable: {}",
            response.status()
        );
    }
    Ok(())
}

fn assert_current_v1_registry_contract() -> Result<()> {
    let bundle =
        operation_bundle_descriptor("ak.operation_bundle.directory_service.public_read.v1")
            .context("missing generated Directory public-read bundle")?;
    let expected_members = [
        OperationBindingPair {
            operation_id: ServiceOperationId::FindDirectoryReadDescribeV1,
            binding_kind: BindingKind::HttpJson,
        },
        OperationBindingPair {
            operation_id: ServiceOperationId::FindDirectoryReadResolveRealmV1,
            binding_kind: BindingKind::HttpJson,
        },
        OperationBindingPair {
            operation_id: ServiceOperationId::FindDirectoryReadSearchRealmsV1,
            binding_kind: BindingKind::HttpJson,
        },
    ];
    assert_eq!(bundle.members, expected_members);
    assert!(
        operation_bundle_descriptor("ak.operation_bundle.directory_service.http_core.v1").is_none()
    );
    for retired_command in ["announce", "withdraw"] {
        assert!(
            ServiceOperationId::from_wire(&format!(
                "ak.find.directory.command.{retired_command}.v1"
            ))
            .is_none(),
            "retired Directory {retired_command} must be absent from the registry"
        );
    }
    Ok(())
}

async fn directory_target() -> Result<Option<DirectoryTarget>> {
    if let Ok(base_url) = std::env::var("TEABAY_BASE_URL")
        && !base_url.trim().is_empty()
    {
        return Ok(Some(DirectoryTarget::Attached(base_url)));
    }
    Ok(try_spawn(&TEABAY_SPEC).await?.map(DirectoryTarget::Spawned))
}

async fn get_json(http: &Client, url: String) -> Result<JsonValue> {
    let response = http
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    let body = response.text().await?;
    assert_eq!(status, StatusCode::OK, "GET {url}: {body}");
    serde_json::from_str(&body).with_context(|| format!("decode JSON from {url}"))
}

async fn get_json_with_operation(
    http: &Client,
    url: String,
    operation_id: &str,
) -> Result<JsonValue> {
    let response = http
        .get(&url)
        .header("Arkret-Operation", operation_id)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    let body = response.text().await?;
    assert_eq!(status, StatusCode::OK, "GET {url}: {body}");
    serde_json::from_str(&body).with_context(|| format!("decode JSON from {url}"))
}

fn assert_array_exact(value: &JsonValue, key: &str, expected: &[&str]) {
    let items = value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} must be an array"));
    assert_eq!(
        items
            .iter()
            .map(|item| item.as_str().unwrap_or("<non-string>"))
            .collect::<Vec<_>>(),
        expected,
        "{key} must be exact"
    );
}
