use anyhow::{Context, Result};
use reqwest::{Client, StatusCode};
use serde_json::{Value as JsonValue, json};

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

    let describe = get_json(&http, directory.url("/api/v1/directory/describe")).await?;
    assert!(
        describe["service_did"]
            .as_str()
            .is_some_and(|service_did| !service_did.is_empty())
    );
    if directory.is_spawned() {
        assert_eq!(describe["service_did"], "did:web:teabay.cotest.local");
    }
    assert_array_contains(
        &describe,
        "discovery_profiles",
        "cx.profile.directory_service.v1",
    );
    if directory.is_spawned() {
        assert_array_contains(
            &describe,
            "discovery_profiles",
            "cx.private_contact_discovery.v1",
        );
    }
    assert_array_contains(&describe, "accepted_resource_kinds", "space");
    assert_array_contains(&describe, "accepted_resource_kinds", "handle");
    assert_array_contains(&describe, "ingest_modes", "push");

    let openapi = get_json(&http, directory.url("/.well-known/contrix/openapi.json")).await?;
    for path in [
        "/api/v1/directory/describe",
        "/api/v1/directory/search-realms",
        "/api/v1/directory/resolve-handle",
        "/api/v1/directory/private-contact-discovery",
        "/api/admin/v1/resources",
    ] {
        assert!(
            openapi["paths"].get(path).is_some(),
            "missing OpenAPI path {path}"
        );
    }

    let not_found = http
        .post(directory.url("/api/v1/directory/resolve-handle"))
        .json(&json!({ "handle": "absent.example" }))
        .send()
        .await?;
    assert_eq!(not_found.status(), StatusCode::NOT_FOUND);
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

fn assert_array_contains(value: &JsonValue, key: &str, expected: &str) {
    let items = value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} must be an array"));
    assert!(
        items.iter().any(|item| item.as_str() == Some(expected)),
        "{key} missing {expected}"
    );
}
