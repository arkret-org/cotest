use anyhow::{Context, Result, anyhow, bail};
use reqwest::StatusCode;
use serde_json::Value;
use url::Url;

use crate::conformance::validate_scaffold_profile_gate;

struct DescribeTarget {
    service: String,
    url: String,
}

pub async fn live_describe_profile_claim_gate_from_env() -> Result<()> {
    let targets = configured_targets()?;
    if targets.is_empty() {
        return Ok(());
    }

    let client = crate::scenarios::_helpers::http::live_probe_client()?;
    for target in targets {
        let response = client
            .get(&target.url)
            .send()
            .await
            .with_context(|| format!("fetch describe for {}", target.service))?;
        let status = response.status();
        let mut body: Value = response
            .json()
            .await
            .with_context(|| format!("parse describe JSON for {}", target.service))?;
        if status != StatusCode::OK {
            bail!(
                "describe for {} returned status {status}: {body}",
                target.service
            );
        }
        if body.get("service").is_none() {
            body["service"] = Value::String(target.service.clone());
        }
        validate_scaffold_profile_gate(&body)
            .with_context(|| format!("profile claim gate failed for {}", target.service))?;
    }

    Ok(())
}

pub fn profile_claim_gate_negative_claims_fail_closed() -> Result<()> {
    let unknown = serde_json::json!({
        "supported_profiles": ["ak.profile.not_registered.v1"],
        "supported_operations": [],
    });
    expect_profile_rejected(&unknown, "unknown claimed profile")?;

    let failed = serde_json::json!({
        "supported_profiles": ["ak.profile.core_event_store.v1"],
        "supported_operations": [
            "ak.server.read.describe",
            "ak.self.events.read.describe",
            "ak.self.events.command.submit",
            "ak.self.events.resource.get",
            "ak.self.events.read.resolve",
            "ak.self.events.read.scan",
            "ak.self.events.read.frontier"
        ],
        "supported_event_kinds": [
            "ak.space.create",
            "ak.member.state"
        ],
        "supported_event_schemas": [
            "ak.schema.event.v1",
            "ak.schema.event_payload.v1",
            "ak.schema.event_batch_receipt.v1",
            "ak.schema.cursor.v1",
            "ak.schema.anchor.v1"
        ],
        "conformance_results": {
            "ak.profile.core_event_store.v1": {
                "status": "failed",
                "failed_suites": ["event_envelope_fixture"]
            }
        }
    });
    expect_profile_rejected(&failed, "failed conformance results")?;

    let limited = serde_json::json!({
        "supported_profiles": ["ak.profile.soland_limited_server.v1"],
        "supported_operations": [],
    });
    expect_profile_rejected(&limited, "limited profile")?;

    let missing_dependency = serde_json::json!({
        "supported_profiles": ["ak.profile.push_gateway.v1"],
        "supported_operations": [],
    });
    expect_profile_rejected(&missing_dependency, "missing profile dependency")?;

    let mutually_exclusive = serde_json::json!({
        "supported_profiles": [
            "ak.profile.e2ee_relaxed.v1",
            "ak.profile.e2ee_client.v1",
            "ak.profile.mls_governance_binding.full.v1",
        ],
        "supported_operations": [],
    });
    expect_profile_rejected(&mutually_exclusive, "mutually exclusive profiles")?;

    let missing_required_cells = serde_json::json!({
        "supported_profiles": ["ak.profile.mls_governance_binding.full.v1"],
        "supported_operations": [
            "ak.self.keys.keypackages.command.claim",
            "ak.self.keys.keypackages.command.consume",
            "ak.self.events.read.scan",
        ],
        "supported_cells": [],
    });
    expect_profile_rejected(&missing_required_cells, "missing required cells")?;

    let missing_required_fixture = serde_json::json!({
        "supported_profiles": ["ak.vector_group.capability.v1"],
        "supported_operations": ["ak.self.authz.read.check"],
        "verified_fixtures": [],
    });
    expect_profile_rejected(&missing_required_fixture, "missing required fixture")?;

    Ok(())
}

fn expect_profile_rejected(describe: &Value, label: &str) -> Result<()> {
    if crate::conformance::validate_server_profile_claims(describe).is_ok() {
        bail!("profile gate accepted {label} claim: {describe}");
    }
    Ok(())
}

fn configured_targets() -> Result<Vec<DescribeTarget>> {
    let mut targets = Vec::new();
    add_exact_targets(
        &mut targets,
        std::env::var("COTEST_PROFILE_GATE_DESCRIBE_URLS").ok(),
    )?;
    add_base_targets(
        &mut targets,
        std::env::var("COTEST_PROFILE_GATE_BASE_URLS").ok(),
        "/_arkret/describe",
    )?;

    for (service, exact_env, base_env, default_path) in [
        (
            "soland",
            "COTEST_SOLAND_DESCRIBE_URL",
            "COTEST_SOLAND_BASE_URL",
            "/_arkret/describe",
        ),
        (
            "floria",
            "COTEST_FLORIA_DESCRIBE_URL",
            "COTEST_FLORIA_BASE_URL",
            "/_arkret/describe",
        ),
        (
            "teabay",
            "COTEST_TEABAY_DESCRIBE_URL",
            "COTEST_TEABAY_BASE_URL",
            "/_arkret/find/directory/describe",
        ),
        (
            "starid",
            "COTEST_STARID_DESCRIBE_URL",
            "COTEST_STARID_BASE_URL",
            "/describe",
        ),
        (
            "coauth",
            "COTEST_COAUTH_DESCRIBE_URL",
            "COTEST_COAUTH_BASE_URL",
            "/_arkret/describe",
        ),
    ] {
        if let Ok(url) = std::env::var(exact_env)
            && !url.trim().is_empty()
        {
            targets.push(DescribeTarget {
                service: service.to_owned(),
                url: url.trim().to_owned(),
            });
        }
        if let Ok(base) = std::env::var(base_env)
            && !base.trim().is_empty()
        {
            targets.push(DescribeTarget {
                service: service.to_owned(),
                url: join_url(base.trim(), default_path)?,
            });
        }
    }

    Ok(targets)
}

fn add_exact_targets(targets: &mut Vec<DescribeTarget>, raw: Option<String>) -> Result<()> {
    let Some(raw) = raw else {
        return Ok(());
    };
    for item in split_targets(&raw) {
        let (service, url) = parse_service_url(item, None)?;
        targets.push(DescribeTarget { service, url });
    }
    Ok(())
}

fn add_base_targets(
    targets: &mut Vec<DescribeTarget>,
    raw: Option<String>,
    default_path: &str,
) -> Result<()> {
    let Some(raw) = raw else {
        return Ok(());
    };
    for item in split_targets(&raw) {
        let (service, base) = parse_service_url(item, Some(default_path))?;
        targets.push(DescribeTarget { service, url: base });
    }
    Ok(())
}

fn split_targets(raw: &str) -> impl Iterator<Item = &str> {
    raw.split([',', ';'])
        .map(str::trim)
        .filter(|item| !item.is_empty())
}

fn parse_service_url(item: &str, append_path: Option<&str>) -> Result<(String, String)> {
    let (service, url) = if let Some((service, url)) = item.split_once('=') {
        (service.trim().to_owned(), url.trim().to_owned())
    } else {
        let parsed = Url::parse(item).with_context(|| format!("invalid describe URL {item}"))?;
        let service = parsed
            .host_str()
            .map(|host| host.split('.').next().unwrap_or("service").to_owned())
            .unwrap_or_else(|| "service".to_owned());
        (service, item.to_owned())
    };
    if service.is_empty() {
        bail!("describe target has empty service label: {item}");
    }
    let url = match append_path {
        Some(path) => join_url(&url, path)?,
        None => {
            Url::parse(&url).with_context(|| format!("invalid describe URL {url}"))?;
            url
        }
    };
    Ok((service, url))
}

fn join_url(base: &str, path: &str) -> Result<String> {
    let parsed = Url::parse(base).with_context(|| format!("invalid base URL {base}"))?;
    parsed
        .join(path.trim_start_matches('/'))
        .map(|url| url.to_string())
        .map_err(|error| anyhow!("failed to append {path} to {base}: {error}"))
}
