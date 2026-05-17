use anyhow::{Context, Result, anyhow};
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::Value;
use url::Url;

use crate::conformance::{
    PrincipalCertificationStatus, validate_principal_server_certification,
    validate_scaffold_profile_gate,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StackCertificationReport {
    pub schema: String,
    pub generated_at: String,
    pub services: Vec<ServiceCertificationEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ServiceCertificationEntry {
    pub service: String,
    pub describe_url: Option<String>,
    pub status: String,
    pub certification: String,
    pub reason: Option<String>,
}

#[derive(Clone, Copy)]
struct ServiceSpec {
    service: &'static str,
    exact_env: &'static str,
    base_env: &'static str,
    default_path: &'static str,
}

const SERVICE_SPECS: &[ServiceSpec] = &[
    ServiceSpec {
        service: "soland",
        exact_env: "COTEST_SOLAND_DESCRIBE_URL",
        base_env: "COTEST_SOLAND_BASE_URL",
        default_path: "/api/v1/server/describe",
    },
    ServiceSpec {
        service: "floria",
        exact_env: "COTEST_FLORIA_DESCRIBE_URL",
        base_env: "COTEST_FLORIA_BASE_URL",
        default_path: "/api/v1/server/describe",
    },
    ServiceSpec {
        service: "teabay",
        exact_env: "COTEST_TEABAY_DESCRIBE_URL",
        base_env: "COTEST_TEABAY_BASE_URL",
        default_path: "/api/v1/directory/describe",
    },
    ServiceSpec {
        service: "starid",
        exact_env: "COTEST_STARID_DESCRIBE_URL",
        base_env: "COTEST_STARID_BASE_URL",
        default_path: "/describe",
    },
    ServiceSpec {
        service: "coauth",
        exact_env: "COTEST_COAUTH_DESCRIBE_URL",
        base_env: "COTEST_COAUTH_BASE_URL",
        default_path: "/api/v1/server/describe",
    },
];

pub async fn live_stack_certification_report_from_env() -> Result<StackCertificationReport> {
    let client = reqwest::Client::new();
    let mut services = Vec::new();
    for spec in SERVICE_SPECS {
        let Some(url) = describe_url_from_env(*spec)? else {
            services.push(skipped_entry(spec.service, "describe URL not configured"));
            continue;
        };
        services.push(fetch_and_evaluate(&client, *spec, url).await);
    }
    Ok(report_with_services(services))
}

pub fn offline_live_stack_certification_report() -> StackCertificationReport {
    report_with_services(
        SERVICE_SPECS
            .iter()
            .map(|spec| skipped_entry(spec.service, "describe URL not configured"))
            .collect(),
    )
}

pub fn render_stack_certification_report_json(report: &StackCertificationReport) -> Result<String> {
    serde_json::to_string_pretty(report).map_err(Into::into)
}

pub fn render_stack_certification_report_markdown(report: &StackCertificationReport) -> String {
    let mut out = String::from(
        "| service | status | certification | describe_url | reason |\n| --- | --- | --- | --- | --- |\n",
    );
    for service in &report.services {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            service.service,
            service.status,
            service.certification,
            service.describe_url.as_deref().unwrap_or(""),
            service.reason.as_deref().unwrap_or("")
        ));
    }
    out
}

async fn fetch_and_evaluate(
    client: &reqwest::Client,
    spec: ServiceSpec,
    url: String,
) -> ServiceCertificationEntry {
    let response = match client.get(&url).send().await {
        Ok(response) => response,
        Err(error) => {
            return ServiceCertificationEntry {
                service: spec.service.to_owned(),
                describe_url: Some(url),
                status: "unsupported".to_owned(),
                certification: "not_evaluated".to_owned(),
                reason: Some(format!("describe endpoint unreachable: {error}")),
            };
        }
    };
    let status = response.status();
    let body = match response.json::<Value>().await {
        Ok(mut body) => {
            if body.get("service").is_none() {
                body["service"] = Value::String(spec.service.to_owned());
            }
            body
        }
        Err(error) => {
            return ServiceCertificationEntry {
                service: spec.service.to_owned(),
                describe_url: Some(url),
                status: "failed".to_owned(),
                certification: "not_evaluated".to_owned(),
                reason: Some(format!("describe response was not JSON: {error}")),
            };
        }
    };
    if status != StatusCode::OK {
        return ServiceCertificationEntry {
            service: spec.service.to_owned(),
            describe_url: Some(url),
            status: "failed".to_owned(),
            certification: "not_evaluated".to_owned(),
            reason: Some(format!("describe endpoint returned HTTP {status}")),
        };
    }
    if let Err(error) = validate_scaffold_profile_gate(&body) {
        return ServiceCertificationEntry {
            service: spec.service.to_owned(),
            describe_url: Some(url),
            status: "failed".to_owned(),
            certification: "not_evaluated".to_owned(),
            reason: Some(format!("profile claim gate failed: {error}")),
        };
    }

    let certification = if spec.service == "soland" || claims_principal_server(&body) {
        match validate_principal_server_certification(&body) {
            Ok(PrincipalCertificationStatus::Certified) => "certified".to_owned(),
            Ok(PrincipalCertificationStatus::NotCertified) => "not_certified".to_owned(),
            Err(error) => {
                return ServiceCertificationEntry {
                    service: spec.service.to_owned(),
                    describe_url: Some(url),
                    status: "failed".to_owned(),
                    certification: "failed".to_owned(),
                    reason: Some(format!("principal_server certification failed: {error}")),
                };
            }
        }
    } else {
        "not_evaluated".to_owned()
    };

    ServiceCertificationEntry {
        service: spec.service.to_owned(),
        describe_url: Some(url),
        status: "passed".to_owned(),
        certification,
        reason: None,
    }
}

fn describe_url_from_env(spec: ServiceSpec) -> Result<Option<String>> {
    if let Ok(url) = std::env::var(spec.exact_env)
        && !url.trim().is_empty()
    {
        Url::parse(url.trim()).with_context(|| format!("invalid {}", spec.exact_env))?;
        return Ok(Some(url.trim().to_owned()));
    }
    if let Ok(base) = std::env::var(spec.base_env)
        && !base.trim().is_empty()
    {
        return Ok(Some(join_url(base.trim(), spec.default_path)?));
    }
    Ok(None)
}

fn join_url(base: &str, path: &str) -> Result<String> {
    let parsed = Url::parse(base).with_context(|| format!("invalid base URL {base}"))?;
    parsed
        .join(path.trim_start_matches('/'))
        .map(|url| url.to_string())
        .map_err(|error| anyhow!("failed to append {path} to {base}: {error}"))
}

fn claims_principal_server(body: &Value) -> bool {
    for field in ["supported_profiles", "profiles", "claimed_profiles"] {
        if body
            .get(field)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|value| value.as_str() == Some("cx.profile.principal_server.v1"))
        {
            return true;
        }
    }
    false
}

fn skipped_entry(service: &str, reason: &str) -> ServiceCertificationEntry {
    ServiceCertificationEntry {
        service: service.to_owned(),
        describe_url: None,
        status: "skipped".to_owned(),
        certification: "not_evaluated".to_owned(),
        reason: Some(reason.to_owned()),
    }
}

fn report_with_services(services: Vec<ServiceCertificationEntry>) -> StackCertificationReport {
    StackCertificationReport {
        schema: "cx.cotest.live_stack_certification_report.v1".to_owned(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        services,
    }
}
