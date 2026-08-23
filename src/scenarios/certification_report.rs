use anyhow::Result;
use serde::Serialize;

use crate::conformance::{
    ProfileGateReport, build_profile_gate_report, render_profile_gate_report_markdown,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StackCertificationReport {
    pub schema: String,
    pub generated_at: String,
    pub services: Vec<ServiceCertificationEntry>,
    /// Per-profile gate rollup (vector + implementation profile manifest
    /// entries from `profile_registry::build_profile_gate_report`). Present
    /// when the runtime gate report could be built from the spec artifact;
    /// `None` when the artifact is unreachable (e.g. running from a release
    /// tarball without `arkret-spec/`).
    pub profile_gate: Option<ProfileGateReport>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ServiceCertificationEntry {
    pub service: String,
    pub describe_url: Option<String>,
    pub status: String,
    pub certification: String,
    pub reason: Option<String>,
}

/// Services the report enumerates, in stable order.
const SERVICE_NAMES: &[&str] = &["soland", "floria", "teabay", "coauth"];

pub fn offline_live_stack_certification_report() -> StackCertificationReport {
    report_with_services(
        SERVICE_NAMES
            .iter()
            .map(|&service| skipped_entry(service, "describe URL not configured"))
            .collect(),
    )
}

pub fn render_stack_certification_report_json(report: &StackCertificationReport) -> Result<String> {
    serde_json::to_string_pretty(report).map_err(Into::into)
}

pub fn render_stack_certification_report_markdown(report: &StackCertificationReport) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(256 + report.services.len() * 128);
    out.push_str(
        "| service | status | certification | describe_url | reason |\n| --- | --- | --- | --- | --- |\n",
    );
    for service in &report.services {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            service.service,
            service.status,
            service.certification,
            service.describe_url.as_deref().unwrap_or(""),
            service.reason.as_deref().unwrap_or("")
        );
    }
    if let Some(gate) = &report.profile_gate {
        out.push('\n');
        out.push_str("### Profile gate\n\n");
        out.push_str(&render_profile_gate_report_markdown(gate));
    }
    out
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
    // Try to load the runtime profile-gate rollup. We deliberately swallow a
    // load error (e.g. spec artifact unreachable in a packaged release run)
    // and emit `profile_gate: None` rather than failing the whole
    // certification report — the certification suite's profile_registry gate
    // (run separately under `cargo test --test conformance_fixtures`) is the
    // authoritative pass/fail signal.
    let profile_gate = build_profile_gate_report().ok();
    StackCertificationReport {
        schema: "ak.cotest.live_stack_certification_report.v1".to_owned(),
        generated_at: arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
        services,
        profile_gate,
    }
}
