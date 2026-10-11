//! DID-boundary call counting over the services' Prometheus endpoints (DID-P1-C01/C02).
//!
//! # Why metrics rather than a resolver spy
//!
//! The task's original shape was an in-process `DidResolver` spy. cotest has no
//! Cargo dependency on coland / flagon / coauth / floria — they are
//! pre-built sibling binaries driven over HTTP ([`super::external_binary`]) —
//! so a Rust trait spy cannot be injected. The network-layer alternative (the
//! counting DID host in [`super::did_host`]) is implemented and self-tested but
//! **cannot be wired to the services**: DID → URL derivation hard-codes
//! `https`, and the SSRF gate rejects `localhost` / loopback *while building the
//! URL*, so a DID that points at the mock cannot even be constructed. Opening a
//! dev-only base-URL override in the SSRF defence would put a test requirement
//! inside a production security boundary.
//!
//! coland and flagon therefore export two counters each, and this module turns
//! them into the two numbers the joint contract is written in:
//!
//! | number | series |
//! | --- | --- |
//! | `authority_network_call_count` | `*_did_resolve_total{source="network"}` |
//! | `signature_verify_count` | `*_signature_verify_total` (all labels) |
//!
//! Only `source="network"` counts as an authority call: both services increment
//! it exclusively on the branches that actually issue an outbound request, so
//! `binding_store` / `local_snapshot` / `sdk_cache` / `did_key` hits — which are
//! precisely what "reuse the accepted binding" means — never inflate it.
//!
//! # Coverage boundary
//!
//! Only **coland** and **flagon** expose these counters. coauth, inkson and
//! bridges have no metrics endpoint, so a scenario about them cannot be
//! expressed here; see the DID-P1-C02 notes in the task file rather than
//! substituting a weaker assertion.
//!
//! The TypeScript twin is `e2e/helpers/service-metrics.ts`; both parse the same
//! text and name the same two numbers, so a claim proved on one side means the
//! same thing on the other.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};

/// Env var carrying coland's `/metrics` base URL (exported by
/// `scripts/run-joint-e2e.ps1`).
pub const COLAND_METRICS_URL_ENV: &str = "COTEST_COLAND_METRICS_URL";
/// Env var carrying flagon's `/metrics` base URL.
pub const FLAGON_METRICS_URL_ENV: &str = "COTEST_FLAGON_METRICS_URL";

/// `coland_did_resolve_total` / `flagon_did_resolve_total` metric names.
pub const COLAND_DID_RESOLVE_TOTAL: &str = "coland_did_resolve_total";
pub const COLAND_SIGNATURE_VERIFY_TOTAL: &str = "coland_signature_verify_total";
pub const FLAGON_DID_RESOLVE_TOTAL: &str = "flagon_did_resolve_total";
pub const FLAGON_SIGNATURE_VERIFY_TOTAL: &str = "flagon_signature_verify_total";

/// The one `source` label value that means "an outbound request was issued".
/// Shared by both services by design.
pub const SOURCE_NETWORK: &str = "network";

/// One Prometheus sample: a metric name, its label set, and its value.
#[derive(Clone, Debug, PartialEq)]
pub struct MetricSample {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    pub value: f64,
}

impl MetricSample {
    /// Whether every `(key, value)` in `selector` appears in this sample's
    /// labels. Extra labels on the sample are ignored, so a selector is a
    /// filter, not an exact match.
    #[must_use]
    pub fn matches(&self, selector: &[(&str, &str)]) -> bool {
        selector
            .iter()
            .all(|(key, value)| self.labels.get(*key).map(String::as_str) == Some(*value))
    }
}

/// A parsed `GET /metrics` response.
#[derive(Clone, Debug, Default)]
pub struct MetricsSnapshot {
    samples: Vec<MetricSample>,
}

impl MetricsSnapshot {
    /// Parse Prometheus text-exposition format. `#`-prefixed HELP / TYPE lines
    /// and blank lines are skipped; a sample line that does not parse is
    /// skipped rather than failing the whole snapshot, because a scrape carries
    /// dozens of unrelated families and one malformed one must not blind an
    /// unrelated assertion.
    #[must_use]
    pub fn parse(body: &str) -> Self {
        let mut samples = Vec::new();
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some(sample) = parse_sample_line(line) else {
                continue;
            };
            samples.push(sample);
        }
        Self { samples }
    }

    #[must_use]
    pub fn samples(&self) -> &[MetricSample] {
        &self.samples
    }

    /// Sum of every sample of `name` whose labels match `selector`. An absent
    /// series reads as `0`, which is what a counter that has never fired means.
    #[must_use]
    pub fn sum(&self, name: &str, selector: &[(&str, &str)]) -> f64 {
        self.samples
            .iter()
            .filter(|sample| sample.name == name && sample.matches(selector))
            .map(|sample| sample.value)
            .sum()
    }

    /// Every series of `name` keyed by its rendered label set, for diagnostics.
    #[must_use]
    pub fn series(&self, name: &str) -> BTreeMap<String, f64> {
        self.samples
            .iter()
            .filter(|sample| sample.name == name)
            .map(|sample| (render_labels(&sample.labels), sample.value))
            .collect()
    }

    /// Whether the exposition mentions `name` at all. `false` means the build
    /// under test predates the counter — a scenario must report that rather
    /// than read the absent series as a passing zero.
    #[must_use]
    pub fn has_metric(&self, name: &str) -> bool {
        self.samples.iter().any(|sample| sample.name == name)
    }
}

fn render_labels(labels: &BTreeMap<String, String>) -> String {
    let inner = labels
        .iter()
        .map(|(key, value)| format!("{key}=\"{value}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{inner}}}")
}

/// `name{a="1",b="2"} 3` → a [`MetricSample`]. Returns `None` for lines that do
/// not have that shape (including `NaN` / `+Inf` values, which no counter uses).
fn parse_sample_line(line: &str) -> Option<MetricSample> {
    let (head, value) = line.rsplit_once(char::is_whitespace)?;
    let value: f64 = value.trim().parse().ok()?;
    let head = head.trim();
    let Some((name, rest)) = head.split_once('{') else {
        return Some(MetricSample {
            name: head.to_owned(),
            labels: BTreeMap::new(),
            value,
        });
    };
    let rest = rest.strip_suffix('}')?;
    let mut labels = BTreeMap::new();
    for pair in split_label_pairs(rest) {
        let (key, raw) = pair.split_once('=')?;
        let raw = raw.trim();
        let raw = raw.strip_prefix('"')?.strip_suffix('"')?;
        labels.insert(key.trim().to_owned(), unescape_label_value(raw));
    }
    Some(MetricSample {
        name: name.trim().to_owned(),
        labels,
        value,
    })
}

/// Split `a="1",b="2"` on commas that are not inside a quoted value.
fn split_label_pairs(rest: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for character in rest.chars() {
        match character {
            _ if escaped => {
                current.push(character);
                escaped = false;
            }
            '\\' if in_quotes => {
                current.push(character);
                escaped = true;
            }
            '"' => {
                in_quotes = !in_quotes;
                current.push(character);
            }
            ',' if !in_quotes => {
                if !current.trim().is_empty() {
                    out.push(std::mem::take(&mut current));
                } else {
                    current.clear();
                }
            }
            _ => current.push(character),
        }
    }
    if !current.trim().is_empty() {
        out.push(current);
    }
    out
}

fn unescape_label_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(character) = chars.next() {
        if character != '\\' {
            out.push(character);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('\\') => out.push('\\'),
            Some('"') => out.push('"'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// The two counts DID-P1-C02 requires every scenario to record.
///
/// They are deliberately separate: "verify one signature" and "resolve one DID"
/// are independent events, and only the first may scale with ordinary traffic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DidBoundaryDelta {
    /// Increment of `*_did_resolve_total{source="network"}`.
    pub authority_network_call_count: u64,
    /// Increment of `*_signature_verify_total` summed over every label.
    pub signature_verify_count: u64,
}

/// Which service's counter family to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MeteredService {
    Coland,
    Flagon,
}

impl MeteredService {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Coland => "coland",
            Self::Flagon => "flagon",
        }
    }

    #[must_use]
    pub fn did_resolve_metric(self) -> &'static str {
        match self {
            Self::Coland => COLAND_DID_RESOLVE_TOTAL,
            Self::Flagon => FLAGON_DID_RESOLVE_TOTAL,
        }
    }

    #[must_use]
    pub fn signature_verify_metric(self) -> &'static str {
        match self {
            Self::Coland => COLAND_SIGNATURE_VERIFY_TOTAL,
            Self::Flagon => FLAGON_SIGNATURE_VERIFY_TOTAL,
        }
    }

    #[must_use]
    pub fn base_url_env(self) -> &'static str {
        match self {
            Self::Coland => COLAND_METRICS_URL_ENV,
            Self::Flagon => FLAGON_METRICS_URL_ENV,
        }
    }
}

/// Reads one service's `/metrics` endpoint.
///
/// Naming and the `from_env` / `expect_no_additional_authority_calls` shape
/// deliberately mirror [`super::did_host::DidHostClient`], so the two
/// observation mechanisms are interchangeable at the call site.
pub struct ServiceMetricsClient {
    service: MeteredService,
    base_url: String,
    http: reqwest::Client,
}

impl ServiceMetricsClient {
    /// Build a client for `base_url` (with or without a trailing `/metrics`).
    pub fn new(service: MeteredService, base_url: impl Into<String>) -> Result<Self> {
        let base_url = base_url.into();
        let base_url = base_url.trim().trim_end_matches('/');
        let base_url = base_url.strip_suffix("/metrics").unwrap_or(base_url);
        Ok(Self {
            service,
            base_url: base_url.to_owned(),
            http: super::http::live_probe_client()?,
        })
    }

    /// Build from the service's env var, or `Ok(None)` when the metrics
    /// listener is not part of this run. Scenarios skip rather than fail,
    /// matching the `try_spawn` convention in [`super::external_binary`].
    pub fn from_env(service: MeteredService) -> Result<Option<Self>> {
        match std::env::var(service.base_url_env()) {
            Ok(value) if !value.trim().is_empty() => Self::new(service, value).map(Some),
            _ => Ok(None),
        }
    }

    #[must_use]
    pub fn service(&self) -> MeteredService {
        self.service
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    #[must_use]
    pub fn metrics_url(&self) -> String {
        format!("{}/metrics", self.base_url)
    }

    /// Scrape and parse `GET /metrics`.
    pub async fn snapshot(&self) -> Result<MetricsSnapshot> {
        let url = self.metrics_url();
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("{} GET {url}", self.service.name()))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .with_context(|| format!("{} GET {url} body", self.service.name()))?;
        if !status.is_success() {
            bail!("{} GET {url} returned HTTP {status}", self.service.name());
        }
        Ok(MetricsSnapshot::parse(&body))
    }

    /// `authority_network_call_count`: `*_did_resolve_total{source="network"}`,
    /// optionally narrowed to one DID `method` label.
    pub async fn authority_network_call_count(&self, method: Option<&str>) -> Result<u64> {
        Ok(authority_calls(
            &self.snapshot().await?,
            self.service,
            method,
        ))
    }

    /// `signature_verify_count`: `*_signature_verify_total` over every label.
    pub async fn signature_verify_count(&self) -> Result<u64> {
        Ok(signature_verifies(&self.snapshot().await?, self.service))
    }

    /// Run `body` and report the DID-boundary counter increments it caused.
    ///
    /// Increments, not absolutes: the counters are process-lifetime totals and
    /// other scenarios share the process, so only a before/after delta is a
    /// statement about `body`.
    pub async fn measure_did_boundary<F, Fut, T>(
        &self,
        method: Option<&str>,
        body: F,
    ) -> Result<(T, DidBoundaryDelta)>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let before = self.snapshot().await?;
        let value = body().await?;
        let after = self.snapshot().await?;
        Ok((value, diff(&before, &after, self.service, method)))
    }

    /// Assert `body` caused zero additional authority network calls, and return
    /// the `signature_verify_count` alongside the value so the scenario can
    /// record both numbers as DID-P1-C02 requires.
    ///
    /// This is the metrics-backed twin of
    /// [`super::did_host::DidHostClient::expect_no_additional_authority_calls`].
    pub async fn expect_no_additional_authority_calls<F, Fut, T>(
        &self,
        method: Option<&str>,
        label: &str,
        body: F,
    ) -> Result<(T, DidBoundaryDelta)>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        self.expect_authority_calls(0, method, label, body).await
    }

    /// Assert `body` caused exactly `expected` additional authority network
    /// calls (the *first* acceptance of a DID legitimately costs one).
    pub async fn expect_authority_calls<F, Fut, T>(
        &self,
        expected: u64,
        method: Option<&str>,
        label: &str,
        body: F,
    ) -> Result<(T, DidBoundaryDelta)>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let before = self.snapshot().await?;
        let value = body().await?;
        let after = self.snapshot().await?;
        let delta = diff(&before, &after, self.service, method);
        if delta.authority_network_call_count != expected {
            let scope = method
                .map(|method| format!(" for method={method}"))
                .unwrap_or_default();
            bail!(
                "{label}: expected {expected} {} authority network call(s){scope}, saw {}. \
                 signature_verify_count delta was {}. before={:?} after={:?}",
                self.service.name(),
                delta.authority_network_call_count,
                delta.signature_verify_count,
                before.series(self.service.did_resolve_metric()),
                after.series(self.service.did_resolve_metric()),
            );
        }
        Ok((value, delta))
    }
}

/// `*_did_resolve_total{source="network"}` in `snapshot`, optionally narrowed
/// to one `method`.
#[must_use]
pub fn authority_calls(
    snapshot: &MetricsSnapshot,
    service: MeteredService,
    method: Option<&str>,
) -> u64 {
    let mut selector = vec![("source", SOURCE_NETWORK)];
    if let Some(method) = method {
        selector.push(("method", method));
    }
    snapshot.sum(service.did_resolve_metric(), &selector) as u64
}

/// `*_signature_verify_total` in `snapshot`, summed over every label.
#[must_use]
pub fn signature_verifies(snapshot: &MetricsSnapshot, service: MeteredService) -> u64 {
    snapshot.sum(service.signature_verify_metric(), &[]) as u64
}

/// Counter increments between two snapshots.
#[must_use]
pub fn diff(
    before: &MetricsSnapshot,
    after: &MetricsSnapshot,
    service: MeteredService,
    method: Option<&str>,
) -> DidBoundaryDelta {
    DidBoundaryDelta {
        authority_network_call_count: authority_calls(after, service, method)
            .saturating_sub(authority_calls(before, service, method)),
        signature_verify_count: signature_verifies(after, service)
            .saturating_sub(signature_verifies(before, service)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COLAND_SAMPLE: &str = "\
# HELP coland_did_resolve_total DID document acquisitions.
# TYPE coland_did_resolve_total counter
coland_did_resolve_total{method=\"key\",source=\"sdk_cache\"} 12
coland_did_resolve_total{method=\"webvh\",source=\"binding_store\"} 7
coland_did_resolve_total{method=\"webvh\",source=\"network\"} 2
coland_did_resolve_total{method=\"web\",source=\"network\"} 1
# TYPE coland_signature_verify_total counter
coland_signature_verify_total{scheme=\"ed25519_accepted_binding\",outcome=\"success\"} 40
coland_signature_verify_total{scheme=\"ed25519_pinned_document\",outcome=\"failure\"} 2
coland_http_requests_total{op=\"events_submit\",status=\"200\"} 99
";

    #[test]
    fn network_source_is_the_only_authority_call() {
        let snapshot = MetricsSnapshot::parse(COLAND_SAMPLE);
        // 2 (webvh) + 1 (web); the 12 sdk_cache and 7 binding_store hits are
        // exactly what "reused the accepted binding" means and must not count.
        assert_eq!(authority_calls(&snapshot, MeteredService::Coland, None), 3);
        assert_eq!(
            authority_calls(&snapshot, MeteredService::Coland, Some("webvh")),
            2
        );
    }

    #[test]
    fn signature_verify_count_sums_every_label() {
        let snapshot = MetricsSnapshot::parse(COLAND_SAMPLE);
        assert_eq!(signature_verifies(&snapshot, MeteredService::Coland), 42);
    }

    #[test]
    fn an_absent_series_reads_as_zero_but_is_detectable() {
        let snapshot = MetricsSnapshot::parse(COLAND_SAMPLE);
        assert_eq!(authority_calls(&snapshot, MeteredService::Flagon, None), 0);
        assert!(!snapshot.has_metric(FLAGON_DID_RESOLVE_TOTAL));
        assert!(snapshot.has_metric(COLAND_DID_RESOLVE_TOTAL));
    }

    #[test]
    fn the_delta_is_what_a_scenario_asserts_on() {
        let before = MetricsSnapshot::parse(COLAND_SAMPLE);
        let after = MetricsSnapshot::parse(
            "coland_did_resolve_total{method=\"webvh\",source=\"network\"} 2\n\
             coland_did_resolve_total{method=\"web\",source=\"network\"} 1\n\
             coland_signature_verify_total{scheme=\"ed25519_accepted_binding\",outcome=\"success\"} 42\n\
             coland_signature_verify_total{scheme=\"ed25519_pinned_document\",outcome=\"failure\"} 2\n",
        );
        assert_eq!(
            diff(&before, &after, MeteredService::Coland, None),
            DidBoundaryDelta {
                authority_network_call_count: 0,
                signature_verify_count: 2,
            }
        );
    }

    #[test]
    fn flagon_families_parse_the_same_way() {
        let snapshot = MetricsSnapshot::parse(
            "flagon_did_resolve_total{method=\"web\",source=\"binding_store\"} 5\n\
             flagon_did_resolve_total{method=\"web\",source=\"network\"} 1\n\
             flagon_did_resolve_total{method=\"key\",source=\"did_key\"} 3\n\
             flagon_signature_verify_total{kind=\"invite_token\",outcome=\"ok\"} 4\n\
             flagon_signature_verify_total{kind=\"invite_token\",outcome=\"no_binding\"} 1\n",
        );
        assert_eq!(authority_calls(&snapshot, MeteredService::Flagon, None), 1);
        assert_eq!(signature_verifies(&snapshot, MeteredService::Flagon), 5);
    }

    #[test]
    fn label_values_containing_commas_and_quotes_survive_parsing() {
        let snapshot = MetricsSnapshot::parse(
            "flagon_did_resolve_total{method=\"web\",source=\"network\",note=\"a,b\\\"c\"} 4\n",
        );
        let sample = &snapshot.samples()[0];
        assert_eq!(
            sample.labels.get("note").map(String::as_str),
            Some("a,b\"c")
        );
        assert_eq!(
            sample.labels.get("source").map(String::as_str),
            Some("network")
        );
        assert_eq!(authority_calls(&snapshot, MeteredService::Flagon, None), 4);
    }

    #[test]
    fn help_and_type_lines_are_not_samples() {
        let snapshot = MetricsSnapshot::parse(COLAND_SAMPLE);
        assert!(
            snapshot
                .samples()
                .iter()
                .all(|sample| !sample.name.starts_with('#'))
        );
        assert_eq!(snapshot.series(COLAND_DID_RESOLVE_TOTAL).len(), 4);
    }

    #[test]
    fn a_url_that_already_ends_in_metrics_is_not_doubled() {
        let client =
            ServiceMetricsClient::new(MeteredService::Coland, "http://127.0.0.1:9090/metrics")
                .unwrap();
        assert_eq!(client.metrics_url(), "http://127.0.0.1:9090/metrics");
        let bare =
            ServiceMetricsClient::new(MeteredService::Flagon, "http://127.0.0.1:9095/").unwrap();
        assert_eq!(bare.metrics_url(), "http://127.0.0.1:9095/metrics");
    }
}
