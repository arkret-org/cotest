//! Rust-side access to the counting DID authority (DID-P1-C01).
//!
//! Two independent pieces live here, for the two kinds of Rust scenario:
//!
//! 1. [`DidHostClient`] — an HTTP client for `e2e/mocks/mock-did-host.mjs`. Rust scenarios read the
//!    *same* counters the TypeScript specs read (`e2e/helpers/did-host.ts`), so a cross-process
//!    claim like "this operation made zero additional authority network calls" means the same thing
//!    on both sides. cotest has no Cargo dependency on soland / teabay / coauth / starid / floria
//!    (they are pre-built sibling binaries driven over HTTP — see [`super::external_binary`]), so
//!    the wire is the only place their DID fetches are observable.
//!
//! 2. [`CountingDidResolver`] — an in-process [`DidResolver`] spy for scenarios that exercise the
//!    SDK directly and never leave the process. It answers from a preloaded document table and
//!    counts resolutions per DID.
//!
//! Follows the timeout convention of [`super::http`] (bounded connect/request
//! timeouts so an unresponsive mock cannot hang CI).

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, Result, bail};
use arkret::identity::{DidDocument, DidResolver};
use arkret_wire::Did;
use serde::Deserialize;

use crate::harness::NonProtocolTestBody;

/// Env var the joint runner exports when `-StartMockDidHost` is used.
pub const DID_HOST_BASE_URL_ENV: &str = "COTEST_MOCK_DID_HOST_BASE_URL";

/// Per-purpose fetch counters for one DID. `total` is that DID's
/// `authority_network_call_count`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
pub struct DidHostCounts {
    /// `did.json` fetches.
    pub document: u64,
    /// `did.jsonl` fetches (did:webvh log).
    pub log: u64,
    /// `did-witness.json` fetches.
    pub witness: u64,
    pub total: u64,
}

/// Body of `GET /inspect/counts`.
#[derive(Clone, Debug, Deserialize)]
pub struct DidHostCountsResponse {
    pub service: String,
    pub now: String,
    /// Sum over every reported DID.
    pub total: u64,
    pub counts: BTreeMap<String, DidHostCounts>,
}

impl DidHostCountsResponse {
    /// Counters for `did`, or all-zero when it has not been fetched.
    #[must_use]
    pub fn for_did(&self, did: &str) -> DidHostCounts {
        self.counts.get(did).copied().unwrap_or_default()
    }
}

/// One registered DID from `GET /control/dids`.
#[derive(Clone, Debug, Deserialize)]
pub struct DidHostDid {
    pub did: String,
    pub method: String,
    pub authority: String,
    pub base_path: String,
    pub scid: Option<String>,
    pub version_index: usize,
    pub version_id: String,
    pub version_count: usize,
    pub deactivated: bool,
}

#[derive(Debug, Deserialize)]
struct DidHostDidList {
    dids: Vec<DidHostDid>,
}

#[derive(Debug, Deserialize)]
struct DidHostControlOutcome {
    did: DidHostDid,
}

/// HTTP client for the mock DID authority.
pub struct DidHostClient {
    base_url: String,
    http: reqwest::Client,
}

impl DidHostClient {
    /// Build a client for `base_url` (trailing slash tolerated).
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            http: super::http::live_probe_client()?,
        })
    }

    /// Build from `COTEST_MOCK_DID_HOST_BASE_URL`, or `Ok(None)` when the mock
    /// is not part of this run — scenarios skip rather than fail, matching the
    /// `try_spawn` convention in [`super::external_binary`].
    pub fn from_env() -> Result<Option<Self>> {
        match std::env::var(DID_HOST_BASE_URL_ENV) {
            Ok(value) if !value.trim().is_empty() => Self::new(value.trim()).map(Some),
            _ => Ok(None),
        }
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Zero every counter and clear the forensic fetch log.
    pub async fn reset_counts(&self) -> Result<()> {
        let response = self
            .http
            .post(format!("{}/inspect/reset", self.base_url))
            .send()
            .await
            .context("mock-did-host POST /inspect/reset")?;
        if !response.status().is_success() {
            bail!(
                "mock-did-host POST /inspect/reset returned HTTP {}",
                response.status()
            );
        }
        Ok(())
    }

    /// Full counter snapshot, optionally narrowed to one DID.
    pub async fn counts(&self, did: Option<&str>) -> Result<DidHostCountsResponse> {
        let mut url = format!("{}/inspect/counts", self.base_url);
        if let Some(did) = did {
            url.push_str("?did=");
            url.push_str(&urlencode(did));
        }
        let response = self
            .http
            .get(url)
            .send()
            .await
            .context("mock-did-host GET /inspect/counts")?;
        if !response.status().is_success() {
            bail!(
                "mock-did-host GET /inspect/counts returned HTTP {}",
                response.status()
            );
        }
        response
            .json::<DidHostCountsResponse>()
            .await
            .context("decoding mock-did-host counts")
    }

    /// `authority_network_call_count`: total authority fetches for `did`, or
    /// across every DID when `did` is `None` (this includes the
    /// `<unresolved>` bucket for fetches that matched no registered DID).
    pub async fn authority_network_call_count(&self, did: Option<&str>) -> Result<u64> {
        let snapshot = self.counts(did).await?;
        Ok(match did {
            Some(did) => snapshot.for_did(did).total,
            None => snapshot.total,
        })
    }

    /// Registered DIDs and their current version / lifecycle state.
    pub async fn list_dids(&self) -> Result<Vec<DidHostDid>> {
        let response = self
            .http
            .get(format!("{}/control/dids", self.base_url))
            .send()
            .await
            .context("mock-did-host GET /control/dids")?;
        if !response.status().is_success() {
            bail!(
                "mock-did-host GET /control/dids returned HTTP {}",
                response.status()
            );
        }
        Ok(response
            .json::<DidHostDidList>()
            .await
            .context("decoding mock-did-host DID list")?
            .dids)
    }

    /// Advance `did` to the next preset version.
    pub async fn rotate(&self, did: &str) -> Result<DidHostDid> {
        self.control("/control/rotate", serde_json::json!({ "did": did }))
            .await
    }

    /// Serve a deactivated document (and a final log entry) for `did`.
    pub async fn deactivate(&self, did: &str) -> Result<DidHostDid> {
        self.control("/control/deactivate", serde_json::json!({ "did": did }))
            .await
    }

    /// Force fetches for `did` to fail with `status`; `None` clears it.
    pub async fn force_status(&self, did: &str, status: Option<u16>) -> Result<DidHostDid> {
        self.control(
            "/control/fail",
            serde_json::json!({ "did": did, "status": status }),
        )
        .await
    }

    /// Restore every DID to version 0 / active / no override. Counters are
    /// untouched — call [`Self::reset_counts`] for those.
    pub async fn reset_documents(&self) -> Result<()> {
        let response = self
            .http
            .post(format!("{}/control/reset", self.base_url))
            .send()
            .await
            .context("mock-did-host POST /control/reset")?;
        if !response.status().is_success() {
            bail!(
                "mock-did-host POST /control/reset returned HTTP {}",
                response.status()
            );
        }
        Ok(())
    }

    /// Reset the counters, run `body`, and return its value alongside the
    /// authority-call count the operation caused. The Rust twin of
    /// `measureAuthorityCalls` in `e2e/helpers/did-host.ts`.
    pub async fn measure_authority_calls<F, Fut, T>(
        &self,
        did: Option<&str>,
        body: F,
    ) -> Result<(T, u64)>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        self.reset_counts().await?;
        let value = body().await?;
        let observed = self.authority_network_call_count(did).await?;
        Ok((value, observed))
    }

    /// Assert `body` caused zero additional authority fetches.
    pub async fn expect_no_additional_authority_calls<F, Fut, T>(
        &self,
        did: Option<&str>,
        label: &str,
        body: F,
    ) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let (value, observed) = self.measure_authority_calls(did, body).await?;
        if observed != 0 {
            let snapshot = self.counts(did).await?;
            bail!(
                "{label}: expected 0 authority network calls{}, saw {observed}. counts: {:?}",
                did.map(|did| format!(" for {did}")).unwrap_or_default(),
                snapshot.counts
            );
        }
        Ok(value)
    }

    async fn control(&self, path: &str, body: serde_json::Value) -> Result<DidHostDid> {
        let body = NonProtocolTestBody::new(body);
        let response = self
            .http
            .post(format!("{}{path}", self.base_url))
            .json(&body)
            .send()
            .await
            .with_context(|| format!("mock-did-host POST {path}"))?;
        let status = response.status();
        if !status.is_success() {
            let detail = response.text().await.unwrap_or_default();
            bail!("mock-did-host POST {path} returned HTTP {status}: {detail}");
        }
        Ok(response
            .json::<DidHostControlOutcome>()
            .await
            .with_context(|| format!("decoding mock-did-host {path} outcome"))?
            .did)
    }
}

/// Percent-encode the characters that matter in a DID query value. DIDs are
/// `:`-separated ASCII, so this only has to cover the reserved delimiters that
/// would otherwise terminate the value.
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

// ── in-process spy ────────────────────────────────────────────────────────

/// In-process [`DidResolver`] spy for pure-SDK Rust scenarios.
///
/// Answers from a preloaded document table and counts every resolution per
/// DID, so a scenario can assert "the second verification reused the cached
/// document" without any network at all. Cross-process scenarios must use
/// [`DidHostClient`] instead — this spy only sees calls made inside the cotest
/// process.
///
/// Counters are interior-mutable because [`DidResolver::resolve_did`] takes
/// `&self`.
#[derive(Debug, Default)]
pub struct CountingDidResolver {
    documents: Mutex<BTreeMap<String, DidDocument>>,
    /// Per-DID resolution count, including misses.
    calls: Mutex<BTreeMap<String, usize>>,
    total: AtomicUsize,
}

impl CountingDidResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Preload `document` as the answer for its own `id`.
    pub fn with_document(self, document: DidDocument) -> Self {
        self.insert(document);
        self
    }

    /// Preload (or replace) a document.
    pub fn insert(&self, document: DidDocument) {
        self.documents
            .lock()
            .expect("CountingDidResolver documents mutex poisoned")
            .insert(document.id.as_str().to_owned(), document);
    }

    /// Resolutions attempted for `did` (hits and misses alike).
    #[must_use]
    pub fn calls_for(&self, did: &str) -> usize {
        self.calls
            .lock()
            .expect("CountingDidResolver calls mutex poisoned")
            .get(did)
            .copied()
            .unwrap_or(0)
    }

    /// Total resolutions across every DID — the in-process analogue of
    /// `authority_network_call_count`.
    #[must_use]
    pub fn total_calls(&self) -> usize {
        self.total.load(Ordering::SeqCst)
    }

    /// Per-DID call counts.
    #[must_use]
    pub fn snapshot(&self) -> BTreeMap<String, usize> {
        self.calls
            .lock()
            .expect("CountingDidResolver calls mutex poisoned")
            .clone()
    }

    /// Zero the counters, keeping the preloaded documents.
    pub fn reset(&self) {
        self.calls
            .lock()
            .expect("CountingDidResolver calls mutex poisoned")
            .clear();
        self.total.store(0, Ordering::SeqCst);
    }
}

impl DidResolver for CountingDidResolver {
    fn supports(&self, did: &Did) -> bool {
        matches!(did.method(), "web" | "webvh" | "key")
    }

    fn resolve_did(&self, did: &Did) -> arkret::identity::Result<arkret::identity::ResolvedDid> {
        *self
            .calls
            .lock()
            .expect("CountingDidResolver calls mutex poisoned")
            .entry(did.as_str().to_owned())
            .or_insert(0) += 1;
        self.total.fetch_add(1, Ordering::SeqCst);
        self.documents
            .lock()
            .expect("CountingDidResolver documents mutex poisoned")
            .get(did.as_str())
            .cloned()
            // The counting helper serves preloaded documents from memory and
            // runs no method verification, so it surfaces no method evidence.
            .map(arkret::identity::ResolvedDid::proofless)
            .ok_or_else(|| {
                arkret::identity::IdentityError::Protocol(format!(
                    "CountingDidResolver has no preloaded document for {did}",
                    did = did.as_str()
                ))
            })
    }
}
