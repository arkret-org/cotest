//! Round-27 / C32.8 — black-box webvh conformance suite.
//!
//! Spawns a real `starid` binary on a random local port and exercises 5 webvh
//! conformance vectors via plain HTTP. The binary is located via the
//! `STARID_BIN` env var (explicit override) or the conventional sibling
//! checkout path (`cokret/starid/target/debug/starid[.exe]`).
//!
//! The thin test wrapper at `tests/webvh_blackbox.rs` is `#[ignore]`'d so CI
//! runners without a built starid binary do not flake; locally, run with
//! `cargo test --test webvh_blackbox -- --ignored` after building starid.

use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::scenarios::_helpers::external_binary::{STARID_SPEC, spawn_required};

/// Spawn a `starid` binary and assert 4 webvh conformance vectors:
///   1. /health              — liveness pings 200
///   2. /_cokret/root/identity/describe — exposes profile/contract metadata
///   3. /openapi.yaml        — published openapi document is reachable
///   4. negative GET on POST-only `/_cokret/root/webvh/dids` returns 404 or 405
///
/// STA-07-002: the legacy starid `/describe` liveness probe (asserting
/// `supported_methods` advertises `did:webvh`) has been removed — that route no
/// longer exists; canonical discovery strands exclusively through
/// `/_cokret/root/identity/describe`.
pub async fn webvh_blackbox_conformance_vectors_run() -> Result<()> {
    let proc = spawn_required(&STARID_SPEC)
        .await
        .context("spawn starid binary for webvh black-box test")?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    // ── Vector 1: liveness ────────────────────────────────────────────────
    let resp = client.get(proc.url("/health")).send().await?;
    if !resp.status().is_success() {
        bail!("/health returned {}", resp.status());
    }
    let body: serde_json::Value = resp.json().await?;
    if body.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        bail!("/health did not report ok=true: {body}");
    }

    // ── Vector 2: /_cokret/root/identity/describe surfaces profile metadata ─────
    let resp = client
        .get(proc.url("/_cokret/root/identity/describe"))
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("/_cokret/root/identity/describe returned {}", resp.status());
    }
    let body: serde_json::Value = resp.json().await?;
    let has_profile_metadata = body.get("profiles").is_some()
        || body.get("profile").is_some()
        || body.get("contract").is_some();
    if !has_profile_metadata {
        bail!("identity/describe missing profile/profiles/contract: {body}");
    }

    // ── Vector 3: /openapi.yaml is reachable + non-empty ──────────────────
    let resp = client.get(proc.url("/openapi.yaml")).send().await?;
    if !resp.status().is_success() {
        bail!("/openapi.yaml returned {}", resp.status());
    }
    let text = resp.text().await?;
    if text.is_empty() || !text.contains("openapi") {
        bail!("/openapi.yaml body did not contain openapi marker");
    }

    // ── Vector 4: GET on a POST-only route surfaces 405/404 ───────────────
    let resp = client
        .get(proc.url("/_cokret/root/webvh/dids"))
        .send()
        .await?;
    let status = resp.status().as_u16();
    if !(status == 405 || status == 404) {
        bail!(
            "GET /_cokret/root/webvh/dids expected 405 (method not allowed) or 404, got {status}"
        );
    }

    Ok(())
}
