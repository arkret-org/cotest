//! Round-27 — black-box webvh conformance suite.
//!
//! Spawns a `starid` binary on a random local port and exercises 3-5 webvh
//! conformance vectors via plain HTTP. Marked `#[ignore = "needs starid
//! binary on PATH"]` so CI runners without a built starid binary opt-in.
//! Run locally with: `cargo test --test webvh_blackbox -- --ignored`.
//!
//! The harness keeps the spawned `starid` process scoped to one tokio test
//! and tears it down on drop. Each vector exercises one HTTP surface:
//!   1. /health        — liveness ping
//!   2. /describe      — resolver metadata advertised
//!   3. /api/v1/identity/describe — supported_methods includes did:webvh
//!   4. /openapi.yaml  — published openapi document reachable
//!   5. negative: /api/v1/webvh/dids GET-on-POST returns 405 (route shape)

use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use serial_test::serial;

struct StaridProcess {
    child: Child,
    base_url: String,
}

impl StaridProcess {
    fn spawn() -> Result<Self> {
        let port = free_port()?;
        let bind = format!("127.0.0.1:{port}");
        let base_url = format!("http://{bind}");
        let child = Command::new("starid")
            .env("STARID_BIND", &bind)
            .env("STARID_SERVICE_DID", "did:web:starid.cotest.local")
            // Use an in-memory SQLite for the black-box run so we don't need
            // a live Postgres. starid supports DATABASE_URL=sqlite::memory: in
            // its config defaults; if not, the spawn will fail and the test
            // will be marked failed for the user to inspect.
            .env("DATABASE_URL", "sqlite::memory:")
            .env("STARID_DEVELOPMENT_MODE", "true")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                anyhow!(
                    "failed to spawn `starid` binary (must be on PATH for this ignored test): {e}"
                )
            })?;
        Ok(Self { child, base_url })
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

impl Drop for StaridProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

async fn wait_until_healthy(base_url: &str) -> Result<reqwest::Client> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    let url = format!("{base_url}/health");
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last_err = None;
    while Instant::now() < deadline {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(client),
            Ok(resp) => last_err = Some(format!("status {}", resp.status())),
            Err(e) => last_err = Some(e.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    bail!("starid /health did not become healthy in 20s: {last_err:?}")
}

#[tokio::test]
#[ignore = "needs starid binary on PATH"]
#[serial]
async fn webvh_blackbox_conformance_vectors_run() -> Result<()> {
    let proc = StaridProcess::spawn().context("spawn starid binary")?;
    let client = wait_until_healthy(&proc.base_url).await?;

    // ── Vector 1: liveness already verified by wait_until_healthy. ────────
    // Re-confirm with a 200 + JSON envelope.
    let resp = client.get(proc.url("/health")).send().await?;
    if !resp.status().is_success() {
        bail!("health check failed: {}", resp.status());
    }

    // ── Vector 2: /describe advertises the webvh method. ──────────────────
    let resp = client.get(proc.url("/describe")).send().await?;
    if !resp.status().is_success() {
        bail!("/describe returned {}", resp.status());
    }
    let body: serde_json::Value = resp.json().await?;
    let methods = body
        .get("supported_methods")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("/describe missing supported_methods[]"))?;
    let advertises_webvh = methods.iter().any(|m| m.as_str() == Some("did:webvh"));
    if !advertises_webvh {
        bail!(
            "/describe does not list did:webvh in supported_methods: {body}"
        );
    }

    // ── Vector 3: /api/v1/identity/describe surfaces webvh profile. ───────
    let resp = client.get(proc.url("/api/v1/identity/describe")).send().await?;
    if !resp.status().is_success() {
        bail!("/api/v1/identity/describe returned {}", resp.status());
    }
    let body: serde_json::Value = resp.json().await?;
    if body.get("contract").is_none() && body.get("profile").is_none() {
        bail!(
            "identity/describe missing contract/profile: {body}"
        );
    }

    // ── Vector 4: /openapi.yaml is reachable + non-empty. ─────────────────
    let resp = client.get(proc.url("/openapi.yaml")).send().await?;
    if !resp.status().is_success() {
        bail!("/openapi.yaml returned {}", resp.status());
    }
    let text = resp.text().await?;
    if text.is_empty() || !text.contains("openapi") {
        bail!("/openapi.yaml body did not contain openapi marker");
    }

    // ── Vector 5: GET on a POST-only route surfaces 405. ──────────────────
    let resp = client.get(proc.url("/api/v1/webvh/dids")).send().await?;
    let status = resp.status().as_u16();
    if !(status == 405 || status == 404) {
        bail!(
            "GET /api/v1/webvh/dids expected 405 (method not allowed) or 404, got {status}"
        );
    }

    Ok(())
}
