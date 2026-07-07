//! C34.3 — orchestrate a fully-spawnable `floria` push gateway for the
//! bridge-contract matrix.
//!
//! Unlike coauth, floria has **no** external runtime dependencies — it just
//! needs a YAML/KDL config wired with at least one app. We render a minimal
//! YAML on the fly (one `custom` pushkin pointed at a sink URL) and spawn
//! floria directly with `FLORIA_CONF` exported so its `Config::load`
//! picks up our temp file.
//!
//! Returns `Ok(None)` if the floria binary cannot be located, mirroring the
//! coauth bootstrap's contract so the bridge matrix can fall back to the
//! synthetic placeholder rows on stripped-down CI runners.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tempfile::NamedTempFile;

use crate::harness::reserve_port;
use crate::scenarios::_helpers::external_binary::{
    ExternalBinarySpec, SpawnedExternalProcess, locate_external_binary,
};

/// Aggregated handle for a spawned floria: rendered config + server.
pub struct SpawnedFloria {
    pub server: SpawnedExternalProcess,
    /// Held so the file isn't deleted while floria is running.
    #[allow(dead_code)]
    pub config: NamedTempFile,
}

impl SpawnedFloria {
    pub fn base_url(&self) -> &str {
        &self.server.base_url
    }
}

/// Render a minimal floria YAML config bound to `127.0.0.1:<port>` with a
/// single `custom` pushkin so `PushkinRegistry::from_config` does not bail
/// on the empty-apps guard. Callers can pass a per-run receiver URL; otherwise
/// the config uses a placeholder 127.0.0.1 sink for health-only bootstraps.
/// The rendered config disables all auth gates (notify_auth, dedup,
/// rate-limits) — production-mode guards are off so `Config::validate` passes
/// without any extra knobs.
pub fn render_floria_config(
    bind_port: u16,
    custom_pushkin_url: Option<&str>,
) -> Result<NamedTempFile> {
    // The custom pushkin only needs a URL. Health-only callers use a
    // placeholder sink that is never reached; CT-7 passes its mock receiver.
    //
    // `notify_dedup_ttl_seconds: 0` disables the dedup backend entirely so
    // the redis branch isn't reached.
    let custom_pushkin_url = custom_pushkin_url.unwrap_or("http://127.0.0.1:1/cotest-floria-sink");
    let body = format!(
        "http:\n  bind_addresses:\n    - 127.0.0.1\n  port: {bind_port}\n  notify_dedup_ttl_seconds: 0\n  notify_dedup:\n    backend: memory\n    key_prefix: cotest-floria\n  notify_auth: {{}}\n  notify_rate_limits:\n    window_seconds: 60\n\napps:\n  cotest.placeholder:\n    type: custom\n    url: {custom_pushkin_url}\n"
    );

    let mut tmp = tempfile::Builder::new()
        .prefix("cotest-floria-")
        .suffix(".yaml")
        .tempfile()
        .context("failed to create temp file for floria config")?;
    tmp.write_all(body.as_bytes())
        .context("failed to write floria config")?;
    tmp.flush().ok();
    Ok(tmp)
}

/// Top-level orchestrator: render config → spawn floria → wait for /health.
///
/// Returns `Ok(None)` if the floria binary is missing or fails to come up.
pub async fn spawn_floria_with_config() -> Result<Option<SpawnedFloria>> {
    spawn_floria_with_custom_pushkin_url(None).await
}

/// Spawn floria using either the default placeholder pushkin URL or a
/// caller-supplied mock receiver URL.
pub async fn spawn_floria_with_custom_pushkin_url(
    custom_pushkin_url: Option<&str>,
) -> Result<Option<SpawnedFloria>> {
    let probe_spec = ExternalBinarySpec {
        service: "floria",
        bin_env: "FLORIA_BIN",
        sibling_path: &["floria", "target", "debug"],
        bind_env: "",
        bind_arg: None,
        extra_env: &[],
        extra_args: &[],
        required_env_vars: &[],
        health_path: "/health",
        health_timeout: Duration::from_secs(20),
    };
    let floria_bin: PathBuf = match locate_external_binary(&probe_spec) {
        Some(p) => p,
        None => return Ok(None),
    };

    let mut bind_port = match reserve_port() {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };
    let bind_addr = format!("127.0.0.1:{}", bind_port.port());
    let config_file = match render_floria_config(bind_port.port(), custom_pushkin_url) {
        Ok(f) => f,
        Err(_) => return Ok(None),
    };

    // Spawn floria directly. We pass FLORIA_CONF as an env var for the
    // child only, so concurrent test threads don't race over the parent
    // process's environment (the bridge_contracts suite is `serial_test`-
    // serialised, but other suites may run in parallel).
    let mut command = Command::new(&floria_bin);
    command
        .env("FLORIA_CONF", config_file.path())
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    bind_port.release();
    let child = match command.spawn() {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    let base_url = format!("http://{bind_addr}");
    let server =
        SpawnedExternalProcess::from_child(base_url.clone(), floria_bin, child, vec![bind_port]);

    if !wait_for_health(&base_url, Duration::from_secs(30)).await {
        return Ok(None);
    }

    Ok(Some(SpawnedFloria {
        server,
        config: config_file,
    }))
}

async fn wait_for_health(base_url: &str, timeout: Duration) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    let url = format!("{base_url}/health");
    let cutoff = Instant::now() + timeout;
    while Instant::now() < cutoff {
        if let Ok(resp) = client.get(&url).send().await
            && resp.status().is_success()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    false
}
