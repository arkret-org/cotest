//! C32.8 — shared spawn helper for sibling-checkout binaries (`starid`,
//! `coauth`, `floria`, etc.) used by black-box scenarios.
//!
//! The helper:
//!   1. Resolves the binary path from an explicit env var override (e.g.
//!      `STARID_BIN`) **first**, then falls back to a sibling-checkout
//!      convention path (`../<crate>/target/debug/<bin>[.exe]` relative to the
//!      cotest workspace root).
//!   2. Allocates a free local port and exports it back to the caller via the
//!      configured bind env var (e.g. `STARID_BIND`).
//!   3. Spawns the child with `stdout` / `stderr` swallowed (Stdio::null) so
//!      cargo test output stays readable; long-form troubleshooting can re-run
//!      with the binary directly.
//!   4. Waits for `/health` (or any caller-supplied liveness path) to return
//!      2xx, with a deadline; returns a `SpawnedExternalProcess` whose `Drop`
//!      kills the child + reaps it so tokio test threads can't leak orphans.
//!
//! `try_spawn` returns `Ok(None)` when the binary cannot be located. Callers
//! that want a hard failure (e.g. when the user explicitly opted in via
//! `--ignored`) should `bail!` on `None`. Callers that want a soft skip path
//! (e.g. a baseline conformance row) can early-return on `None`.

use std::{
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use reqwest::Client;

/// Configuration for spawning a sibling-checkout binary.
pub struct ExternalBinarySpec {
    /// Logical service name used in error messages (e.g. `"starid"`).
    pub service: &'static str,
    /// Env var that, when set, overrides the binary path
    /// (e.g. `"STARID_BIN"`).
    pub bin_env: &'static str,
    /// Sibling-checkout convention path segments under `contrix-dev/`
    /// (e.g. `&["starid", "target", "debug"]`). The binary file name is
    /// derived from `service` (`+ ".exe"` on Windows).
    pub sibling_path: &'static [&'static str],
    /// Env var that controls the bind address (e.g. `"STARID_BIND"`).
    pub bind_env: &'static str,
    /// Extra environment variables to inject into the child process
    /// (e.g. `&[("STARID_DEVELOPMENT_MODE", "true")]`).
    pub extra_env: &'static [(&'static str, &'static str)],
    /// Liveness probe path relative to base URL (e.g. `"/health"`).
    pub health_path: &'static str,
    /// Maximum time to wait for the liveness probe to succeed.
    pub health_timeout: Duration,
}

/// A spawned child process bound to a known base URL. Drop kills + reaps.
pub struct SpawnedExternalProcess {
    pub base_url: String,
    pub bin_path: PathBuf,
    child: Option<Child>,
}

impl SpawnedExternalProcess {
    pub fn url(&self, path: &str) -> String {
        if path.starts_with('/') {
            format!("{}{path}", self.base_url)
        } else {
            format!("{}/{path}", self.base_url)
        }
    }
}

impl Drop for SpawnedExternalProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Try to locate `<service>` binary by checking the `bin_env` override first,
/// then the conventional sibling-checkout path. Returns `None` when neither is
/// available — callers decide whether to skip or fail.
pub fn locate_external_binary(spec: &ExternalBinarySpec) -> Option<PathBuf> {
    if let Ok(value) = std::env::var(spec.bin_env)
        && !value.trim().is_empty()
    {
        let candidate = PathBuf::from(value);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    let exe_name = if cfg!(windows) {
        format!("{}.exe", spec.service)
    } else {
        spec.service.to_owned()
    };
    let mut candidate = workspace_root()?;
    for segment in spec.sibling_path {
        candidate.push(segment);
    }
    candidate.push(exe_name);
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

/// Spawn the binary if locatable, wait until healthy, and return the handle.
/// Returns `Ok(None)` when the binary cannot be located.
pub async fn try_spawn(spec: &ExternalBinarySpec) -> Result<Option<SpawnedExternalProcess>> {
    let Some(bin_path) = locate_external_binary(spec) else {
        return Ok(None);
    };
    let port = free_port()?;
    let bind = format!("127.0.0.1:{port}");
    let base_url = format!("http://{bind}");

    let mut command = Command::new(&bin_path);
    command
        .env(spec.bind_env, &bind)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for &(key, value) in spec.extra_env {
        command.env(key, value);
    }

    let child = command.spawn().with_context(|| {
        format!(
            "failed to spawn `{}` binary at {}",
            spec.service,
            bin_path.display()
        )
    })?;

    // Wrap the child immediately so any early-return below kills it via Drop.
    let handle = SpawnedExternalProcess {
        base_url: base_url.clone(),
        bin_path,
        child: Some(child),
    };

    wait_until_healthy(&base_url, spec.health_path, spec.health_timeout)
        .await
        .with_context(|| format!("`{}` failed liveness probe", spec.service))?;

    Ok(Some(handle))
}

/// Spawn or fail loudly with an explanatory message — for `#[ignore]` tests
/// that are explicitly opted into and should not silently skip.
pub async fn spawn_required(spec: &ExternalBinarySpec) -> Result<SpawnedExternalProcess> {
    match try_spawn(spec).await? {
        Some(handle) => Ok(handle),
        None => Err(anyhow!(
            "could not locate `{}` binary — set `{}=path/to/{}` or build the sibling \
             checkout under `contrix-dev/{}/target/debug/`",
            spec.service,
            spec.bin_env,
            spec.service,
            spec.sibling_path.first().copied().unwrap_or(spec.service),
        )),
    }
}

fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

async fn wait_until_healthy(base_url: &str, path: &str, timeout: Duration) -> Result<Client> {
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("{base_url}{path}");
    let deadline = Instant::now() + timeout;
    let mut last_err: Option<String> = None;
    while Instant::now() < deadline {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(client),
            Ok(resp) => last_err = Some(format!("status {}", resp.status())),
            Err(e) => last_err = Some(e.to_string()),
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    bail!("liveness probe {url} did not become healthy in {timeout:?}: {last_err:?}")
}

/// Resolve the `contrix-dev/` workspace root by walking up from the cotest
/// crate manifest dir until a sibling layout is detected.
fn workspace_root() -> Option<PathBuf> {
    // CARGO_MANIFEST_DIR points at .../contrix-dev/cotest at compile time.
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.parent().map(Path::to_path_buf)
}
