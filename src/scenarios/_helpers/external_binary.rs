//! C32.8 + C33.4 — shared spawn helper for sibling-checkout binaries
//! (`starid`, `soland`, `coauth`, `floria`, ...) used by black-box scenarios.
//!
//! The helper:
//!   1. Resolves the binary path from an explicit env var override (e.g.
//!      `STARID_BIN`) **first**, then falls back to a sibling-checkout
//!      convention path (`../<crate>/target/debug/<bin>[.exe]` relative to the
//!      cotest workspace root).
//!   2. Optionally checks `required_env_vars` (e.g. `COAUTH_DATABASE_URI`)
//!      are present in the caller's env before attempting to spawn — when a
//!      required dependency env var is missing we treat the binary as
//!      unavailable (returns `Ok(None)` from `try_spawn`). This is how coauth
//!      / floria gate themselves until a DB / config is wired into the test
//!      run.
//!   3. Allocates a free local port and exports it back to the caller via the
//!      configured bind env var (e.g. `STARID_BIND`) and / or `--bind` CLI
//!      arg if `bind_arg` is set.
//!   4. Spawns the child with `stdout` / `stderr` swallowed (Stdio::null) so
//!      cargo test output stays readable; long-form troubleshooting can re-run
//!      with the binary directly.
//!   5. Waits for `/health` (or any caller-supplied liveness path) to return
//!      2xx, with a deadline; returns a `SpawnedExternalProcess` whose `Drop`
//!      kills the child + reaps it so tokio test threads can't leak orphans.
//!
//! `try_spawn` returns `Ok(None)` when the binary cannot be located **or**
//! when any `required_env_vars` are missing. Callers that want a hard failure
//! (e.g. when the user explicitly opted in via `--ignored`) should use
//! `spawn_required` (which folds None into a descriptive `bail!`). Callers
//! that want a soft skip path (e.g. a baseline conformance row) can early-
//! return on `None`.

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
    /// Set to `""` if the binary does not accept a bind env var (in that
    /// case `bind_arg` must be set so the helper still pins a free port).
    pub bind_env: &'static str,
    /// Optional CLI flag to pass the bind address as a positional argument
    /// (e.g. `Some("--bind")` for soland). Set to `None` if the bind is
    /// supplied solely via `bind_env`.
    pub bind_arg: Option<&'static str>,
    /// Extra environment variables to inject into the child process
    /// (e.g. `&[("STARID_DEVELOPMENT_MODE", "true")]`).
    pub extra_env: &'static [(&'static str, &'static str)],
    /// Extra CLI args appended after `--bind <addr>` (rarely needed).
    pub extra_args: &'static [&'static str],
    /// Env vars that **must** be present in the caller's environment for the
    /// spawn to be attempted. Missing values cause `try_spawn` to return
    /// `Ok(None)` (treated identically to a missing binary). Used for gating
    /// services that need external runtime dependencies (e.g. coauth needs
    /// `COAUTH_DATABASE_URI`).
    pub required_env_vars: &'static [&'static str],
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

    /// Construct a `SpawnedExternalProcess` from a pre-spawned `Child`. Used
    /// by the bootstrap helpers in `coauth_bootstrap` / `floria_bootstrap`
    /// where the bind address is not allocated by `try_spawn` but is
    /// instead baked into a generated config file.
    pub(crate) fn from_child(base_url: String, bin_path: PathBuf, child: Child) -> Self {
        Self {
            base_url,
            bin_path,
            child: Some(child),
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

/// Reason a `try_spawn` returned `Ok(None)`. Useful for diagnostics in
/// `--ignored` opt-in tests and bridge-matrix placeholder rows.
#[derive(Debug, Clone)]
pub enum SkipReason {
    BinaryMissing { searched: String },
    MissingEnvVar { name: &'static str },
}

impl SkipReason {
    pub fn describe(&self, service: &str) -> String {
        match self {
            SkipReason::BinaryMissing { searched } => format!(
                "could not locate `{service}` binary — set `*_BIN` env or build sibling \
                 checkout (searched {searched})"
            ),
            SkipReason::MissingEnvVar { name } => {
                format!("skipping `{service}` spawn — required env var `{name}` is unset")
            }
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

/// Determine whether the spec is currently spawnable; if not, return a
/// machine-readable `SkipReason` so the caller can log + decide.
pub fn skip_reason(spec: &ExternalBinarySpec) -> Option<SkipReason> {
    for &name in spec.required_env_vars {
        let present = std::env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
            .is_some();
        if !present {
            return Some(SkipReason::MissingEnvVar { name });
        }
    }
    if locate_external_binary(spec).is_none() {
        let searched = format!(
            "`{}` env var or `contrix-dev/{}/target/debug/{}`",
            spec.bin_env,
            spec.sibling_path.first().copied().unwrap_or(spec.service),
            spec.service,
        );
        return Some(SkipReason::BinaryMissing { searched });
    }
    None
}

/// Spawn the binary if locatable + dependencies satisfied, wait until
/// healthy, and return the handle. Returns `Ok(None)` when the binary cannot
/// be located OR a `required_env_vars` entry is missing.
pub async fn try_spawn(spec: &ExternalBinarySpec) -> Result<Option<SpawnedExternalProcess>> {
    try_spawn_with_extra_env(spec, &[]).await
}

/// Spawn like [`try_spawn`] while adding caller-supplied env vars on top of
/// `spec.extra_env`. Dynamic entries are applied last, so callers can override
/// a static spec value when a scenario needs per-run wiring such as a freshly
/// allocated mock service URL.
pub async fn try_spawn_with_extra_env(
    spec: &ExternalBinarySpec,
    extra_env: &[(&str, &str)],
) -> Result<Option<SpawnedExternalProcess>> {
    if skip_reason(spec).is_some() {
        return Ok(None);
    }
    let bin_path = locate_external_binary(spec)
        .ok_or_else(|| anyhow!("locate_external_binary returned None after skip_reason check"))?;
    let port = free_port()?;
    let bind = format!("127.0.0.1:{port}");
    let base_url = format!("http://{bind}");

    let mut command = Command::new(&bin_path);
    if !spec.bind_env.is_empty() {
        command.env(spec.bind_env, &bind);
    }
    if let Some(flag) = spec.bind_arg {
        command.arg(flag).arg(&bind);
    }
    for &arg in spec.extra_args {
        command.arg(arg);
    }
    command.stdout(Stdio::null()).stderr(Stdio::null());
    for &(key, value) in spec.extra_env {
        command.env(key, value);
    }
    for &(key, value) in extra_env {
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
        None => {
            let reason = skip_reason(spec)
                .map(|r| r.describe(spec.service))
                .unwrap_or_else(|| {
                    format!(
                        "could not locate `{}` binary — set `{}=path/to/{}` or build the sibling \
                         checkout under `contrix-dev/{}/target/debug/`",
                        spec.service,
                        spec.bin_env,
                        spec.service,
                        spec.sibling_path.first().copied().unwrap_or(spec.service),
                    )
                });
            Err(anyhow!(reason))
        }
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

// ── Pre-canned specs for the cross-project sibling binaries ────────────────
//
// Tests/scenarios should prefer to import these constants over rolling their
// own — they encode the bind-flag / env-var / dependency-gate conventions of
// each service in one place and keep the cross-project conventions auditable.

/// `starid` (DID resolver) spec — env-driven bind, no external deps.
pub const STARID_SPEC: ExternalBinarySpec = ExternalBinarySpec {
    service: "starid",
    bin_env: "STARID_BIN",
    sibling_path: &["starid", "target", "debug"],
    bind_env: "STARID_BIND",
    bind_arg: None,
    extra_env: &[
        ("STARID_SERVICE_DID", "did:web:starid.cotest.local"),
        ("STARID_DEVELOPMENT_MODE", "true"),
    ],
    extra_args: &[],
    required_env_vars: &[],
    health_path: "/health",
    health_timeout: Duration::from_secs(20),
};

/// `soland` (principal server) spec — `--bind` CLI flag + a few env vars.
/// No external deps in its development-mode default (in-memory persistence).
pub const SOLAND_SPEC: ExternalBinarySpec = ExternalBinarySpec {
    service: "soland",
    bin_env: "SOLAND_BIN",
    sibling_path: &["soland", "target", "debug"],
    bind_env: "SOLAND_BIND",
    bind_arg: Some("--bind"),
    extra_env: &[("SOLAND_DEVELOPMENT_MODE", "1")],
    extra_args: &[],
    required_env_vars: &[],
    health_path: "/health",
    health_timeout: Duration::from_secs(20),
};

/// `teabay` (Directory Service) spec — env-driven bind plus a caller-supplied
/// Postgres DSN. `try_spawn` returns `Ok(None)` until `DATABASE_URL` is set,
/// so normal cotest runs do not need a database just to load the suite.
pub const TEABAY_SPEC: ExternalBinarySpec = ExternalBinarySpec {
    service: "teabay",
    bin_env: "TEABAY_BIN",
    sibling_path: &["teabay", "target", "debug"],
    bind_env: "TEABAY_BIND",
    bind_arg: None,
    extra_env: &[
        ("TEABAY_PUBLIC_BASE_URL", "http://teabay.cotest.local"),
        ("TEABAY_SERVICE_DID", "did:web:teabay.cotest.local"),
        ("TEABAY_DEVELOPMENT_MODE", "true"),
        ("TEABAY_PRIVATE_CONTACT_DISCOVERY_ENABLED", "true"),
    ],
    extra_args: &[],
    required_env_vars: &["DATABASE_URL"],
    health_path: "/health",
    health_timeout: Duration::from_secs(30),
};

/// `coauth` (auth/account server) spec — needs a Postgres DSN to boot.
/// `try_spawn` returns `Ok(None)` until both `COAUTH_BIN` (or sibling
/// binary) **and** `COAUTH_DATABASE_URI` are set, so CI runners without a
/// Postgres test DB get a clean skip rather than a partial-spawn failure.
pub const COAUTH_SPEC: ExternalBinarySpec = ExternalBinarySpec {
    service: "coauth",
    bin_env: "COAUTH_BIN",
    sibling_path: &["coauth", "target", "debug"],
    bind_env: "COAUTH_HTTP_BIND",
    bind_arg: None,
    extra_env: &[],
    extra_args: &[],
    required_env_vars: &["COAUTH_DATABASE_URI"],
    health_path: "/health",
    health_timeout: Duration::from_secs(30),
};

/// `floria` (push gateway) spec — config-file driven (KDL/YAML); we treat a
/// `FLORIA_CONFIG` env var as a hard prerequisite. Without it the binary
/// cannot pick a listen port from `--bind` alone, so we gate on the env.
pub const FLORIA_SPEC: ExternalBinarySpec = ExternalBinarySpec {
    service: "floria",
    bin_env: "FLORIA_BIN",
    sibling_path: &["floria", "target", "debug"],
    // floria reads its bind from the config file, not an env var; we leave
    // bind_env empty so the helper does not export a stray FLORIA_BIND.
    bind_env: "",
    // floria's CLI doesn't take a positional `--bind`; the helper still
    // pins a free port for the health check below, but the actual listen
    // address is whatever the operator wired into FLORIA_CONFIG. Tests that
    // want to exercise the live gateway must align FLORIA_CONFIG with the
    // port the helper expects (e.g. via a templated config).
    bind_arg: None,
    extra_env: &[],
    extra_args: &[],
    required_env_vars: &["FLORIA_CONFIG"],
    health_path: "/health",
    health_timeout: Duration::from_secs(30),
};
