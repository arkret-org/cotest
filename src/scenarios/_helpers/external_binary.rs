//! C32.8 + C33.4 — shared spawn helper for sibling-checkout binaries
//! (`coland`, `coauth`, `flagon`, `floria`, ...) used by black-box scenarios.
//!
//! The helper:
//!   1. Resolves the binary path from an explicit env var override (e.g. `COLAND_BIN`) **first**,
//!      then falls back to the Cargo target directory this test binary itself was built into
//!      (derived from `current_exe`, so it follows `build.target-dir` / `CARGO_TARGET_DIR` wherever
//!      the workspace points them), and finally to the per-repository sibling-checkout convention
//!      path (`../<crate>/target/debug/<bin>[.exe]`). Never assume one layout: the workspace
//!      `.cargo/config.toml` may redirect every sibling repo into one shared tree, in which case
//!      `<crate>/target/` does not exist at all.
//!   2. Optionally checks `required_env_vars` (e.g. `COAUTH_DATABASE_URI`) are present in the
//!      caller's env before attempting to spawn — when a required dependency env var is missing we
//!      treat the binary as unavailable (returns `Ok(None)` from `try_spawn`). This is how coauth /
//!      floria gate themselves until a DB / config is wired into the test run.
//!   3. Reserves a local port and exports it back to the caller via the configured bind env var
//!      (e.g. `FLAGON_BIND`) and / or `--bind` CLI arg if `bind_arg` is set.
//!   4. Spawns the child with `stdout` / `stderr` swallowed (Stdio::null) so cargo test output
//!      stays readable; long-form troubleshooting can re-run with the binary directly.
//!   5. Waits for `/health` (or any caller-supplied liveness path) to return 2xx, with a deadline;
//!      returns a `SpawnedExternalProcess` whose `Drop` kills the child + reaps it so tokio test
//!      threads can't leak orphans.
//!
//! `try_spawn` returns `Ok(None)` when the binary cannot be located **or**
//! when any `required_env_vars` are missing. Callers that want a hard failure
//! (e.g. when the user explicitly opted in via `--ignored`) should use
//! `spawn_required` (which folds None into a descriptive `bail!`). Callers
//! that want a soft skip path (e.g. a baseline conformance row) can early-
//! return on `None`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use reqwest::Client;

use crate::harness::{ReservedPort, reserve_port};

/// Configuration for spawning a sibling-checkout binary.
pub struct ExternalBinarySpec {
    /// Logical service name used in error messages (e.g. `"coland"`).
    pub service: &'static str,
    /// Env var that, when set, overrides the binary path
    /// (e.g. `"COLAND_BIN"`).
    pub bin_env: &'static str,
    /// Sibling-checkout convention path segments under `arkret/`
    /// (e.g. `&["coland", "target", "debug"]`). The binary file name is
    /// derived from `service` (`+ ".exe"` on Windows). Only meaningful when the
    /// sibling repository builds into its own `target/`; with a shared
    /// workspace `build.target-dir` the binary is found through
    /// [`cargo_target_profile_dirs`] instead.
    pub sibling_path: &'static [&'static str],
    /// Env var that controls the bind address (e.g. `"FLAGON_BIND"`).
    /// Set to `""` if the binary does not accept a bind env var (in that
    /// case `bind_arg` must be set so the helper still pins a free port).
    pub bind_env: &'static str,
    /// Optional CLI flag to pass the bind address as a positional argument
    /// (e.g. `Some("--bind")` for coland). Set to `None` if the bind is
    /// supplied solely via `bind_env`.
    pub bind_arg: Option<&'static str>,
    /// Extra environment variables to inject into the child process
    /// (e.g. `&[("COLAND_DEVELOPMENT_MODE", "1")]`).
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
    _port_reservations: Vec<ReservedPort>,
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
    pub(crate) fn from_child(
        base_url: String,
        bin_path: PathBuf,
        child: Child,
        port_reservations: Vec<ReservedPort>,
    ) -> Self {
        Self {
            base_url,
            bin_path,
            child: Some(child),
            _port_reservations: port_reservations,
        }
    }

    /// Terminate and reap the owned child while retaining its durable spawn
    /// metadata and port reservations for an in-place restart.
    pub(crate) fn kill_and_wait(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            child.wait().context("wait for stopped external service")?;
        }
        Ok(())
    }

    /// Install a replacement child after [`Self::kill_and_wait`].
    pub(crate) fn replace_child(&mut self, child: Child) -> Result<()> {
        if self.child.is_some() {
            bail!("cannot replace a running external service child");
        }
        self.child = Some(child);
        Ok(())
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

/// Profile directories of the Cargo target tree this test binary was built
/// into, most specific first.
///
/// The running test executable lives at `<target-dir>/<profile>/deps/<name>`,
/// so walking up from `current_exe` yields the target directory Cargo actually
/// used, whether that comes from a workspace-level `build.target-dir`, a
/// `CARGO_TARGET_DIR` override, or the default `<repo>/target`. Sibling
/// services built from the same workspace land in that same profile
/// directory, which is what makes this the primary lookup.
pub fn cargo_target_profile_dirs() -> Vec<PathBuf> {
    let Ok(exe) = std::env::current_exe() else {
        return Vec::new();
    };
    let mut dirs = Vec::new();
    // `<profile>/deps/<test-exe>` walks up to `<profile>`; a plain
    // `<profile>/<exe>` layout is already covered by the first entry.
    if let Some(parent) = exe.parent() {
        dirs.push(parent.to_path_buf());
        if parent.file_name().is_some_and(|name| name == "deps")
            && let Some(profile) = parent.parent()
        {
            dirs.push(profile.to_path_buf());
        }
    }
    dirs
}

/// Binary file name for a spec (`<service>` plus the platform executable
/// suffix).
fn external_binary_file_name(spec: &ExternalBinarySpec) -> String {
    if cfg!(windows) {
        format!("{}.exe", spec.service)
    } else {
        spec.service.to_owned()
    }
}

/// Every path consulted by [`locate_external_binary`], in lookup order and
/// independent of whether those files exist. Used for the skip/failure text so
/// a missing binary reports the layout that was actually searched.
pub fn external_binary_candidates(spec: &ExternalBinarySpec) -> Vec<PathBuf> {
    let exe_name = external_binary_file_name(spec);
    let mut candidates: Vec<PathBuf> = cargo_target_profile_dirs()
        .into_iter()
        .map(|dir| dir.join(&exe_name))
        .collect();
    if let Some(root) = workspace_root() {
        let mut sibling = root;
        for segment in spec.sibling_path {
            sibling.push(segment);
        }
        sibling.push(&exe_name);
        candidates.push(sibling);
    }
    candidates
}

/// Try to locate `<service>` binary by checking the `bin_env` override first,
/// then the Cargo target directory this test binary was built into, then the
/// conventional sibling-checkout path. Returns `None` when none of them is
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
    external_binary_candidates(spec)
        .into_iter()
        .find(|candidate| candidate.is_file())
}

/// Render [`external_binary_candidates`] as a comma-separated list for
/// operator-facing skip and failure messages.
fn describe_external_binary_candidates(spec: &ExternalBinarySpec) -> String {
    external_binary_candidates(spec)
        .iter()
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
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
            "`{}` env var or {}",
            spec.bin_env,
            describe_external_binary_candidates(spec),
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
    let mut port = reserve_port()?;
    let bind = format!("127.0.0.1:{}", port.port());
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
    if std::env::var_os("COTEST_EXTERNAL_BINARY_DEBUG").is_some() {
        command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }
    for &(key, value) in spec.extra_env {
        command.env(key, value);
    }
    for &(key, value) in extra_env {
        command.env(key, value);
    }

    port.release();
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
        _port_reservations: vec![port],
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
                        "could not locate `{}` binary — set `{}=path/to/{}` or build the \
                         sibling checkout into this run's Cargo target directory (searched {})",
                        spec.service,
                        spec.bin_env,
                        spec.service,
                        describe_external_binary_candidates(spec),
                    )
                });
            Err(anyhow!(reason))
        }
    }
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

/// Resolve the `arkret/` workspace root by walking up from the cotest
/// crate manifest dir until a sibling layout is detected.
pub(crate) fn workspace_root() -> Option<PathBuf> {
    // CARGO_MANIFEST_DIR points at .../arkret/cotest at compile time.
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.parent().map(Path::to_path_buf)
}

// ── Pre-canned specs for the cross-project sibling binaries ────────────────
//
// Tests/scenarios should prefer to import these constants over rolling their
// own — they encode the bind-flag / env-var / dependency-gate conventions of
// each service in one place and keep the cross-project conventions auditable.

/// `coland` (Station) spec — `--bind` CLI flag + a few env vars. With no
/// explicit `COLAND_BIN`, resolution prefers `coland(.exe)` in the Cargo target
/// directory this run was built into (the shared workspace tree whenever
/// `build.target-dir` is set), then the per-repository
/// `coland/target/debug/coland(.exe)` artifact.
/// No external deps in its development-mode default (in-memory persistence).
pub const COLAND_SPEC: ExternalBinarySpec = ExternalBinarySpec {
    service: "coland",
    bin_env: "COLAND_BIN",
    sibling_path: &["coland", "target", "debug"],
    bind_env: "COLAND_BIND",
    bind_arg: Some("--bind"),
    extra_env: &[("COLAND_DEVELOPMENT_MODE", "1")],
    extra_args: &[],
    required_env_vars: &[],
    health_path: "/health",
    health_timeout: Duration::from_secs(20),
};

/// `flagon` (Directory Service) spec — env-driven bind plus a caller-supplied
/// Postgres DSN. `try_spawn` returns `Ok(None)` until `DATABASE_URL` is set,
/// so normal cotest runs do not need a database just to load the suite.
pub const FLAGON_SPEC: ExternalBinarySpec = ExternalBinarySpec {
    service: "flagon",
    bin_env: "FLAGON_BIN",
    sibling_path: &["flagon", "target", "debug"],
    bind_env: "FLAGON_BIND",
    bind_arg: None,
    extra_env: &[
        ("FLAGON_PUBLIC_BASE_URL", "http://flagon.cotest.local"),
        ("FLAGON_SERVICE_DID", "did:web:flagon.cotest.local"),
        (
            "FLAGON_SERVICE_METHOD_HISTORY_HEAD",
            "cotest-directory-history-head",
        ),
        ("FLAGON_SERVICE_VERSION_ID", "cotest-directory-version"),
        ("FLAGON_DEVELOPMENT_MODE", "true"),
    ],
    extra_args: &[],
    required_env_vars: &["DATABASE_URL"],
    health_path: "/health",
    health_timeout: Duration::from_secs(30),
};

#[cfg(test)]
mod tests {
    use super::*;

    fn exe_name(service: &str) -> String {
        if cfg!(windows) {
            format!("{service}.exe")
        } else {
            service.to_owned()
        }
    }

    /// The profile directory is derived from the running test binary, so it
    /// tracks whatever `build.target-dir` / `CARGO_TARGET_DIR` the run used
    /// instead of assuming `<repo>/target`.
    #[test]
    fn profile_dirs_track_the_running_target_directory() {
        let exe = std::env::current_exe().expect("current_exe");
        let dirs = cargo_target_profile_dirs();
        assert!(
            !dirs.is_empty(),
            "no profile directory derived from {}",
            exe.display()
        );
        assert_eq!(dirs[0], exe.parent().expect("exe parent"));
        // Cargo puts integration/unit test binaries in `<profile>/deps`; the
        // sibling service binaries sit one level up, so that level has to be a
        // candidate too.
        if dirs[0].file_name().is_some_and(|name| name == "deps") {
            assert_eq!(
                dirs.last().expect("profile dir"),
                &dirs[0].parent().expect("profile parent").to_path_buf()
            );
        }
        for dir in &dirs {
            assert!(
                dir.is_absolute(),
                "profile directory {} is not absolute",
                dir.display()
            );
        }
    }

    /// Both supported layouts are searched: the target directory this run was
    /// built into (shared workspace tree included) and the per-repository
    /// sibling checkout.
    #[test]
    fn candidates_cover_shared_and_per_repository_layouts() {
        let candidates = external_binary_candidates(&COLAND_SPEC);
        let name = exe_name(COLAND_SPEC.service);

        let profile_dirs = cargo_target_profile_dirs();
        for dir in &profile_dirs {
            assert!(
                candidates.contains(&dir.join(&name)),
                "missing target-directory candidate {}",
                dir.join(&name).display()
            );
        }

        let sibling = workspace_root()
            .expect("workspace root")
            .join("coland")
            .join("target")
            .join("debug")
            .join(&name);
        assert!(
            candidates.contains(&sibling),
            "missing sibling-checkout candidate {}",
            sibling.display()
        );

        // The target-directory lookup runs first so a freshly built binary
        // wins over a stale sibling artifact.
        assert_eq!(candidates.len(), profile_dirs.len() + 1);
        assert_eq!(candidates.last(), Some(&sibling));
    }

    /// A missing binary has to name every path that was tried, otherwise the
    /// skip message sends the reader to a directory this layout never uses.
    #[test]
    fn skip_reason_reports_every_searched_path() {
        // Service name that no checkout builds, so resolution always fails.
        const MISSING_SPEC: ExternalBinarySpec = ExternalBinarySpec {
            service: "cotest-no-such-service",
            bin_env: "COTEST_NO_SUCH_SERVICE_BIN",
            sibling_path: &["cotest-no-such-service", "target", "debug"],
            bind_env: "",
            bind_arg: None,
            extra_env: &[],
            extra_args: &[],
            required_env_vars: &[],
            health_path: "/health",
            health_timeout: Duration::from_secs(1),
        };

        assert!(locate_external_binary(&MISSING_SPEC).is_none());
        let Some(SkipReason::BinaryMissing { searched }) = skip_reason(&MISSING_SPEC) else {
            panic!("expected a BinaryMissing skip reason");
        };
        assert!(searched.contains(MISSING_SPEC.bin_env), "{searched}");
        for candidate in external_binary_candidates(&MISSING_SPEC) {
            assert!(
                searched.contains(&candidate.display().to_string()),
                "{searched} does not mention {}",
                candidate.display()
            );
        }
    }
}
