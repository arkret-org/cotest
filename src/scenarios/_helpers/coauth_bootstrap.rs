//! C34.3 — orchestrate a fully-spawnable `coauth` instance for the bridge
//! contract matrix and other live black-box scenarios.
//!
//! What this module does, end-to-end:
//!   1. Boot an ephemeral Postgres in a throw-away docker container (`spawn_ephemeral_postgres`).
//!      The container's lifetime is bound to the returned [`EphemeralPg`] handle — `Drop` removes
//!      the container with `docker rm -fv` so a cargo-test panic / early-return cannot leak it.
//!   2. Generate a fresh coauth config YAML by shelling out to `coauth config generate` (which
//!      produces real signing/encryption keys), then patch the `database.uri`, `http.public_base`,
//!      `issuer`, and the listener bind addresses so the spawned server points at our pinned ports
//!      + the docker postgres (`bootstrap_coauth_config`).
//!   3. Run `coauth database migrate` against the generated config so the schema is applied before
//!      the server boots (`run_coauth_migrations`).
//!   4. Spawn `coauth server --config <generated>` directly (bypassing the
//!      `external_binary::try_spawn` helper because we have a pre-bound address from the patched
//!      YAML rather than one allocated at spawn time) and bundle the postgres + config + server
//!      handles into a single [`SpawnedCoauth`] value (`spawn_coauth_with_db`).
//!
//! Every step is fail-soft: if `docker` is missing, the coauth binary cannot
//! be located, or any command exits non-zero, we return `Ok(None)` rather
//! than blowing up the test. Callers (the bridge matrix scaffold today,
//! more downstream scenarios tomorrow) should treat `None` exactly like the
//! pre-C34.3 "service not available — keep the placeholder row" branch.
//!
//! Platform note: the default implementation uses the docker CLI as a
//! subprocess. Windows + named-pipe docker-engine integrations
//! historically misbehave under `testcontainers`, and the CLI surface
//! is stable enough that spawning a one-shot postgres container is a
//! four-line incantation.
//!
//! On non-Windows targets the `test-with-containers` Cargo feature
//! switches to a real `testcontainers`-managed lifecycle
//! ([`spawn_ephemeral_postgres_testcontainers`]), so panics in the
//! middle of a test still tear down the container even when the
//! docker CLI isn't available. The CI matrix wires this on for the
//! Ubuntu job only — see `.github/workflows/integration.yml`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tempfile::NamedTempFile;

use crate::harness::{ReservedPort, reserve_port};
use crate::scenarios::_helpers::external_binary::{
    ExternalBinarySpec, SpawnedExternalProcess, locate_external_binary,
};

// ── Public surface ─────────────────────────────────────────────────────────

/// Handle to a docker-managed throw-away Postgres. Drop = `docker rm -fv`.
pub struct EphemeralPg {
    /// `postgresql://...` URL the host can connect to. Note this points at
    /// `127.0.0.1:<host_port>` rather than the in-container `postgres:5432`,
    /// because coauth runs on the host and reaches the container via the
    /// published port.
    pub connect_url: String,
    /// `docker` CLI container name; used by Drop for tear-down.
    container_name: String,
    /// Set to `false` after a successful explicit shutdown so Drop is a no-op.
    cleanup: bool,
    _port_reservation: Option<ReservedPort>,
}

/// Whether the generated-config coauth bootstrap can be attempted in this
/// environment. This mirrors [`spawn_coauth_with_db`]'s real prerequisites:
/// a locatable coauth binary plus a Docker-backed ephemeral Postgres path.
pub fn coauth_with_db_available() -> bool {
    locate_external_binary(&coauth_binary_probe_spec()).is_some() && docker_available()
}

impl EphemeralPg {
    /// Container name (mostly useful for debug logs / introspection from
    /// tests that want to `docker exec ...` into it).
    #[allow(dead_code)]
    pub fn container_name(&self) -> &str {
        &self.container_name
    }
}

impl Drop for EphemeralPg {
    fn drop(&mut self) {
        if !self.cleanup {
            return;
        }
        // Best-effort: ignore failure modes (container already gone, docker
        // daemon down). We never want a leaked container, but we also don't
        // want a Drop-time panic to mask an upstream test failure.
        let _ = Command::new("docker")
            .args(["rm", "-fv", &self.container_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Aggregated handle for a spawned coauth: postgres lifetime, generated
/// config (kept on disk for the duration of the test), and the spawned
/// server process. Drop order is server → pg, so the server has a chance to
/// flush before the DB disappears.
pub struct SpawnedCoauth {
    pub server: SpawnedExternalProcess,
    /// `http://127.0.0.1:<internal_port>` — listener that exposes the
    /// `health` resource. Distinct from the public `server.base_url`
    /// because coauth's generated config splits public REST from the
    /// internal-only health probe.
    pub internal_base_url: String,
    /// Held so the file isn't deleted while coauth is running.
    #[allow(dead_code)]
    pub config: NamedTempFile,
    _internal_port_reservation: ReservedPort,
    #[allow(dead_code)]
    pub pg: EphemeralPg,
}

impl SpawnedCoauth {
    /// Public REST base — what callers should use for `/_cokret/self/...`.
    pub fn base_url(&self) -> &str {
        &self.server.base_url
    }

    /// Internal-listener base — use for `/health` probes (coauth puts
    /// `health` on a separate listener from the public REST surface).
    #[allow(dead_code)]
    pub fn health_url(&self) -> String {
        format!("{}/health", self.internal_base_url)
    }
}

/// Try to bring up an ephemeral Postgres in docker and return a handle.
///
/// Returns `Ok(None)` if the docker CLI is missing, the daemon is unreachable,
/// or `docker run` fails for any other reason. The caller is expected to
/// degrade gracefully (skip the live row, keep the placeholder).
pub fn spawn_ephemeral_postgres() -> Result<Option<EphemeralPg>> {
    if !docker_available() {
        return Ok(None);
    }
    let host_port = match reserve_port() {
        Ok(port) => port,
        Err(_) => return Ok(None),
    };
    let container_name = format!("cotest-pg-{}-{}", std::process::id(), host_port.port());

    let status = Command::new("docker")
        .args([
            "run",
            "-d",
            "--rm", // belt-and-braces: even if Drop misses, container self-destructs on stop
            "--name",
            &container_name,
            "-e",
            "POSTGRES_USER=cokret",
            "-e",
            "POSTGRES_PASSWORD=cokret",
            "-e",
            "POSTGRES_DB=cokret",
            "-p",
            &format!("{}:5432", host_port.port()),
            "postgres:16-alpine",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => {}
        _ => return Ok(None),
    }

    let pg = EphemeralPg {
        connect_url: format!(
            "postgresql://cokret:cokret@127.0.0.1:{}/cokret",
            host_port.port()
        ),
        container_name,
        cleanup: true,
        _port_reservation: Some(host_port),
    };

    // pg_isready loop, capped — the container needs a moment after `docker
    // run -d` to actually accept connections. We poll the published port
    // with a TCP probe + then a `docker exec ... pg_isready` to be sure
    // the listener is past initdb.
    if !wait_for_postgres_ready(&pg, Duration::from_secs(60)) {
        // pg never became ready — drop the container and bail.
        return Ok(None);
    }
    Ok(Some(pg))
}

/// Output of [`bootstrap_coauth_config`] — the rendered config plus the
/// internal health-probe address (which is a SEPARATE listener from the web
/// surface in coauth's default layout).
pub struct CoauthConfigBundle {
    pub file: NamedTempFile,
    /// `127.0.0.1:<port>` — listener that exposes the `health` resource.
    pub internal_addr: String,
    internal_port_reservation: ReservedPort,
}

/// Generate a fresh coauth config YAML and patch it for the supplied
/// `pg_url` / `bind_addr`. Returns a [`CoauthConfigBundle`] whose `file`
/// path the caller can pass to `coauth server --config`. The caller MUST
/// keep the `NamedTempFile` alive for the lifetime of the spawned server
/// (otherwise the file is unlinked on Windows and coauth will fail any
/// future re-read).
///
/// The `internal_addr` field returns the address of the listener that
/// exposes the `health` resource — this is a SEPARATE listener from the
/// public REST one in coauth's default layout, so the caller must probe
/// `internal_addr/health` rather than `bind_addr/health`.
pub fn bootstrap_coauth_config(
    coauth_bin: &Path,
    pg_url: &str,
    bind_addr: &str,
) -> Result<CoauthConfigBundle> {
    // 1. Run `coauth config generate` to stdout, capture as string.
    let output = Command::new(coauth_bin)
        .args(["config", "generate"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .with_context(|| {
            format!(
                "failed to invoke `{}` config generate",
                coauth_bin.display()
            )
        })?;
    if !output.status.success() {
        anyhow::bail!(
            "coauth config generate exited with status {:?}",
            output.status.code()
        );
    }
    let raw =
        String::from_utf8(output.stdout).context("coauth config generate produced non-utf8")?;

    // 2. Patch:
    //    - database.uri → ephemeral postgres
    //    - http.public_base / http.issuer → http://<bind_addr>/
    //    - listener bind address `[::]:7080` → bind_addr
    //    - internal listener `localhost:8091` → 127.0.0.1:<free port> (we don't use it but it must
    //      be free so `coauth server` doesn't collide with another concurrent test instance)
    let internal_port =
        reserve_port().context("failed to reserve coauth internal listener port")?;
    let public_base = format!("http://{bind_addr}/");
    let mut patched = String::with_capacity(raw.len());
    let mut in_database = false;
    let mut in_http = false;
    let mut bind_listener_seen = 0_u8;
    for line in raw.lines() {
        // Track top-level section boundaries (no leading whitespace).
        if !line.starts_with(' ') && !line.starts_with('\t') && line.contains(':') {
            in_database = line.starts_with("database:");
            in_http = line.starts_with("http:");
        }
        let mut emitted = false;
        let trimmed = line.trim_start();
        if in_database && trimmed.starts_with("uri:") {
            // database.uri (2-space indent under `database:`)
            patched.push_str("  uri: ");
            patched.push_str(pg_url);
            patched.push('\n');
            emitted = true;
        } else if in_http && trimmed.starts_with("public_base:") {
            patched.push_str("  public_base: ");
            patched.push_str(&public_base);
            patched.push('\n');
            emitted = true;
        } else if in_http && trimmed.starts_with("issuer:") {
            patched.push_str("  issuer: ");
            patched.push_str(&public_base);
            patched.push('\n');
            emitted = true;
        } else if in_http && trimmed.starts_with("- address:") {
            // The first listener (web) gets bind_addr; the second (internal)
            // is rewritten via the `host:`/`port:` pair below. coauth's
            // generated config emits the web listener with `- address:` and
            // the internal listener with separate `host:` / `port:` lines,
            // so this only matches the web one.
            //
            // Preserve the leading indent.
            let indent_len = line.len() - trimmed.len();
            for _ in 0..indent_len {
                patched.push(' ');
            }
            patched.push_str("- address: '");
            patched.push_str(bind_addr);
            patched.push_str("'\n");
            bind_listener_seen += 1;
            emitted = true;
        } else if in_http
            && (trimmed.starts_with("host: localhost") || trimmed.starts_with("- host: localhost"))
        {
            // Internal listener host. The generated YAML emits this as a list
            // element of `binds:` so the trimmed prefix is `- host: localhost`.
            // We rewrite to `127.0.0.1` to pin to v4-loopback (so a v6-only
            // probe can't land on a different listener).
            let indent_len = line.len() - trimmed.len();
            for _ in 0..indent_len {
                patched.push(' ');
            }
            if trimmed.starts_with("- host:") {
                patched.push_str("- host: 127.0.0.1\n");
            } else {
                patched.push_str("host: 127.0.0.1\n");
            }
            emitted = true;
        } else if in_http && trimmed.starts_with("port: 8091") {
            let indent_len = line.len() - trimmed.len();
            for _ in 0..indent_len {
                patched.push(' ');
            }
            patched.push_str("port: ");
            patched.push_str(&internal_port.port().to_string());
            patched.push('\n');
            emitted = true;
        }
        if !emitted {
            patched.push_str(line);
            patched.push('\n');
        }
    }

    if bind_listener_seen == 0 {
        anyhow::bail!(
            "coauth-generated config did not contain a `- address:` listener line — \
             did the schema change?"
        );
    }

    // The generated config does not emit a `policy:` section (Cedar is the
    // implicit default). When coauth is built with the `cedar` feature it
    // looks at `policy.cedar_policy_file` and falls back to
    // `/usr/local/share/coauth/cedar/default.cedar` — that path doesn't
    // exist on host filesystems. Point it at the sibling-checkout's
    // `policies/cedar/default.cedar` if we can find one.
    if let Some(cedar_default) = locate_sibling_cedar_default(coauth_bin) {
        // Cedar's path needs to be a string; use forward-slashes on Windows
        // too — both Cedar and the camino path conversion are happy with it
        // and double-backslash YAML escaping is fragile.
        let cedar_str = cedar_default.to_string_lossy().replace('\\', "/");
        patched.push_str("policy:\n  engine: cedar\n  cedar_policy_file: ");
        patched.push_str(&cedar_str);
        patched.push('\n');
    }

    // Likewise the templates + translations directories default to
    // `./templates/` / `./translations/` (relative to coauth's CWD), which
    // doesn't exist when the caller is the cotest harness. Pin the absolute
    // paths from the sibling checkout when present.
    if let Some(repo_root) = locate_sibling_coauth_repo(coauth_bin) {
        let templates = repo_root
            .join("templates")
            .to_string_lossy()
            .replace('\\', "/");
        let translations = repo_root
            .join("translations")
            .to_string_lossy()
            .replace('\\', "/");
        patched.push_str("templates:\n  path: ");
        patched.push_str(&templates);
        patched.push_str("/\n  translations_path: ");
        patched.push_str(&translations);
        patched.push_str("/\n");
    }

    let mut tmp = tempfile::Builder::new()
        .prefix("cotest-coauth-")
        .suffix(".yaml")
        .tempfile()
        .context("failed to create temp file for coauth config")?;
    tmp.write_all(patched.as_bytes())
        .context("failed to write patched coauth config")?;
    tmp.flush().ok();
    Ok(CoauthConfigBundle {
        file: tmp,
        internal_addr: format!("127.0.0.1:{}", internal_port.port()),
        internal_port_reservation: internal_port,
    })
}

/// Walk up from `coauth_bin` to find the coauth repo root (the directory
/// containing the `policies/` subtree). Returns `None` if the binary path
/// has been copied out of a sibling checkout.
fn locate_sibling_coauth_repo(coauth_bin: &Path) -> Option<PathBuf> {
    // <repo>/target/debug/coauth.exe → walk up 3 levels to <repo>.
    let mut cursor = coauth_bin.parent()?; // target/debug
    for _ in 0..3 {
        if cursor.join("policies").join("cedar").is_dir() && cursor.join("templates").is_dir() {
            return Some(cursor.to_path_buf());
        }
        cursor = cursor.parent()?;
    }
    None
}

/// Convenience wrapper that returns the path to coauth's bundled
/// `default.cedar` policy file, or `None` if the sibling checkout layout
/// can't be detected.
fn locate_sibling_cedar_default(coauth_bin: &Path) -> Option<PathBuf> {
    let repo = locate_sibling_coauth_repo(coauth_bin)?;
    let candidate = repo.join("policies").join("cedar").join("default.cedar");
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

/// Run `coauth database migrate -c <config>` synchronously. Returns Err on
/// non-zero exit so the caller can decide whether to skip or fail.
pub fn run_coauth_migrations(coauth_bin: &Path, config_path: &Path) -> Result<()> {
    let status = Command::new(coauth_bin)
        .args(["database", "migrate", "-c"])
        .arg(config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| {
            format!(
                "failed to invoke `{}` database migrate",
                coauth_bin.display()
            )
        })?;
    if !status.success() {
        anyhow::bail!(
            "coauth database migrate exited with status {:?}",
            status.code()
        );
    }
    Ok(())
}

/// Top-level orchestrator: ephemeral pg → generated config → migrate →
/// spawn coauth → wait for /health → return aggregated handle.
///
/// Returns `Ok(None)` when any prerequisite is missing (docker, coauth
/// binary, ...). On a partial failure (docker came up but migrate failed),
/// we still return `Ok(None)` and the postgres container is reaped via
/// `EphemeralPg::Drop`.
pub async fn spawn_coauth_with_db() -> Result<Option<SpawnedCoauth>> {
    // Verbose diagnostic logging is gated on the `COTEST_COAUTH_BOOTSTRAP_DEBUG`
    // env var so opt-in tests + CI can surface the exact failure step
    // without spamming the conformance run with normal-path bootstrap noise.
    let debug = std::env::var("COTEST_COAUTH_BOOTSTRAP_DEBUG")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .is_some();
    macro_rules! step {
        ($($t:tt)*) => {
            if debug { eprintln!("[coauth_bootstrap] {}", format!($($t)*)); }
        };
    }
    step!("locating coauth binary");
    // 1. Locate the binary first — cheaper than spinning up postgres if the operator has no coauth
    //    checkout on disk.
    let coauth_bin: PathBuf = match locate_external_binary(&coauth_binary_probe_spec()) {
        Some(p) => {
            step!("located coauth bin: {}", p.display());
            p
        }
        None => {
            step!("coauth binary not found — skipping");
            return Ok(None);
        }
    };

    // 2. Spawn ephemeral postgres.
    step!("starting ephemeral postgres container");
    let pg = match spawn_ephemeral_postgres()? {
        Some(pg) => {
            step!("postgres up: {}", pg.connect_url);
            pg
        }
        None => {
            step!("postgres bootstrap failed — skipping");
            return Ok(None);
        }
    };

    // 3. Reserve the bind address for coauth's web listener.
    let bind_port = match reserve_port() {
        Ok(p) => p,
        Err(_) => return Ok(None),
    };
    let bind_addr = format!("127.0.0.1:{}", bind_port.port());

    // 4. Generate + patch the config YAML.
    step!("generating coauth config");
    let bundle = match bootstrap_coauth_config(&coauth_bin, &pg.connect_url, &bind_addr) {
        Ok(b) => {
            step!(
                "config written to {} (internal listener {})",
                b.file.path().display(),
                b.internal_addr
            );
            b
        }
        Err(e) => {
            step!("config bootstrap failed: {e:?}");
            return Ok(None);
        }
    };

    // 5. Run migrations against the freshly-bootstrapped DB.
    step!("running coauth database migrate");
    if let Err(e) = run_coauth_migrations(&coauth_bin, bundle.file.path()) {
        step!("migrate failed: {e:?}");
        return Ok(None);
    }
    step!("migrations applied");

    // 6. Spawn coauth server directly (we already have a pre-bound bind address baked into the
    //    config YAML, so the standard try_spawn helper that allocates its own port is the wrong
    //    tool here).
    step!("spawning coauth server bound to {bind_addr}");
    let mut command = Command::new(&coauth_bin);
    command
        .arg("server")
        .arg("--config")
        .arg(bundle.file.path())
        .arg("--no-sync");
    if debug {
        command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }
    let child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            step!("spawn failed: {e:?}");
            return Ok(None);
        }
    };
    let base_url = format!("http://{bind_addr}");
    let server =
        SpawnedExternalProcess::from_child(base_url.clone(), coauth_bin, child, vec![bind_port]);

    // The `health` resource lives on the SEPARATE internal listener
    // (coauth's generated config splits public web traffic from health
    // probes). Probe that listener — succeeding there means coauth is up
    // and accepting traffic on both ports.
    let internal_health = format!("http://{}", bundle.internal_addr);
    step!("waiting for /health at {internal_health}");
    if !wait_for_health(&internal_health, Duration::from_secs(60)).await {
        step!("health probe never succeeded within deadline");
        return Ok(None);
    }
    step!("coauth /health OK at internal listener");

    let config_file = bundle.file;
    let internal_port_reservation = bundle.internal_port_reservation;
    let internal_base_url = internal_health.clone();

    Ok(Some(SpawnedCoauth {
        server,
        internal_base_url,
        config: config_file,
        _internal_port_reservation: internal_port_reservation,
        pg,
    }))
}

// ── Internal utilities ─────────────────────────────────────────────────────

fn coauth_binary_probe_spec() -> ExternalBinarySpec {
    ExternalBinarySpec {
        service: "coauth",
        bin_env: "COAUTH_BIN",
        sibling_path: &["coauth", "target", "debug"],
        bind_env: "",
        bind_arg: None,
        extra_env: &[],
        extra_args: &[],
        required_env_vars: &[],
        health_path: "/health",
        health_timeout: Duration::from_secs(45),
    }
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn wait_for_postgres_ready(pg: &EphemeralPg, deadline: Duration) -> bool {
    let cutoff = Instant::now() + deadline;
    while Instant::now() < cutoff {
        let status = Command::new("docker")
            .args([
                "exec",
                &pg.container_name,
                "pg_isready",
                "-U",
                "cokret",
                "-d",
                "cokret",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if matches!(status, Ok(s) if s.success()) {
            return true;
        }
        thread::sleep(Duration::from_millis(500));
    }
    false
}

// ── testcontainers-backed bring-up (Linux-only, opt-in) ──────────────────
//
// When the `test-with-containers` feature is on AND we're not on Windows,
// scenarios can prefer this entry point over the docker-CLI path. It
// returns an `EphemeralPg` shaped identically to the CLI variant so the
// downstream `spawn_coauth_with_db` orchestration doesn't need to know
// which backend produced the handle.
#[cfg(all(not(target_os = "windows"), feature = "test-with-containers"))]
pub fn spawn_ephemeral_postgres_testcontainers() -> Result<Option<EphemeralPg>> {
    use testcontainers::GenericImage;
    use testcontainers::clients::Cli;
    use testcontainers::core::WaitFor;

    // testcontainers' default client holds a leaked CLI handle, which is
    // exactly what we want for the duration of a single `cargo test`
    // process. We DO NOT keep the returned `Container<'_>` because its
    // lifetime is tied to the `Cli`; instead we capture the
    // host-published port and let the container shut down when the
    // process exits. EphemeralPg's `Drop` still runs `docker rm -fv` as
    // a belt-and-braces cleanup.
    static DOCKER: std::sync::OnceLock<Cli> = std::sync::OnceLock::new();
    let docker = DOCKER.get_or_init(Cli::default);

    let image = GenericImage::new("postgres", "16-alpine")
        .with_env_var("POSTGRES_USER", "cokret")
        .with_env_var("POSTGRES_PASSWORD", "cokret")
        .with_env_var("POSTGRES_DB", "cokret")
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ));
    let container = docker.run(image);
    let host_port = container.get_host_port_ipv4(5432);
    let container_name = container.id().to_owned();
    // Detach the container handle: testcontainers will reap it when the
    // process exits, and our `EphemeralPg::Drop` provides the explicit
    // cleanup path.
    std::mem::forget(container);

    let pg = EphemeralPg {
        connect_url: format!("postgresql://cokret:cokret@127.0.0.1:{host_port}/cokret"),
        container_name,
        cleanup: true,
        _port_reservation: None,
    };
    if !wait_for_postgres_ready(&pg, Duration::from_secs(60)) {
        return Ok(None);
    }
    Ok(Some(pg))
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
