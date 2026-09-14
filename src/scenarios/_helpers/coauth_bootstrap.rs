//! C34.3 — orchestrate a fully-spawnable `coauth` instance for the bridge
//! contract matrix and other live black-box scenarios.
//!
//! What this module does, end-to-end:
//!   1. Boot an ephemeral Postgres in a throw-away docker container (`spawn_ephemeral_postgres`).
//!      The container's lifetime is bound to the returned [`EphemeralPg`] handle — `Drop` removes
//!      the container with `docker rm -fv` so a cargo-test panic / early-return cannot leak it.
//!   2. Generate a fresh coauth config YAML by shelling out to `coauth config generate` (which
//!      produces real signing/encryption keys), then patch the `database.uri`,
//!      `http.public_base_url`, `issuer`, and the listener bind addresses so the spawned server
//!      points at our pinned ports
//!      + the docker postgres (`bootstrap_coauth_config`).
//!   3. Run `coauth database migrate` against the generated config so the schema is applied before
//!      the server boots (`run_coauth_migrations`).
//!   4. Spawn `coprivate authentication process --config <generated>` directly (bypassing the
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

use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tempfile::NamedTempFile;

use crate::harness::{ReservedPort, reserve_port};
use crate::scenarios::_helpers::external_binary::{
    ExternalBinarySpec, SpawnedExternalProcess, locate_external_binary, workspace_root,
};
use crate::scenarios::_helpers::health::wait_for_health;

pub const JOINT_TRUST_DOMAIN: &str = "ak:trust_domain:127.0.0.1";

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
    external_database: Option<ExternalDatabase>,
    _port_reservation: Option<ReservedPort>,
}

struct ExternalDatabase {
    admin_url: String,
    name: String,
}

/// Whether the generated-config coauth bootstrap can be attempted in this
/// environment. This mirrors [`spawn_coauth_with_db`]'s real prerequisites:
/// a locatable coauth binary plus either `COTEST_COAUTH_DATABASE_URL` or a
/// Docker-backed ephemeral Postgres path.
pub fn coauth_with_db_available() -> bool {
    locate_external_binary(&coauth_binary_probe_spec()).is_some()
        && (external_database_url("COTEST_COAUTH_DATABASE_URL").is_some() || docker_available())
}

impl EphemeralPg {
    /// Container name (mostly useful for debug logs / introspection from
    /// tests that want to `docker exec ...` into it).
    pub fn container_name(&self) -> &str {
        &self.container_name
    }
}

impl Drop for EphemeralPg {
    fn drop(&mut self) {
        if let Some(database) = self.external_database.take() {
            let _ = thread::spawn(move || {
                if let Ok(mut client) =
                    postgres::Client::connect(&database.admin_url, postgres::NoTls)
                {
                    let _ = client.execute(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
                        &[&database.name],
                    );
                    let _ = client.batch_execute(&format!(
                        "DROP DATABASE IF EXISTS \"{}\"",
                        database.name
                    ));
                }
            })
            .join();
        }
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
    pub config: NamedTempFile,
    _internal_port_reservation: ReservedPort,
    pub pg: EphemeralPg,
    restart_with_test_endpoints: bool,
    restart_chaos: Option<CoauthChaosConfig>,
    station_ca_path: Option<PathBuf>,
}

/// Debug-only post-commit pause injected into a spawned Coauth process.
#[derive(Clone)]
pub struct CoauthChaosConfig {
    /// Exact handler breakpoint name.
    pub breakpoint: String,
    /// Optional exact durable request identity selector.
    pub request_identity: Option<String>,
    /// Time the real handler pauses after commit and before response rendering.
    pub delay_ms: u64,
    /// Optional marker written only after the durable commit is visible and
    /// immediately before the pause begins.
    pub reached_file: Option<PathBuf>,
}

impl SpawnedCoauth {
    /// Public REST base — what callers should use for `/_arkret/self/...`.
    pub fn base_url(&self) -> &str {
        &self.server.base_url
    }

    /// Internal-listener base — use for `/health` probes (coauth puts
    /// `health` on a separate listener from the public REST surface).
    pub fn health_url(&self) -> String {
        format!("{}/health", self.internal_base_url)
    }

    /// Kill the real Coauth process without touching its PostgreSQL database,
    /// generated configuration, service keys, or reserved listener ports.
    pub fn kill_immediately(&mut self) -> Result<()> {
        self.server.kill_and_wait()
    }

    /// Restart Coauth from the exact same binary and generated config over the
    /// same PostgreSQL ledger and listener ports.
    pub async fn restart_same_config(&mut self) -> Result<()> {
        self.server.kill_and_wait()?;
        let mut command = coauth_process_command(
            &self.server.bin_path,
            self.config.path(),
            self.restart_with_test_endpoints,
            self.restart_chaos.as_ref(),
        );
        if let Some(ca_path) = &self.station_ca_path {
            command.env("SSL_CERT_FILE", ca_path);
        }
        if std::env::var_os("COTEST_COAUTH_BOOTSTRAP_DEBUG").is_some() {
            command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        } else {
            command.stdout(Stdio::null()).stderr(Stdio::null());
        }
        let child = command
            .spawn()
            .context("restart coauth from retained config")?;
        self.server.replace_child(child)?;
        if !wait_for_health(&self.internal_base_url, Duration::from_secs(60)).await {
            self.server.kill_and_wait()?;
            anyhow::bail!(
                "restarted coauth did not become healthy at {}",
                self.internal_base_url
            );
        }
        Ok(())
    }
}

/// Coauth resources reserved before Soland starts. This breaks the bootstrap
/// cycle cleanly: Soland can be configured with [`Self::base_url`] first, then
/// Coauth is rendered with that live Soland as its Station.
pub struct PreparedCoauth {
    coauth_bin: PathBuf,
    pg: EphemeralPg,
    bind_port: ReservedPort,
    bind_addr: String,
}

impl PreparedCoauth {
    pub fn base_url(&self) -> String {
        format!("http://{}", self.bind_addr)
    }

    pub async fn spawn_for_station(
        self,
        station_endpoint: &str,
        internal_authority_shared_secret: &str,
        embedded_webvh_registration_bearer: &str,
        station_ca_path: Option<&Path>,
    ) -> Result<SpawnedCoauth> {
        let Self {
            coauth_bin,
            pg,
            mut bind_port,
            bind_addr,
        } = self;
        let mut bundle = bootstrap_coauth_config(&coauth_bin, &pg.connect_url, &bind_addr)?;
        patch_station_config(
            &mut bundle,
            station_endpoint,
            internal_authority_shared_secret,
            embedded_webvh_registration_bearer,
        )?;
        run_coauth_migrations(&coauth_bin, bundle.file.path())?;

        let mut command = coauth_process_command(&coauth_bin, bundle.file.path(), true, None);
        if let Some(ca_path) = station_ca_path {
            command.env("SSL_CERT_FILE", ca_path);
        }
        if std::env::var_os("COTEST_COAUTH_BOOTSTRAP_DEBUG").is_some() {
            command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        } else {
            command.stdout(Stdio::null()).stderr(Stdio::null());
        }
        bind_port.release();
        bundle.internal_port_reservation.release();
        let child = command
            .spawn()
            .context("spawn prepared coprivate authentication process")?;
        let base_url = format!("http://{bind_addr}");
        let server =
            SpawnedExternalProcess::from_child(base_url, coauth_bin, child, vec![bind_port]);
        let internal_base_url = format!("http://{}", bundle.internal_addr);
        if !wait_for_health(&internal_base_url, Duration::from_secs(60)).await {
            anyhow::bail!("prepared coauth did not become healthy at {internal_base_url}");
        }
        Ok(SpawnedCoauth {
            server,
            internal_base_url,
            config: bundle.file,
            _internal_port_reservation: bundle.internal_port_reservation,
            pg,
            restart_with_test_endpoints: true,
            restart_chaos: None,
            station_ca_path: station_ca_path.map(Path::to_path_buf),
        })
    }
}

/// Reserve Coauth's public address and database without starting the process.
/// Live cross-service tests use the address to configure Soland, then call
/// [`PreparedCoauth::spawn_for_station`] with that Soland endpoint.
pub fn prepare_coauth_with_db_required() -> Result<PreparedCoauth> {
    let coauth_bin = locate_external_binary(&coauth_binary_probe_spec())
        .context("coauth binary is required for the live Agent MLS test")?;
    let pg = spawn_ephemeral_postgres()?
        .context("Docker-backed Postgres is required for the live Agent MLS test")?;
    let bind_port = reserve_port().context("reserve prepared coauth public port")?;
    let bind_addr = format!("127.0.0.1:{}", bind_port.port());
    Ok(PreparedCoauth {
        coauth_bin,
        pg,
        bind_port,
        bind_addr,
    })
}

fn patch_station_config(
    bundle: &mut CoauthConfigBundle,
    endpoint: &str,
    internal_authority_shared_secret: &str,
    embedded_webvh_registration_bearer: &str,
) -> Result<()> {
    let file = bundle.file.as_file_mut();
    file.seek(SeekFrom::Start(0))?;
    let mut config: serde_yaml_ng::Value = serde_yaml_ng::from_reader(&mut *file)
        .context("decode generated coauth config for Station wiring")?;
    let root = config
        .as_mapping_mut()
        .context("generated coauth config root must be a mapping")?;
    let arkret_key = serde_yaml_ng::Value::String("arkret".to_owned());
    let arkret = root
        .entry(arkret_key)
        .or_insert_with(|| serde_yaml_ng::Value::Mapping(Default::default()))
        .as_mapping_mut()
        .context("generated coauth arkret config must be a mapping")?;
    arkret.insert(
        serde_yaml_ng::Value::String("trust_domain".to_owned()),
        serde_yaml_ng::Value::String(JOINT_TRUST_DOMAIN.to_owned()),
    );
    arkret.insert(
        serde_yaml_ng::Value::String("stations".to_owned()),
        serde_yaml_ng::to_value(vec![serde_json::json!({
            "name": "cotest-soland",
            "endpoint": endpoint,
            "internal_authority_shared_secret": internal_authority_shared_secret,
            "embedded_webvh_registration_bearer": embedded_webvh_registration_bearer,
            "trust_domain": JOINT_TRUST_DOMAIN
        })])?,
    );
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    serde_yaml_ng::to_writer(&mut *file, &config).context("write Station-wired coauth config")?;
    file.flush()?;
    Ok(())
}

/// Use an explicitly configured test database or bring up ephemeral Postgres.
///
/// `COTEST_COAUTH_DATABASE_URL` takes precedence. Otherwise this returns
/// `Ok(None)` if Docker is unavailable. The caller is expected to degrade
/// gracefully (skip the live row, keep the placeholder).
pub fn spawn_ephemeral_postgres() -> Result<Option<EphemeralPg>> {
    spawn_ephemeral_postgres_for("COTEST_COAUTH_DATABASE_URL")
}

/// Use the database URL named by `database_url_env`, or provision an
/// isolated Docker-backed PostgreSQL instance when it is unset.
///
/// Soland and Coauth deliberately use distinct configuration variables. A
/// shared helper must therefore take the variable name explicitly instead of
/// accidentally wiring one service to the other's database.
pub fn spawn_ephemeral_postgres_for(database_url_env: &str) -> Result<Option<EphemeralPg>> {
    if let Some(connect_url) = external_database_url(database_url_env) {
        let (connect_url, external_database) = provision_external_database(&connect_url)?;
        return Ok(Some(EphemeralPg {
            connect_url,
            container_name: "external-postgres".to_owned(),
            cleanup: false,
            external_database: Some(external_database),
            _port_reservation: None,
        }));
    }
    if !docker_available() {
        return Ok(None);
    }
    let mut host_port = match reserve_port() {
        Ok(port) => port,
        Err(_) => return Ok(None),
    };
    let container_name = format!("cotest-pg-{}-{}", std::process::id(), host_port.port());

    host_port.release();
    let status = Command::new("docker")
        .args([
            "run",
            "-d",
            "--rm", // belt-and-braces: even if Drop misses, container self-destructs on stop
            "--name",
            &container_name,
            "-e",
            "POSTGRES_USER=arkret",
            "-e",
            "POSTGRES_PASSWORD=arkret",
            "-e",
            "POSTGRES_DB=arkret",
            "-p",
            &format!("{}:5432", host_port.port()),
            "postgres:18.6-alpine",
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
            "postgresql://arkret:arkret@127.0.0.1:{}/arkret",
            host_port.port()
        ),
        container_name,
        cleanup: true,
        external_database: None,
        _port_reservation: Some(host_port),
    };

    // Wait for an authenticated SQL query over the host-published endpoint.
    // The image's temporary initdb server only accepts local socket clients.
    if !wait_for_postgres_ready(&pg, Duration::from_secs(60)) {
        // pg never became ready — drop the container and bail.
        return Ok(None);
    }
    Ok(Some(pg))
}

fn external_database_url(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

fn provision_external_database(admin_url: &str) -> Result<(String, ExternalDatabase)> {
    static DATABASE_COUNTER: AtomicU64 = AtomicU64::new(0);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock precedes Unix epoch")?
        .as_millis();
    let sequence = DATABASE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let name = format!("cotest_{}_{}_{}", std::process::id(), timestamp, sequence);
    let admin_url_owned = admin_url.to_owned();
    let database_name = name.clone();
    thread::spawn(move || -> Result<()> {
        let mut client = postgres::Client::connect(&admin_url_owned, postgres::NoTls)
            .with_context(|| {
                format!("connect to configured PostgreSQL administrator at {admin_url_owned}")
            })?;
        client
            .batch_execute(&format!("CREATE DATABASE \"{database_name}\""))
            .with_context(|| format!("create isolated Cotest database {database_name}"))?;
        Ok(())
    })
    .join()
    .map_err(|_| anyhow::anyhow!("isolated Cotest database provision thread panicked"))??;

    let mut database_url = url::Url::parse(admin_url)
        .with_context(|| format!("parse configured PostgreSQL URL {admin_url}"))?;
    database_url.set_path(&format!("/{name}"));
    Ok((
        database_url.into(),
        ExternalDatabase {
            admin_url: admin_url.to_owned(),
            name,
        },
    ))
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
/// path the caller can pass to `coprivate authentication process --config`. The caller MUST
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
    //    - http.public_base_url / http.issuer → http://<bind_addr>/
    //    - listener bind address `[::]:7080` → bind_addr
    //    - internal listener `localhost:8091` → 127.0.0.1:<free port> (we don't use it but it must
    //      be free so `coprivate authentication process` doesn't collide with another concurrent
    //      test instance)
    let internal_port =
        reserve_port().context("failed to reserve coauth internal listener port")?;
    let public_base_url = format!("http://{bind_addr}/");
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
        } else if in_http && trimmed.starts_with("public_base_url:") {
            patched.push_str("  public_base_url: ");
            patched.push_str(&public_base_url);
            patched.push('\n');
            emitted = true;
        } else if in_http && trimmed.starts_with("issuer:") {
            patched.push_str("  issuer: ");
            patched.push_str(&public_base_url);
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

/// Find the coauth repo root — the directory holding `policies/cedar` and
/// `templates`. Returns `None` when neither layout below matches.
///
/// A per-repository build lands in `<repo>/target/`, so walking up from that
/// binary finds coauth directly. That walk finds nothing when the workspace
/// redirects every repo into one shared `build.target-dir`, or when an
/// explicitly supplied external binary sits outside any checkout, so the
/// sibling-checkout fallback is what actually resolves the repository in those
/// layouts; without it the generated config would retain relative
/// `./templates/` and `./policies/cedar` paths and fail at process startup.
fn locate_sibling_coauth_repo(coauth_bin: &Path) -> Option<PathBuf> {
    fn is_coauth_repo(candidate: &Path) -> bool {
        candidate.join("policies").join("cedar").is_dir() && candidate.join("templates").is_dir()
    }

    // <repo>/target/debug/coauth.exe → walk up 3 levels to <repo>. A shared
    // workspace target directory has no such ancestor; the fallback below covers it.
    if let Some(mut cursor) = coauth_bin.parent() {
        for _ in 0..3 {
            if is_coauth_repo(cursor) {
                return Some(cursor.to_path_buf());
            }
            match cursor.parent() {
                Some(parent) => cursor = parent,
                None => break,
            }
        }
    }

    let sibling = workspace_root()?.join("coauth");
    is_coauth_repo(&sibling).then_some(sibling)
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
    spawn_coauth_with_db_options(None).await
}

/// Spawn the real Coprivate authentication process over PostgreSQL with one selected debug-only
/// post-commit response pause. Intended solely for owned-process fault tests.
pub async fn spawn_coauth_with_db_chaos(chaos: CoauthChaosConfig) -> Result<Option<SpawnedCoauth>> {
    spawn_coauth_with_db_options(Some(chaos)).await
}

async fn spawn_coauth_with_db_options(
    chaos: Option<CoauthChaosConfig>,
) -> Result<Option<SpawnedCoauth>> {
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
    macro_rules! fail_summary {
        ($stage:literal) => {
            eprintln!(
                "[coauth_bootstrap] {} failed; set COTEST_COAUTH_BOOTSTRAP_DEBUG=1 for command details",
                $stage
            );
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
            fail_summary!("locating coauth binary");
            return Ok(None);
        }
    };

    // 2. Spawn ephemeral postgres.
    step!("resolving coauth postgres");
    let pg = match spawn_ephemeral_postgres()? {
        Some(pg) => {
            step!("postgres up: {}", pg.connect_url);
            pg
        }
        None => {
            step!("postgres bootstrap failed — skipping");
            fail_summary!("starting ephemeral postgres");
            return Ok(None);
        }
    };

    // 3. Reserve the bind address for coauth's web listener.
    let mut bind_port = match reserve_port() {
        Ok(p) => p,
        Err(e) => {
            step!("reserve bind port failed: {e:?}");
            fail_summary!("reserving coauth bind port");
            return Ok(None);
        }
    };
    let bind_addr = format!("127.0.0.1:{}", bind_port.port());

    // 4. Generate + patch the config YAML.
    step!("generating coauth config");
    let mut bundle = match bootstrap_coauth_config(&coauth_bin, &pg.connect_url, &bind_addr) {
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
            fail_summary!("generating coauth config");
            return Ok(None);
        }
    };

    // 5. Run migrations against the freshly-bootstrapped DB.
    step!("running coauth database migrate");
    if let Err(e) = run_coauth_migrations(&coauth_bin, bundle.file.path()) {
        step!("migrate failed: {e:?}");
        fail_summary!("running coauth database migrate");
        return Ok(None);
    }
    step!("migrations applied");

    // 6. Spawn coprivate authentication process directly (we already have a pre-bound bind address
    //    baked into the config YAML, so the standard try_spawn helper that allocates its own port
    //    is the wrong tool here).
    step!("spawning coprivate authentication process bound to {bind_addr}");
    let mut command = coauth_process_command(
        &coauth_bin,
        bundle.file.path(),
        chaos.is_some(),
        chaos.as_ref(),
    );
    if debug {
        command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
    }
    bind_port.release();
    bundle.internal_port_reservation.release();
    let child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            step!("spawn failed: {e:?}");
            fail_summary!("spawning coprivate authentication process");
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
        fail_summary!("waiting for coauth /health");
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
        restart_with_test_endpoints: chaos.is_some(),
        restart_chaos: chaos,
        station_ca_path: None,
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

fn coauth_process_command(
    bin_path: &Path,
    config_path: &Path,
    test_endpoints: bool,
    chaos: Option<&CoauthChaosConfig>,
) -> Command {
    let mut command = Command::new(bin_path);
    command
        .arg("server")
        .arg("--config")
        .arg(config_path)
        .arg("--no-sync");
    if test_endpoints {
        command
            .env("COAUTH_ENABLE_TEST_ENDPOINTS", "1")
            .env("COAUTH_ALLOW_INSECURE_LOOPBACK_HTTP", "1");
    }
    if let Some(chaos) = chaos {
        command
            .env("COAUTH_TEST_CHAOS_BREAKPOINT", &chaos.breakpoint)
            .env("COAUTH_TEST_CHAOS_DELAY_MS", chaos.delay_ms.to_string());
        if let Some(request_identity) = &chaos.request_identity {
            command.env("COAUTH_TEST_CHAOS_REQUEST_IDENTITY", request_identity);
        }
        if let Some(reached_file) = &chaos.reached_file {
            command.env("COAUTH_TEST_CHAOS_REACHED_FILE", reached_file);
        }
    }
    command
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
    // postgres::Client owns a Tokio runtime. Keep it off any async scenario's
    // runtime thread, including its Drop path.
    thread::scope(|scope| {
        scope
            .spawn(|| probe_postgres_ready(&pg.connect_url, deadline))
            .join()
            .unwrap_or(false)
    })
}

fn probe_postgres_ready(connect_url: &str, deadline: Duration) -> bool {
    let cutoff = Instant::now() + deadline;
    let Ok(mut config) = connect_url.parse::<postgres::Config>() else {
        return false;
    };
    // Probe the same host TCP endpoint used by services, not the temporary
    // Unix-socket server started by the image during database initialization.
    config.connect_timeout(Duration::from_secs(2));
    while Instant::now() < cutoff {
        if let Ok(mut client) = config.connect(postgres::NoTls)
            && client.simple_query("SELECT 1").is_ok()
        {
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
        .with_env_var("POSTGRES_USER", "arkret")
        .with_env_var("POSTGRES_PASSWORD", "arkret")
        .with_env_var("POSTGRES_DB", "arkret")
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
        connect_url: format!("postgresql://arkret:arkret@127.0.0.1:{host_port}/arkret"),
        container_name,
        cleanup: true,
        external_database: None,
        _port_reservation: None,
    };
    if !wait_for_postgres_ready(&pg, Duration::from_secs(60)) {
        return Ok(None);
    }
    Ok(Some(pg))
}
