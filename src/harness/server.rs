use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};
use std::{fs, mem};

use anyhow::{Context, Result, anyhow};
use arkret_http_client::{Auth, Client as SdkClient};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::Utc;
use reqwest::{Client as HttpClient, StatusCode};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use url::Url;

use super::assertions::expect_json;
use super::canonical_device_id;
use super::client::TestActorClient;
use super::event_builder::{dev_login, register_account, register_account_with_handle};

pub(crate) const EMBEDDED_WEBVH_REGISTRATION_BEARER: &str = "cotest-embedded-webvh-registration";

pub struct ArkretServer {
    handle: SutHandle,
    base_url: Url,
    service_id: String,
    notary_signing_key_seed: [u8; 32],
    blob_root: Option<PathBuf>,
    log_path: Option<PathBuf>,
    _port_reservations: Vec<ReservedPort>,
}

pub struct TestServerGroup {
    servers: Vec<ArkretServer>,
    docker_network: Option<String>,
}

enum SutHandle {
    Local(Child),
    Docker { container_name: String },
    Terminated,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SutRuntimeMode {
    Process,
    Docker,
}

fn test_service_signing_key(name: &str) -> (String, [u8; 32]) {
    let digest = Sha256::digest(format!("cotest:notary:{name}").as_bytes());
    let mut seed = [0_u8; 32];
    seed.copy_from_slice(&digest);
    (BASE64_STANDARD.encode(seed), seed)
}

impl ArkretServer {
    pub async fn spawn(name: &str) -> Result<Self> {
        Self::spawn_with_env(name, &[]).await
    }

    pub async fn spawn_with_env(name: &str, extra_env: &[(&str, &str)]) -> Result<Self> {
        Self::spawn_with_network_and_env(name, None, extra_env).await
    }

    pub async fn spawn_with_database_url(
        name: &str,
        database_url: &str,
        extra_env: &[(&str, &str)],
    ) -> Result<Self> {
        let mut env = Vec::with_capacity(extra_env.len() + 1);
        env.push(("DATABASE_URL", database_url));
        env.extend_from_slice(extra_env);
        Self::spawn_with_env(name, &env).await
    }

    async fn spawn_with_network(name: &str, docker_network: Option<&str>) -> Result<Self> {
        Self::spawn_with_network_and_env(name, docker_network, &[]).await
    }

    async fn spawn_with_network_and_env(
        name: &str,
        docker_network: Option<&str>,
        extra_env: &[(&str, &str)],
    ) -> Result<Self> {
        match sut_runtime_mode() {
            SutRuntimeMode::Process => Self::spawn_process(name, extra_env).await,
            SutRuntimeMode::Docker => Self::spawn_docker(name, docker_network, extra_env).await,
        }
    }

    /// spawn a pre-built soland binary directly (no `cargo run`), injecting
    /// `extra_env` into the child process. Mirrors `spawn_process` but invokes
    /// the binary at `bin_path` with `--bind <addr>` so federation scenarios
    /// can promote out of the slow `cargo run --manifest-path` path when a
    /// SOLAND_BIN is supplied. Used by `spawn_process` so the fast
    /// pre-built-binary path supports the same `extra_env` knob the slow
    /// `cargo run` path always supported.
    async fn spawn_external_binary_with_env(
        name: &str,
        bin_path: &Path,
        extra_env: &[(&str, &str)],
    ) -> Result<Self> {
        let port = reserve_port()?;
        let metrics_port = reserve_port()?;
        Self::spawn_external_binary_with_ports_and_env(
            name,
            bin_path,
            port,
            metrics_port,
            extra_env,
        )
        .await
    }

    /// Spawn a pre-built soland binary on already-reserved ports. Splitting the
    /// port reservation out of [`spawn_external_binary_with_env`] lets the
    /// multi-node federation path compute every node's `did:webvh` + base URL up
    /// front so each node can be started with the others wired in via
    /// `SOLAND_FEDERATION_PEERS`.
    async fn spawn_external_binary_with_ports_and_env(
        name: &str,
        bin_path: &Path,
        mut port: ReservedPort,
        mut metrics_port: ReservedPort,
        extra_env: &[(&str, &str)],
    ) -> Result<Self> {
        let bind = format!("127.0.0.1:{}", port.port());
        let metrics_bind = format!("127.0.0.1:{}", metrics_port.port());
        let base_url = Url::parse(&format!("http://127.0.0.1:{}/", port.port()))?;
        let (notary_signing_key, notary_signing_key_seed) = test_service_signing_key(name);
        let blob_root = std::env::temp_dir().join(format!("cotest-{name}-{}-blobs", port.port()));
        let log_path = service_log_path(name)?;
        initialize_service_log(log_path.as_deref(), name, "external_binary")?;
        let _ = fs::remove_dir_all(&blob_root);
        fs::create_dir_all(&blob_root)?;
        let (stdout, stderr) = service_log_stdio(log_path.as_deref())?;

        let mut command = Command::new(bin_path);
        command
            .arg("--bind")
            .arg(&bind)
            .env_remove("DATABASE_URL")
            .env("SOLAND_PUBLIC_BASE_URL", base_url.as_str())
            .env("SOLAND_NOTARY_SIGNING_KEY", &notary_signing_key)
            .env("SOLAND_METRICS_BIND", &metrics_bind)
            .env("SOLAND_DEVELOPMENT_MODE", "1")
            .env("SOLAND_FIRST_PROVISIONING", "1")
            .env("SOLAND_SEED_DEMO_DATA", "1")
            .env(
                "SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER",
                EMBEDDED_WEBVH_REGISTRATION_BEARER,
            )
            .env("SOLAND_BLOB_ROOT", &blob_root)
            .stdout(stdout)
            .stderr(stderr);
        for &(key, value) in extra_env {
            command.env(key, value);
        }
        // Release the guard listeners at the last possible moment so the child
        // can bind the ports it was handed (the file-lock keeps this manager
        // from re-selecting them).
        port.release();
        metrics_port.release();
        let mut child = command.spawn().with_context(|| {
            format!(
                "failed to start external soland binary at {}",
                bin_path.display()
            )
        })?;

        if let Err(error) = wait_until_healthy(base_url.clone()).await {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        let service_id = fetch_service_id(&base_url).await?;

        Ok(Self {
            handle: SutHandle::Local(child),
            base_url,
            service_id,
            notary_signing_key_seed,
            blob_root: Some(blob_root),
            log_path,
            _port_reservations: vec![port, metrics_port],
        })
    }

    async fn spawn_process(name: &str, extra_env: &[(&str, &str)]) -> Result<Self> {
        // fast path: if a pre-built `soland` binary is available
        // (either via `SOLAND_BIN=` or the sibling-checkout convention
        // `../soland/target/debug/soland[.exe]`), spawn it directly. This
        // avoids the historical cargo-lock deadlock where `cargo run`
        // invoked from inside `cargo test` waits forever on the workspace
        // lock the test runner already holds.
        //
        // Falls back to the slow `cargo run --manifest-path` path when the
        // sibling binary has not been built yet.
        use crate::scenarios::_helpers::external_binary::{SOLAND_SPEC, locate_external_binary};
        if let Some(bin_path) = locate_external_binary(&SOLAND_SPEC) {
            return Self::spawn_external_binary_with_env(name, &bin_path, extra_env).await;
        }

        let mut port = reserve_port()?;
        let mut metrics_port = reserve_port()?;
        let bind = format!("127.0.0.1:{}", port.port());
        let metrics_bind = format!("127.0.0.1:{}", metrics_port.port());
        let base_url = Url::parse(&format!("http://127.0.0.1:{}/", port.port()))?;
        let (notary_signing_key, notary_signing_key_seed) = test_service_signing_key(name);
        let manifest = sut_manifest();
        let blob_root = std::env::temp_dir().join(format!("cotest-{name}-{}-blobs", port.port()));
        let log_path = service_log_path(name)?;
        initialize_service_log(log_path.as_deref(), name, "process")?;
        let _ = fs::remove_dir_all(&blob_root);
        fs::create_dir_all(&blob_root)?;
        let (stdout, stderr) = service_log_stdio(log_path.as_deref())?;

        let mut command = Command::new("cargo");
        command
            .arg("run")
            .arg("--quiet")
            .arg("--manifest-path")
            .arg(&manifest)
            .arg("--")
            .arg("--bind")
            .arg(&bind)
            .env_remove("DATABASE_URL")
            .env("SOLAND_PUBLIC_BASE_URL", base_url.as_str())
            .env("SOLAND_NOTARY_SIGNING_KEY", &notary_signing_key)
            .env("SOLAND_METRICS_BIND", &metrics_bind)
            .env("SOLAND_DEVELOPMENT_MODE", "1")
            .env("SOLAND_FIRST_PROVISIONING", "1")
            .env("SOLAND_SEED_DEMO_DATA", "1")
            .env(
                "SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER",
                EMBEDDED_WEBVH_REGISTRATION_BEARER,
            )
            .env("SOLAND_BLOB_ROOT", &blob_root)
            .stdout(stdout)
            .stderr(stderr);
        for &(key, value) in extra_env {
            command.env(key, value);
        }
        // Release the guard listeners right before the child binds them.
        port.release();
        metrics_port.release();
        let mut child = command
            .spawn()
            .with_context(|| format!("failed to start SUT from {}", manifest.display()))?;

        if let Err(error) = wait_until_healthy(base_url.clone()).await {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        let service_id = fetch_service_id(&base_url).await?;

        Ok(Self {
            handle: SutHandle::Local(child),
            base_url,
            service_id,
            notary_signing_key_seed,
            blob_root: Some(blob_root),
            log_path,
            _port_reservations: vec![port, metrics_port],
        })
    }

    async fn spawn_docker(
        name: &str,
        docker_network: Option<&str>,
        extra_env: &[(&str, &str)],
    ) -> Result<Self> {
        let mut host_port = reserve_port()?;
        let container_port = sut_container_port();
        let alias = sanitize_runtime_name(name);
        let base_url = Url::parse(&format!("http://127.0.0.1:{}/", host_port.port()))?;
        let (notary_signing_key, notary_signing_key_seed) = test_service_signing_key(name);
        let public_base_url = if docker_network.is_some() {
            format!("http://{alias}:{container_port}/")
        } else {
            base_url.as_str().to_owned()
        };
        let image = sut_image();
        let container_name = format!(
            "cotest-{}-{}-{}",
            alias,
            std::process::id(),
            host_port.port()
        );
        let log_path = service_log_path(name)?;
        initialize_service_log(log_path.as_deref(), name, "docker")?;

        let mut command = Command::new("docker");
        command
            .arg("run")
            .arg("--detach")
            .arg("--rm")
            .arg("--name")
            .arg(&container_name)
            .arg("--publish")
            .arg(format!("127.0.0.1:{}:{container_port}", host_port.port()));
        if let Some(network_name) = docker_network {
            command
                .arg("--network")
                .arg(network_name)
                .arg("--network-alias")
                .arg(&alias)
                .arg("--hostname")
                .arg(&alias);
        }
        command
            .arg("--env")
            .arg(format!("SOLAND_BIND=0.0.0.0:{container_port}"))
            .arg("--env")
            .arg(format!("SOLAND_PUBLIC_BASE_URL={public_base_url}"))
            .arg("--env")
            .arg(format!("SOLAND_NOTARY_SIGNING_KEY={}", notary_signing_key))
            .arg("--env")
            .arg("SOLAND_DEVELOPMENT_MODE=1")
            .arg("--env")
            .arg("SOLAND_FIRST_PROVISIONING=1")
            .arg("--env")
            .arg("SOLAND_SEED_DEMO_DATA=1")
            .arg("--env")
            .arg(format!(
                "SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER={EMBEDDED_WEBVH_REGISTRATION_BEARER}"
            ))
            .arg("--env")
            .arg("SOLAND_BLOB_ROOT=/tmp/soland-blobs");
        for &(key, value) in extra_env {
            command.arg("--env").arg(format!("{key}={value}"));
        }
        command.arg(&image);

        // Release the guard listener right before docker publishes the port.
        host_port.release();
        run_command(
            &mut command,
            &format!("failed to start docker SUT from image {image}"),
        )?;

        if let Err(error) = wait_until_healthy(base_url.clone()).await {
            let logs = docker_logs(&container_name).unwrap_or_default();
            let _ = append_service_log(log_path.as_deref(), &logs);
            let _ = docker_remove_container(&container_name);
            let log_suffix = if logs.trim().is_empty() {
                String::new()
            } else {
                format!("; container logs:\n{logs}")
            };
            return Err(anyhow!("{error}{log_suffix}"));
        }
        let service_id = fetch_service_id(&base_url).await?;

        Ok(Self {
            handle: SutHandle::Docker { container_name },
            base_url,
            service_id,
            notary_signing_key_seed,
            blob_root: None,
            log_path,
            _port_reservations: vec![host_port],
        })
    }

    pub fn base_url(&self) -> Url {
        self.base_url.clone()
    }

    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    pub(crate) fn notary_signing_key_seed(&self) -> &[u8; 32] {
        &self.notary_signing_key_seed
    }

    pub fn http(&self) -> HttpClient {
        HttpClient::new()
    }

    pub fn sdk(&self) -> Result<SdkClient> {
        // Harness-only: cotest SUTs bind to loopback/self-signed local
        // endpoints. Do not copy this into non-local service clients.
        Ok(SdkClient::builder(self.base_url())
            .allow_insecure_localhost()
            .build()?)
    }

    pub fn url(&self, path: &str) -> String {
        self.base_url
            .join(path.trim_start_matches('/'))
            .expect("valid test path")
            .to_string()
    }

    pub async fn kill_immediately(&mut self) -> Result<()> {
        let handle = mem::replace(&mut self.handle, SutHandle::Terminated);
        match handle {
            SutHandle::Local(mut child) => {
                let _ = child.kill();
                child.wait().context("wait for killed soland child")?;
            }
            SutHandle::Docker { container_name } => {
                if let Ok(logs) = docker_logs(&container_name) {
                    let _ = append_service_log(self.log_path.as_deref(), &logs);
                }
                docker_remove_container(&container_name)
                    .with_context(|| format!("remove killed docker SUT {container_name}"))?;
            }
            SutHandle::Terminated => {}
        }
        if let Some(blob_root) = self.blob_root.take() {
            let _ = fs::remove_dir_all(blob_root);
        }
        Ok(())
    }

    pub async fn diagnostic_operation_query(&self, operation_id: &str) -> Result<Value> {
        let mut url = self.base_url.join("api/v1/conformance/chaos/operation")?;
        url.query_pairs_mut()
            .append_pair("operation_id", operation_id);
        expect_json(self.http().get(url), StatusCode::OK).await
    }

    pub async fn demo_client(&self, actor: &str, device_id: &str) -> Result<TestActorClient> {
        let token = dev_login(self, actor, device_id).await?;
        self.actor_client(actor, &canonical_device_id(device_id), token)
    }

    pub async fn register_client(
        &self,
        did: &str,
        handle: &str,
        device_id: &str,
    ) -> Result<TestActorClient> {
        let token = register_account(self, did, handle, device_id).await?;
        self.actor_client(did, &canonical_device_id(device_id), token)
    }

    /// Like [`register_client`] but also publishes a primary localpart binding
    /// via the canonical `<localpart>:<domain>` `published_handle`, so the
    /// account resolves a directory handle instead of `null`.
    pub async fn register_client_with_handle(
        &self,
        did: &str,
        display_handle: &str,
        published_handle: &str,
        device_id: &str,
    ) -> Result<TestActorClient> {
        let token = register_account_with_handle(
            self,
            did,
            display_handle,
            Some(published_handle),
            device_id,
        )
        .await?;
        self.actor_client(did, &canonical_device_id(device_id), token)
    }

    fn actor_client(&self, actor: &str, device_id: &str, token: String) -> Result<TestActorClient> {
        // Harness-only: actor clients talk to the same loopback SUT created
        // above, so insecure localhost TLS is acceptable for test traffic.
        let sdk = SdkClient::builder(self.base_url())
            .allow_insecure_localhost()
            .auth(Auth::Bearer(token.clone()))
            .build()?;
        Ok(TestActorClient {
            http: self.http(),
            sdk,
            base_url: self.base_url(),
            service_id: self.service_id.clone(),
            actor: actor.to_owned(),
            device_id: device_id.to_owned(),
            token,
        })
    }
}

impl Drop for ArkretServer {
    fn drop(&mut self) {
        match &mut self.handle {
            SutHandle::Local(child) => {
                let _ = child.kill();
                let _ = child.wait();
            }
            SutHandle::Docker { container_name } => {
                if let Ok(logs) = docker_logs(container_name) {
                    let _ = append_service_log(self.log_path.as_deref(), &logs);
                }
                let _ = docker_remove_container(container_name);
            }
            SutHandle::Terminated => {}
        }
        if let Some(blob_root) = &self.blob_root {
            let _ = fs::remove_dir_all(blob_root);
        }
    }
}

impl TestServerGroup {
    pub async fn single(name: &str) -> Result<Self> {
        Ok(Self {
            servers: vec![ArkretServer::spawn(name).await?],
            docker_network: None,
        })
    }

    /// fast path that spawns `count` pre-built soland binaries via
    /// the [`external_binary`] helper. Returns `Ok(None)` when the binary
    /// cannot be located or required env vars are missing — scenarios use
    /// this to silently skip federation tests on CI runners that have no
    /// `soland.exe` built and no `SOLAND_BIN=...` set, while still running
    /// the full multi-node strand on developer machines that do.
    ///
    /// Falls back to the slow `cargo run` `multi` path if `SOLAND_BIN` is
    /// unset *and* the sibling binary is also unavailable — callers that
    /// want strict skip semantics should prefer this constructor; callers
    /// that want best-effort spin-up via cargo can keep using `multi`.
    pub async fn try_multi_external(name: &str, count: usize) -> Result<Option<Self>> {
        use crate::scenarios::_helpers::external_binary::{SOLAND_SPEC, locate_external_binary};

        let Some(bin_path) = locate_external_binary(&SOLAND_SPEC) else {
            return Ok(None);
        };

        let servers = Self::spawn_external_federated(name, count, &bin_path).await?;
        Ok(Some(Self {
            servers,
            docker_network: None,
        }))
    }

    /// Spawn `count` pre-built soland binaries with each node wired to every
    /// other through endpoint-only `SOLAND_FEDERATION_PEERS` entries. Ports
    /// are reserved up front and each node resolves the peer service DID from
    /// standard describe after startup. Without the resulting mutual mesh, an inbound
    /// `/_arkret/peer/events` submission can never resolve the source peer's
    /// ServiceDescribe, so the federation profile gate falls back to
    /// `federation_minimal` and rejects core kinds like `ak.message.create`.
    ///
    /// The outbound dispatcher is disabled (`SOLAND_FEDERATION_OUTBOUND=0`)
    /// because federation scenarios drive cross-server delivery with explicit
    /// `/_arkret/peer/events` POSTs; leaving the background dispatcher on would
    /// race those deterministic submissions with unsolicited broadcasts.
    async fn spawn_external_federated(
        name: &str,
        count: usize,
        bin_path: &Path,
    ) -> Result<Vec<ArkretServer>> {
        struct Pending {
            name: String,
            port: ReservedPort,
            metrics: ReservedPort,
            url: String,
        }

        let mut pending = Vec::with_capacity(count);
        for index in 0..count {
            let node_name = format!("{name}-{index}");
            let port = reserve_port()?;
            let metrics = reserve_port()?;
            let url = format!("http://127.0.0.1:{}", port.port());
            pending.push(Pending {
                name: node_name,
                port,
                metrics,
                url,
            });
        }

        let peer_lists: Vec<String> = (0..count)
            .map(|index| {
                pending
                    .iter()
                    .enumerate()
                    .filter(|(other, _)| *other != index)
                    .map(|(_, peer)| peer.url.clone())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .collect();

        let mut servers = Vec::with_capacity(count);
        for (index, node) in pending.into_iter().enumerate() {
            let extra_env: Vec<(&str, &str)> = vec![
                ("SOLAND_FEDERATION_PEERS", peer_lists[index].as_str()),
                ("SOLAND_FEDERATION_OUTBOUND", "0"),
            ];
            match ArkretServer::spawn_external_binary_with_ports_and_env(
                &node.name,
                bin_path,
                node.port,
                node.metrics,
                &extra_env,
            )
            .await
            {
                Ok(server) => servers.push(server),
                Err(error) => {
                    drop(servers);
                    return Err(error);
                }
            }
        }
        Ok(servers)
    }

    pub async fn multi(name: &str, count: usize) -> Result<Self> {
        // Process-mode fast path: when a pre-built soland binary is available,
        // spawn the nodes as a mutually-wired federation mesh so inbound
        // `/_arkret/peer/events` submissions can resolve each peer's
        // ServiceDescribe (see `spawn_external_federated`). The slow
        // `cargo run` and Docker paths below keep their original behavior.
        if sut_runtime_mode() == SutRuntimeMode::Process {
            use crate::scenarios::_helpers::external_binary::{
                SOLAND_SPEC, locate_external_binary,
            };
            if let Some(bin_path) = locate_external_binary(&SOLAND_SPEC) {
                let servers = Self::spawn_external_federated(name, count, &bin_path).await?;
                return Ok(Self {
                    servers,
                    docker_network: None,
                });
            }
        }

        let docker_network = if sut_runtime_mode() == SutRuntimeMode::Docker {
            let network_name = format!(
                "cotest-{}-{}-{}",
                sanitize_runtime_name(name),
                std::process::id(),
                Utc::now().timestamp_millis()
            );
            docker_create_network(&network_name)?;
            Some(network_name)
        } else {
            None
        };
        let mut servers = Vec::with_capacity(count);
        for index in 0..count {
            match ArkretServer::spawn_with_network(
                &format!("{name}-{index}"),
                docker_network.as_deref(),
            )
            .await
            {
                Ok(server) => servers.push(server),
                Err(error) => {
                    drop(servers);
                    if let Some(network_name) = &docker_network {
                        let _ = docker_remove_network(network_name);
                    }
                    return Err(error);
                }
            }
        }
        Ok(Self {
            servers,
            docker_network,
        })
    }

    pub fn server(&self, index: usize) -> &ArkretServer {
        &self.servers[index]
    }

    pub fn len(&self) -> usize {
        self.servers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }
}

impl Drop for TestServerGroup {
    fn drop(&mut self) {
        self.servers.clear();
        if let Some(network_name) = self.docker_network.take() {
            let _ = docker_remove_network(&network_name);
        }
    }
}

fn sut_manifest() -> PathBuf {
    std::env::var_os("COTEST_SUT_MANIFEST")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join("soland")
                .join("Cargo.toml")
        })
}

fn sut_runtime_mode() -> SutRuntimeMode {
    match std::env::var("COTEST_SUT_MODE") {
        Ok(value) if value.eq_ignore_ascii_case("docker") => SutRuntimeMode::Docker,
        _ => SutRuntimeMode::Process,
    }
}

fn sut_image() -> String {
    std::env::var("COTEST_SUT_IMAGE").unwrap_or_else(|_| "cotest-soland:latest".to_owned())
}

fn sut_container_port() -> u16 {
    std::env::var("COTEST_SUT_CONTAINER_PORT")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(8008)
}

fn service_log_root() -> Option<PathBuf> {
    std::env::var_os("COTEST_SERVICE_LOG_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("COTEST_ARTIFACT_DIR")
                .map(PathBuf::from)
                .map(|path| path.join("services"))
        })
}

fn service_log_path(name: &str) -> Result<Option<PathBuf>> {
    let Some(root) = service_log_root() else {
        return Ok(None);
    };
    fs::create_dir_all(&root)?;
    Ok(Some(
        root.join(format!("{}.log", sanitize_runtime_name(name))),
    ))
}

fn service_log_stdio(path: Option<&Path>) -> Result<(Stdio, Stdio)> {
    let Some(path) = path else {
        return Ok((Stdio::null(), Stdio::null()));
    };
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    let stderr = file.try_clone()?;
    Ok((Stdio::from(file), Stdio::from(stderr)))
}

fn initialize_service_log(path: Option<&Path>, name: &str, runtime: &str) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let header = format!("[cotest] service={name} runtime={runtime}\n");
    fs::write(path, header)?;
    Ok(())
}

fn append_service_log(path: Option<&Path>, content: &str) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    if !content.trim().is_empty() {
        use std::io::Write as _;
        writeln!(file, "{content}")?;
    }
    Ok(())
}

fn sanitize_runtime_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

fn run_command(command: &mut Command, context: &str) -> Result<String> {
    let output = command.output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "{context}: status {} stdout: {} stderr: {}",
            output.status,
            stdout.trim(),
            stderr.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn docker_create_network(network_name: &str) -> Result<()> {
    let mut command = Command::new("docker");
    command.arg("network").arg("create").arg(network_name);
    run_command(
        &mut command,
        &format!("failed to create docker network {network_name}"),
    )?;
    Ok(())
}

fn docker_remove_network(network_name: &str) -> Result<()> {
    let mut command = Command::new("docker");
    command.arg("network").arg("rm").arg(network_name);
    let output = command.output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("No such network") {
        return Ok(());
    }
    Err(anyhow!(
        "failed to remove docker network {network_name}: {}",
        stderr.trim()
    ))
}

fn docker_remove_container(container_name: &str) -> Result<()> {
    let mut command = Command::new("docker");
    command.arg("rm").arg("--force").arg(container_name);
    let output = command.output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("No such container") {
        return Ok(());
    }
    Err(anyhow!(
        "failed to remove docker container {container_name}: {}",
        stderr.trim()
    ))
}

fn docker_logs(container_name: &str) -> Result<String> {
    let mut command = Command::new("docker");
    command.arg("logs").arg(container_name);
    let output = command.output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(anyhow!(
            "failed to read logs for {container_name}: status {} stdout: {} stderr: {}",
            output.status,
            stdout.trim(),
            stderr.trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = if stderr.trim().is_empty() {
        stdout.trim().to_owned()
    } else if stdout.trim().is_empty() {
        stderr.trim().to_owned()
    } else {
        format!("{}\n{}", stdout.trim(), stderr.trim())
    };
    Ok(combined)
}

/// A loopback port reservation held for the lifetime of the service that will
/// bind it.
///
/// The reservation keeps the originally-bound [`TcpListener`] alive in
/// `listener` until [`ReservedPort::release`] is called immediately before the
/// child process binds the port. Holding the socket open prevents the OS from
/// handing the same ephemeral port to another `bind("127.0.0.1:0")` caller
/// (the classic reserve→spawn TOCTOU window), shrinking the unguarded gap to the
/// few instructions between `release()` and the child's own `bind()`.
pub(crate) struct ReservedPort {
    port: u16,
    path: PathBuf,
    listener: Option<TcpListener>,
}

impl ReservedPort {
    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    /// Drop the guard listener so the child process can bind the port. MUST be
    /// called right before spawning the child that will bind `port`; the
    /// file-lock + in-process set still prevent this manager from re-selecting
    /// the same number.
    pub(crate) fn release(&mut self) {
        self.listener = None;
    }
}

impl Drop for ReservedPort {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Reserve an ephemeral loopback port. The returned guard coordinates with
/// other cotest binaries through a temp-file reservation and must be held until
/// the service using the port has shut down.
pub(crate) fn reserve_port() -> Result<ReservedPort> {
    static RESERVED_PORTS: OnceLock<Mutex<BTreeSet<u16>>> = OnceLock::new();
    let reservation_dir = port_reservation_dir()?;
    cleanup_stale_port_reservations(&reservation_dir);

    let reserved = RESERVED_PORTS.get_or_init(|| Mutex::new(BTreeSet::new()));
    let mut reserved = reserved
        .lock()
        .map_err(|_| anyhow!("port reservation set is poisoned"))?;

    for _ in 0..128 {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        if reserved.contains(&port) {
            continue;
        }
        let path = reservation_dir.join(format!("port-{port}.lock"));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                writeln!(file, "pid={}", std::process::id())?;
                writeln!(file, "port={port}")?;
                reserved.insert(port);
                return Ok(ReservedPort {
                    port,
                    path,
                    listener: Some(listener),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to create port reservation {}", path.display())
                });
            }
        }
    }

    Err(anyhow!(
        "failed to reserve a unique loopback port after 128 attempts"
    ))
}

fn port_reservation_dir() -> Result<PathBuf> {
    let dir = std::env::temp_dir().join("cotest-port-reservations-v1");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn cleanup_stale_port_reservations(dir: &Path) {
    let stale_after = Duration::from_secs(6 * 60 * 60);
    let now = SystemTime::now();
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some(port) = file_name
            .strip_prefix("port-")
            .and_then(|value| value.strip_suffix(".lock"))
            .and_then(|value| value.parse::<u16>().ok())
        else {
            continue;
        };
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let is_stale = metadata
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age > stale_after);
        if is_stale && TcpListener::bind(("127.0.0.1", port)).is_ok() {
            let _ = fs::remove_file(path);
        }
    }
}

async fn wait_until_healthy(base_url: Url) -> Result<()> {
    let client = HttpClient::new();
    let health_url = base_url.join("health")?;
    let mut last_error = None;
    let attempts = std::env::var("COTEST_SUT_HEALTH_ATTEMPTS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(480);

    for _ in 0..attempts {
        match client.get(health_url.clone()).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                let body = body.trim();
                last_error = Some(if body.is_empty() {
                    anyhow!("health status {status}")
                } else {
                    anyhow!("health status {status}: {body}")
                });
            }
            Err(error) => last_error = Some(error.into()),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    Err(last_error.unwrap_or_else(|| anyhow!("server did not become healthy")))
}

async fn fetch_service_id(base_url: &Url) -> Result<String> {
    let url = base_url.join("/_arkret/describe")?;
    let response = HttpClient::new()
        .get(url.clone())
        .send()
        .await
        .with_context(|| format!("fetch service describe from {url}"))?
        .error_for_status()
        .with_context(|| format!("service describe failed at {url}"))?;
    let body: Value = response.json().await?;
    body.get("service_id")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("did:"))
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("service describe at {url} omitted a valid service_id"))
}
