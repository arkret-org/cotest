use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};
use std::{fs, mem};

use anyhow::{Context, Result, anyhow};
use arkret::{Did, DidCoreId, TrustDomainId};
use arkret_http_client::{Auth, Client as SdkClient};
use arkret_models_identity::service_identity::SERVICE_REGISTRATION_ENSURE_PATH;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as BASE64_STANDARD, URL_SAFE_NO_PAD};
use chrono::Utc;
use reqwest::{Client as HttpClient, IntoUrl, Method, RequestBuilder, StatusCode};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use url::Url;

use super::assertions::expect_json;
use super::canonical_device_id;
use super::client::TestActorClient;
use super::principal::ProvisionedTestPrincipal;
use crate::scenarios::_helpers::coauth_bootstrap::{EphemeralPg, spawn_ephemeral_postgres_for};
use crate::scenarios::identity_test_support::{
    ActorBootstrapRegistration, HARNESS_ACCOUNT_AUTHORITY_ORIGIN, bootstrap_registered_actor,
    harness_account_authority_id, harness_account_authority_public_key_multibase,
};

const EMBEDDED_WEBVH_REGISTRATION_BEARER: &str = "cotest-embedded-webvh-registration";
const DURABLE_TEST_KEYSTORE_MASTER_KEY: &str = "d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3c=";
const HARNESS_HTTP_TIMEOUT: Duration = Duration::from_secs(45);
const HARNESS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// What [`ArkretServer::canonical_client`] needs from its caller.
///
/// Packed rather than passed as seven strings, where a swapped pair would type
/// check and fail somewhere deep in the chain. Every field is supplied by the
/// caller: this harness never discovers or defaults a deployment endpoint,
/// because a defaulted one is how a test ends up provisioning against the wrong
/// Station and reporting it as a protocol failure.
pub struct CanonicalClientRequest<'a> {
    /// The HTTP client the chain runs on. It must trust the run-scoped CA and
    /// keep a cookie jar: Coauth's account session lives in a cookie and the
    /// gate handoff authorizes against it.
    pub http: &'a reqwest::Client,
    pub endpoints: &'a cotest_test_support::provisioning::DeploymentEndpoints,
    pub oidc_client_id: &'a str,
    /// Bare localpart; the email is derived from it.
    pub handle: &'a str,
    pub password: &'a str,
    pub device_id: &'a str,
    pub display_name: &'a str,
}

#[derive(Clone)]
pub struct OperationSelectingHttpClient {
    inner: HttpClient,
}

impl OperationSelectingHttpClient {
    fn request_with_selector<U>(&self, method: Method, url: U) -> RequestBuilder
    where
        U: IntoUrl,
    {
        let builder = self.inner.request(method.clone(), url);
        let operation = builder
            .try_clone()
            .and_then(|candidate| candidate.build().ok())
            .and_then(|request| {
                arkret_wire::ServiceOperationId::from_http_request(
                    method.as_str(),
                    request.url().path(),
                )
            });
        match operation {
            Some(operation) => {
                builder.header(arkret_http_client::HEADER_OPERATION, operation.as_str())
            }
            None => builder,
        }
    }

    pub fn request<U>(&self, method: Method, url: U) -> RequestBuilder
    where
        U: IntoUrl,
    {
        self.request_with_selector(method, url)
    }

    pub fn delete<U>(&self, url: U) -> RequestBuilder
    where
        U: IntoUrl,
    {
        self.request_with_selector(Method::DELETE, url)
    }

    pub fn get<U>(&self, url: U) -> RequestBuilder
    where
        U: IntoUrl,
    {
        self.request_with_selector(Method::GET, url)
    }

    pub fn head<U>(&self, url: U) -> RequestBuilder
    where
        U: IntoUrl,
    {
        self.request_with_selector(Method::HEAD, url)
    }

    pub fn patch<U>(&self, url: U) -> RequestBuilder
    where
        U: IntoUrl,
    {
        self.request_with_selector(Method::PATCH, url)
    }

    pub fn post<U>(&self, url: U) -> RequestBuilder
    where
        U: IntoUrl,
    {
        self.request_with_selector(Method::POST, url)
    }

    pub fn put<U>(&self, url: U) -> RequestBuilder
    where
        U: IntoUrl,
    {
        self.request_with_selector(Method::PUT, url)
    }
}

impl std::ops::Deref for OperationSelectingHttpClient {
    type Target = HttpClient;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

pub struct ArkretServer {
    handle: SutHandle,
    http_client: HttpClient,
    external_restart: Option<ExternalRestartConfig>,
    base_url: Url,
    service_id: DidCoreId,
    service_did: Did,
    service_notary_signer: arkret_wire::NotarySignerDescriptor,
    trust_domain: TrustDomainId,
    blob_root: Option<PathBuf>,
    log_path: Option<PathBuf>,
    /// `host:port` this soland's Prometheus listener was bound to, when the
    /// harness owns the bind (DID-P1-C02 reads
    /// `soland_did_resolve_total{source="network"}` and
    /// `soland_signature_verify_total` from it). `None` for the docker path,
    /// which publishes only the HTTP port.
    metrics_bind: Option<String>,
    _port_reservations: Vec<ReservedPort>,
    /// Owns the isolated PostgreSQL instance provisioned by the default
    /// harness spawn path. Soland runtime persistence is PostgreSQL-only; the
    /// harness must therefore keep the database alive for exactly as long as
    /// the child process rather than falling back to a test-only memory store.
    _database: Option<EphemeralPg>,
    /// Keeps the process-only TLS authority and certificate files alive for
    /// exactly as long as at least one server from the run still needs them.
    _tls: Option<Arc<HarnessTls>>,
}

struct HarnessTls {
    _directory: tempfile::TempDir,
    ca_path: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
    ca_pem: Vec<u8>,
}

impl HarnessTls {
    fn new() -> Result<Self> {
        use rcgen::{
            BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
            KeyUsagePurpose,
        };

        let directory = tempfile::tempdir().context("create Cotest TLS authority directory")?;
        let ca_path = directory.path().join("ca.pem");
        let cert_path = directory.path().join("server-chain.pem");
        let key_path = directory.path().join("server-key.pem");

        let mut ca_params = CertificateParams::new(Vec::new())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .key_usages
            .extend([KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]);
        let ca_key = KeyPair::generate()?;
        let ca_cert = ca_params.self_signed(&ca_key)?;
        let issuer = Issuer::new(ca_params, ca_key);

        // Keep the SAN deliberately limited to the exact URL used by the
        // harness. `localhost` must fail hostname verification even though it
        // reaches the same loopback listener.
        let mut server_params = CertificateParams::new(vec!["127.0.0.1".to_owned()])?;
        server_params
            .key_usages
            .push(KeyUsagePurpose::DigitalSignature);
        server_params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let server_key = KeyPair::generate()?;
        let server_cert = server_params.signed_by(&server_key, &issuer)?;

        let ca_pem = ca_cert.pem().into_bytes();
        let mut server_chain = server_cert.pem();
        server_chain.push_str(std::str::from_utf8(&ca_pem)?);
        fs::write(&ca_path, &ca_pem).context("write Cotest TLS CA")?;
        fs::write(&cert_path, server_chain).context("write Cotest TLS certificate chain")?;
        fs::write(&key_path, server_key.serialize_pem()).context("write Cotest TLS private key")?;

        Ok(Self {
            _directory: directory,
            ca_path,
            cert_path,
            key_path,
            ca_pem,
        })
    }

    fn http_client(&self) -> Result<HttpClient> {
        let certificates =
            reqwest::Certificate::from_pem_bundle(&self.ca_pem).context("parse Cotest TLS CA")?;
        HttpClient::builder()
            // This is a run-scoped test PKI, so validate it with rustls/webpki
            // directly instead of routing the extra root through the platform
            // verifier.  On Windows the latter delegates the chain signature
            // check to CryptoAPI and rejects rcgen's ephemeral CA even though
            // the same DER validates under webpki.  Keeping this root-only
            // store also makes the negative trust-boundary checks exact.
            .tls_backend_rustls()
            .tls_certs_only(certificates)
            .connect_timeout(HARNESS_CONNECT_TIMEOUT)
            .timeout(HARNESS_HTTP_TIMEOUT)
            .no_proxy()
            .build()
            .context("build Cotest TLS client")
    }

    fn apply_to_command(&self, command: &mut Command) {
        command
            .env("SOLAND_TLS_CERT_PATH", &self.cert_path)
            .env("SOLAND_TLS_KEY_PATH", &self.key_path)
            .env("SSL_CERT_FILE", &self.ca_path);
    }
}

#[derive(Clone)]
struct ExternalRestartConfig {
    bin_path: PathBuf,
    bind: String,
    metrics_bind: String,
    notary_signing_key: String,
    name: String,
    extra_env: Vec<(String, String)>,
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

fn test_service_notary_signer(
    service_id: &DidCoreId,
    service_did: &Did,
    signing_seed: [u8; 32],
) -> Result<arkret_wire::NotarySignerDescriptor> {
    let public_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed)
        .verifying_key()
        .to_bytes();
    let descriptor = arkret_wire::NotarySignerDescriptor {
        actor_id: arkret_wire::ActorId::service(service_id.clone()),
        verification_method: arkret_wire::DidUrl::new(format!("{service_did}#notary-key"))
            .map_err(anyhow::Error::msg)?,
        key_kind: arkret_wire::NotaryKeyKind::Ed25519Raw32,
        jose_algorithm: arkret_wire::NotaryJoseAlgorithm::Ed25519,
        frozen_public_key_b64u: URL_SAFE_NO_PAD.encode(public_key),
        frozen_public_key_digest: arkret_wire::Hash::new(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(public_key))
        ))?,
    };
    descriptor.validate()?;
    Ok(descriptor)
}

/// Every cotest SUT trusts the harness-owned Account Authority identity so the
/// canonical actor bootstrap can relay PCR genesis units no matter which spawn
/// path produced the process. Callers that wire a real Account Authority
/// (joint stack, durable federation lives) keep their own values.
fn harness_account_authority_env(has: impl Fn(&str) -> bool) -> Vec<(String, String)> {
    let mut env = Vec::new();
    if !has("SOLAND_ACCOUNT_AUTHORITY_URL") {
        env.push((
            "SOLAND_ACCOUNT_AUTHORITY_URL".to_owned(),
            HARNESS_ACCOUNT_AUTHORITY_ORIGIN.to_owned(),
        ));
    }
    if !has("SOLAND_ACCOUNT_AUTHORITY_SERVICE_ID") {
        env.push((
            "SOLAND_ACCOUNT_AUTHORITY_SERVICE_ID".to_owned(),
            harness_account_authority_id().to_string(),
        ));
    }
    if !has("SOLAND_ACCOUNT_AUTHORITY_PUBLIC_KEY_MULTIBASE") {
        env.push((
            "SOLAND_ACCOUNT_AUTHORITY_PUBLIC_KEY_MULTIBASE".to_owned(),
            harness_account_authority_public_key_multibase(),
        ));
    }
    env
}

impl ArkretServer {
    pub async fn spawn(name: &str) -> Result<Self> {
        Self::spawn_with_env(name, &[]).await
    }

    pub async fn spawn_with_env(name: &str, extra_env: &[(&str, &str)]) -> Result<Self> {
        let database = spawn_ephemeral_postgres_for("COTEST_SOLAND_DATABASE_URL")?
            .context(
                "Soland Cotest runtime requires PostgreSQL; set COTEST_SOLAND_DATABASE_URL or make Docker available for an isolated test database",
            )?;
        let mut env = Vec::with_capacity(extra_env.len() + 1);
        env.push(("DATABASE_URL", database.connect_url.as_str()));
        env.extend_from_slice(extra_env);
        let mut server = Self::spawn_with_network_and_env(name, None, &env).await?;
        server._database = Some(database);
        Ok(server)
    }

    pub async fn spawn_with_database_url(
        name: &str,
        database_url: &str,
        extra_env: &[(&str, &str)],
    ) -> Result<Self> {
        let mut env = Vec::with_capacity(extra_env.len() + 1);
        env.push(("DATABASE_URL", database_url));
        env.extend_from_slice(extra_env);
        Self::spawn_with_network_and_env(name, None, &env).await
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

    /// Spawn a pre-built Soland binary directly and inject `extra_env` into
    /// the child process. The binary receives `--bind <addr>` and shares the
    /// same environment path used by federation scenarios.
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
    pub(crate) async fn spawn_external_binary_with_ports_and_env(
        name: &str,
        bin_path: &Path,
        port: ReservedPort,
        metrics_port: ReservedPort,
        extra_env: &[(&str, &str)],
    ) -> Result<Self> {
        Self::spawn_external_binary_with_ports_env_and_tls(
            name,
            bin_path,
            port,
            metrics_port,
            extra_env,
            Arc::new(HarnessTls::new()?),
        )
        .await
    }

    async fn spawn_external_binary_with_ports_env_and_tls(
        name: &str,
        bin_path: &Path,
        mut port: ReservedPort,
        mut metrics_port: ReservedPort,
        extra_env: &[(&str, &str)],
        tls: Arc<HarnessTls>,
    ) -> Result<Self> {
        let bind = format!("127.0.0.1:{}", port.port());
        let metrics_bind = format!("127.0.0.1:{}", metrics_port.port());
        let metrics_bind_for_handle = metrics_bind.clone();
        let base_url = Url::parse(&format!("https://127.0.0.1:{}/", port.port()))?;
        let (notary_signing_key, notary_signing_seed) = test_service_signing_key(name);
        let blob_root = std::env::temp_dir().join(format!("cotest-{name}-{}-blobs", port.port()));
        let _ = fs::remove_dir_all(&blob_root);
        fs::create_dir_all(&blob_root)?;
        // Always retain process output for restart diagnostics. When the caller
        // does not request a persistent artifact directory, keep the log in the
        // run-scoped blob root so Drop removes it with the rest of the fixture.
        let log_path = service_log_path(name)?.or_else(|| Some(blob_root.join("service.log")));
        initialize_service_log(log_path.as_deref(), name, "external_binary")?;
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
            .env("SOLAND_TRUST_DOMAIN", test_trust_domain(name))
            .env(
                "SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER",
                EMBEDDED_WEBVH_REGISTRATION_BEARER,
            )
            .env("SOLAND_BLOB_ROOT", &blob_root)
            .stdout(stdout)
            .stderr(stderr);
        tls.apply_to_command(&mut command);
        // `SOLAND_KEYSTORE_PATH` / `_MASTER_KEY` only mean anything to the
        // `encrypted_file` backend, so injecting them under a caller-chosen
        // backend hands soland a contradictory keystore config that it rejects
        // at startup. A caller that names a backend owns the whole trio.
        let durable_keystore_needed = extra_env.iter().any(|(key, _)| {
            matches!(
                *key,
                "DATABASE_URL" | "SOLAND_EXTERNAL_WEBVH_REGISTRATION_BEARER"
            )
        });
        let keystore_backend_chosen = extra_env
            .iter()
            .any(|(key, _)| *key == "SOLAND_KEYSTORE_BACKEND");
        if durable_keystore_needed && !keystore_backend_chosen {
            command
                .env("SOLAND_KEYSTORE_BACKEND", "encrypted_file")
                .env("SOLAND_KEYSTORE_PATH", blob_root.join("keystore.v1"))
                .env(
                    "SOLAND_KEYSTORE_MASTER_KEY",
                    DURABLE_TEST_KEYSTORE_MASTER_KEY,
                );
        }
        for (key, value) in
            harness_account_authority_env(|key| extra_env.iter().any(|(k, _)| *k == key))
        {
            command.env(key, value);
        }
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

        if let Err(error) = wait_until_process_healthy(
            base_url.clone(),
            &mut child,
            log_path.as_deref(),
            Some(&tls),
        )
        .await
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        let (service_id, service_did, trust_domain) =
            match fetch_service_identity(&base_url, Some(&tls)).await {
                Ok(identity) => identity,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(error);
                }
            };
        let service_notary_signer =
            test_service_notary_signer(&service_id, &service_did, notary_signing_seed)?;

        Ok(Self {
            handle: SutHandle::Local(child),
            http_client: probe_http_client(Some(&tls))?,
            external_restart: Some(ExternalRestartConfig {
                bin_path: bin_path.to_owned(),
                bind,
                metrics_bind,
                notary_signing_key,
                name: name.to_owned(),
                extra_env: extra_env
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                    .collect(),
            }),
            base_url,
            service_id,
            service_did,
            service_notary_signer,
            trust_domain,
            blob_root: Some(blob_root),
            log_path,
            metrics_bind: Some(metrics_bind_for_handle),
            _port_reservations: vec![port, metrics_port],
            _database: None,
            _tls: Some(tls),
        })
    }

    async fn spawn_process(name: &str, extra_env: &[(&str, &str)]) -> Result<Self> {
        // Process mode requires a pre-built binary supplied explicitly or
        // found in the sibling checkout. Test execution never compiles a SUT.
        use crate::scenarios::_helpers::external_binary::{SOLAND_SPEC, locate_external_binary};
        if let Some(bin_path) = locate_external_binary(&SOLAND_SPEC) {
            return Self::spawn_external_binary_with_env(name, &bin_path, extra_env).await;
        }
        Err(anyhow!(
            "process-mode Soland requires a pre-built binary; set SOLAND_BIN or build the sibling soland target first"
        ))
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
        let (notary_signing_key, notary_signing_seed) = test_service_signing_key(name);
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
            .arg(format!("SOLAND_TRUST_DOMAIN={}", test_trust_domain(name)))
            .arg("--env")
            .arg(format!(
                "SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER={EMBEDDED_WEBVH_REGISTRATION_BEARER}"
            ))
            .arg("--env")
            .arg("SOLAND_BLOB_ROOT=/tmp/soland-blobs");
        for (key, value) in
            harness_account_authority_env(|key| extra_env.iter().any(|(k, _)| *k == key))
        {
            command.arg("--env").arg(format!("{key}={value}"));
        }
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
        let (service_id, service_did, trust_domain) =
            match fetch_service_identity(&base_url, None).await {
                Ok(identity) => identity,
                Err(error) => {
                    let logs = docker_logs(&container_name).unwrap_or_default();
                    let _ = append_service_log(log_path.as_deref(), &logs);
                    let _ = docker_remove_container(&container_name);
                    return Err(error);
                }
            };
        let service_notary_signer =
            test_service_notary_signer(&service_id, &service_did, notary_signing_seed)?;

        Ok(Self {
            handle: SutHandle::Docker { container_name },
            http_client: probe_http_client(None)?,
            external_restart: None,
            base_url,
            service_id,
            service_did,
            service_notary_signer,
            trust_domain,
            blob_root: None,
            log_path,
            // The container publishes only the HTTP port, so the metrics
            // listener is unreachable from the host.
            metrics_bind: None,
            _port_reservations: vec![host_port],
            _database: None,
            _tls: None,
        })
    }

    pub fn base_url(&self) -> Url {
        self.base_url.clone()
    }

    /// Explicit trust anchor for subprocesses that call this harness-owned
    /// HTTPS server. It is absent for ordinary production-style HTTP handles.
    pub(crate) fn tls_ca_path(&self) -> Option<&Path> {
        self._tls.as_ref().map(|tls| tls.ca_path.as_path())
    }

    pub fn service_id(&self) -> &DidCoreId {
        &self.service_id
    }

    pub fn service_did(&self) -> &Did {
        &self.service_did
    }

    pub fn service_notary_signer(&self) -> &arkret_wire::NotarySignerDescriptor {
        &self.service_notary_signer
    }

    /// Sign a Station-admission binding with this external fixture Station's
    /// configured notary key. This is intentionally limited to the harness:
    /// conformance fixtures sometimes need accepted envelopes without driving
    /// unrelated production fanout work for every synthetic history row.
    pub(crate) fn sign_station_admission_proof(
        &self,
        proof: &mut arkret_wire::StationAdmissionProof,
    ) -> Result<()> {
        let config = self
            .external_restart
            .as_ref()
            .context("Station admission fixture requires an external Soland process")?;
        let seed = BASE64_STANDARD
            .decode(&config.notary_signing_key)
            .context("decode external Soland notary seed")?;
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| anyhow!("external Soland notary seed must contain 32 bytes"))?;
        let binding = proof
            .canonical_binding_bytes()
            .context("encode Station admission binding")?;
        proof.jws = arkret_signatures::sign_ed25519_detached_jws(
            &ed25519_dalek::SigningKey::from_bytes(&seed),
            &binding,
        )
        .context("sign Station admission fixture proof")?;
        Ok(())
    }

    pub fn trust_domain(&self) -> &TrustDomainId {
        &self.trust_domain
    }

    /// `http://host:port` of this soland's Prometheus listener, when the
    /// harness owns the bind.
    ///
    /// `None` means the metrics endpoint is unreachable for this spawn mode
    /// (docker publishes only the HTTP port). A DID-P1-C02 scenario must skip
    /// on `None` rather than treat an unreadable counter as a passing zero.
    pub fn metrics_base_url(&self) -> Option<String> {
        self.metrics_bind
            .as_deref()
            .map(|bind| format!("http://{bind}"))
    }

    /// Client for this soland's DID-boundary counters
    /// (`soland_did_resolve_total{source="network"}` →
    /// `authority_network_call_count`, `soland_signature_verify_total` →
    /// `signature_verify_count`). `Ok(None)` when the metrics listener is not
    /// reachable for this spawn mode.
    pub fn did_boundary_metrics(
        &self,
    ) -> Result<Option<crate::scenarios::_helpers::service_metrics::ServiceMetricsClient>> {
        use crate::scenarios::_helpers::service_metrics::{MeteredService, ServiceMetricsClient};
        let Some(base_url) = self.metrics_base_url() else {
            return Ok(None);
        };
        ServiceMetricsClient::new(MeteredService::Soland, base_url).map(Some)
    }

    pub fn http(&self) -> OperationSelectingHttpClient {
        OperationSelectingHttpClient {
            inner: self.http_client.clone(),
        }
    }

    /// Build a request for Soland's deployment-local account projection fixture.
    /// Canonical Account Authority registration is not owned by a Station; live Cotest setup
    /// materializes its result through `/_soland`.
    pub fn account_registration_request(&self) -> reqwest::RequestBuilder {
        self.http()
            .post(self.url("/_soland/self/account/register"))
            .bearer_auth(EMBEDDED_WEBVH_REGISTRATION_BEARER)
    }

    /// Build an authenticated request to the embedded WebVH provider used by
    /// Cotest's deterministic service-registration fixtures.
    pub(crate) fn service_registration_ensure_request(&self) -> reqwest::RequestBuilder {
        self.http()
            .post(self.url(SERVICE_REGISTRATION_ENSURE_PATH))
            .bearer_auth(EMBEDDED_WEBVH_REGISTRATION_BEARER)
    }

    /// Stop an externally spawned Soland while retaining every restart input.
    pub async fn stop_external_process(&mut self) -> Result<()> {
        if self.external_restart.is_none() {
            return Err(anyhow!(
                "Soland stop requires the pre-built external-binary harness"
            ));
        }
        let handle = mem::replace(&mut self.handle, SutHandle::Terminated);
        let SutHandle::Local(mut child) = handle else {
            self.handle = handle;
            return Err(anyhow!("Soland stop is only supported in process mode"));
        };
        let _ = child.kill();
        child.wait().context("wait for stopped Soland child")?;
        Ok(())
    }

    /// Start a previously stopped external Soland from the exact retained
    /// ports, durable database, service identity inputs, blob root, and peer
    /// wiring.
    pub async fn start_external_process(&mut self) -> Result<()> {
        let Some(config) = self.external_restart.clone() else {
            return Err(anyhow!(
                "Soland start requires the pre-built external-binary harness"
            ));
        };
        if !matches!(&self.handle, SutHandle::Terminated) {
            return Err(anyhow!("Soland start requires a stopped process"));
        }
        append_service_log(
            self.log_path.as_deref(),
            &format!("[cotest] starting retained service={}", config.name),
        )?;

        let (stdout, stderr) = service_log_stdio(self.log_path.as_deref())?;
        let blob_root = self
            .blob_root
            .as_ref()
            .context("external Soland restart lost its blob root")?;
        let mut command = Command::new(&config.bin_path);
        command
            .arg("--bind")
            .arg(&config.bind)
            .env_remove("DATABASE_URL")
            .env("SOLAND_PUBLIC_BASE_URL", self.base_url.as_str())
            .env("SOLAND_NOTARY_SIGNING_KEY", &config.notary_signing_key)
            .env("SOLAND_METRICS_BIND", &config.metrics_bind)
            .env("SOLAND_DEVELOPMENT_MODE", "1")
            .env("SOLAND_FIRST_PROVISIONING", "1")
            .env("SOLAND_SEED_DEMO_DATA", "1")
            .env("SOLAND_TRUST_DOMAIN", self.trust_domain.as_str())
            .env(
                "SOLAND_EMBEDDED_WEBVH_REGISTRATION_BEARER",
                EMBEDDED_WEBVH_REGISTRATION_BEARER,
            )
            .env("SOLAND_BLOB_ROOT", blob_root)
            .stdout(stdout)
            .stderr(stderr);
        if let Some(tls) = &self._tls {
            tls.apply_to_command(&mut command);
        }
        // Same rule as the initial spawn: a caller-chosen backend owns the whole
        // keystore trio, so the `encrypted_file`-only path and master key are
        // never mixed into it.
        let durable_keystore_needed = config.extra_env.iter().any(|(key, _)| {
            matches!(
                key.as_str(),
                "DATABASE_URL" | "SOLAND_EXTERNAL_WEBVH_REGISTRATION_BEARER"
            )
        });
        let keystore_backend_chosen = config
            .extra_env
            .iter()
            .any(|(key, _)| key == "SOLAND_KEYSTORE_BACKEND");
        if durable_keystore_needed && !keystore_backend_chosen {
            command
                .env("SOLAND_KEYSTORE_BACKEND", "encrypted_file")
                .env("SOLAND_KEYSTORE_PATH", blob_root.join("keystore.v1"))
                .env(
                    "SOLAND_KEYSTORE_MASTER_KEY",
                    DURABLE_TEST_KEYSTORE_MASTER_KEY,
                );
        }
        for (key, value) in
            harness_account_authority_env(|key| config.extra_env.iter().any(|(k, _)| k == key))
        {
            command.env(key, value);
        }
        for (key, value) in &config.extra_env {
            command.env(key, value);
        }
        let mut restarted = command.spawn().with_context(|| {
            format!(
                "failed to restart external Soland binary at {}",
                config.bin_path.display()
            )
        })?;
        if let Err(error) = wait_until_process_healthy(
            self.base_url.clone(),
            &mut restarted,
            self.log_path.as_deref(),
            self._tls.as_deref(),
        )
        .await
        {
            let _ = restarted.kill();
            let _ = restarted.wait();
            return Err(error);
        }
        let (service_id, service_did, trust_domain) =
            fetch_service_identity(&self.base_url, self._tls.as_deref()).await?;
        if service_id != self.service_id
            || service_did != self.service_did
            || trust_domain != self.trust_domain
        {
            let _ = restarted.kill();
            let _ = restarted.wait();
            return Err(anyhow!(
                "restarted Soland changed durable identity: {} / {}",
                service_id,
                trust_domain
            ));
        }
        self.handle = SutHandle::Local(restarted);
        Ok(())
    }

    /// Kill and restart an externally spawned Soland process without changing
    /// its ports, durable database, service identity inputs, blob root, or
    /// upstream participant wiring.
    pub async fn restart_external_process(&mut self) -> Result<()> {
        self.stop_external_process().await?;
        self.start_external_process().await
    }

    pub fn sdk(&self) -> Result<SdkClient> {
        let builder = SdkClient::builder(self.base_url());
        Ok(if self._tls.is_some() {
            builder.http_client(self.http_client.clone()).build()?
        } else {
            builder
                .allow_insecure_localhost()
                .timeout(HARNESS_HTTP_TIMEOUT)
                .connect_timeout(HARNESS_CONNECT_TIMEOUT)
                .build()?
        })
    }

    pub fn url(&self, path: &str) -> String {
        self.base_url
            .join(path.trim_start_matches('/'))
            .expect("valid test path")
            .to_string()
    }

    pub async fn assert_tls_trust_boundaries(&self) -> Result<()> {
        let Some(_) = &self._tls else {
            return Err(anyhow!(
                "TLS trust assertion requires the HTTPS process harness"
            ));
        };
        let health_url = self.base_url.join("health")?;
        let untrusted = HttpClient::builder()
            .connect_timeout(HARNESS_CONNECT_TIMEOUT)
            .timeout(HARNESS_CONNECT_TIMEOUT)
            .no_proxy()
            .build()?;
        anyhow::ensure!(
            untrusted.get(health_url).send().await.is_err(),
            "Cotest HTTPS endpoint unexpectedly trusted without its run-scoped CA"
        );

        let mut wrong_hostname = self.base_url.clone();
        wrong_hostname
            .set_host(Some("localhost"))
            .map_err(|_| anyhow!("failed to construct wrong-hostname TLS probe"))?;
        let wrong_hostname_url = wrong_hostname.join("health")?;
        anyhow::ensure!(
            self.http().get(wrong_hostname_url).send().await.is_err(),
            "Cotest HTTPS certificate unexpectedly accepted the localhost hostname"
        );

        self.http()
            .get(self.base_url.join("health")?)
            .send()
            .await?
            .error_for_status()
            .context("Cotest HTTPS endpoint rejected its run-scoped CA and IP SAN")?;
        Ok(())
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

    /// An actor with a real PCR genesis and a **development session**.
    ///
    /// What is canonical here is the §5.1 PCR genesis unit, installed
    /// atomically so the founding device holds an accepted
    /// `ak.device.authorize`. What is not is how the session is obtained:
    /// `dev_login`, the deployment-private endpoint — no account
    /// authorization, no OAuth handoff, no identity binding, no DPoP.
    ///
    /// The distinction matters because this is the entry point 52 scenarios
    /// call. A scenario asserting anything about *how* a principal or a session
    /// comes to exist is not testing that here; the canonical chain lives in
    /// `cotest_test_support::provisioning`. This doc comment used to open with
    /// "Canonical actor provisioning", which read as a claim about the whole
    /// thing.
    pub async fn demo_client(&self, actor: &str, device_id: &str) -> Result<TestActorClient> {
        let (principal, token) = bootstrap_registered_actor(
            self,
            actor,
            device_id,
            ActorBootstrapRegistration::DevLogin,
        )
        .await?;
        let client = self.actor_client(
            actor,
            principal.device_id.as_str(),
            crate::harness::ClientSession::DevBearer(token),
            Some(principal.clone()),
        )?;
        client.track_controlled_realm(&principal.pcr_realm_id);
        Ok(client)
    }

    pub async fn register_client(
        &self,
        did: &str,
        handle: &str,
        device_id: &str,
    ) -> Result<TestActorClient> {
        let (principal, token) = bootstrap_registered_actor(
            self,
            did,
            device_id,
            ActorBootstrapRegistration::Account { handle },
        )
        .await?;
        let client = self.actor_client(
            did,
            principal.device_id.as_str(),
            crate::harness::ClientSession::DevBearer(token),
            Some(principal.clone()),
        )?;
        client.track_controlled_realm(&principal.pcr_realm_id);
        Ok(client)
    }

    /// A client carrying a bearer the caller already holds.
    ///
    /// Development seam by construction: a canonical grant is not a bearer.
    /// Negative fixtures that present a bad or foreign token use this.
    pub fn client_with_token(
        &self,
        actor: &str,
        device_id: &str,
        token: String,
    ) -> Result<TestActorClient> {
        self.actor_client(
            actor,
            &canonical_device_id(device_id),
            crate::harness::ClientSession::DevBearer(token),
            None,
        )
    }

    /// A client whose principal was founded through the canonical chain.
    ///
    /// This is the entry point the dev-seam ones are measured against. The
    /// account is registered at Coauth, authorized through OAuth, handed off,
    /// and founds its PCR genesis and verified binding — the same code
    /// `cotest-provision` runs for the TypeScript suite, so the two cannot
    /// drift on what founding a principal means.
    ///
    /// Needs a Coauth deployment; `endpoints` and `oidc_client_id` come from
    /// the runner's topology, never from a default. The session it returns is
    /// [`ClientSession::Canonical`](crate::harness::ClientSession::Canonical):
    /// every request carries a DPoP proof, and scenarios that reach for a
    /// bearer will find `None` rather than a credential that 401s.
    pub async fn canonical_client(
        &self,
        request: CanonicalClientRequest<'_>,
    ) -> Result<TestActorClient> {
        use cotest_test_support::provisioning;

        let CanonicalClientRequest {
            http,
            endpoints,
            oidc_client_id,
            handle,
            password,
            device_id,
            display_name,
        } = request;

        let account = provisioning::UnboundAccount {
            handle: handle.to_owned(),
            email: format!("{handle}@example.test"),
            password: password.to_owned(),
            display_name: display_name.to_owned(),
        };
        provisioning::provision_unbound_account(http, endpoints, &account)
            .await
            .context("register and authenticate the Coauth account")?;

        let facts = provisioning::describe_station(http, endpoints)
            .await
            .context("describe the Station under test")?;
        let authorization = provisioning::authorize_with_current_account(
            http,
            &endpoints.coauth_base_url,
            oidc_client_id,
        )
        .await
        .context("complete the authorization-code flow")?;
        let device_key = provisioning::FoundingDeviceKey::derive(handle);
        let handoff = provisioning::create_account_handoff(
            http,
            &endpoints.coauth_base_url,
            &facts.service_id,
            &authorization,
            device_key,
        )
        .await
        .context("exchange the authorization for an account handoff")?;

        let device_id = canonical_device_id(device_id);
        let founded = provisioning::found_principal(
            http,
            provisioning::FoundPrincipalRequest {
                coauth_base: &endpoints.coauth_base_url,
                station_base: &endpoints.soland_base_url,
                trust_domain: &facts.trust_domain,
                audience_id: &facts.service_id,
                device_id: &device_id,
                display_name,
            },
            &handoff,
        )
        .await
        .context("found the principal through the canonical chain")?;

        // The Station this client will talk to has to be the one that bound the
        // principal. A grant for another Station is well formed and refused on
        // first use, which reads as a broken scenario rather than a wrong
        // deployment.
        let account_id = founded.account_id();
        if account_id.station_id.as_str() != self.service_id.as_str() {
            anyhow::bail!(
                "canonical provisioning bound {} to Station {}, not {}",
                account_id.principal_id.as_str(),
                account_id.station_id.as_str(),
                self.service_id.as_str()
            );
        }

        let session = crate::harness::ClientSession::Canonical {
            grant: founded.session_grant().session_grant.clone(),
            signing_key: std::sync::Arc::new(handoff.device_key.signing_key()),
        };
        self.actor_client(account_id.principal_id.as_str(), &device_id, session, None)
    }

    /// Register account-first, then publish a primary localpart through the
    /// service-authenticated account-localpart lifecycle.
    pub async fn register_client_with_localpart(
        &self,
        did: &str,
        display_handle: &str,
        localpart: &str,
        device_id: &str,
    ) -> Result<TestActorClient> {
        let (principal, token) = bootstrap_registered_actor(
            self,
            did,
            device_id,
            ActorBootstrapRegistration::AccountWithLocalpart {
                handle: display_handle,
                localpart,
            },
        )
        .await?;
        let client = self.actor_client(
            did,
            principal.device_id.as_str(),
            crate::harness::ClientSession::DevBearer(token),
            Some(principal.clone()),
        )?;
        client.track_controlled_realm(&principal.pcr_realm_id);
        Ok(client)
    }

    pub(crate) fn account_localpart_request(&self, did: &str) -> Result<reqwest::RequestBuilder> {
        let account_id = arkret::project_did_to_core_id(&Did::new(did.to_owned())?)?;
        let mut url = self.base_url();
        url.path_segments_mut()
            .map_err(|_| anyhow!("SUT base URL cannot carry path segments"))?
            .extend(["_soland", "accounts", account_id.as_str(), "localparts"]);
        Ok(self
            .http()
            .post(url)
            .bearer_auth(EMBEDDED_WEBVH_REGISTRATION_BEARER))
    }

    fn actor_client(
        &self,
        actor: &str,
        device_id: &str,
        session: crate::harness::ClientSession,
        principal: Option<ProvisionedTestPrincipal>,
    ) -> Result<TestActorClient> {
        // The SDK client authenticates the same way the raw request path does.
        // Two different credentials on one client is the shape that produces a
        // scenario passing through one surface and 401-ing on the other.
        let auth = match &session {
            crate::harness::ClientSession::DevBearer(token) => Auth::Bearer(token.clone()),
            crate::harness::ClientSession::Canonical { grant, signing_key } => {
                let signing_key = signing_key.clone();
                Auth::Dpop(arkret_http_client::DpopAuth::with_dpop_token(
                    grant.clone(),
                    move |request| {
                        garth::session::dpop::build_http_dpop_proof(request, &signing_key).map_err(
                            |error| {
                                arkret_http_client::Error::Protocol(format!(
                                    "build DPoP proof: {error}"
                                ))
                            },
                        )
                    },
                ))
            }
        };
        let builder = SdkClient::builder(self.base_url()).auth(auth);
        let sdk = if self._tls.is_some() {
            builder.http_client(self.http_client.clone()).build()?
        } else {
            builder
                .allow_insecure_localhost()
                .timeout(HARNESS_HTTP_TIMEOUT)
                .connect_timeout(HARNESS_CONNECT_TIMEOUT)
                .build()?
        };
        Ok(TestActorClient {
            http: self.http(),
            sdk,
            base_url: self.base_url(),
            service_id: self.service_id.to_string(),
            service_notary_signer: self.service_notary_signer.clone(),
            actor: actor.to_owned(),
            device_id: device_id.to_owned(),
            session,
            principal,
            controlled_realms: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::BTreeSet::new(),
            )),
            default_strands: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::BTreeMap::new(),
            )),
            held_grants: std::sync::Arc::new(std::sync::Mutex::new(
                std::collections::BTreeMap::new(),
            )),
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

    /// Spawn a mutually wired pre-built Soland mesh while giving every node
    /// its own environment. Durable cross-service scenarios use this to bind
    /// each process to a distinct PostgreSQL database without weakening the
    /// normal role-scoped Describe federation bootstrap.
    pub async fn try_multi_external_with_node_envs(
        name: &str,
        node_envs: &[Vec<(String, String)>],
    ) -> Result<Option<Self>> {
        use crate::scenarios::_helpers::external_binary::{SOLAND_SPEC, locate_external_binary};

        let Some(bin_path) = locate_external_binary(&SOLAND_SPEC) else {
            return Ok(None);
        };
        let servers =
            Self::spawn_external_federated_with_node_envs(name, node_envs, &bin_path).await?;
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
        let mut databases = Vec::with_capacity(count);
        let mut node_envs = Vec::with_capacity(count);
        for _ in 0..count {
            let database = spawn_ephemeral_postgres_for("COTEST_SOLAND_DATABASE_URL")?
                .context(
                    "federated Soland Cotest runtime requires one isolated PostgreSQL database per node",
                )?;
            node_envs.push(vec![(
                "DATABASE_URL".to_owned(),
                database.connect_url.clone(),
            )]);
            databases.push(database);
        }
        let mut servers =
            Self::spawn_external_federated_with_node_envs(name, &node_envs, bin_path).await?;
        for (server, database) in servers.iter_mut().zip(databases) {
            server._database = Some(database);
        }
        Ok(servers)
    }

    async fn spawn_external_federated_with_node_envs(
        name: &str,
        node_envs: &[Vec<(String, String)>],
        bin_path: &Path,
    ) -> Result<Vec<ArkretServer>> {
        let count = node_envs.len();
        if count == 0 {
            return Err(anyhow!("federated Soland group requires at least one node"));
        }
        let shared_trust_domain = test_trust_domain(name);
        let tls = Arc::new(HarnessTls::new()?);
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
            let url = format!("https://127.0.0.1:{}", port.port());
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
            let mut owned_env = node_envs[index].clone();
            owned_env.retain(|(key, _)| {
                !matches!(
                    key.as_str(),
                    "SOLAND_FEDERATION_PEERS" | "SOLAND_TRUST_DOMAIN"
                )
            });
            if !owned_env
                .iter()
                .any(|(key, _)| key == "SOLAND_FEDERATION_OUTBOUND")
            {
                owned_env.push(("SOLAND_FEDERATION_OUTBOUND".to_owned(), "0".to_owned()));
            }
            owned_env.push((
                "SOLAND_FEDERATION_PEERS".to_owned(),
                peer_lists[index].clone(),
            ));
            owned_env.push((
                "SOLAND_TRUST_DOMAIN".to_owned(),
                shared_trust_domain.clone(),
            ));
            let extra_env = owned_env
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str()))
                .collect::<Vec<_>>();
            match ArkretServer::spawn_external_binary_with_ports_env_and_tls(
                &node.name,
                bin_path,
                node.port,
                node.metrics,
                &extra_env,
                tls.clone(),
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
        // In process mode, spawn the pre-built Soland binaries as a
        // mutually-wired federation mesh so inbound
        // `/_arkret/peer/events` submissions can resolve each peer's
        // ServiceDescribe (see `spawn_external_federated`). Docker mode uses
        // the container path below.
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
        let shared_trust_domain = test_trust_domain(name);
        for index in 0..count {
            match ArkretServer::spawn_with_network_and_env(
                &format!("{name}-{index}"),
                docker_network.as_deref(),
                &[("SOLAND_TRUST_DOMAIN", shared_trust_domain.as_str())],
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

    pub fn server_mut(&mut self, index: usize) -> &mut ArkretServer {
        &mut self.servers[index]
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
    wait_until_healthy_inner(base_url, None, None, None).await
}

async fn wait_until_process_healthy(
    base_url: Url,
    child: &mut Child,
    log_path: Option<&Path>,
    tls: Option<&HarnessTls>,
) -> Result<()> {
    wait_until_healthy_inner(base_url, Some(child), log_path, tls).await
}

async fn wait_until_healthy_inner(
    base_url: Url,
    mut child: Option<&mut Child>,
    log_path: Option<&Path>,
    tls: Option<&HarnessTls>,
) -> Result<()> {
    let client = probe_http_client(tls)?;
    let health_url = base_url.join("health")?;
    let mut last_error = None;
    let attempts = std::env::var("COTEST_SUT_HEALTH_ATTEMPTS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(480);

    for _ in 0..attempts {
        if let Some(status) = child
            .as_deref_mut()
            .map(Child::try_wait)
            .transpose()
            .context("inspect Soland child status during startup")?
            .flatten()
        {
            let log = log_path
                .and_then(|path| fs::read_to_string(path).ok())
                .unwrap_or_default();
            let detail = log.trim();
            if detail.is_empty() {
                return Err(anyhow!(
                    "Soland exited before becoming healthy with status {status}"
                ));
            }
            return Err(anyhow!(
                "Soland exited before becoming healthy with status {status}; service log:\n{detail}"
            ));
        }
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

fn test_trust_domain(name: &str) -> String {
    format!(
        "ak:trust_domain:{}.cotest.local",
        sanitize_runtime_name(name)
    )
}

async fn fetch_service_identity(
    base_url: &Url,
    tls: Option<&HarnessTls>,
) -> Result<(DidCoreId, Did, TrustDomainId)> {
    let url = base_url.join("/_arkret/describe")?;
    let response = probe_http_client(tls)?
        .get(url.clone())
        .header("arkret-operation", "ak.server.read.describe.v1")
        .send()
        .await
        .with_context(|| format!("fetch service describe from {url}"))?
        .error_for_status()
        .with_context(|| format!("service describe failed at {url}"))?;
    let description: arkret::ServiceDescribe = response
        .json()
        .await
        .with_context(|| format!("service describe at {url} returned an invalid response"))?;
    description
        .validate()
        .with_context(|| format!("service describe at {url} failed validation"))?;
    let service_id = description.service_id;
    let service_did = description.service_resolution.did;
    anyhow::ensure!(
        arkret::project_did_to_core_id(&service_did)? == service_id,
        "service describe at {url} returned a mismatched service_id/did"
    );
    let trust_domain = description.trust_domain;
    Ok((service_id, service_did, trust_domain))
}

fn probe_http_client(tls: Option<&HarnessTls>) -> Result<HttpClient> {
    if let Some(tls) = tls {
        tls.http_client()
    } else {
        HttpClient::builder()
            .connect_timeout(HARNESS_CONNECT_TIMEOUT)
            .timeout(HARNESS_HTTP_TIMEOUT)
            .build()
            .context("build bounded Cotest health-probe client")
    }
}
