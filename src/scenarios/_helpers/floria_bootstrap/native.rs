//! Required native Push Gateway supply with real TLS and a fixed operator proxy.
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, ensure};
use base64::Engine as _;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use salvo::conn::rustls::{Keycert, RustlsConfig};
use salvo::conn::{Listener, TcpListener};
use salvo::prelude::*;
use serde_json::{Value, json};
use tempfile::{NamedTempFile, TempDir};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::task::{JoinHandle, JoinSet};

use crate::harness::{ArkretServer, reserve_port};
use crate::scenarios::_helpers::coauth_bootstrap::{EphemeralPg, spawn_ephemeral_postgres_for};
use crate::scenarios::_helpers::external_binary::SpawnedExternalProcess;

const PROVIDER_HOST: &str = "1.1.1.1";
const PROVIDER_AUTHORITY: &str = "1.1.1.1:443";
const APP_ID: &str = "org.arkret.native-push";
type Captures = Arc<Mutex<Vec<Value>>>;

fn bytes(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn headers(value: &salvo::http::HeaderMap) -> Value {
    Value::Array(
        value
            .iter()
            .map(|(name, value)| json!([name.as_str(), bytes(value.as_bytes())]))
            .collect(),
    )
}

/// An actual provider boundary reached through an explicitly configured proxy.
/// No production egress exception or private provider URL is configured.
pub struct NativePushProvider {
    _directory: TempDir,
    ca_path: PathBuf,
    proxy_url: String,
    provider_url: String,
    bearer: String,
    captures: Captures,
    tunnels: Captures,
    tasks: Vec<AbortTask>,
}

struct AbortTask(JoinHandle<()>);
impl Drop for AbortTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Clone)]
struct ProviderSink {
    bearer: String,
    captures: Captures,
}

#[handler]
impl ProviderSink {
    async fn handle(&self, req: &mut Request, res: &mut Response) {
        let result = async {
            ensure!(req.method() == salvo::http::Method::POST, "provider method");
            ensure!(req.header::<String>("authorization") == Some(format!("Bearer {}", self.bearer)), "provider authentication");
            let raw = req.payload_with_max_size(512 * 1024).await?.to_vec();
            let body: Value = serde_json::from_slice(&raw)?;
            ensure!(body["app_id"] == APP_ID, "provider app route");
            ensure!(req.uri().path().starts_with("/deliver/"), "provider device route");
            self.captures.lock().unwrap().push(json!({"method":req.method().as_str(),"uri":req.uri().to_string(),"headers":headers(req.headers()),"raw_body_base64":bytes(&raw),"body":body}));
            Ok::<_,anyhow::Error>(())
        }.await;
        match result {
            Ok(()) => {
                res.status_code(StatusCode::NO_CONTENT);
            }
            Err(error) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(error.to_string());
            }
        }
    }
}

impl NativePushProvider {
    pub async fn spawn() -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory = tempfile::tempdir().context("native push provider TLS custody")?;
        let mut ca_params = CertificateParams::new(Vec::new())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .key_usages
            .extend([KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign]);
        let ca_key = KeyPair::generate()?;
        let ca = ca_params.self_signed(&ca_key)?;
        let issuer = Issuer::new(ca_params, ca_key);
        let mut params = CertificateParams::new(vec![PROVIDER_HOST.to_owned()])?;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &issuer)?;
        let ca_path = directory.path().join("ca.pem");
        let cert_path = directory.path().join("chain.pem");
        let key_path = directory.path().join("key.pem");
        std::fs::write(&ca_path, ca.pem())?;
        std::fs::write(&cert_path, format!("{}{}", cert.pem(), ca.pem()))?;
        std::fs::write(&key_path, key.serialize_pem())?;
        let mut port = reserve_port()?;
        let sink_address = format!("127.0.0.1:{}", port.port());
        port.release();
        let acceptor = TcpListener::new(sink_address.clone())
            .rustls(RustlsConfig::new(
                Keycert::new()
                    .cert_from_path(&cert_path)?
                    .key_from_path(&key_path)?,
            ))
            .try_bind()
            .await?;
        let captures = Captures::default();
        let bearer = format!("native-provider-{}", uuid::Uuid::new_v4().simple());
        let sink = ProviderSink {
            bearer: bearer.clone(),
            captures: captures.clone(),
        };
        let router = Router::with_path("{**rest}").goal(sink);
        let sink_task = AbortTask(tokio::spawn(async move {
            Server::new(acceptor).serve(router).await;
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy_url = format!("http://{}/", listener.local_addr()?);
        let tunnels = Captures::default();
        let seen = tunnels.clone();
        let proxy_task = AbortTask(tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    connection = listener.accept() => {
                        let Ok((socket, _)) = connection else { break };
                        let address = sink_address.clone();
                        let seen = seen.clone();
                        tasks.spawn(async move {
                            let result = fixed_provider_tunnel(socket, &address, &seen).await;
                            if let Err(error) = result { seen.lock().unwrap().push(json!({"error":error.to_string()})); }
                        });
                    }
                    _ = tasks.join_next(), if !tasks.is_empty() => {}
                }
            }
        }));
        Ok(Self {
            _directory: directory,
            ca_path,
            proxy_url,
            provider_url: format!("https://{PROVIDER_HOST}/deliver/{{push_key}}"),
            bearer,
            captures,
            tunnels,
            tasks: vec![sink_task, proxy_task],
        })
    }

    pub fn observations(&self) -> Result<Value> {
        Ok(
            json!({"deployment":"explicit_operator_connect_proxy","declared_provider_url":self.provider_url,"proxy_url":self.proxy_url,"provider_received":self.captures.lock().unwrap().clone(),"connect_observations":self.tunnels.lock().unwrap().clone(),"tls_ca_sha256":arkret_canonical::sha256_digest(std::fs::read(&self.ca_path)?)}),
        )
    }
}

impl Drop for NativePushProvider {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.0.abort();
        }
    }
}

async fn fixed_provider_tunnel(
    mut socket: tokio::net::TcpStream,
    target: &str,
    captures: &Captures,
) -> Result<()> {
    let mut request = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        ensure!(
            socket.read(&mut byte).await? == 1,
            "incomplete proxy request"
        );
        request.push(byte[0]);
        ensure!(request.len() <= 8192, "proxy request header limit");
        if request.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = std::str::from_utf8(&request)?;
    let first = head.lines().next().context("proxy request line")?;
    if first != format!("CONNECT {PROVIDER_AUTHORITY} HTTP/1.1") {
        socket
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
        captures
            .lock()
            .unwrap()
            .push(json!({"request":head,"accepted":false}));
        return Ok(());
    }
    let mut backend = tokio::net::TcpStream::connect(target).await?;
    captures
        .lock()
        .unwrap()
        .push(json!({"request":head,"accepted":true,"fixed_owned_target":target}));
    socket
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    tokio::io::copy_bidirectional(&mut socket, &mut backend).await?;
    Ok(())
}

/// Keeps the real binary, database, config, identity and TLS ingress alive.
pub struct NativeFloria {
    pub server: SpawnedExternalProcess,
    pub identity: arkret_test_kit::service_identity::ServiceIdentityFixture,
    pub database: EphemeralPg,
    pub config: NamedTempFile,
    pub log: NamedTempFile,
    pub source_resolution: arkret_models_identity::AuthenticatedServiceResolution,
    pub source_http_method: arkret_wire::DidUrl,
    provider: NativePushProvider,
    forwarded: Captures,
    relay: AbortTask,
}

#[derive(Clone)]
struct GatewayIngress {
    backend: url::Url,
    authority: String,
    captures: Captures,
}

#[handler]
impl GatewayIngress {
    async fn forward(&self, req: &mut Request, res: &mut Response) -> Result<()> {
        let path = req
            .uri()
            .path_and_query()
            .context("gateway ingress path")?
            .as_str()
            .to_owned();
        let authority = req
            .uri()
            .authority()
            .map(|value| value.as_str())
            .or_else(|| {
                req.headers()
                    .get("host")
                    .and_then(|value| value.to_str().ok())
            })
            .context("actual gateway ingress authority")?;
        ensure!(
            authority == self.authority
                && req
                    .uri()
                    .scheme_str()
                    .is_none_or(|scheme| scheme == "https"),
            "Gateway ingress changed public TLS origin"
        );
        let target = format!("https://{}{path}", self.authority);
        let raw = req.payload_with_max_size(512 * 1024).await?.to_vec();
        let received_headers = headers(req.headers());
        let mut outbound = req.headers().clone();
        outbound.remove("connection");
        outbound.remove("transfer-encoding");
        outbound.remove("forwarded");
        outbound.remove("x-forwarded-host");
        outbound.insert("host", self.authority.parse()?);
        outbound.insert("x-forwarded-proto", "https".parse()?);
        outbound.insert("content-length", raw.len().to_string().parse()?);
        // The low-level HTTP/1 connection serializes this exact absolute-form
        // public target. Salvo therefore preserves the real HTTPS signed URI
        // instead of synthesizing the private HTTP listener's scheme.
        ensure!(
            self.backend.host_str() == Some("127.0.0.1") && self.backend.scheme() == "http",
            "Gateway backend is not the owned private listener"
        );
        let socket = tokio::net::TcpStream::connect(format!(
            "127.0.0.1:{}",
            self.backend.port().context("private Gateway port")?
        ))
        .await?;
        let (mut sender, connection) =
            salvo::hyper::client::conn::http1::handshake(TokioIo::new(socket)).await?;
        let _connection = AbortTask(tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::debug!(error=%error,"native Gateway private connection closed");
            }
        }));
        let mut request = salvo::hyper::Request::builder()
            .method(req.method().clone())
            .uri(&target)
            .body(Full::new(salvo::hyper::body::Bytes::from(raw.clone())))?;
        *request.headers_mut() = outbound;
        let response = sender.send_request(request).await?;
        let status = response.status();
        let response_headers = headers(response.headers());
        let mut outgoing = response.headers().clone();
        outgoing.remove("content-length");
        outgoing.remove("transfer-encoding");
        outgoing.remove("connection");
        let body = Limited::new(response.into_body(), 512 * 1024)
            .collect()
            .await
            .map_err(|error| anyhow::anyhow!("native Gateway response stream: {error}"))?
            .to_bytes();
        self.captures.lock().unwrap().push(json!({"public_target":target,"private_request_target":target,"observed_at":arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),"method":req.method().as_str(),"request_headers":received_headers,"request_body_base64":bytes(&raw),"response_status":status.as_u16(),"response_headers":response_headers,"response_body_base64":bytes(&body)}));
        res.status_code(status);
        *res.headers_mut() = outgoing;
        res.write_body(body)?;
        Ok(())
    }
}

impl NativeFloria {
    pub async fn spawn_required(
        station: &ArkretServer,
        provider: NativePushProvider,
    ) -> Result<Self> {
        let executable = PathBuf::from(
            std::env::var_os("FLORIA_BIN")
                .context("native push requires the runner-built FLORIA_BIN")?,
        );
        ensure!(
            executable.is_absolute() && executable.is_file(),
            "native push requires an actual absolute FLORIA_BIN"
        );
        let database_supply = std::env::var("COTEST_FLORIA_DATABASE_URL")
            .context("native push requires an explicit owned Floria PostgreSQL supply")?;
        ensure!(
            !database_supply.trim().is_empty(),
            "native push PostgreSQL supply is empty"
        );
        let database = spawn_ephemeral_postgres_for("COTEST_FLORIA_DATABASE_URL")?
            .context("native push requires PostgreSQL, without fallback")?;
        let mut port = reserve_port()?;
        let public = url::Url::parse(&format!("https://127.0.0.1:{}/", port.port()))?;
        let mut private = reserve_port()?;
        let backend = url::Url::parse(&format!("http://127.0.0.1:{}/", private.port()))?;
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).context("gateway assertion key entropy")?;
        let mut master = [0u8; 32];
        getrandom::fill(&mut master).context("gateway route encryption entropy")?;
        let mut rng = [0u8; 8];
        getrandom::fill(&mut rng).context("gateway update key entropy")?;
        let identity =
            arkret_test_kit::service_identity::ServiceIdentityFixture::webvh_push_gateway(
                &public,
                u64::from_le_bytes(rng),
                seed,
                "push-receipt",
                at,
                at,
            )?;
        arkret_identity::verify_authenticated_service_resolution_history(
            &identity.resolution,
            &identity.service_id,
            at,
        )?;
        let boundary = identity.resolution.method_history_evidence.boundary();
        let station_key = station.federation_signing_key()?;
        let encoded =
            url::form_urlencoded::byte_serialize(station.service_id().as_str().as_bytes())
                .collect::<String>();
        let source_resolution: arkret_models_identity::AuthenticatedServiceResolution = station
            .http()
            .get(station.url(&format!("/_arkret/open/services/{encoded}/resolution")))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        arkret_identity::verify_authenticated_service_resolution_history(
            &source_resolution,
            station.service_id(),
            at,
        )?;
        ensure!(
            source_resolution.projection()?.base_url == station.base_url().as_str(),
            "onboarded Station route changed"
        );
        let arkret_models_identity::ResolutionMethodHistoryEvidence::WebvhLog {
            log_entries, ..
        } = &source_resolution.method_history_evidence
        else {
            anyhow::bail!("native Push source requires the actual Station WebVH history");
        };
        let state = &log_entries
            .last()
            .context("current Station WebVH original")?["state"];
        let expected_multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(
            station_key.verifying_key().as_bytes(),
        );
        let assertions = state["assertionMethod"]
            .as_array()
            .context("current Station assertion relationships")?;
        // Match the source production receipt/HTTP signer: its first current
        // assertion method for this exact durable runtime key, in original order.
        let method = state["verificationMethod"]
            .as_array()
            .context("current Station methods")?
            .iter()
            .find(|entry| {
                entry["publicKeyMultibase"] == expected_multibase
                    && assertions.contains(&entry["id"])
            })
            .and_then(|entry| entry["id"].as_str())
            .context("actual Station receipt/HTTP assertion method")?
            .to_owned();
        let method_id = arkret_wire::DidUrl::new(method.clone()).map_err(anyhow::Error::msg)?;
        let did = &source_resolution.normalized_did_document.id;
        arkret_identity::validate_verification_method_relationship(
            &source_resolution.normalized_did_document,
            &method_id,
            did,
            arkret_identity::DidVerificationRelationship::AssertionMethod,
        )?;
        let published = arkret_identity::public_key_material_from_document(
            &source_resolution.normalized_did_document,
            &method_id,
        )?;
        ensure!(
            published.ed25519_bytes()? == station_key.verifying_key().to_bytes(),
            "onboarded Station HTTP key differs from its accepted current document"
        );
        let config_value = json!({"http":{"bind_addresses":["127.0.0.1"],"port":private.port(),"public_base_url":public.as_str(),"notify_dedup_ttl_seconds":300,"notify_dedup":{"backend":"memory"},"notify_auth":{"production_mode":true,"require_message_signatures":true,"gateway_service_did":identity.history.did,"gateway_service_method_history_head":boundary.to_method_history_head,"gateway_service_version_id":boundary.to_version_id,"gateway_service_resolution":identity.resolution,"replay_window_seconds":300,"nonce_store":{"backend":"memory"},"service_principals":{(station.service_id().as_str()):{"service_kind":"station","signature_verification_method":method,"signature_public_key_hex":hex::encode(station_key.verifying_key().to_bytes())}}},"registration_handoff":{"postgres_url":database.connect_url,"encryption_key_hex":hex::encode(master),"receipt_signing_key_seed_hex":hex::encode(seed),"receipt_verification_method":identity.verification_method},"notify_rate_limits":{"window_seconds":60}},"proxy":provider.proxy_url,"apps":{(APP_ID):{"type":"custom","url":provider.provider_url,"auth":"bearer","bearer_token":provider.bearer}}});
        let mut config = tempfile::Builder::new()
            .prefix("cotest-native-floria-")
            .suffix(".yaml")
            .tempfile()?;
        config.write_all(&serde_json::to_vec_pretty(&config_value)?)?;
        config.flush()?;
        let log = tempfile::Builder::new()
            .prefix("cotest-native-floria-")
            .suffix(".log")
            .tempfile()?;
        let (cert, key) = station.native_test_tls_identity_paths()?;
        let _ = rustls::crypto::ring::default_provider().install_default();
        port.release();
        let acceptor = TcpListener::new(format!(
            "127.0.0.1:{}",
            public.port().context("gateway port")?
        ))
        .rustls(RustlsConfig::new(
            Keycert::new().cert_from_path(cert)?.key_from_path(key)?,
        ))
        .try_bind()
        .await?;
        let forwarded = Captures::default();
        let ingress = GatewayIngress {
            backend,
            authority: format!("127.0.0.1:{}", public.port().unwrap()),
            captures: forwarded.clone(),
        };
        let router = Router::new()
            .goal(ingress.clone())
            .push(Router::with_path("{**rest}").goal(ingress));
        let relay = AbortTask(tokio::spawn(async move {
            Server::new(acceptor).serve(router).await;
        }));
        let mut command = Command::new(&executable);
        command
            .args([
                "--config",
                config.path().to_str().context("gateway config path")?,
                "--no-env-overrides",
            ])
            .env_remove("HTTPS_PROXY")
            .env_remove("HTTP_PROXY")
            .env_remove("ALL_PROXY")
            .env_remove("NO_PROXY")
            .env("SSL_CERT_FILE", &provider.ca_path)
            .stdout(Stdio::from(
                std::fs::OpenOptions::new().append(true).open(log.path())?,
            ))
            .stderr(Stdio::from(
                std::fs::OpenOptions::new().append(true).open(log.path())?,
            ));
        private.release();
        let child = command
            .spawn()
            .context("start required real Floria binary")?;
        let server = SpawnedExternalProcess::from_child(
            public.as_str().trim_end_matches('/').to_owned(),
            executable,
            child,
            vec![port, private],
        );
        let instance = Self {
            server,
            identity,
            database,
            config,
            log,
            source_resolution,
            source_http_method: method_id,
            provider,
            forwarded,
            relay,
        };
        let cutoff = Instant::now() + Duration::from_secs(30);
        while Instant::now() < cutoff {
            if let Ok(response) = station.http().get(public.join("health")?).send().await
                && response.status().is_success()
            {
                return Ok(instance);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        anyhow::bail!(
            "required native Floria did not become healthy; actual child log: {}",
            std::fs::read_to_string(instance.log.path())?
        )
    }

    pub fn observations(&self) -> Result<Value> {
        Ok(
            json!({"process":self.server.native_process_identity()?,"gateway_resolution":self.identity.resolution,"gateway_history":self.identity.history,"onboarded_station_resolution":self.source_resolution,"onboarded_station_http_method":self.source_http_method,"config_sha256":arkret_canonical::sha256_digest(std::fs::read(self.config.path())?),"forwarded":self.forwarded.lock().unwrap().clone(),"provider":self.provider.observations()?}),
        )
    }
}

impl Drop for NativeFloria {
    fn drop(&mut self) {
        let _ = self.server.kill_and_wait();
        self.relay.0.abort();
    }
}
