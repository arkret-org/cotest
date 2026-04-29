use std::{
    collections::BTreeMap,
    fs,
    fs::OpenOptions,
    future::Future,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use contrix_sdk::{
    Auth, Client as SdkClient, Commit, CommitId, Did, Hash, Operation, OperationId, Proof, SpaceId,
};
use reqwest::{
    Client as HttpClient, Request, RequestBuilder, StatusCode,
    header::{HeaderMap, HeaderValue},
};
use serde_json::{Value, json};
use url::Url;

pub struct ContrixServer {
    handle: SutHandle,
    base_url: Url,
    service_did: String,
    blob_root: Option<PathBuf>,
    log_path: Option<PathBuf>,
}

pub struct TestServerGroup {
    servers: Vec<ContrixServer>,
    docker_network: Option<String>,
}

#[derive(Clone)]
pub struct TestActorClient {
    http: HttpClient,
    sdk: SdkClient,
    base_url: Url,
    service_did: String,
    pub actor: String,
    pub device_id: String,
    pub token: String,
}

pub struct RecordedResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
    context: String,
}

enum SutHandle {
    Local(Child),
    Docker { container_name: String },
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SutRuntimeMode {
    Process,
    Docker,
}

impl ContrixServer {
    pub async fn spawn(name: &str) -> Result<Self> {
        Self::spawn_with_network(name, None).await
    }

    async fn spawn_with_network(name: &str, docker_network: Option<&str>) -> Result<Self> {
        match sut_runtime_mode() {
            SutRuntimeMode::Process => Self::spawn_process(name).await,
            SutRuntimeMode::Docker => Self::spawn_docker(name, docker_network).await,
        }
    }

    async fn spawn_process(name: &str) -> Result<Self> {
        let port = free_port()?;
        let bind = format!("127.0.0.1:{port}");
        let base_url = Url::parse(&format!("http://127.0.0.1:{port}/"))?;
        let service_did = format!("did:web:{name}.cotest.local");
        let manifest = sut_manifest();
        let blob_root = std::env::temp_dir().join(format!("cotest-{name}-{port}-blobs"));
        let log_path = service_log_path(name)?;
        initialize_service_log(log_path.as_deref(), name, "process")?;
        let _ = fs::remove_dir_all(&blob_root);
        fs::create_dir_all(&blob_root)?;
        let (stdout, stderr) = service_log_stdio(log_path.as_deref())?;

        let mut child = Command::new("cargo")
            .arg("run")
            .arg("--quiet")
            .arg("--manifest-path")
            .arg(&manifest)
            .arg("--")
            .arg("--bind")
            .arg(&bind)
            .env_remove("DATABASE_URL")
            .env("SERVERX_PUBLIC_BASE_URL", base_url.as_str())
            .env("SERVERX_SERVICE_DID", &service_did)
            .env("SERVERX_DEVELOPMENT_MODE", "1")
            .env("SERVERX_BLOB_ROOT", &blob_root)
            .stdout(stdout)
            .stderr(stderr)
            .spawn()
            .with_context(|| format!("failed to start SUT from {}", manifest.display()))?;

        if let Err(error) = wait_until_healthy(base_url.clone()).await {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }

        Ok(Self {
            handle: SutHandle::Local(child),
            base_url,
            service_did,
            blob_root: Some(blob_root),
            log_path,
        })
    }

    async fn spawn_docker(name: &str, docker_network: Option<&str>) -> Result<Self> {
        let host_port = free_port()?;
        let container_port = sut_container_port();
        let alias = sanitize_runtime_name(name);
        let base_url = Url::parse(&format!("http://127.0.0.1:{host_port}/"))?;
        let service_did = format!("did:web:{name}.cotest.local");
        let public_base_url = if docker_network.is_some() {
            format!("http://{alias}:{container_port}/")
        } else {
            base_url.as_str().to_owned()
        };
        let image = sut_image();
        let container_name = format!("cotest-{}-{}-{}", alias, std::process::id(), host_port);
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
            .arg(format!("127.0.0.1:{host_port}:{container_port}"));
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
            .arg(format!("SERVERX_BIND=0.0.0.0:{container_port}"))
            .arg("--env")
            .arg(format!("SERVERX_PUBLIC_BASE_URL={public_base_url}"))
            .arg("--env")
            .arg(format!("SERVERX_SERVICE_DID={service_did}"))
            .arg("--env")
            .arg("SERVERX_DEVELOPMENT_MODE=1")
            .arg("--env")
            .arg("SERVERX_BLOB_ROOT=/tmp/soland-blobs")
            .arg(&image);

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

        Ok(Self {
            handle: SutHandle::Docker { container_name },
            base_url,
            service_did,
            blob_root: None,
            log_path,
        })
    }

    pub fn base_url(&self) -> Url {
        self.base_url.clone()
    }

    pub fn service_did(&self) -> &str {
        &self.service_did
    }

    pub fn http(&self) -> HttpClient {
        HttpClient::new()
    }

    pub fn sdk(&self) -> Result<SdkClient> {
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

    pub async fn demo_client(&self, actor: &str, device_id: &str) -> Result<TestActorClient> {
        let token = dev_login(self, actor, device_id).await?;
        self.actor_client(actor, device_id, token)
    }

    pub async fn register_client(
        &self,
        did: &str,
        handle: &str,
        device_id: &str,
    ) -> Result<TestActorClient> {
        let token = register_account(self, did, handle, device_id).await?;
        self.actor_client(did, device_id, token)
    }

    fn actor_client(&self, actor: &str, device_id: &str, token: String) -> Result<TestActorClient> {
        let sdk = SdkClient::builder(self.base_url())
            .allow_insecure_localhost()
            .auth(Auth::Bearer(token.clone()))
            .build()?;
        Ok(TestActorClient {
            http: self.http(),
            sdk,
            base_url: self.base_url(),
            service_did: self.service_did.clone(),
            actor: actor.to_owned(),
            device_id: device_id.to_owned(),
            token,
        })
    }
}

impl Drop for ContrixServer {
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
        }
        if let Some(blob_root) = &self.blob_root {
            let _ = fs::remove_dir_all(blob_root);
        }
    }
}

impl TestServerGroup {
    pub async fn single(name: &str) -> Result<Self> {
        Ok(Self {
            servers: vec![ContrixServer::spawn(name).await?],
            docker_network: None,
        })
    }

    pub async fn multi(name: &str, count: usize) -> Result<Self> {
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
            match ContrixServer::spawn_with_network(
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

    pub fn server(&self, index: usize) -> &ContrixServer {
        &self.servers[index]
    }

    pub fn len(&self) -> usize {
        self.servers.len()
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

impl TestActorClient {
    pub fn sdk(&self) -> SdkClient {
        self.sdk.clone()
    }

    pub fn service_did(&self) -> &str {
        &self.service_did
    }

    pub fn url(&self, path: &str) -> String {
        self.base_url
            .join(path.trim_start_matches('/'))
            .expect("valid test path")
            .to_string()
    }

    pub fn get(&self, path: &str) -> reqwest::RequestBuilder {
        self.http.get(self.url(path)).bearer_auth(&self.token)
    }

    pub fn post(&self, path: &str) -> reqwest::RequestBuilder {
        self.http.post(self.url(path)).bearer_auth(&self.token)
    }

    pub fn put(&self, path: &str) -> reqwest::RequestBuilder {
        self.http.put(self.url(path)).bearer_auth(&self.token)
    }

    pub fn delete(&self, path: &str) -> reqwest::RequestBuilder {
        self.http.delete(self.url(path)).bearer_auth(&self.token)
    }

    pub async fn create_space(&self, title: &str) -> Result<String> {
        let created = self
            .create_space_with(json!({
                "title": title,
                "summary": title,
                "public": false,
                "plaintext_visible_services": [self.service_did.clone()]
            }))
            .await?;
        created["space_id"]
            .as_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| anyhow!("create space response did not include space_id: {created}"))
    }

    pub async fn create_space_with(&self, body: Value) -> Result<Value> {
        expect_json(self.post("/api/v1/spaces").json(&body), StatusCode::CREATED).await
    }

    pub async fn add_member(&self, space_id: &str, member: &TestActorClient) -> Result<Value> {
        expect_json(
            self.post(&format!("/api/v1/spaces/{space_id}/members"))
                .json(&json!({"member": member.actor})),
            StatusCode::OK,
        )
        .await
    }

    pub async fn send_message(&self, space_id: &str, thread_id: &str, body: &str) -> Result<Value> {
        expect_json(
            self.post("/api/v1/messages/send").json(&json!({
                "space_id": space_id,
                "thread_id": thread_id,
                "content": {"body": body},
                "encrypted": false
            })),
            StatusCode::CREATED,
        )
        .await
    }

    pub async fn sync(&self) -> Result<Value> {
        expect_json(self.post("/api/v1/sync").json(&json!({})), StatusCode::OK).await
    }
}

impl RecordedResponse {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> Result<Value> {
        serde_json::from_slice(&self.body)
            .with_context(|| format!("invalid JSON body:\n{}", self.context))
    }

    pub fn context(&self) -> &str {
        &self.context
    }
}

pub async fn register_account(
    server: &ContrixServer,
    did: &str,
    handle: &str,
    device_id: &str,
) -> Result<String> {
    expect_json(
        server
            .http()
            .post(server.url("/api/v1/account/register"))
            .json(&json!({
                "did": did,
                "handle": handle,
                "display_name": handle.trim_start_matches('@'),
                "device_id": device_id
            })),
        StatusCode::CREATED,
    )
    .await?;

    dev_login(server, did, device_id).await
}

pub async fn dev_login(server: &ContrixServer, actor: &str, device_id: &str) -> Result<String> {
    let login = expect_json(
        server
            .http()
            .post(server.url("/api/v1/auth/dev-login"))
            .json(&json!({
                "actor": actor,
                "device_id": device_id,
                "display_name": device_id
            })),
        StatusCode::OK,
    )
    .await?;
    login["access_token"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("login response did not include access_token: {login}"))
}

pub async fn expect_json(builder: reqwest::RequestBuilder, status: StatusCode) -> Result<Value> {
    expect_response(builder, status).await?.json()
}

pub async fn expect_status(builder: reqwest::RequestBuilder, status: StatusCode) -> Result<()> {
    let _ = expect_response(builder, status).await?;
    Ok(())
}

pub async fn expect_api_error(
    builder: reqwest::RequestBuilder,
    status: StatusCode,
    errcode: &str,
) -> Result<Value> {
    let response = expect_response(builder, status).await?;
    let body = response.json()?;
    if body["ok"] != false || body["error"]["errcode"] != errcode {
        return Err(anyhow!(
            "expected error {errcode} at HTTP {status}, got body {body}:\n{}",
            response.context()
        ));
    }
    Ok(body)
}

pub async fn expect_response(
    builder: reqwest::RequestBuilder,
    status: StatusCode,
) -> Result<RecordedResponse> {
    let response = send_recorded(builder).await?;
    if response.status != status {
        return Err(anyhow!(
            "expected HTTP {status}, got {}:\n{}",
            response.status,
            response.context()
        ));
    }
    Ok(response)
}

pub async fn expect_text(builder: reqwest::RequestBuilder, status: StatusCode) -> Result<String> {
    Ok(expect_response(builder, status).await?.text())
}

pub async fn expect_indistinguishable_api_errors(
    hidden: reqwest::RequestBuilder,
    missing: reqwest::RequestBuilder,
    status: StatusCode,
    errcode: &str,
) -> Result<Value> {
    let hidden_body = normalize_transient_fields(expect_api_error(hidden, status, errcode).await?);
    let missing_body =
        normalize_transient_fields(expect_api_error(missing, status, errcode).await?);
    if hidden_body != missing_body {
        return Err(anyhow!(
            "expected indistinguishable {errcode} errors, got hidden={hidden_body} missing={missing_body}"
        ));
    }
    Ok(hidden_body)
}

pub fn expect_audit_action<'a>(audit: &'a Value, action: &str) -> Result<&'a Value> {
    audit["events"]
        .as_array()
        .and_then(|events| events.iter().find(|event| event["action"] == action))
        .ok_or_else(|| anyhow!("missing audit action {action} in body {audit}"))
}

pub async fn eventually<F, Fut, T>(
    label: &str,
    timeout: Duration,
    interval: Duration,
    mut operation: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let started = Instant::now();
    let mut last_error = None;
    loop {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(error) => {
                if started.elapsed() >= timeout {
                    let message = last_error.unwrap_or_else(|| error.to_string());
                    return Err(anyhow!("timed out waiting for {label}: {message}"));
                }
                last_error = Some(error.to_string());
                tokio::time::sleep(interval).await;
            }
        }
    }
}

pub async fn create_space(server: &ContrixServer, token: &str, title: &str) -> Result<String> {
    let created = expect_json(
        server
            .http()
            .post(server.url("/api/v1/spaces"))
            .bearer_auth(token)
            .json(&json!({
                "title": title,
                "summary": title,
                "public": false,
                "plaintext_visible_services": [server.service_did()]
            })),
        StatusCode::CREATED,
    )
    .await?;
    created["space_id"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("create space response did not include space_id: {created}"))
}

pub async fn add_member(
    server: &ContrixServer,
    token: &str,
    space_id: &str,
    member: &str,
) -> Result<()> {
    expect_json(
        server
            .http()
            .post(server.url(&format!("/api/v1/spaces/{space_id}/members")))
            .bearer_auth(token)
            .json(&json!({"member": member})),
        StatusCode::OK,
    )
    .await?;
    Ok(())
}

pub async fn send_message(
    server: &ContrixServer,
    token: &str,
    space_id: &str,
    thread_id: &str,
    body: &str,
) -> Result<Value> {
    expect_json(
        server
            .http()
            .post(server.url("/api/v1/messages/send"))
            .bearer_auth(token)
            .json(&json!({
                "space_id": space_id,
                "thread_id": thread_id,
                "content": {"body": body},
                "encrypted": false
            })),
        StatusCode::CREATED,
    )
    .await
}

pub fn encrypted_envelope(content_type: &str, ciphertext: &str) -> Value {
    json!({
        "scheme": "mls-rfc9420",
        "version": 1,
        "group_id": "cx:mls:test",
        "epoch": 1,
        "content_type": content_type,
        "ciphertext": ciphertext,
        "authentication_tag": "opaque-tag",
        "aad": {"suite": "test"},
        "key_ref": {"kid": "did:web:alice.example#device"},
        "digests": {
            "ciphertext": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
    })
}

pub fn repo_message_operation(
    operation_id: &str,
    event_id: &str,
    space_id: &str,
    sender: &str,
    thread_id: &str,
    body: &str,
) -> Result<Operation> {
    Ok(Operation::create(
        OperationId::new(operation_id.to_owned())?,
        SpaceId::new(space_id.to_owned())?,
        "cx.message.create",
        json!({
            "event_id": event_id,
            "sender": sender,
            "thread_id": thread_id,
            "body": body
        }),
    ))
}

pub fn signed_commit(
    commit_id: &str,
    repo_id: &str,
    author_seq: u64,
    operations: &[Operation],
    prev_commit: Option<&str>,
) -> Result<Commit> {
    let mut commit = Commit::new(
        CommitId::new(commit_id.to_owned())?,
        repo_id.to_owned(),
        Did::new(repo_id.to_owned())?,
        author_seq,
    );
    if let Some(prev_commit) = prev_commit {
        commit.prev_commit = Some(Hash::new(prev_commit.to_owned())?);
    }
    for operation in operations {
        commit
            .operations
            .push(Hash::new(operation.operation_digest()?)?);
    }
    commit.proofs.push(dummy_proof(repo_id));
    Ok(commit)
}

pub fn dummy_proof(actor: &str) -> Proof {
    Proof {
        kind: "detached_jws".to_owned(),
        alg: "none".to_owned(),
        verification_method: format!("{actor}#dev"),
        payload_hash: Hash::new(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap(),
        created_at: Utc::now(),
        domain: None,
        audience: None,
        jws: "dev-proof".to_owned(),
    }
}

fn sut_manifest() -> PathBuf {
    std::env::var_os("COTEST_SUT_MANIFEST")
        .or_else(|| std::env::var_os("SERVERX_MANIFEST"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"E:\Works\contrix-dev\soland\Cargo.toml"))
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

fn transcript_path() -> Option<PathBuf> {
    std::env::var_os("COTEST_TRANSCRIPT_PATH")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("COTEST_ARTIFACT_DIR")
                .map(PathBuf::from)
                .map(|path| path.join("transcript.ndjson"))
        })
}

fn service_log_path(name: &str) -> Result<Option<PathBuf>> {
    let Some(root) = service_log_root() else {
        return Ok(None);
    };
    fs::create_dir_all(&root)?;
    Ok(Some(root.join(format!("{}.log", sanitize_runtime_name(name)))))
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

fn append_transcript_entry(entry: &Value) -> Result<()> {
    let Some(path) = transcript_path() else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    use std::io::Write as _;
    writeln!(file, "{}", serde_json::to_string(entry)?)?;
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

async fn send_recorded(builder: RequestBuilder) -> Result<RecordedResponse> {
    let request = snapshot_request_builder(&builder);
    let started = Instant::now();
    let response = match builder.send().await {
        Ok(response) => response,
        Err(error) => {
            let error_snapshot = json!({
                "transport_error": truncate_string(&error.to_string(), 512),
            });
            let _ = append_transcript_entry(&json!({
                "timestamp": Utc::now().to_rfc3339(),
                "duration_ms": started.elapsed().as_millis(),
                "request": request,
                "error": error_snapshot,
            }));
            return Err(anyhow!(
                "HTTP request failed:\n{}",
                format_exchange_context(&request, &error_snapshot)
            ));
        }
    };

    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await?.to_vec();
    let response_snapshot = snapshot_response(status, &headers, &body);
    let context = format_exchange_context(&request, &response_snapshot);
    let _ = append_transcript_entry(&json!({
        "timestamp": Utc::now().to_rfc3339(),
        "duration_ms": started.elapsed().as_millis(),
        "request": request,
        "response": response_snapshot,
    }));
    Ok(RecordedResponse {
        status,
        headers,
        body,
        context,
    })
}

fn snapshot_request_builder(builder: &RequestBuilder) -> Value {
    let Some(clone) = builder.try_clone() else {
        return json!({
            "unavailable": "request builder could not be cloned for transcript capture"
        });
    };
    match clone.build() {
        Ok(request) => snapshot_request(&request),
        Err(error) => json!({
            "error": truncate_string(&error.to_string(), 256),
        }),
    }
}

fn snapshot_request(request: &Request) -> Value {
    json!({
        "method": request.method().as_str(),
        "url": sanitize_url(request.url()),
        "headers": sanitize_headers(request.headers()),
        "body": request
            .body()
            .and_then(|body| body.as_bytes())
            .map(sanitize_body_bytes)
            .unwrap_or_else(|| json!("[unavailable]")),
    })
}

fn snapshot_response(status: StatusCode, headers: &HeaderMap, body: &[u8]) -> Value {
    json!({
        "status": status.as_u16(),
        "headers": sanitize_headers(headers),
        "body": sanitize_body_bytes(body),
    })
}

fn sanitize_url(url: &Url) -> String {
    let mut sanitized = url.clone();
    let query_pairs: Vec<_> = sanitized
        .query_pairs()
        .map(|(key, value)| {
            let value = if is_secret_field(key.as_ref()) {
                "[redacted]".to_owned()
            } else {
                truncate_string(value.as_ref(), 128)
            };
            (key.into_owned(), value)
        })
        .collect();
    sanitized.query_pairs_mut().clear().extend_pairs(query_pairs);
    sanitized.to_string()
}

fn sanitize_headers(headers: &HeaderMap) -> Value {
    let mut sanitized = BTreeMap::new();
    for (name, value) in headers {
        let key = name.as_str().to_owned();
        let rendered = if is_secret_field(name.as_str()) {
            "[redacted]".to_owned()
        } else {
            truncate_string(&header_value_to_string(value), 256)
        };
        sanitized.insert(key, rendered);
    }
    serde_json::to_value(sanitized).unwrap_or_else(|_| json!({}))
}

fn header_value_to_string(value: &HeaderValue) -> String {
    value
        .to_str()
        .map(ToOwned::to_owned)
        .unwrap_or_else(|_| format!("base64url:{}", URL_SAFE_NO_PAD.encode(value.as_bytes())))
}

fn sanitize_body_bytes(bytes: &[u8]) -> Value {
    if bytes.is_empty() {
        return Value::Null;
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        if let Ok(value) = serde_json::from_str::<Value>(text) {
            return sanitize_json_value(value);
        }
        return Value::String(truncate_string(text, 512));
    }
    json!({
        "encoding": "base64url",
        "size": bytes.len(),
        "preview": truncate_string(&URL_SAFE_NO_PAD.encode(bytes), 512),
    })
}

fn sanitize_json_value(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .map(|(key, value)| {
                    let value = if is_secret_field(&key) {
                        Value::String("[redacted]".to_owned())
                    } else {
                        sanitize_json_value(value)
                    };
                    (key, value)
                })
                .collect(),
        ),
        Value::Array(values) => {
            Value::Array(values.into_iter().map(sanitize_json_value).collect())
        }
        Value::String(text) => Value::String(truncate_string(&text, 256)),
        other => other,
    }
}

fn is_secret_field(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "authorization"
            | "cookie"
            | "set-cookie"
            | "access_token"
            | "token"
            | "auth"
            | "password"
            | "secret"
            | "push_key"
            | "invite_token"
            | "signed_link"
            | "jws"
            | "sig"
    )
}

fn truncate_string(value: &str, max_chars: usize) -> String {
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        format!("{truncated}...[truncated]")
    } else {
        truncated
    }
}

fn format_exchange_context(request: &Value, response: &Value) -> String {
    format!(
        "request:\n{}\nresponse:\n{}",
        serde_json::to_string_pretty(request).unwrap_or_else(|_| request.to_string()),
        serde_json::to_string_pretty(response).unwrap_or_else(|_| response.to_string())
    )
}

fn normalize_transient_fields(value: Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .into_iter()
                .filter(|(key, _)| key != "request_id")
                .map(|(key, value)| (key, normalize_transient_fields(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(normalize_transient_fields)
                .collect(),
        ),
        other => other,
    }
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

fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
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
