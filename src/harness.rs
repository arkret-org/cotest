use std::{
    fs,
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use contrix_sdk::{
    Auth, Client as SdkClient, Commit, CommitId, Did, Hash, Operation, OperationId, Proof, SpaceId,
};
use reqwest::{Client as HttpClient, StatusCode};
use serde_json::{Value, json};
use url::Url;

pub struct ContrixServer {
    handle: SutHandle,
    base_url: Url,
    service_did: String,
    blob_root: Option<PathBuf>,
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
        let _ = fs::remove_dir_all(&blob_root);
        fs::create_dir_all(&blob_root)?;

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
            .stdout(Stdio::null())
            .stderr(Stdio::null())
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
    let response = builder.send().await?;
    let actual = response.status();
    let body = response.text().await?;
    if actual != status {
        return Err(anyhow!("expected HTTP {status}, got {actual}: {body}"));
    }
    serde_json::from_str(&body).with_context(|| format!("invalid JSON body: {body}"))
}

pub async fn expect_status(builder: reqwest::RequestBuilder, status: StatusCode) -> Result<()> {
    let response = builder.send().await?;
    let actual = response.status();
    let body = response.text().await.unwrap_or_default();
    if actual != status {
        return Err(anyhow!("expected HTTP {status}, got {actual}: {body}"));
    }
    Ok(())
}

pub async fn expect_api_error(
    builder: reqwest::RequestBuilder,
    status: StatusCode,
    errcode: &str,
) -> Result<Value> {
    let body = expect_json(builder, status).await?;
    if body["ok"] != false || body["error"]["errcode"] != errcode {
        return Err(anyhow!(
            "expected error {errcode} at HTTP {status}, got body {body}"
        ));
    }
    Ok(body)
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
    run_command(
        &mut command,
        &format!("failed to read logs for {container_name}"),
    )
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
