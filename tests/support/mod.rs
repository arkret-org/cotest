#![allow(dead_code)]

use std::{
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use contrix_sdk::{Commit, CommitId, Did, Hash, Operation, OperationId, Proof, SpaceId};
use reqwest::{Client as HttpClient, StatusCode};
use serde_json::{Value, json};
use url::Url;

pub struct ServerxInstance {
    child: Child,
    base_url: Url,
}

pub struct TestServerGroup {
    servers: Vec<ServerxInstance>,
}

#[derive(Clone)]
pub struct TestClient {
    http: HttpClient,
    base_url: Url,
    pub actor: String,
    pub device_id: String,
    pub token: String,
}

impl ServerxInstance {
    pub async fn spawn(name: &str) -> Result<Self> {
        let port = free_port()?;
        let bind = format!("127.0.0.1:{port}");
        let base_url = Url::parse(&format!("http://127.0.0.1:{port}/"))?;
        let manifest = serverx_manifest();

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
            .env("SERVERX_SERVICE_DID", format!("did:web:{name}.cotest.local"))
            .env("SERVERX_DEVELOPMENT_MODE", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("failed to start serverx from {}", manifest.display()))?;

        if let Err(error) = wait_until_healthy(base_url.clone()).await {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }

        Ok(Self { child, base_url })
    }

    pub fn base_url(&self) -> Url {
        self.base_url.clone()
    }

    pub fn http(&self) -> HttpClient {
        HttpClient::new()
    }

    pub fn url(&self, path: &str) -> String {
        self.base_url
            .join(path.trim_start_matches('/'))
            .expect("valid test path")
            .to_string()
    }

    pub async fn demo_client(&self, actor: &str, device_id: &str) -> Result<TestClient> {
        let token = dev_login(self, actor, device_id).await?;
        Ok(TestClient {
            http: self.http(),
            base_url: self.base_url(),
            actor: actor.to_owned(),
            device_id: device_id.to_owned(),
            token,
        })
    }

    pub async fn register_client(
        &self,
        did: &str,
        handle: &str,
        device_id: &str,
    ) -> Result<TestClient> {
        let token = register_account(self, did, handle, device_id).await?;
        Ok(TestClient {
            http: self.http(),
            base_url: self.base_url(),
            actor: did.to_owned(),
            device_id: device_id.to_owned(),
            token,
        })
    }
}

impl Drop for ServerxInstance {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl TestServerGroup {
    pub async fn single(name: &str) -> Result<Self> {
        Ok(Self {
            servers: vec![ServerxInstance::spawn(name).await?],
        })
    }

    pub async fn multi(name: &str, count: usize) -> Result<Self> {
        let mut servers = Vec::with_capacity(count);
        for index in 0..count {
            servers.push(ServerxInstance::spawn(&format!("{name}-{index}")).await?);
        }
        Ok(Self { servers })
    }

    pub fn server(&self, index: usize) -> &ServerxInstance {
        &self.servers[index]
    }

    pub fn len(&self) -> usize {
        self.servers.len()
    }
}

impl TestClient {
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
        let created = expect_json(
            self.post("/api/v1/spaces")
                .json(&json!({"title": title, "summary": title, "public": false})),
            StatusCode::CREATED,
        )
        .await?;
        created["space_id"]
            .as_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| anyhow!("create space response did not include space_id: {created}"))
    }

    pub async fn add_member(&self, space_id: &str, member: &TestClient) -> Result<Value> {
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
    server: &ServerxInstance,
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

pub async fn dev_login(server: &ServerxInstance, actor: &str, device_id: &str) -> Result<String> {
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

pub async fn create_space(server: &ServerxInstance, token: &str, title: &str) -> Result<String> {
    let created = expect_json(
        server
            .http()
            .post(server.url("/api/v1/spaces"))
            .bearer_auth(token)
            .json(&json!({"title": title, "summary": title, "public": false})),
        StatusCode::CREATED,
    )
    .await?;
    created["space_id"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("create space response did not include space_id: {created}"))
}

pub async fn add_member(
    server: &ServerxInstance,
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
    server: &ServerxInstance,
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

pub fn message_operation(
    operation_id: &str,
    space_id: &str,
    sender: &str,
    body: &str,
) -> Result<Operation> {
    Ok(Operation::create(
        OperationId::new(operation_id.to_owned())?,
        SpaceId::new(space_id.to_owned())?,
        "message",
        json!({
            "event_id": operation_id.replace("cx:operation:", "cx:event:"),
            "sender": sender,
            "thread_id": format!("cx:thread:{}", operation_id.replace(':', "-")),
            "members": [sender],
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

fn serverx_manifest() -> PathBuf {
    std::env::var_os("SERVERX_MANIFEST")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"E:\Works\contrix-dev\serverx\Cargo.toml"))
}

fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

async fn wait_until_healthy(base_url: Url) -> Result<()> {
    let client = HttpClient::new();
    let health_url = base_url.join("health")?;
    let mut last_error = None;

    for _ in 0..120 {
        match client.get(health_url.clone()).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => last_error = Some(anyhow!("health status {}", response.status())),
            Err(error) => last_error = Some(error.into()),
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    Err(last_error.unwrap_or_else(|| anyhow!("server did not become healthy")))
}
