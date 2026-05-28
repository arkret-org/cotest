//! Bridge-contract scenario helpers shared by `principal_bridge_contracts_are_discoverable`
//! and `session_grant_exchange_uses_configured_coauth_introspection`.
//!
//! Pure mechanical extraction from the previous `bridge_contracts.rs` —
//! no logic changes.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::{
    env,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration as StdDuration,
};

use crate::harness::expect_json;

#[derive(Debug)]
#[allow(dead_code)]
pub struct BridgeContractSnapshot {
    pub service: &'static str,
    pub surface: &'static str,
    pub contract: String,
    pub version: String,
    pub required_paths: Vec<String>,
    pub example_keys: Vec<String>,
    pub todo: &'static str,
}

#[derive(Debug)]
pub struct BridgeContractMatrixScaffold {
    pub rows: Vec<BridgeContractSnapshot>,
}

pub fn configured_external_service_base(env_key: &str) -> Option<String> {
    env::var(env_key)
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_owned())
        .filter(|value| !value.is_empty())
}

pub async fn load_optional_live_contract(
    base_url: Option<&str>,
    path: &str,
) -> Result<Option<Value>> {
    let Some(base_url) = base_url else {
        return Ok(None);
    };
    let url = format!("{base_url}{path}");
    let client = reqwest::Client::new();
    let body = expect_json(client.get(url), StatusCode::OK).await?;
    Ok(Some(body))
}

pub fn snapshot_from_live(
    service: &'static str,
    surface: &'static str,
    body: &Value,
    required_paths: &[&str],
    example_keys: &[&str],
) -> BridgeContractSnapshot {
    BridgeContractSnapshot {
        service,
        surface,
        contract: body
            .get("contract")
            .and_then(Value::as_str)
            .unwrap_or("missing")
            .to_owned(),
        version: body
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("missing")
            .to_owned(),
        required_paths: required_paths
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        example_keys: example_keys
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        todo: "TODO(cotest): expand this live bridge row with cross-service semantic assertions once the composed stack harness lands",
    }
}

pub fn snapshot_placeholder(
    service: &'static str,
    surface: &'static str,
    contract: &'static str,
    required_paths: &[&str],
    example_keys: &[&str],
    todo: &'static str,
) -> BridgeContractSnapshot {
    let _placeholder_body = json!({
        "service": service,
        "surface": surface,
        "contract": contract,
        "required_paths": required_paths,
        "example_keys": example_keys,
    });
    BridgeContractSnapshot {
        service,
        surface,
        contract: contract.to_owned(),
        version: "2026-05-04-scaffold".to_owned(),
        required_paths: required_paths
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        example_keys: example_keys
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        todo,
    }
}

pub struct EnvOverride {
    previous: Vec<(&'static str, Option<String>)>,
}

impl EnvOverride {
    pub fn set(pairs: &[(&'static str, Option<String>)]) -> Self {
        let previous = pairs
            .iter()
            .map(|(key, _)| (*key, env::var(key).ok()))
            .collect();
        for (key, value) in pairs {
            unsafe {
                match value {
                    Some(value) => env::set_var(key, value),
                    None => env::remove_var(key),
                }
            }
        }
        Self { previous }
    }
}

impl Drop for EnvOverride {
    fn drop(&mut self) {
        for (key, value) in &self.previous {
            unsafe {
                match value {
                    Some(value) => env::set_var(key, value),
                    None => env::remove_var(key),
                }
            }
        }
    }
}

pub struct MockCoauthIntrospectionServer {
    url: String,
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<Value>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockCoauthIntrospectionServer {
    pub fn spawn(subject: &str, device_id: &str) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let url = format!("http://{addr}/api/v1/session-grants/introspect");
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread_stop = Arc::clone(&stop);
        let thread_requests = Arc::clone(&requests);
        let subject = subject.to_owned();
        let device_id = device_id.to_owned();
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let request_subject = subject.clone();
                        let request_device_id = device_id.clone();
                        let request_log = Arc::clone(&thread_requests);
                        thread::spawn(move || {
                            handle_mock_coauth_request(
                                stream,
                                &request_subject,
                                &request_device_id,
                                request_log,
                            );
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(StdDuration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            url,
            addr,
            stop,
            requests,
            handle: Some(handle),
        })
    }

    pub fn url(&self) -> String {
        self.url.clone()
    }

    pub fn requests(&self) -> Vec<Value> {
        self.requests.lock().expect("mock requests lock").clone()
    }
}

impl Drop for MockCoauthIntrospectionServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn handle_mock_coauth_request(
    mut stream: TcpStream,
    subject: &str,
    device_id: &str,
    requests: Arc<Mutex<Vec<Value>>>,
) {
    let Ok(request) = read_http_request(&mut stream) else {
        return;
    };
    let request_text = String::from_utf8_lossy(&request);
    if !request_text
        .to_ascii_lowercase()
        .contains("authorization: bearer principal-token")
    {
        write_http_response(&mut stream, 401, json!({"error": "unauthorized"}));
        return;
    }
    let body = parse_http_json_body(&request).unwrap_or_else(|| json!({}));
    requests
        .lock()
        .expect("mock requests lock")
        .push(body.clone());
    let audience = body
        .get("audience")
        .and_then(Value::as_str)
        .unwrap_or("did:web:missing-audience");
    write_http_response(
        &mut stream,
        200,
        json!({
            "active": true,
            "status": "active",
            "proof_required": true,
            "one_time_use_consumed": true,
            "grant": {
                "id": "01HZSESSIONGRANTMOCK000000000",
                "issuer": "did:web:coauth.cotest.local",
                "subject": subject,
                "service_account_id": "alice-session-grant",
                "device_id": device_id,
                "audience": audience,
                "scopes": ["urn:contrix:principal-server:session.bind"],
                "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
                "revoked_at": null,
                "revocation_ref": "cx:session:mock"
            }
        }),
    );
}

fn read_http_request(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(StdDuration::from_secs(2)))?;
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
        if http_request_complete(&request) {
            break;
        }
    }
    Ok(request)
}

fn http_request_complete(request: &[u8]) -> bool {
    let Some(header_end) = request.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let body_start = header_end + 4;
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    request.len() >= body_start + content_length
}

fn parse_http_json_body(request: &[u8]) -> Option<Value> {
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    let body = &request[header_end + 4..];
    serde_json::from_slice(body).ok()
}

fn write_http_response(stream: &mut TcpStream, status: u16, body: Value) {
    let body = body.to_string();
    let reason = if status == 200 { "OK" } else { "Unauthorized" };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}
