//! Bridge-contract scenario helpers shared by `principal_bridge_contracts_are_discoverable`
//! and `session_grant_presentation_uses_configured_coauth_introspection`.
use std::env;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use anyhow::Result;
use reqwest::StatusCode;
use salvo::affix_state;
use salvo::prelude::{Depot, Json, Request, Response, Router, handler};
use serde_json::{Value, json};

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
    let client = super::http::live_probe_client()?;
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
    _guard: MutexGuard<'static, ()>,
}

impl EnvOverride {
    pub fn set(pairs: &[(&'static str, Option<String>)]) -> Self {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("EnvOverride global lock poisoned");
        let previous = pairs
            .iter()
            .map(|(key, _)| (*key, env::var(key).ok()))
            .collect();
        for (key, value) in pairs {
            // SAFETY: EnvOverride serializes all writes performed through this
            // helper with a process-wide mutex and holds the guard until Drop
            // restores the previous values.
            unsafe {
                match value {
                    Some(value) => env::set_var(key, value),
                    None => env::remove_var(key),
                }
            }
        }
        Self {
            previous,
            _guard: guard,
        }
    }
}

impl Drop for EnvOverride {
    fn drop(&mut self) {
        for (key, value) in &self.previous {
            // SAFETY: the EnvOverride guard is still held while restoring the
            // previous process environment values.
            unsafe {
                match value {
                    Some(value) => env::set_var(key, value),
                    None => env::remove_var(key),
                }
            }
        }
    }
}

#[derive(Clone)]
struct CoauthIntrospectionState {
    subject: String,
    device_id: String,
    requests: Arc<Mutex<Vec<Value>>>,
}

pub struct MockCoauthIntrospectionServer {
    url: String,
    requests: Arc<Mutex<Vec<Value>>>,
    _server: super::mock_http::MockServer,
}

impl MockCoauthIntrospectionServer {
    pub async fn spawn(subject: &str, device_id: &str) -> Result<Self> {
        let requests: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
        let state = CoauthIntrospectionState {
            subject: subject.to_owned(),
            device_id: device_id.to_owned(),
            requests: Arc::clone(&requests),
        };
        let router = Router::with_path("_cokret/gate/account/session-grants/introspect")
            .hoop(affix_state::inject(state))
            .post(coauth_introspect);
        let server = super::mock_http::spawn_mock(router).await?;
        let url = format!(
            "http://{}/_cokret/gate/account/session-grants/introspect",
            server.addr()
        );
        Ok(Self {
            url,
            requests,
            _server: server,
        })
    }

    pub fn url(&self) -> String {
        self.url.clone()
    }

    pub fn requests(&self) -> Vec<Value> {
        self.requests.lock().expect("mock requests lock").clone()
    }
}

#[handler]
async fn coauth_introspect(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let (subject, device_id, requests) = {
        let state = depot
            .get_typed::<CoauthIntrospectionState>()
            .expect("coauth mock state injected");
        (
            state.subject.clone(),
            state.device_id.clone(),
            Arc::clone(&state.requests),
        )
    };
    let authorized = req
        .headers()
        .get(salvo::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .to_ascii_lowercase()
                .contains("bearer principal-token")
        });
    if !authorized {
        res.status_code(salvo::http::StatusCode::UNAUTHORIZED);
        res.render(Json(json!({ "error": "unauthorized" })));
        return;
    }
    let body: Value = req.parse_json().await.unwrap_or_else(|_| json!({}));
    let audience = body
        .get("audience")
        .and_then(Value::as_str)
        .unwrap_or("did:web:missing-audience")
        .to_owned();
    requests.lock().expect("mock requests lock").push(body);
    res.render(Json(json!({
        "active": true,
        "status": "active",
        "proof_required": false,
        "one_time_use_consumed": false,
        "grant": {
            "id": "ak:grant:0196419b-0000-7000-8000-000000000901",
            "issuer": "did:web:coauth.cotest.local",
            "subject": subject,
            "service_account_id": "alice-session-grant",
            "device_id": device_id,
            "audience": audience,
            "scopes": ["urn:arkret:principal-server:session.bind"],
            "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(10)).to_rfc3339(),
            "revoked_at": null,
            "revocation_ref": "ak:session:mock",
            // `SessionGrantIntrospectGrant.session_public_key` is a required
            // (non-Option) field in the SDK wire type; omitting it makes soland
            // fail to deserialize the introspection outcome and return 503.
            // Supply a well-formed Ed25519 OKP JWK so the S2S contract holds.
            "session_public_key": "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}"
        }
    })));
}
