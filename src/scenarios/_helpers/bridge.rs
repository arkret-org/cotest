//! Bridge-contract scenario helpers for
//! `session_grant_presentation_uses_configured_coauth_introspection`.
use std::env;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use anyhow::Result;
use salvo::affix_state;
use salvo::prelude::{Depot, Json, Request, Response, Router, handler};
use serde_json::{Value, json};

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
        let router = Router::with_path("_arkret/gate/account/session-grants/introspect")
            .hoop(affix_state::inject(state))
            .post(coauth_introspect);
        let server = super::mock_http::spawn_mock(router).await?;
        let url = format!(
            "http://{}/_arkret/gate/account/session-grants/introspect",
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
            "id": "ak:session_grant:AREUYrj1_BH7OOg12-uDdXYf2SrPpdqagciUGa9tJ-nD",
            "issuer": "did:web:coauth.cotest.local",
            "subject": subject,
            "service_account_id": "alice-session-grant",
            "device_id": device_id,
            "audience": audience,
            "scopes": ["urn:arkret:principal-server:session.bind"],
            "expires_at": arkret_canonical::format_timestamp_canonical(
                chrono::Utc::now() + chrono::Duration::minutes(10)
            ),
            "revoked_at": null,
            "revocation_ref": "ak:session:mock",
            "credential_class": "standard",
            "cnf_jkt": "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k",
            "holder_binding": {
                "kind": "human_device",
                "device_binding": device_id
            },
            // `SessionGrantIntrospectGrant.session_public_key` is a required
            // (non-Option) field in the SDK wire type; omitting it makes soland
            // fail to deserialize the introspection outcome and return 503.
            // Supply a well-formed Ed25519 OKP JWK so the S2S contract holds.
            "session_public_key": "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}"
        }
    })));
}
