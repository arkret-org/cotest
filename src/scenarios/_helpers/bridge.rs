//! Bridge-contract scenario helpers for
//! `session_grant_presentation_uses_configured_coauth_introspection`.
use std::env;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use anyhow::{Context, Result};
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
            #[allow(
                unsafe_code,
                reason = "the test helper configures process environment while holding its global guard"
            )]
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
            #[allow(
                unsafe_code,
                reason = "the test helper restores process environment while holding its global guard"
            )]
            unsafe {
                match value {
                    Some(value) => env::set_var(key, value),
                    None => env::remove_var(key),
                }
            }
        }
    }
}

/// Grant metadata the mock returns on introspection. `cnf_jkt` and
/// `session_public_key` both derive from the same holder signing key, and the
/// device selector replays the provisioned principal's accepted founding
/// `ak.device.authorize` Event, mirroring what a real Account Authority learns
/// from its issuance gate.
#[derive(Clone)]
struct CoauthGrantBinding {
    subject: String,
    device_id: String,
    authorization_event_id: String,
    cnf_jkt: String,
    session_public_key: String,
}

#[derive(Clone)]
struct CoauthIntrospectionState {
    binding: Arc<Mutex<Option<CoauthGrantBinding>>>,
    requests: Arc<Mutex<Vec<Value>>>,
}

pub struct MockCoauthIntrospectionServer {
    url: String,
    binding: Arc<Mutex<Option<CoauthGrantBinding>>>,
    requests: Arc<Mutex<Vec<Value>>>,
    _server: super::mock_http::MockServer,
}

impl MockCoauthIntrospectionServer {
    /// Spawn the mock before the SUT exists so its URL can be wired into the
    /// SUT environment; bind the provisioned principal afterwards through
    /// [`Self::bind_founding_device_grant`].
    pub async fn spawn() -> Result<Self> {
        let requests: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
        let binding: Arc<Mutex<Option<CoauthGrantBinding>>> = Arc::new(Mutex::new(None));
        let state = CoauthIntrospectionState {
            binding: Arc::clone(&binding),
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
            binding,
            requests,
            _server: server,
        })
    }

    /// Bind the introspected grant to a provisioned principal's founding
    /// device. Both the DPoP thumbprint (`cnf.jkt`) and the RFC 9421
    /// `session_public_key` derive from `holder_key`, so the same signing key
    /// satisfies the DPoP binding and any PoP-signed follow-up request.
    pub fn bind_founding_device_grant(
        &self,
        subject: &str,
        device_id: &str,
        authorization_event_id: &str,
        holder_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<()> {
        let jwk = arkret_signatures::JsonWebKey::from_ed25519_verifying_key(holder_key);
        let cnf_jkt = arkret_signatures::dpop::dpop_jwk_thumbprint(&jwk)?;
        let x = jwk
            .ed25519_x_for_verification()
            .context("holder key is an Ed25519 JWK")?
            .as_str();
        let session_public_key =
            arkret_models_identity::session_credential::CanonicalSessionPublicJwk::new(
                serde_json::to_string(&json!({ "crv": "Ed25519", "kty": "OKP", "x": x }))?,
            )?
            .into_string();
        *self.binding.lock().expect("coauth mock binding lock") = Some(CoauthGrantBinding {
            subject: subject.to_owned(),
            device_id: device_id.to_owned(),
            authorization_event_id: authorization_event_id.to_owned(),
            cnf_jkt,
            session_public_key,
        });
        Ok(())
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
    let state = depot
        .get_typed::<CoauthIntrospectionState>()
        .expect("coauth mock state injected")
        .clone();
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
    state
        .requests
        .lock()
        .expect("mock requests lock")
        .push(body.clone());
    // The contract surface is the typed wire shape: only a by-JWT
    // introspection request with an audience is in-contract.
    let parsed = serde_json::from_value::<
        arkret_models_collaboration::session_grant_bodies::SessionGrantIntrospectRequestBody,
    >(body);
    let Ok(
        arkret_models_collaboration::session_grant_bodies::SessionGrantIntrospectRequestBody::ByJwt(
            by_jwt,
        ),
    ) = parsed
    else {
        res.status_code(salvo::http::StatusCode::BAD_REQUEST);
        res.render(Json(json!({ "error": "invalid_typed_request" })));
        return;
    };
    let Some(binding) = state
        .binding
        .lock()
        .expect("coauth mock binding lock")
        .clone()
    else {
        res.status_code(salvo::http::StatusCode::SERVICE_UNAVAILABLE);
        res.render(Json(json!({ "error": "grant_not_bound" })));
        return;
    };
    let audience = by_jwt
        .audience_id
        .map(|value| value.as_str().to_owned())
        .unwrap_or_default();
    res.render(Json(json!({
        "active": true,
        "status": "active",
        "proof_required": false,
        "one_time_use_consumed": false,
        "grant": {
            "id": "ak:session_grant:AREUYrj1_BH7OOg12-uDdXYf2SrPpdqagciUGa9tJ-nD",
            "issuer_id": "ak:did_core:web:coauth.cotest.local",
            "account_id": {
                "principal_id": binding.subject,
                "station_id": audience
            },
            "device_id": binding.device_id,
            "audience_id": audience,
            "scopes": [
                "ak.self.account.read.describe.v1",
                "ak.self.events.read.scan.v1",
                "ak.root.identity.recovery_policy.resource.get.v1"
            ],
            "expires_at": arkret_canonical::format_timestamp_canonical(
                chrono::Utc::now() + chrono::Duration::minutes(10)
            ),
            "revoked_at": null,
            "revocation_ref": "ak:session:mock",
            "credential_class": "standard",
            "cnf_jkt": binding.cnf_jkt,
            "session_public_key": binding.session_public_key,
            "holder_binding": {
                "kind": "human_device",
                "device_binding": binding.device_id
            },
            // The human lane requires the exact device authorization selector;
            // it replays the accepted founding `ak.device.authorize` Event of
            // the bound principal at its current generation (founding = 1).
            "device_binding": {
                "device_id": binding.device_id,
                "authorization_event_id": binding.authorization_event_id,
                "model_generation_ref": 1
            }
        }
    })));
}
