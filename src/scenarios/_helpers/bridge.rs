//! Bridge-contract scenario helpers for
//! `session_grant_presentation_uses_configured_coauth_introspection`.
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use salvo::affix_state;
use salvo::prelude::{Depot, Json, Request, Response, Router, handler};
use serde_json::{Value, json};

/// Grant metadata the mock returns on introspection. `cnf_jkt` and
/// `session_public_key` both derive from the same holder signing key, and the
/// device selector replays the provisioned principal's accepted founding
/// `ak.device.authorize` Event, mirroring what a real Account Authority learns
/// from its issuance gate.
///
/// `grant_jwt` is the exact credential the issuer ledger holds. The Account
/// Authority is the only authority on session-grant state
/// (`key-management.md` §6.1, `api-conventions.md` §3.3): a submitted token is
/// active only when it is byte-identical to that record, so this mock matches
/// on the complete token rather than on a `jti` or grant id.
#[derive(Clone)]
struct CoauthGrantBinding {
    grant_jwt: String,
    subject: String,
    holder: CoauthGrantHolder,
    cnf_jkt: String,
    session_public_key: String,
}

/// The closed holder of one recorded grant: a human device with its accepted
/// authorization selector, or an Agent runtime bound to the exact accepted
/// key authorization and method, with the operations its scope admits.
#[derive(Clone)]
enum CoauthGrantHolder {
    HumanDevice {
        device_id: String,
        authorization_event_id: String,
    },
    AgentRuntime {
        agent_key_authorization_ref: String,
        verification_method: String,
        scopes: Vec<String>,
    },
}

/// What the deployment-internal authenticated channel actually carried on one
/// call, as `service-http-binding.md` §2.2.3 constrains it: the caller identity
/// MUST come from credential verification and deployment configuration, and
/// self-reported `Source-Service-ID` / `Destination-Service-ID` / `internal`
/// markers MUST NOT decide it.
#[derive(Clone, Debug)]
pub struct ChannelObservation {
    pub presented_configured_credential: bool,
    pub self_reported_identity_headers: Vec<String>,
}

const SELF_REPORTED_IDENTITY_HEADERS: [&str; 3] = [
    "source-service-id",
    "destination-service-id",
    "x-arkret-internal",
];

#[derive(Clone)]
struct CoauthIntrospectionState {
    internal_secret: String,
    bindings: Arc<Mutex<Vec<CoauthGrantBinding>>>,
    requests: Arc<Mutex<Vec<Value>>>,
    channel: Arc<Mutex<Vec<ChannelObservation>>>,
}

pub struct MockCoauthIntrospectionServer {
    origin: String,
    url: String,
    bindings: Arc<Mutex<Vec<CoauthGrantBinding>>>,
    requests: Arc<Mutex<Vec<Value>>>,
    channel: Arc<Mutex<Vec<ChannelObservation>>>,
    _server: super::mock_http::MockServer,
}

impl MockCoauthIntrospectionServer {
    /// Spawn the mock before the SUT exists so its URL can be wired into the
    /// SUT environment; bind the provisioned principal afterwards through
    /// [`Self::bind_founding_device_grant`].
    pub async fn spawn() -> Result<Self> {
        Self::spawn_with_internal_secret("principal-token").await
    }

    pub async fn spawn_with_internal_secret(internal_secret: &str) -> Result<Self> {
        let requests: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
        let bindings: Arc<Mutex<Vec<CoauthGrantBinding>>> = Arc::new(Mutex::new(Vec::new()));
        let channel: Arc<Mutex<Vec<ChannelObservation>>> = Arc::new(Mutex::new(Vec::new()));
        let state = CoauthIntrospectionState {
            internal_secret: internal_secret.to_owned(),
            bindings: Arc::clone(&bindings),
            requests: Arc::clone(&requests),
            channel: Arc::clone(&channel),
        };
        let router = Router::with_path("_coauth/internal/session-grants/introspect")
            .hoop(affix_state::inject(state))
            .post(coauth_introspect);
        let server = super::mock_http::spawn_mock(router).await?;
        let origin = format!("http://{}", server.addr());
        let url = format!("{origin}/_coauth/internal/session-grants/introspect");
        Ok(Self {
            origin,
            url,
            bindings,
            requests,
            channel,
            _server: server,
        })
    }

    /// Record `grant_jwt` as the one exact active credential in the issuer
    /// ledger and bind it to a provisioned principal's founding device. Both
    /// the DPoP thumbprint (`cnf.jkt`) and the RFC 9421 `session_public_key`
    /// derive from `holder_key`, so the same signing key satisfies the DPoP
    /// binding and any PoP-signed follow-up request. Any other submitted token
    /// — including a self-consistent forgery minted with a leaked issuer
    /// signing key — has no active record and introspects as `not_found`.
    pub fn bind_founding_device_grant(
        &self,
        grant_jwt: &str,
        subject: &str,
        device_id: &str,
        authorization_event_id: &str,
        holder_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<()> {
        self.record(
            grant_jwt,
            subject,
            CoauthGrantHolder::HumanDevice {
                device_id: device_id.to_owned(),
                authorization_event_id: authorization_event_id.to_owned(),
            },
            holder_key,
        )
    }

    /// Record `grant_jwt` as the exact Agent runtime SessionGrant of
    /// `agent_id`, bound to its accepted `ak.agent.key.authorize` Event and
    /// method (`key-management.md` section 3.6.1). The runtime key is the
    /// DPoP holder; the grant admits exactly `scopes`.
    pub fn bind_agent_runtime_grant(
        &self,
        grant_jwt: &str,
        agent_id: &str,
        agent_key_authorization_ref: &str,
        verification_method: &str,
        runtime_key: &ed25519_dalek::VerifyingKey,
        scopes: &[&str],
    ) -> Result<()> {
        self.record(
            grant_jwt,
            agent_id,
            CoauthGrantHolder::AgentRuntime {
                agent_key_authorization_ref: agent_key_authorization_ref.to_owned(),
                verification_method: verification_method.to_owned(),
                scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            },
            runtime_key,
        )
    }

    fn record(
        &self,
        grant_jwt: &str,
        subject: &str,
        holder: CoauthGrantHolder,
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
        let binding = CoauthGrantBinding {
            grant_jwt: grant_jwt.to_owned(),
            subject: subject.to_owned(),
            holder,
            cnf_jkt,
            session_public_key,
        };
        // Each exact credential is its own ledger record, so a second device
        // of the same principal can hold a grant beside the first one.
        let mut bindings = self.bindings.lock().expect("coauth mock binding lock");
        bindings.retain(|existing| existing.grant_jwt != binding.grant_jwt);
        bindings.push(binding);
        Ok(())
    }

    pub fn url(&self) -> String {
        self.url.clone()
    }

    pub fn origin(&self) -> String {
        self.origin.clone()
    }

    pub fn requests(&self) -> Vec<Value> {
        self.requests.lock().expect("mock requests lock").clone()
    }

    /// Every internal call this mock saw, credential and self-reported identity
    /// headers included. Recorded before authorization, so a call that arrives
    /// without the configured credential still shows up here.
    pub fn channel_observations(&self) -> Vec<ChannelObservation> {
        self.channel.lock().expect("mock channel lock").clone()
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
        .is_some_and(|value| value == format!("Bearer {}", state.internal_secret));
    state
        .channel
        .lock()
        .expect("mock channel lock")
        .push(ChannelObservation {
            presented_configured_credential: authorized,
            self_reported_identity_headers: SELF_REPORTED_IDENTITY_HEADERS
                .iter()
                .filter(|name| req.headers().contains_key(**name))
                .map(|name| (*name).to_owned())
                .collect(),
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
        arkret_models_collaboration::session_grants::SessionGrantValidationInput,
    >(body);
    let Ok(arkret_models_collaboration::session_grants::SessionGrantValidationInput::ByJwt(by_jwt)) =
        parsed
    else {
        res.status_code(salvo::http::StatusCode::BAD_REQUEST);
        res.render(Json(json!({ "error": "invalid_typed_request" })));
        return;
    };
    let bindings = state
        .bindings
        .lock()
        .expect("coauth mock binding lock")
        .clone();
    if bindings.is_empty() {
        res.status_code(salvo::http::StatusCode::SERVICE_UNAVAILABLE);
        res.render(Json(json!({ "error": "grant_not_bound" })));
        return;
    }
    // Exact-token authority: only the complete credential the ledger recorded
    // is active. A token that merely parses, or that reuses a known `jti` under
    // re-signed claims, has no active record here.
    let Some((index, binding)) = bindings
        .iter()
        .enumerate()
        .find(|(_, binding)| binding.grant_jwt == by_jwt.grant_jwt)
    else {
        res.render(Json(json!({
            "active": false,
            "status": "not_found",
            "proof_required": false,
            "one_time_use_consumed": false
        })));
        return;
    };
    let audience = by_jwt
        .audience_id
        .map(|value| value.as_str().to_owned())
        .unwrap_or_default();
    // The first recorded grant keeps its historical id; later grants get an
    // id derived from their exact credential so records stay distinct.
    let grant_id = if index == 0 {
        "ak:session_grant:AREUYrj1_BH7OOg12-uDdXYf2SrPpdqagciUGa9tJ-nD".to_owned()
    } else {
        let mut token = vec![0x01];
        token.extend(arkret_canonical::sha256_bytes(binding.grant_jwt.as_bytes()));
        format!(
            "ak:session_grant:{}",
            arkret_canonical::base64url_encode(token)
        )
    };
    let expires_at = arkret_canonical::format_timestamp_canonical(
        chrono::Utc::now() + chrono::Duration::minutes(10),
    );
    let mut grant = json!({
        "id": grant_id,
        "issuer_id": "ak:did_core:web:coauth.cotest.local",
        "account_id": {
            "principal_id": binding.subject,
            "station_id": audience
        },
        "audience_id": audience,
        "expires_at": expires_at,
        "revoked_at": null,
        "revocation_ref": "org.arkret.coauth.browser_session:cotest-mock",
        "credential_class": "standard",
        "cnf_jkt": binding.cnf_jkt,
        "session_public_key": binding.session_public_key
    });
    match &binding.holder {
        CoauthGrantHolder::HumanDevice {
            device_id,
            authorization_event_id,
        } => {
            grant["device_id"] = json!(device_id);
            grant["scopes"] = json!([
                "ak.self.account.read.describe.v1",
                "ak.self.committed_event.read.scan.v1",
                "ak.root.identity.recovery_policy.resource.get.v1"
            ]);
            grant["holder_binding"] = json!({
                "kind": "human_device",
                "device_binding": device_id
            });
            // The human lane requires the exact device authorization
            // selector; it replays the accepted founding
            // `ak.device.authorize` Event of the bound principal at its
            // current generation (founding = 1).
            grant["device_binding"] = json!({
                "device_id": device_id,
                "authorization_event_id": authorization_event_id,
                "model_generation_ref": 1
            });
        }
        // An Agent grant carries no device: its holder is the exact
        // (agent_id, method, accepted key authorization) triple.
        CoauthGrantHolder::AgentRuntime {
            agent_key_authorization_ref,
            verification_method,
            scopes,
        } => {
            grant["scopes"] = json!(scopes);
            grant["holder_binding"] = json!({
                "kind": "agent_runtime",
                "agent_id": binding.subject,
                "agent_key_authorization_ref": agent_key_authorization_ref,
                "verification_method": verification_method
            });
        }
    }
    res.render(Json(json!({
        "active": true,
        "status": "active",
        "proof_required": false,
        "one_time_use_consumed": false,
        "grant": grant
    })));
}
