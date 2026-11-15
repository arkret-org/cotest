//! Bridge-contract scenario helpers for
//! `session_grant_presentation_uses_configured_coauth_introspection`.
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use arkret_models_collaboration::device_pairing::{
    DevicePairingCode, DevicePairingNonce, DevicePairingRequestId, DevicePairingResolveRequestBody,
    DevicePairingStageRequestBody, DevicePairingStageResponseBody, DevicePairingState,
    DevicePairingStatusRequestBody, DevicePairingStatusResponseBody,
};
use salvo::affix_state;
use salvo::prelude::{Depot, Json, Request, Response, Router, handler};
use serde_json::{Value, json};

/// Grant metadata the mock returns on introspection. `cnf_jkt` and
/// `session_public_key` both derive from the same holder signing key, and the
/// device selector replays the provisioned principal's accepted founding
/// `ak.device.authorize` Event, mirroring what a real Account Authority learns
/// from its issuance gate.
///
/// `session_grant` is the exact credential the issuer ledger holds. The Account
/// Authority is the only authority on session-grant state
/// (`key-management.md` §6.1, `api-conventions.md` §3.3): a submitted token is
/// active only when it is byte-identical to that record, so this mock matches
/// on the complete token rather than on a `jti` or grant id.
#[derive(Clone)]
struct CoauthGrantBinding {
    session_grant: String,
    account_id: arkret_wire::AccountId,
    grant_ref: arkret_wire::SessionGrantRef,
    subject: String,
    holder: CoauthGrantHolder,
    cnf_jkt: String,
    session_public_key: String,
    revoked: bool,
    recorded_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

/// The closed holder of one recorded grant: a human device with its accepted
/// authorization selector, or an Agent runtime bound to the exact accepted
/// key authorization and method, with the operations its scope admits.
#[derive(Clone, PartialEq, Eq)]
enum CoauthGrantHolder {
    HumanDevice {
        device_id: String,
        authorization_event_id: String,
    },
    AgentRuntime {
        agent_key_authorization_ref: String,
        verification_method: String,
        scopes: Vec<String>,
        scope_details: serde_json::Map<String, Value>,
    },
    RecoveryCandidateDevice {
        device_id: String,
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
    pairing: Option<Arc<Mutex<MockPairingLedger>>>,
}

#[derive(Default)]
struct MockPairingLedger {
    staged: Vec<(DevicePairingRequestId, DevicePairingCode)>,
    calls: Vec<&'static str>,
}

pub struct MockCoauthIntrospectionServer {
    origin: String,
    url: String,
    bindings: Arc<Mutex<Vec<CoauthGrantBinding>>>,
    requests: Arc<Mutex<Vec<Value>>>,
    channel: Arc<Mutex<Vec<ChannelObservation>>>,
    pairing: Option<Arc<Mutex<MockPairingLedger>>>,
    _server: super::mock_http::MockServer,
}

#[derive(Clone)]
pub(crate) struct MockCoauthGrantLedger {
    bindings: Arc<Mutex<Vec<CoauthGrantBinding>>>,
}

impl MockCoauthGrantLedger {
    /// Host state from the same exact issuer record consumed by the SUT.
    /// This fixture does not claim to exercise Coauth issuance.
    pub(crate) fn own_station_session_state(
        &self,
        credential: &str,
        station: &arkret_wire::DidCoreId,
    ) -> Result<garth::SessionGrantState> {
        let bindings = self.bindings.lock().expect("coauth mock binding lock");
        let binding = bindings
            .iter()
            .find(|binding| binding.session_grant == credential)
            .context("own Station credential has no issuer record")?;
        anyhow::ensure!(
            !binding.revoked && binding.expires_at > chrono::Utc::now(),
            "own Station issuer record is revoked or expired"
        );
        anyhow::ensure!(
            binding.account_id.station_id == *station,
            "issuer record belongs to another Station"
        );
        let (device_id, granted_scope) = match &binding.holder {
            CoauthGrantHolder::HumanDevice { device_id, .. } => (
                Some(arkret_wire::DeviceId::new(device_id.clone())?),
                standard_human_grant_scopes()
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
            ),
            CoauthGrantHolder::AgentRuntime { scopes, .. } => (None, scopes.clone()),
            CoauthGrantHolder::RecoveryCandidateDevice { .. } => {
                anyhow::bail!("recovery credential cannot become an ordinary own-Station host");
            }
        };
        Ok(garth::SessionGrantState {
            account_id: arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new(binding.subject.clone())?,
                station.clone(),
            ),
            device_id,
            grant_ref: binding.grant_ref.clone(),
            session_grant: arkret_wire::SessionGrantSecret::new(binding.session_grant.clone())?,
            expires_at: binding.expires_at,
            audience_id: station.clone(),
            granted_scope,
            session_public_key: Some(binding.session_public_key.clone()),
            dpop_jkt: Some(binding.cnf_jkt.clone()),
            pending_refresh: None,
        })
    }
}

impl MockCoauthIntrospectionServer {
    /// Spawn the mock before the SUT exists so its URL can be wired into the
    /// SUT environment; bind the provisioned principal afterwards through
    /// [`Self::bind_founding_device_grant`].
    pub async fn spawn() -> Result<Self> {
        Self::spawn_with_internal_secret("principal-token").await
    }

    pub async fn spawn_with_internal_secret(internal_secret: &str) -> Result<Self> {
        Self::spawn_with_optional_pairing(internal_secret, false).await
    }

    /// Test AA for the Station's three open handoff routes only. This models
    /// account-less stage and staged visibility; it cannot finalize or pair a
    /// device, so the separate real Coauth two-process suite remains required.
    pub async fn spawn_with_pairing_handoff(internal_secret: &str) -> Result<Self> {
        Self::spawn_with_optional_pairing(internal_secret, true).await
    }

    async fn spawn_with_optional_pairing(
        internal_secret: &str,
        pairing_enabled: bool,
    ) -> Result<Self> {
        let requests: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
        let bindings: Arc<Mutex<Vec<CoauthGrantBinding>>> = Arc::new(Mutex::new(Vec::new()));
        let channel: Arc<Mutex<Vec<ChannelObservation>>> = Arc::new(Mutex::new(Vec::new()));
        let pairing = pairing_enabled.then(|| Arc::new(Mutex::new(MockPairingLedger::default())));
        let state = CoauthIntrospectionState {
            internal_secret: internal_secret.to_owned(),
            bindings: Arc::clone(&bindings),
            requests: Arc::clone(&requests),
            channel: Arc::clone(&channel),
            pairing: pairing.clone(),
        };
        let mut router = Router::new()
            .hoop(affix_state::inject(state))
            .push(
                Router::with_path("_coauth/internal/session-grants/introspect")
                    .post(coauth_introspect),
            )
            .push(
                Router::with_path("_arkret/gate/account/session-grants/revoke").post(coauth_revoke),
            );
        if pairing_enabled {
            router = router
                .push(
                    Router::with_path("_coauth/internal/device-pairing/stages")
                        .post(mock_pairing_stage),
                )
                .push(
                    Router::with_path("_coauth/internal/device-pairing/resolutions")
                        .post(mock_pairing_resolve),
                )
                .push(
                    Router::with_path("_coauth/internal/device-pairing/status-queries")
                        .post(mock_pairing_status),
                );
        }
        let server = super::mock_http::spawn_mock(router).await?;
        let origin = format!("http://{}", server.addr());
        let url = format!("{origin}/_coauth/internal/session-grants/introspect");
        Ok(Self {
            origin,
            url,
            bindings,
            requests,
            channel,
            pairing,
            _server: server,
        })
    }

    /// Record `session_grant` as the one exact active credential in the issuer
    /// ledger and bind it to a provisioned principal's founding device. Both
    /// the DPoP thumbprint (`cnf.jkt`) and the RFC 9421 `session_public_key`
    /// derive from `holder_key`, so the same signing key satisfies the DPoP
    /// binding and any PoP-signed follow-up request. Any other submitted token
    /// — including a self-consistent forgery minted with a leaked issuer
    /// signing key — has no active record and introspects as `not_found`.
    pub fn bind_founding_device_grant(
        &self,
        session_grant: &str,
        subject: &str,
        device_id: &str,
        authorization_event_id: &str,
        holder_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<()> {
        self.record(
            session_grant,
            subject,
            CoauthGrantHolder::HumanDevice {
                device_id: device_id.to_owned(),
                authorization_event_id: authorization_event_id.to_owned(),
            },
            holder_key,
        )
    }

    /// First-bind expiry for fixtures that exercise actual passage of time.
    /// A recorded credential's immutable lifetime cannot subsequently be changed.
    pub fn bind_founding_device_grant_until(
        &self,
        session_grant: &str,
        subject: &str,
        device_id: &str,
        authorization_event_id: &str,
        holder_key: &ed25519_dalek::VerifyingKey,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        self.record_with_expiry(
            session_grant,
            subject,
            CoauthGrantHolder::HumanDevice {
                device_id: device_id.to_owned(),
                authorization_event_id: authorization_event_id.to_owned(),
            },
            holder_key,
            Some(expires_at),
        )
    }

    /// Record `session_grant` as the exact Agent runtime SessionGrant of
    /// `agent_id`, bound to its accepted `ak.agent.key.authorize` Event and
    /// method (`key-management.md` section 3.6.1). The runtime key is the
    /// DPoP holder; the grant admits exactly `scopes`.
    pub fn bind_agent_runtime_grant(
        &self,
        session_grant: &str,
        authorization_ref: &arkret_wire::EventId,
        authorization: &arkret_models_collaboration::events_payloads::agent::AgentKeyAuthorizePayload,
        runtime_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<()> {
        use arkret_models_collaboration::events_payloads::agent::AgentKeyScopeResourceKind;
        anyhow::ensure!(
            authorization
                .agent_key_scope
                .resources
                .iter()
                .all(
                    |resource| resource.kind == AgentKeyScopeResourceKind::Operation
                        || (resource.kind == AgentKeyScopeResourceKind::Strand
                            && resource.realm_id.is_some()
                            && resource.resource_ref.is_some()
                            && resource.schema_ref.is_none()
                            && resource.operation.is_none()
                            && resource.service_id.is_none())
                        || (resource.kind == AgentKeyScopeResourceKind::Realm
                            && resource.realm_id.is_some()
                            && resource.resource_ref.is_none()
                            && resource.schema_ref.is_none()
                            && resource.operation.is_none()
                            && resource.service_id.is_none())
                ),
            "fixture issuer cannot discard an unrepresented key constraint or content resource ceiling"
        );
        let mut allowed_labels: Option<std::collections::BTreeSet<String>> = None;
        for constraint in &authorization.agent_key_scope.constraints {
            let supported: arkret_models_collaboration::governance::grant_constraint::GrantConstraint =
                serde_json::from_value(json!({
                    "constraint_kind": "scope_limitation",
                    "effect": "allow",
                    "allowed_data_labels": constraint.allowed_data_labels,
                }))?;
            anyhow::ensure!(
                constraint == &supported && !constraint.allowed_data_labels.is_empty(),
                "fixture issuer cannot discard an unrepresented key constraint"
            );
            let labels = constraint.allowed_data_labels.iter().cloned().collect();
            allowed_labels = Some(match allowed_labels {
                None => labels,
                Some(current) => current.intersection(&labels).cloned().collect(),
            });
        }
        anyhow::ensure!(
            allowed_labels
                .as_ref()
                .is_none_or(|labels| !labels.is_empty()),
            "fixture issuer cannot express an empty mandatory label intersection as unrestricted"
        );
        let allowed_labels: Vec<_> = allowed_labels.unwrap_or_default().into_iter().collect();
        let key = serde_json::to_value(&authorization.public_key)?;
        anyhow::ensure!(
            key["key"].as_str()
                == Some(arkret_canonical::base64url_encode(runtime_key.as_bytes()).as_str()),
            "issuer runtime holder differs from the accepted authorization key"
        );
        let realm_ids: std::collections::BTreeSet<_> = authorization
            .agent_key_scope
            .resources
            .iter()
            .filter(|resource| resource.kind == AgentKeyScopeResourceKind::Realm)
            .filter_map(|resource| resource.realm_id.as_ref())
            .collect();
        let strand_ids: std::collections::BTreeSet<_> = authorization
            .agent_key_scope
            .resources
            .iter()
            .filter(|resource| resource.kind == AgentKeyScopeResourceKind::Strand)
            .filter_map(|resource| resource.resource_ref.as_ref())
            .map(ToString::to_string)
            .collect();
        let scope_details = json!({
            "controller_principal_id": authorization.accountable_principal_id,
            "agent_key_authorization_ref": authorization_ref,
            "realm_ids": realm_ids, "strand_ids": strand_ids,
            "resources": {"realm_ids": realm_ids, "strand_ids": strand_ids},
            "constraints": {"allowed_tracks": [], "allowed_data_labels": allowed_labels, "allowed_endpoints": []},
            "capability_grant_refs": [], "policy_refs": []
        }).as_object().unwrap().clone();
        self.record(
            session_grant,
            authorization.agent_id.as_str(),
            CoauthGrantHolder::AgentRuntime {
                agent_key_authorization_ref: authorization_ref.to_string(),
                verification_method: authorization.verification_method.to_string(),
                scopes: authorization.agent_key_scope.actions.clone(),
                scope_details,
            },
            runtime_key,
        )
    }

    /// Record the exact short-lived grant of a candidate recovery device.
    /// Unlike a Standard human grant this carries no accepted-device binding;
    /// introspection returns the protocol's closed recovery operation set.
    pub fn bind_recovery_session_grant(
        &self,
        session_grant: &str,
        subject: &str,
        device_id: &str,
        holder_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<()> {
        self.record(
            session_grant,
            subject,
            CoauthGrantHolder::RecoveryCandidateDevice {
                device_id: device_id.to_owned(),
            },
            holder_key,
        )
    }

    fn record(
        &self,
        session_grant: &str,
        subject: &str,
        holder: CoauthGrantHolder,
        holder_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<()> {
        self.record_with_expiry(session_grant, subject, holder, holder_key, None)
    }

    fn record_with_expiry(
        &self,
        session_grant: &str,
        subject: &str,
        holder: CoauthGrantHolder,
        holder_key: &ed25519_dalek::VerifyingKey,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<()> {
        arkret_wire::SessionGrantSecret::new(session_grant.to_owned())?;
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
        let coordinates =
            crate::scenarios::bridge_contracts::session_grant::mock_session_grant_coordinates(
                session_grant,
            )?;
        anyhow::ensure!(
            coordinates.account_id.principal_id.as_str() == subject,
            "mock issuer principal differs from its reserved coordinates"
        );
        if let CoauthGrantHolder::HumanDevice { device_id, .. }
        | CoauthGrantHolder::RecoveryCandidateDevice { device_id } = &holder
        {
            anyhow::ensure!(
                coordinates.device_id.as_str() == device_id,
                "mock issuer Device differs from its reserved coordinates"
            );
        }
        let mut bindings = self.bindings.lock().expect("coauth mock binding lock");
        if let Some(existing) = bindings
            .iter()
            .find(|binding| binding.session_grant == session_grant)
        {
            anyhow::ensure!(
                existing.account_id == coordinates.account_id
                    && existing.grant_ref == coordinates.grant_ref
                    && existing.subject == subject
                    && existing.holder == holder
                    && existing.cnf_jkt == cnf_jkt
                    && existing.session_public_key == session_public_key
                    && expires_at.is_none_or(|expiry| {
                        arkret_canonical::normalize_timestamp_canonical(expiry)
                            == existing.expires_at
                    }),
                "the exact fixture credential already has different immutable issuer facts"
            );
            // Rebinding never extends the original lifetime or clears revocation.
            return Ok(());
        }
        let recorded_at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let expires_at = arkret_canonical::normalize_timestamp_canonical(
            expires_at.unwrap_or(recorded_at + chrono::Duration::minutes(10)),
        );
        anyhow::ensure!(
            expires_at > recorded_at,
            "fixture grant must first be recorded before its immutable expiry"
        );
        let binding = CoauthGrantBinding {
            session_grant: session_grant.to_owned(),
            account_id: coordinates.account_id,
            grant_ref: coordinates.grant_ref,
            subject: subject.to_owned(),
            holder,
            cnf_jkt,
            session_public_key,
            revoked: false,
            recorded_at,
            expires_at,
        };
        // Each exact credential is its own ledger record, so a second device
        // of the same principal can hold a grant beside the first one.
        bindings.push(binding);
        Ok(())
    }

    pub fn url(&self) -> String {
        self.url.clone()
    }

    pub fn origin(&self) -> String {
        self.origin.clone()
    }

    pub(crate) fn grant_ledger(&self) -> MockCoauthGrantLedger {
        MockCoauthGrantLedger {
            bindings: self.bindings.clone(),
        }
    }

    pub(crate) fn own_station_session_state(
        &self,
        credential: &str,
        station: &arkret_wire::DidCoreId,
    ) -> Result<garth::SessionGrantState> {
        self.grant_ledger()
            .own_station_session_state(credential, station)
    }

    pub fn requests(&self) -> Vec<Value> {
        self.requests.lock().expect("mock requests lock").clone()
    }

    pub fn revoke_grant(&self, credential: &str) -> Result<()> {
        let mut bindings = self.bindings.lock().expect("coauth mock binding lock");
        let binding = bindings
            .iter_mut()
            .find(|binding| binding.session_grant == credential)
            .context("the issuer ledger contains the exact credential")?;
        binding.revoked = true;
        Ok(())
    }

    /// Every internal call this mock saw, credential and self-reported identity
    /// headers included. Recorded before authorization, so a call that arrives
    /// without the configured credential still shows up here.
    pub fn channel_observations(&self) -> Vec<ChannelObservation> {
        self.channel.lock().expect("mock channel lock").clone()
    }

    pub fn pairing_calls(&self) -> Vec<&'static str> {
        self.pairing
            .as_ref()
            .expect("pairing handoff mock was enabled")
            .lock()
            .expect("mock pairing lock")
            .calls
            .clone()
    }
}

fn pairing_channel_authorized(req: &Request, state: &CoauthIntrospectionState) -> bool {
    req.headers()
        .get(salvo::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == format!("Bearer {}", state.internal_secret))
}

#[handler]
async fn mock_pairing_stage(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .get_typed::<CoauthIntrospectionState>()
        .expect("mock AA state");
    if !pairing_channel_authorized(req, state) || req.headers().get("idempotency-key").is_none() {
        res.status_code(salvo::http::StatusCode::UNAUTHORIZED);
        return;
    }
    let Ok(_stage) = req.parse_json::<DevicePairingStageRequestBody>().await else {
        res.status_code(salvo::http::StatusCode::BAD_REQUEST);
        return;
    };
    let uuid = crate::scenarios::mls_lifecycle_live::fresh_uuid_v7();
    let id = DevicePairingRequestId::new(format!("device_pairing_request:{uuid}"))
        .expect("UUIDv7 pairing id");
    let entropy = arkret_canonical::sha256_bytes(uuid.as_bytes());
    let alphabet = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let code = DevicePairingCode::new(
        entropy[..8]
            .iter()
            .map(|byte| alphabet[usize::from(byte & 31)] as char)
            .collect(),
    )
    .expect("closed pairing code");
    let nonce = DevicePairingNonce::new(arkret_canonical::base64url_encode(entropy))
        .expect("32-byte pairing nonce");
    let host = req
        .headers()
        .get(salvo::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let outcome = DevicePairingStageResponseBody {
        device_pairing_request_id: id.clone(),
        pairing_code: code.clone(),
        gate_audience_uri: format!("http://{host}"),
        server_nonce: nonce,
        expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
    };
    let mut ledger = state
        .pairing
        .as_ref()
        .expect("pairing enabled")
        .lock()
        .expect("mock pairing lock");
    ledger.calls.push("stage");
    ledger.staged.push((id, code));
    res.render(Json(outcome));
}

#[handler]
async fn mock_pairing_resolve(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .get_typed::<CoauthIntrospectionState>()
        .expect("mock AA state");
    if !pairing_channel_authorized(req, state) {
        res.status_code(salvo::http::StatusCode::UNAUTHORIZED);
        return;
    }
    if req
        .parse_json::<DevicePairingResolveRequestBody>()
        .await
        .is_err()
    {
        res.status_code(salvo::http::StatusCode::BAD_REQUEST);
        return;
    }
    state
        .pairing
        .as_ref()
        .expect("pairing enabled")
        .lock()
        .expect("mock pairing lock")
        .calls
        .push("resolve");
    // A merely staged record is intentionally invisible until finalize.
    res.status_code(salvo::http::StatusCode::NOT_FOUND);
}

#[handler]
async fn mock_pairing_status(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .get_typed::<CoauthIntrospectionState>()
        .expect("mock AA state");
    if !pairing_channel_authorized(req, state) {
        res.status_code(salvo::http::StatusCode::UNAUTHORIZED);
        return;
    }
    let Ok(query) = req.parse_json::<DevicePairingStatusRequestBody>().await else {
        res.status_code(salvo::http::StatusCode::BAD_REQUEST);
        return;
    };
    let mut ledger = state
        .pairing
        .as_ref()
        .expect("pairing enabled")
        .lock()
        .expect("mock pairing lock");
    ledger.calls.push("status");
    if !ledger
        .staged
        .iter()
        .any(|(id, code)| *id == query.device_pairing_request_id && *code == query.pairing_code)
    {
        res.status_code(salvo::http::StatusCode::NOT_FOUND);
        return;
    }
    res.render(Json(DevicePairingStatusResponseBody {
        state: DevicePairingState::Staged,
        device_id: None,
        authorized_event_ref: None,
    }));
}

/// The same public Account Authority operation exercised by a live Coauth
/// deployment. This test ledger records the exact grant transition so the
/// Station's next introspection observes it.
#[handler]
async fn coauth_revoke(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .get_typed::<CoauthIntrospectionState>()
        .expect("coauth mock state injected");
    let token = req
        .headers()
        .get(salvo::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("DPoP "))
        .map(str::to_owned);
    let proof = req
        .headers()
        .get("dpop")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let (Some(token), Some(proof)) = (token, proof) else {
        res.status_code(salvo::http::StatusCode::UNAUTHORIZED);
        return;
    };
    let host = req
        .headers()
        .get(salvo::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let htu = format!("http://{host}{}", req.uri().path());
    let verified = arkret_signatures::dpop::verify_dpop_proof(
        &arkret_signatures::dpop::DpopVerificationRequest {
            proof_jwt: &proof,
            method: "POST",
            htu: &htu,
            access_token: Some(&token),
            now: chrono::Utc::now(),
            max_age: chrono::Duration::seconds(300),
            max_future_skew: chrono::Duration::seconds(30),
            expected_nonce: None,
        },
    );
    let Ok(verified) = verified else {
        res.status_code(salvo::http::StatusCode::UNAUTHORIZED);
        return;
    };
    let body = req.payload().await.ok();
    if body.is_some_and(|bytes| !bytes.is_empty() && bytes.as_ref() != b"{}") {
        res.status_code(salvo::http::StatusCode::BAD_REQUEST);
        return;
    }
    let mut bindings = state.bindings.lock().expect("coauth mock binding lock");
    let Some(binding) = bindings
        .iter_mut()
        .find(|binding| binding.session_grant == token && binding.cnf_jkt == verified.jkt)
    else {
        res.status_code(salvo::http::StatusCode::UNAUTHORIZED);
        return;
    };
    if binding.revoked {
        res.status_code(salvo::http::StatusCode::CONFLICT);
        return;
    }
    binding.revoked = true;
    let grant_id = binding.grant_ref.id.clone();
    res.render(Json(json!({
        "revoked_count": 1,
        "revoked_session_grant_ids": [grant_id]
    })));
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
    // The contract surface is the typed wire shape: only a by-secret
    // introspection request with an audience is in-contract.
    let parsed = serde_json::from_value::<
        arkret_models_collaboration::session_grants::SessionGrantValidationInput,
    >(body);
    let Ok(arkret_models_collaboration::session_grants::SessionGrantValidationInput::BySecret(
        by_secret,
    )) = parsed
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
    let Some(binding) = bindings
        .iter()
        .find(|binding| binding.session_grant == by_secret.session_grant.as_str())
    else {
        res.render(Json(json!({
            "active": false,
            "status": "not_found",
            "proof_required": false,
            "one_time_use_consumed": false
        })));
        return;
    };
    if binding.revoked {
        res.render(Json(json!({
            "active": false,
            "status": "revoked",
            "proof_required": false,
            "one_time_use_consumed": false
        })));
        return;
    }
    if chrono::Utc::now() >= binding.expires_at {
        res.render(Json(json!({"active":false,"status":"expired","proof_required":false,"one_time_use_consumed":false})));
        return;
    }
    let audience = by_secret.audience_id.as_str();
    // The independent issuer-scoped reference was frozen at first bind.
    let grant_id = binding.grant_ref.id.clone();
    let expires_at = arkret_canonical::format_timestamp_canonical(binding.expires_at);
    let mut grant = json!({
        "id": grant_id,
        "issuer_id": binding.grant_ref.issuer_id,
        "account_id": {
            "principal_id": binding.subject,
            "station_id": audience
        },
        "audience_id": audience,
        "expires_at": expires_at,
        "not_before": arkret_canonical::format_timestamp_canonical(binding.recorded_at),
        "revocation_ref": format!("cotest-mock:{}:{}", binding.grant_ref.issuer_id, binding.grant_ref.id),
        "session_id": "cotest-mock-session",
        "credential_class": "standard",
        "cnf_jkt": binding.cnf_jkt,
        "session_public_key": binding.session_public_key
    });
    if audience != binding.account_id.station_id.as_str() {
        res.render(Json(json!({"active":false,"status":"not_found","proof_required":false,"one_time_use_consumed":false})));
        return;
    }
    match &binding.holder {
        CoauthGrantHolder::HumanDevice {
            device_id,
            authorization_event_id,
        } => {
            grant["device_id"] = json!(device_id);
            grant["proof_kind"] = json!("account_handoff");
            grant["scopes"] = json!(standard_human_grant_scopes());
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
            scope_details,
        } => {
            grant["proof_kind"] = json!("agent_key_proof");
            grant["scopes"] = json!(scopes);
            grant["scope_details"] = json!(scope_details);
            grant["holder_binding"] = json!({
                "kind": "agent_runtime",
                "agent_id": binding.subject,
                "agent_key_authorization_ref": agent_key_authorization_ref,
                "verification_method": verification_method
            });
        }
        CoauthGrantHolder::RecoveryCandidateDevice { device_id } => {
            grant["credential_class"] = json!("recovery_session");
            grant["proof_kind"] = json!("account_handoff");
            grant["device_id"] = json!(device_id);
            grant["scopes"] = json!(arkret_models_identity::RECOVERY_SESSION_GRANT_OPERATIONS);
            grant["holder_binding"] = json!({
                "kind": "recovery_candidate_device",
                "device_id": device_id
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

fn standard_human_grant_scopes() -> [&'static str; 3] {
    [
        "ak.root.identity.recovery_policy.resource.get.v1",
        "ak.self.account.read.describe.v1",
        "ak.self.committed_event.read.scan.v1",
    ]
}

#[cfg(test)]
mod opaque_grant_tests {
    use super::*;

    const PRINCIPAL: &str = "ak:did_core:web:alice.example";
    const DEVICE: &str = "ak:device:01904100-0000-7000-8000-0000000000a1";
    const STATION: &str = "ak:did_core:web:station.example";

    fn credential() -> String {
        crate::scenarios::bridge_contracts::session_grant::mock_session_grant(
            PRINCIPAL, DEVICE, STATION,
        )
    }

    async fn introspect(
        issuer: &MockCoauthIntrospectionServer,
        secret: &str,
        audience: &str,
    ) -> Result<arkret_models_collaboration::session_grants::SessionGrantValidationResponseBody>
    {
        use arkret_models_collaboration::session_grants::{
            SessionGrantValidationBySecret, SessionGrantValidationInput,
        };
        let request = SessionGrantValidationInput::BySecret(SessionGrantValidationBySecret {
            session_grant: arkret_wire::SessionGrantSecret::new(secret.to_owned())?,
            audience_id: audience.parse()?,
            proof: None,
        });
        let response = reqwest::Client::new()
            .post(issuer.url())
            .bearer_auth("principal-token")
            .json(&request)
            .send()
            .await?
            .error_for_status()?
            .json::<arkret_models_collaboration::session_grants::SessionGrantValidationResponseBody>()
            .await?;
        response.validate()?;
        Ok(response)
    }

    #[tokio::test]
    async fn exact_fixture_credential_rebinding_preserves_immutable_facts_and_revocation()
    -> Result<()> {
        let issuer = MockCoauthIntrospectionServer::spawn().await?;
        let secret = credential();
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x52; 32]);
        let expiry = arkret_canonical::normalize_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::minutes(2),
        );
        issuer.bind_founding_device_grant_until(
            &secret,
            PRINCIPAL,
            DEVICE,
            "fixture-authorize",
            &key.verifying_key(),
            expiry,
        )?;
        let station = STATION.parse()?;
        let original = issuer.own_station_session_state(&secret, &station)?;
        issuer.bind_founding_device_grant(
            &secret,
            PRINCIPAL,
            DEVICE,
            "fixture-authorize",
            &key.verifying_key(),
        )?;
        issuer.bind_founding_device_grant_until(
            &secret,
            PRINCIPAL,
            DEVICE,
            "fixture-authorize",
            &key.verifying_key(),
            expiry,
        )?;
        anyhow::ensure!(issuer.own_station_session_state(&secret, &station)? == original);
        anyhow::ensure!(
            issuer
                .bind_founding_device_grant_until(
                    &secret,
                    PRINCIPAL,
                    DEVICE,
                    "fixture-authorize",
                    &key.verifying_key(),
                    expiry + chrono::Duration::seconds(1),
                )
                .is_err()
        );
        anyhow::ensure!(
            issuer
                .bind_founding_device_grant(
                    &secret,
                    PRINCIPAL,
                    DEVICE,
                    "another-authorization",
                    &key.verifying_key(),
                )
                .is_err()
        );
        let wrong_key = ed25519_dalek::SigningKey::from_bytes(&[0x53; 32]);
        anyhow::ensure!(
            issuer
                .bind_founding_device_grant(
                    &secret,
                    PRINCIPAL,
                    DEVICE,
                    "fixture-authorize",
                    &wrong_key.verifying_key(),
                )
                .is_err()
        );
        issuer.revoke_grant(&secret)?;
        issuer.bind_founding_device_grant(
            &secret,
            PRINCIPAL,
            DEVICE,
            "fixture-authorize",
            &key.verifying_key(),
        )?;
        anyhow::ensure!(issuer.own_station_session_state(&secret, &station).is_err());
        let response = introspect(&issuer, &secret, STATION).await?;
        anyhow::ensure!(!response.active && response.grant.is_none());
        let bindings = issuer.bindings.lock().expect("fixture ledger");
        anyhow::ensure!(bindings.len() == 1 && bindings[0].expires_at == expiry);
        Ok(())
    }

    #[tokio::test]
    async fn fixture_by_secret_http_metadata_is_typed_and_audience_bound() -> Result<()> {
        let issuer = MockCoauthIntrospectionServer::spawn().await?;
        let secret = credential();
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x52; 32]);
        issuer.bind_founding_device_grant(
            &secret,
            PRINCIPAL,
            DEVICE,
            "fixture-authorize",
            &key.verifying_key(),
        )?;
        let response = introspect(&issuer, &secret, STATION).await?;
        anyhow::ensure!(response.active);
        let grant = response.grant.context("active fixture omitted metadata")?;
        let state = issuer.own_station_session_state(&secret, &STATION.parse()?)?;
        anyhow::ensure!(grant.grant_ref() == state.grant_ref);
        anyhow::ensure!(
            grant.account_id == state.account_id && grant.audience_id == state.audience_id
        );
        anyhow::ensure!(grant.scopes == state.granted_scope);
        anyhow::ensure!(
            !grant.revocation_ref.is_empty() && !grant.revocation_ref.contains(&secret)
        );
        let replay = introspect(&issuer, &secret, STATION).await?;
        anyhow::ensure!(
            replay
                .grant
                .context("replay omitted metadata")?
                .revocation_ref
                == grant.revocation_ref
        );
        let wrong_audience = introspect(&issuer, &secret, "ak:did_core:web:other.example").await?;
        anyhow::ensure!(!wrong_audience.active && wrong_audience.grant.is_none());
        let unissued = credential();
        anyhow::ensure!(unissued != secret);
        let response = introspect(&issuer, &unissued, STATION).await?;
        anyhow::ensure!(!response.active && response.grant.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn first_bind_expiry_elapses_without_changing_metadata() -> Result<()> {
        let issuer = MockCoauthIntrospectionServer::spawn().await?;
        let secret = credential();
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x52; 32]);
        let expiry = arkret_canonical::normalize_timestamp_canonical(
            chrono::Utc::now() + chrono::Duration::seconds(1),
        );
        issuer.bind_founding_device_grant_until(
            &secret,
            PRINCIPAL,
            DEVICE,
            "fixture-authorize",
            &key.verifying_key(),
            expiry,
        )?;
        let original = issuer.bindings.lock().expect("fixture ledger")[0].clone();
        let remaining = expiry
            .signed_duration_since(chrono::Utc::now())
            .to_std()
            .unwrap_or_default();
        tokio::time::sleep(remaining + std::time::Duration::from_millis(20)).await;
        anyhow::ensure!(
            issuer
                .own_station_session_state(&secret, &STATION.parse()?)
                .is_err()
        );
        let response = introspect(&issuer, &secret, STATION).await?;
        anyhow::ensure!(!response.active && response.grant.is_none());
        let bindings = issuer.bindings.lock().expect("fixture ledger");
        anyhow::ensure!(
            bindings[0].expires_at == original.expires_at
                && bindings[0].recorded_at == original.recorded_at
                && bindings[0].grant_ref == original.grant_ref
                && !bindings[0].revoked
        );
        Ok(())
    }
}
