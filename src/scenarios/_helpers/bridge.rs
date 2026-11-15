//! Bridge-contract scenario helpers for
//! `session_grant_presentation_uses_configured_coauth_introspection`.
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use arkret_models_collaboration::device_pairing::{
    DevicePairingCode, DevicePairingNonce, DevicePairingRequestId, DevicePairingResolveRequestBody,
    DevicePairingStageRequestBody, DevicePairingStageResponseBody, DevicePairingState,
    DevicePairingStatusRequestBody, DevicePairingStatusResponseBody,
};
use arkret_models_collaboration::session_grants::{
    SessionGrantValidationInput, SessionGrantValidationMetadata, SessionGrantValidationResponseBody,
};
use arkret_models_identity::{
    CanonicalSessionPublicJwk, SessionGrantAdminIntrospectionStatus, SessionGrantCredentialClass,
    SessionGrantDeviceBinding, SessionGrantHolderBinding, SessionGrantMetadata, SessionGrantScope,
};
use arkret_wire::{AccountId, DeviceId, DidCoreId, EventId, SessionGrantId, SessionGrantSecret};
use salvo::affix_state;
use salvo::prelude::{Depot, Json, Request, Response, Router, handler};
use serde_json::{Value, json};

/// Grant metadata the mock returns on introspection. `cnf_jkt` and
/// `session_public_key` both derive from the same holder signing key, and the
/// device selector replays the provisioned principal's accepted founding
/// `ak.device.authorize` Event, mirroring what a real Account Authority learns
/// from its issuance gate.
///
/// `session_grant` is the exact opaque credential the fixture issuer holds. The Account
/// Authority is the only authority on session-grant state
/// (`key-management.md` §6.1, `api-conventions.md` §3.3): a submitted token is
/// active only when it is byte-identical to that record, so this mock matches
/// on the complete credential rather than deriving any fact from its bytes.
#[derive(Clone)]
struct CoauthGrantBinding {
    session_grant: SessionGrantSecret,
    metadata: SessionGrantMetadata,
    revoked_at: Option<chrono::DateTime<chrono::Utc>>,
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
        scope_details: SessionGrantScope,
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
            .find(|binding| binding.session_grant.as_str() == credential)
            .context("own Station credential has no issuer record")?;
        let metadata = &binding.metadata;
        let now = chrono::Utc::now();
        anyhow::ensure!(
            binding.revoked_at.is_none() && metadata.not_before <= now && now < metadata.expires_at,
            "own Station issuer record is revoked or expired"
        );
        anyhow::ensure!(
            metadata.audience_id == *station && metadata.account_id.station_id == *station,
            "issuer record belongs to another Station"
        );
        anyhow::ensure!(
            metadata.credential_class == SessionGrantCredentialClass::Standard,
            "recovery credential cannot become an ordinary own-Station host"
        );
        metadata.validate()?;
        Ok(garth::SessionGrantState {
            account_id: metadata.account_id.clone(),
            device_id: metadata.device_id.clone(),
            grant_ref: metadata.grant_ref(),
            session_grant: binding.session_grant.clone(),
            expires_at: metadata.expires_at,
            audience_id: metadata.audience_id.clone(),
            granted_scope: metadata.scopes.clone(),
            session_public_key: Some(metadata.session_public_key.as_str().to_owned()),
            dpop_jkt: Some(metadata.cnf_jkt.clone()),
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

    /// Record `session_grant` as the one exact active credential in the fixture issuer
    /// ledger and bind it to a provisioned principal's founding device. Both
    /// the DPoP thumbprint (`cnf.jkt`) and the RFC 9421 `session_public_key`
    /// derive from `holder_key`, so the same signing key satisfies the DPoP
    /// binding and any PoP-signed follow-up request. Any other submitted token
    /// — including a self-consistent forgery minted with a leaked issuer
    /// signing key — has no active record and introspects as `not_found`.
    pub fn bind_founding_device_grant(
        &self,
        session_grant: &str,
        audience_id: &DidCoreId,
        subject: &str,
        device_id: &str,
        authorization_event_id: &str,
        holder_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<()> {
        self.record(
            session_grant,
            audience_id,
            subject,
            CoauthGrantHolder::HumanDevice {
                device_id: device_id.to_owned(),
                authorization_event_id: authorization_event_id.to_owned(),
            },
            holder_key,
        )
    }

    /// Record `session_grant` as the exact Agent runtime SessionGrant of
    /// `agent_id`, bound to its accepted `ak.agent.key.authorize` Event and
    /// method (`key-management.md` section 3.6.1). The runtime key is the
    /// DPoP holder; the grant admits exactly `scopes`.
    pub fn bind_agent_runtime_grant(
        &self,
        session_grant: &str,
        audience_id: &DidCoreId,
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
        let scope_details: SessionGrantScope = serde_json::from_value(json!({
            "controller_principal_id": authorization.accountable_principal_id,
            "agent_key_authorization_ref": authorization_ref,
            "realm_ids": realm_ids, "strand_ids": strand_ids,
            "resources": {"realm_ids": realm_ids, "strand_ids": strand_ids},
            "constraints": {"allowed_tracks": [], "allowed_data_labels": allowed_labels, "allowed_endpoints": []},
            "capability_grant_refs": [], "policy_refs": []
        }))?;
        self.record(
            session_grant,
            audience_id,
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
        audience_id: &DidCoreId,
        subject: &str,
        device_id: &str,
        holder_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<()> {
        self.record(
            session_grant,
            audience_id,
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
        audience_id: &DidCoreId,
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
        let session_public_key = CanonicalSessionPublicJwk::new(serde_json::to_string(
            &json!({ "crv": "Ed25519", "kty": "OKP", "x": x }),
        )?)?;
        let session_grant = SessionGrantSecret::new(session_grant)?;
        let principal_id = DidCoreId::new(subject)?;
        let (
            device_id,
            mut scopes,
            credential_class,
            holder_binding,
            device_binding,
            scope_details,
        ) = match holder {
            CoauthGrantHolder::HumanDevice {
                device_id,
                authorization_event_id,
            } => {
                let device_id = DeviceId::new(device_id)?;
                (
                    Some(device_id.clone()),
                    standard_human_grant_scopes().map(str::to_owned).to_vec(),
                    SessionGrantCredentialClass::Standard,
                    SessionGrantHolderBinding::HumanDevice {
                        device_binding: device_id.to_string(),
                    },
                    Some(SessionGrantDeviceBinding {
                        device_id,
                        authorization_event_id: EventId::new(authorization_event_id)?,
                        model_generation_ref: 1,
                    }),
                    None,
                )
            }
            CoauthGrantHolder::AgentRuntime {
                agent_key_authorization_ref,
                verification_method,
                scopes,
                scope_details,
            } => (
                None,
                scopes,
                SessionGrantCredentialClass::Standard,
                SessionGrantHolderBinding::AgentRuntime {
                    agent_id: principal_id.clone(),
                    agent_key_authorization_ref: EventId::new(agent_key_authorization_ref)?,
                    verification_method: arkret_wire::DidUrl::new(verification_method)
                        .map_err(anyhow::Error::msg)?,
                },
                None,
                Some(scope_details),
            ),
            CoauthGrantHolder::RecoveryCandidateDevice { device_id } => {
                let device_id = DeviceId::new(device_id)?;
                (
                    Some(device_id.clone()),
                    arkret_models_identity::RECOVERY_SESSION_GRANT_OPERATIONS
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect(),
                    SessionGrantCredentialClass::RecoverySession,
                    SessionGrantHolderBinding::RecoveryCandidateDevice { device_id },
                    None,
                    None,
                )
            }
        };
        scopes.sort();
        scopes.dedup();
        // Each exact credential is its own ledger record, so a second device
        // of the same principal can hold a grant beside the first one.
        let mut bindings = self.bindings.lock().expect("coauth mock binding lock");
        let existing = bindings
            .iter()
            .find(|binding| binding.session_grant == session_grant)
            .cloned();
        let id = existing
            .as_ref()
            .map(|binding| binding.metadata.id.clone())
            .unwrap_or_else(|| {
                SessionGrantId::new_v7_at(chrono::Utc::now().timestamp_millis() as u64)
            });
        let not_before = existing.as_ref().map_or_else(
            || arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
            |binding| binding.metadata.not_before,
        );
        // This is fixture issuance state, not a reconstruction of a production
        // issuer response. Its identity and independent session coordinate are
        // allocated here, never decoded from the opaque credential or copied
        // from the introspection request's audience.
        let metadata = SessionGrantMetadata {
            id,
            issuer_id: DidCoreId::new("ak:did_core:web:coauth.cotest.local")?,
            account_id: AccountId::new(principal_id, audience_id.clone()),
            device_id,
            audience_id: audience_id.clone(),
            scopes,
            not_before,
            expires_at: existing
                .as_ref()
                .map_or(not_before + chrono::Duration::minutes(10), |binding| {
                    binding.metadata.expires_at
                }),
            session_id: existing.as_ref().map_or_else(
                || arkret_identifiers::new_prefixed_uuid7("fixture-session-"),
                |binding| binding.metadata.session_id.clone(),
            ),
            session_public_key,
            cnf_jkt,
            credential_class,
            holder_binding,
            device_binding,
            proof_kind: None,
            scope_details,
        };
        metadata.validate()?;
        if let Some(existing) = existing {
            anyhow::ensure!(
                existing.metadata == metadata
                    && existing.revoked_at.is_none()
                    && metadata.expires_at > chrono::Utc::now(),
                "exact fixture credential is immutable and cannot be rebound or reactivated"
            );
            return Ok(());
        }
        bindings.push(CoauthGrantBinding {
            session_grant,
            metadata,
            revoked_at: None,
        });
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

    /// Read coordinates from this fixture issuer's exact recovery record.
    /// Neither the record id nor its issuer is derived from credential bytes.
    pub(crate) fn recovery_grant_coordinates(
        &self,
        credential: &str,
    ) -> Result<(arkret_wire::SessionGrantRef, arkret_wire::Base64UrlString)> {
        let bindings = self.bindings.lock().expect("coauth mock binding lock");
        let binding = bindings
            .iter()
            .find(|binding| binding.session_grant.as_str() == credential)
            .context("exact recovery credential has no fixture issuer record")?;
        let metadata = &binding.metadata;
        metadata.validate()?;
        anyhow::ensure!(
            metadata.credential_class == SessionGrantCredentialClass::RecoverySession
                && binding.revoked_at.is_none()
                && metadata.not_before <= chrono::Utc::now()
                && metadata.expires_at > chrono::Utc::now(),
            "fixture recovery record is not active"
        );
        Ok((
            metadata.grant_ref(),
            arkret_wire::Base64UrlString::new(metadata.cnf_jkt.clone())
                .map_err(anyhow::Error::msg)?,
        ))
    }

    pub fn set_grant_expiry(
        &self,
        credential: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        let mut bindings = self.bindings.lock().expect("coauth mock binding lock");
        let binding = bindings
            .iter_mut()
            .find(|binding| binding.session_grant.as_str() == credential)
            .context("the issuer ledger contains the exact credential")?;
        binding.metadata.expires_at = arkret_canonical::normalize_timestamp_canonical(expires_at);
        Ok(())
    }

    pub fn revoke_grant(&self, credential: &str) -> Result<()> {
        let mut bindings = self.bindings.lock().expect("coauth mock binding lock");
        let binding = bindings
            .iter_mut()
            .find(|binding| binding.session_grant.as_str() == credential)
            .context("the issuer ledger contains the exact credential")?;
        binding.revoked_at = Some(arkret_canonical::normalize_timestamp_canonical(
            chrono::Utc::now(),
        ));
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
    let Some(binding) = bindings.iter_mut().find(|binding| {
        binding.session_grant.as_str() == token && binding.metadata.cnf_jkt == verified.jkt
    }) else {
        res.status_code(salvo::http::StatusCode::UNAUTHORIZED);
        return;
    };
    if binding.revoked_at.is_some() {
        res.status_code(salvo::http::StatusCode::CONFLICT);
        return;
    }
    binding.revoked_at = Some(arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now(),
    ));
    res.render(Json(json!({
        "revoked_count": 1,
        "revoked_session_grant_ids": [binding.metadata.id]
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
    // This read-only fixture endpoint authorizes only the exact opaque
    // credential branch. An issuer-local management id is never a credential.
    let parsed = serde_json::from_value::<SessionGrantValidationInput>(body);
    let Ok(SessionGrantValidationInput::BySecret(request)) = parsed else {
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
    // Only the exact credential and its already-recorded audience can select
    // an active fixture record. The caller cannot supply issuer metadata.
    let Some(binding) = bindings
        .iter()
        .find(|binding| binding.session_grant == request.session_grant)
    else {
        res.render(Json(inactive_grant_response(
            SessionGrantAdminIntrospectionStatus::NotFound,
        )));
        return;
    };
    if request.audience_id != binding.metadata.audience_id {
        res.render(Json(inactive_grant_response(
            SessionGrantAdminIntrospectionStatus::AudienceMismatch,
        )));
        return;
    }
    if binding.revoked_at.is_some() {
        res.render(Json(inactive_grant_response(
            SessionGrantAdminIntrospectionStatus::Revoked,
        )));
        return;
    }
    if chrono::Utc::now() >= binding.metadata.expires_at {
        res.render(Json(inactive_grant_response(
            SessionGrantAdminIntrospectionStatus::Expired,
        )));
        return;
    }
    let response = SessionGrantValidationResponseBody {
        active: true,
        status: SessionGrantAdminIntrospectionStatus::Active,
        proof_required: false,
        one_time_use_consumed: false,
        grant: Some(SessionGrantValidationMetadata {
            metadata: binding.metadata.clone(),
            revoked_at: None,
            revocation_ref: "org.arkret.coauth.browser_session:cotest-mock".to_owned(),
        }),
    };
    if response.validate().is_err() {
        res.status_code(salvo::http::StatusCode::INTERNAL_SERVER_ERROR);
        return;
    }
    res.render(Json(response));
}

fn inactive_grant_response(
    status: SessionGrantAdminIntrospectionStatus,
) -> SessionGrantValidationResponseBody {
    SessionGrantValidationResponseBody {
        active: false,
        status,
        proof_required: false,
        one_time_use_consumed: false,
        grant: None,
    }
}

fn standard_human_grant_scopes() -> [&'static str; 3] {
    [
        "ak.self.account.read.describe.v1",
        "ak.self.committed_event.read.scan.v1",
        "ak.root.identity.recovery_policy.resource.get.v1",
    ]
}

#[cfg(test)]
mod opaque_grant_tests {
    use super::*;

    async fn bound_fixture()
    -> Result<(MockCoauthIntrospectionServer, SessionGrantSecret, DidCoreId)> {
        let issuer = MockCoauthIntrospectionServer::spawn().await?;
        let secret = SessionGrantSecret::from_bytes([0x61; 32]);
        let station = DidCoreId::new("ak:did_core:web:station.example")?;
        let authorization = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0x62; 32]);
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x63; 32]);
        issuer.bind_founding_device_grant(
            secret.as_str(),
            &station,
            "ak:did_core:web:alice.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
            authorization.as_str(),
            &key.verifying_key(),
        )?;
        Ok((issuer, secret, station))
    }

    async fn introspect(
        issuer: &MockCoauthIntrospectionServer,
        body: Value,
    ) -> Result<reqwest::Response> {
        Ok(reqwest::Client::new()
            .post(issuer.url())
            .bearer_auth("principal-token")
            .json(&body)
            .send()
            .await?)
    }

    #[tokio::test]
    async fn opaque_lookup_is_exact_and_keeps_issuer_audience_and_native_holder_binding()
    -> Result<()> {
        let (issuer, secret, station) = bound_fixture().await?;
        let response: SessionGrantValidationResponseBody = introspect(
            &issuer,
            json!({"session_grant":secret,"audience_id":station}),
        )
        .await?
        .error_for_status()?
        .json()
        .await?;
        response.validate()?;
        ensure_active(&response)?;
        let metadata = &response.grant.as_ref().context("active metadata")?.metadata;
        let host = issuer.own_station_session_state(secret.as_str(), &station)?;
        assert_eq!(host.grant_ref, metadata.grant_ref());
        assert_eq!(host.account_id, metadata.account_id);
        assert_eq!(host.session_grant, secret);
        assert_ne!(host.grant_ref.issuer_id, station);
        assert_eq!(
            metadata.human_device_authorization_selector()?.device_id,
            host.device_id.clone().unwrap()
        );
        let other = SessionGrantSecret::from_bytes([0x64; 32]);
        let unknown: SessionGrantValidationResponseBody = introspect(
            &issuer,
            json!({"session_grant":other,"audience_id":station}),
        )
        .await?
        .json()
        .await?;
        assert_eq!(
            unknown.status,
            SessionGrantAdminIntrospectionStatus::NotFound
        );
        assert!(unknown.grant.is_none());
        let other_station = DidCoreId::new("ak:did_core:web:other.example")?;
        let mismatch: SessionGrantValidationResponseBody = introspect(
            &issuer,
            json!({"session_grant":secret,"audience_id":other_station}),
        )
        .await?
        .json()
        .await?;
        assert_eq!(
            mismatch.status,
            SessionGrantAdminIntrospectionStatus::AudienceMismatch
        );
        assert!(mismatch.grant.is_none());
        assert!(
            issuer
                .own_station_session_state(secret.as_str(), &other_station)
                .is_err()
        );
        Ok(())
    }

    fn ensure_active(response: &SessionGrantValidationResponseBody) -> Result<()> {
        anyhow::ensure!(
            response.active
                && response.status == SessionGrantAdminIntrospectionStatus::Active
                && response.grant.is_some()
        );
        Ok(())
    }

    #[tokio::test]
    async fn opaque_lookup_rejects_old_dual_and_management_fields() -> Result<()> {
        let (issuer, secret, station) = bound_fixture().await?;
        let reference = issuer
            .own_station_session_state(secret.as_str(), &station)?
            .grant_ref
            .clone();
        for request in [
            json!({"grant_jwt":secret,"audience_id":station}),
            json!({"session_grant":secret,"grant_jwt":secret,"audience_id":station}),
            json!({"id":reference.id,"audience_id":station}),
            json!({"session_grant":"header.payload.signature","audience_id":station}),
        ] {
            assert_eq!(
                introspect(&issuer, request).await?.status(),
                reqwest::StatusCode::BAD_REQUEST
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn exact_record_rebinding_preserves_metadata_and_never_reactivates() -> Result<()> {
        let (issuer, secret, station) = bound_fixture().await?;
        let before = issuer.bindings.lock().unwrap()[0].metadata.clone();
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x63; 32]);
        let bind = |audience: &DidCoreId| {
            issuer.bind_founding_device_grant(
                secret.as_str(),
                audience,
                before.account_id.principal_id.as_str(),
                before.device_id.as_ref().unwrap().as_str(),
                before
                    .device_binding
                    .as_ref()
                    .unwrap()
                    .authorization_event_id
                    .as_str(),
                &key.verifying_key(),
            )
        };
        bind(&station)?;
        assert_eq!(issuer.bindings.lock().unwrap()[0].metadata, before);
        let other = DidCoreId::new("ak:did_core:web:other.example")?;
        assert!(bind(&other).is_err());
        assert_eq!(issuer.bindings.lock().unwrap()[0].metadata, before);
        issuer.revoke_grant(secret.as_str())?;
        assert!(bind(&station).is_err());
        assert!(
            issuer
                .own_station_session_state(secret.as_str(), &station)
                .is_err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn expired_and_revoked_records_never_create_a_live_host() -> Result<()> {
        let (issuer, secret, station) = bound_fixture().await?;
        issuer.set_grant_expiry(
            secret.as_str(),
            chrono::Utc::now() - chrono::Duration::seconds(1),
        )?;
        let response: SessionGrantValidationResponseBody = introspect(
            &issuer,
            json!({"session_grant":secret,"audience_id":station}),
        )
        .await?
        .json()
        .await?;
        assert_eq!(
            response.status,
            SessionGrantAdminIntrospectionStatus::Expired
        );
        assert!(response.grant.is_none());
        assert!(
            issuer
                .own_station_session_state(secret.as_str(), &station)
                .is_err()
        );
        let (issuer, secret, station) = bound_fixture().await?;
        issuer.revoke_grant(secret.as_str())?;
        let response: SessionGrantValidationResponseBody = introspect(
            &issuer,
            json!({"session_grant":secret,"audience_id":station}),
        )
        .await?
        .json()
        .await?;
        assert_eq!(
            response.status,
            SessionGrantAdminIntrospectionStatus::Revoked
        );
        assert!(response.grant.is_none());
        assert!(
            issuer
                .own_station_session_state(secret.as_str(), &station)
                .is_err()
        );
        Ok(())
    }
}
