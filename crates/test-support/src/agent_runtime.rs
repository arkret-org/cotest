//! Real Agent pairing and session transport for a browser-driven member case.
//! Private runtime and holder keys never leave this in-process handle.
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use arkret_http_client::{Auth, Client as SdkClient, DpopAuth};
use arkret_models_collaboration::agent_operations::*;
use arkret_models_collaboration::agent_scope::*;
use arkret_models_collaboration::events_payloads::agent::*;
use arkret_models_collaboration::session_grants::*;
use arkret_signatures::{Ed25519DetachedJwsSigner, SignEventOptions, sign_event};
use arkret_wire::{
    AccountId, ActorId, DidCoreId, DidUrl, EventId, NonEmptyString, PayloadProof, RealmId,
    RequestId, SchemaId, ScopeRef, ServiceOperationId, StrandId,
};
use ed25519_dalek::{Signer as _, SigningKey};
use garth::{
    ArkretClient, FileStore, OutboundEngine, OutboundEngineOutcome, SessionEngine, SystemClock,
};
use serde_json::{Value, json};

/// Diagnostics expose only fixed stage labels and registered HTTP codes.
pub fn runtime_pair_error_summary(error: &anyhow::Error) -> String {
    fn boundary(problem: &arkret_wire::Problem) -> &'static str {
        if problem.detail.starts_with("invalid initial holder proof:") {
            "initial_holder_dpop"
        } else if problem
            .detail
            .starts_with("invalid grant-binding DPoP proof:")
        {
            "http_holder_dpop"
        } else if problem.detail == "initial and current holder keys differ" {
            "holder_key_binding"
        } else if problem.detail == "signature_invalid" {
            "issuer_agent_proof"
        } else {
            "registered_issuer_refusal"
        }
    }
    const SAFE: &[&str] = &[
        "pairing/read-agent-current",
        "pairing/resolve",
        "pairing/request-key",
        "pairing/accept-key",
        "pairing/observe-key",
        "pairing/signer-evidence",
        "pairing/read-accepted-key",
        "pairing/describe",
        "pairing/issue-session",
        "pairing/observe-session",
        "accepted Agent key state unavailable",
        "accepted pairing handle missing",
        "accepted pairing code missing",
        "accepted pairing expiry missing",
        "original pairing has expired",
        "controller Device signer belongs to another principal",
        "accepted Agent controller binding changed",
        "pairing bootstrap changed the original accepted binding",
        "pairing request kind invalid",
        "original pairing handle missing",
        "pair outcome names another authorization",
        "activated Agent signer differs from the original frozen key",
        "activated key omitted authenticated signer evidence",
        "accepted runtime key activation did not complete",
        "PCR authorization read-back changed Event",
        "Station did not declare its Account Authority",
        "configured Coauth differs from declared Account Authority",
        "accepted provision did not select the tested runtime operations",
        "accepted runtime scope is incomplete",
        "issued session changed the runtime holder or requested scope",
        "initial pairing session unexpectedly contains content authority",
    ];
    let stage = error
        .chain()
        .find_map(|cause| {
            let text = cause.to_string();
            SAFE.iter().copied().find(|label| *label == text)
        })
        .unwrap_or("unclassified pairing boundary");
    let api =
        error.chain().find_map(
            |cause| match cause.downcast_ref::<arkret_http_client::Error>() {
                Some(arkret_http_client::Error::Api { status, error }) => Some((
                    *status,
                    error
                        .error_code()
                        .map(|code| code.as_str())
                        .unwrap_or("unregistered"),
                    boundary(error),
                )),
                _ => match cause.downcast_ref::<garth::Error>() {
                    Some(garth::Error::Api { status, error }) => Some((
                        *status,
                        error
                            .error_code()
                            .map(|code| code.as_str())
                            .unwrap_or("unregistered"),
                        boundary(error),
                    )),
                    _ => None,
                },
            },
        );
    match api {
        Some((status, code, boundary)) => format!(
            "accepted controller Agent pairing/session failed: {stage}; status={status}; code={code}; boundary={boundary}"
        ),
        None => format!("accepted controller Agent pairing/session failed: {stage}"),
    }
}

pub struct AgentRuntimeHandle {
    runtime: ArkretClient<SdkClient, FileStore>,
    outbound: OutboundEngine<FileStore, SystemClock>,
    signer: Ed25519DetachedJwsSigner,
    account: AccountId,
    controller: SdkClient,
    pub authorization: EventId,
    issuer: SessionEngine<SdkClient>,
    session_request: UnsignedAgentSessionGrantRequest,
    holder: Arc<SigningKey>,
    runtime_key: SigningKey,
    http: reqwest::Client,
    station_base: String,
    grant_url: String,
}

fn random_key() -> Result<SigningKey> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).context("obtain runtime key OS entropy")?;
    Ok(SigningKey::from_bytes(&seed))
}

fn sdk(http: reqwest::Client, base: &str, auth: Option<Auth>) -> Result<SdkClient> {
    sdk_with_retry(
        http,
        base,
        auth,
        arkret_http_client::RetryConfig::disabled(),
    )
}

fn sdk_with_retry(
    http: reqwest::Client,
    base: &str,
    auth: Option<Auth>,
    retry: arkret_http_client::RetryConfig,
) -> Result<SdkClient> {
    let endpoint = url::Url::parse(base)?;
    let mut builder = SdkClient::builder(endpoint.clone())
        .http_client(http)
        .retry(retry);
    if let Some(auth) = auth {
        builder = builder.auth(auth);
    }
    if let Some(host) = endpoint.host_str() {
        for namespace in ["localhost", "local.host"] {
            if host == namespace || host.ends_with(&format!(".{namespace}")) {
                builder = builder.loopback_service_discovery(
                    namespace,
                    endpoint
                        .port_or_known_default()
                        .context("Station port missing")?,
                )?;
                break;
            }
        }
    }
    Ok(builder.build()?)
}

pub fn controller_transport(
    http: reqwest::Client,
    base: &str,
    grant: String,
    holder: SigningKey,
) -> Result<SdkClient> {
    let holder = Arc::new(holder);
    sdk(
        http,
        base,
        Some(Auth::Dpop(DpopAuth::with_dpop_token(
            grant,
            move |request| {
                garth::session::dpop::build_http_dpop_proof(request, &holder).map_err(|_| {
                    arkret_http_client::Error::Protocol("controller DPoP signing failed".into())
                })
            },
        ))),
    )
}

fn disclosure(
    controller: &AccountId,
    method: &DidUrl,
    key: &SigningKey,
    state: &KeyState,
) -> Result<AgentRequestedScopeDisclosure> {
    let pairing = state
        .pairing_request_id
        .as_ref()
        .context("original pairing handle missing")?;
    let uuid = pairing
        .as_str()
        .strip_prefix("agent_pairing_request:")
        .context("pairing request kind invalid")?;
    let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let mut disclosure = AgentRequestedScopeDisclosure {
        schema: SchemaId::AgentRequestedScopeDisclosureV1,
        request_id: RequestId::new(format!("ak:request:{uuid}"))?,
        agent_id: state.agent_id.clone(),
        controller_principal_id: controller.principal_id.clone(),
        requested_scope: state.requested_scope.clone(),
        verifier_id: controller.station_id.clone(),
        audience: NonEmptyString::new(ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1)
            .map_err(anyhow::Error::msg)?,
        challenge: NonEmptyString::new(pairing.as_str()).map_err(anyhow::Error::msg)?,
        issued_at: now,
        expires_at: now + chrono::Duration::seconds(240),
        proofs: vec![],
    };
    let mut proof = PayloadProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.into(),
        verification_method: method.clone(),
        payload_digest: disclosure.payload_digest()?,
        created_at: now,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    };
    proof.jws = arkret_signatures::sign_ed25519_detached_jws(
        key,
        &disclosure.canonical_proof_binding_bytes(&proof)?,
    )?;
    disclosure.proofs.push(proof);
    disclosure.validate()?;
    Ok(disclosure)
}

impl AgentRuntimeHandle {
    /// The accepted controller transport reads the original create-locked
    /// key state. No pairing code or scope supplied by the caller is trusted.
    #[allow(
        clippy::too_many_arguments,
        reason = "The pairing fixture binds each accepted controller credential, service endpoint and durable device location explicitly."
    )]
    pub async fn pair(
        http: reqwest::Client,
        station_base: &str,
        coauth_base: &str,
        controller: &SdkClient,
        controller_account: &AccountId,
        controller_device_method: &DidUrl,
        controller_device_key: &SigningKey,
        agent_id: DidCoreId,
        strand: StrandId,
        store_root: &Path,
    ) -> Result<Self> {
        ensure!(
            arkret_wire::project_did_to_core_id(&arkret_identity::verification_method_did(
                controller_device_method.as_str()
            )?)? == controller_account.principal_id,
            "controller Device signer belongs to another principal"
        );
        let view = controller
            .agent_get(agent_id.as_str())
            .await
            .context("pairing/read-agent-current")?;
        let state = view
            .key_state
            .context("accepted Agent key state unavailable")?;
        ensure!(
            state.agent_id == agent_id && state.controller_account_id == *controller_account,
            "accepted Agent controller binding changed"
        );
        let request_id = state
            .pairing_request_id
            .as_ref()
            .context("accepted pairing handle missing")?;
        let code = state
            .pairing_code
            .as_ref()
            .context("accepted pairing code missing")?;
        let expires = state
            .pairing_expires_at
            .context("accepted pairing expiry missing")?;
        ensure!(expires > chrono::Utc::now(), "original pairing has expired");
        let open = sdk(http.clone(), station_base, None)?;
        let describe = open.describe().await.context("pairing/describe")?;
        let authority = describe
            .auth_metadata
            .account_authority
            .as_ref()
            .context("Station did not declare its Account Authority")?;
        ensure!(
            url::Url::parse(authority.origin.as_str())?.origin()
                == url::Url::parse(coauth_base)?.origin(),
            "configured Coauth differs from declared Account Authority"
        );
        // Pairing custody must be retained by the declared Account Authority
        // that will issue the session, as in the normal product pairing flow.
        let controller_authority =
            controller.with_base_url(url::Url::parse(authority.origin.as_str())?)?;
        let bootstrap: AgentPairingBootstrap = open
            .resolve_agent_pairing(&AgentPairingResolveRequestBody {
                pairing_token: arkret_canonical::base64url_encode(serde_json::to_vec(
                    &json!({"r":request_id,"c":code}),
                )?),
            })
            .await
            .context("pairing/resolve")?;
        let identity = bootstrap
            .validated_runtime_identity()
            .map_err(anyhow::Error::msg)?
            .clone();
        ensure!(
            identity.controller_account_id == *controller_account
                && bootstrap.agent_id == agent_id
                && bootstrap.service_id == controller_account.station_id
                && bootstrap.pairing_request_id == *request_id
                && bootstrap.pairing_expires_at == expires,
            "pairing bootstrap changed the original accepted binding"
        );
        let runtime_key = random_key()?;
        let candidate =
            arkret_signatures::agent::RuntimeKeyRequestBuilder::new_with_verification_method(
                &runtime_key,
                bootstrap.clone(),
                &identity.verification_method,
            );
        let approval_request = candidate.build_approval_request()?;
        let approval: AgentRuntimeApprovalOutcome = open
            .request_agent_runtime_approval(&approval_request.body)
            .await
            .context("pairing/request-key")?;
        let runtime_digest = agent_runtime_key_binding_digest(
            &agent_id,
            request_id,
            &identity.verification_method,
            &approval_request.body.public_key,
            None,
        )?;
        let request_digest = agent_key_pairing_request_binding_digest(
            ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1,
            &controller_account.principal_id,
            &agent_id,
            request_id,
            &approval.approval_request_id,
            expires,
            &controller_account.station_id,
            &runtime_digest,
        )?;
        let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let expected_public_key = approval_request.body.public_key.clone();
        let authorization_payload = AgentKeyAuthorizePayload {
            agent_id: agent_id.clone(),
            key_id: NonEmptyString::new(identity.verification_method.as_str())
                .map_err(anyhow::Error::msg)?,
            verification_method: identity.verification_method.clone(),
            public_key: approval_request.body.public_key,
            accountable_principal_id: controller_account.principal_id.clone(),
            agent_key_scope: state.requested_scope.clone(),
            audience: vec![controller_account.station_id.to_string()],
            issued_at: now,
            expires_at: None,
            approval_evidence: AgentKeyApprovalEvidence {
                kind: AgentKeyApprovalEvidenceKind::PairingRequest,
                evidence_ref: None,
                request_canonical_digest: Some(request_digest),
                pairing_request_id: Some(request_id.clone()),
                approved_by: Some(controller_account.principal_id.clone()),
            },
            supersedes: vec![],
            revocation_check_ref: None,
            runtime_attestation: None,
        };
        let account = AccountId::new(agent_id.clone(), controller_account.station_id.clone());
        let mut authorize = arkret_event_draft::build_agent_key_authorize_intent(
            &authorization_payload,
            ScopeRef::Realm {
                realm_id: state.principal_control_realm_id.clone(),
            },
            ActorId::account(account.clone()),
            ActorId::account(controller_account.clone()),
            state.controller_authorization_ref.clone(),
            now,
        )?
        .author_with_digest_suite(arkret_canonical::DigestSuite::Sha256)?;
        sign_event(
            &mut authorize,
            &Ed25519DetachedJwsSigner::new(
                controller_device_key.clone(),
                controller_device_method.as_str(),
            ),
            SignEventOptions::default(),
        )?;
        let authorization = authorize.event_id.clone();
        let original_authorization = authorize.event().clone();
        let pair = candidate.build_key_pair_request(
            approval.approval_request_id,
            disclosure(
                controller_account,
                controller_device_method,
                controller_device_key,
                &state,
            )?,
            authorize.into_event(),
        )?;
        let producer = arkret_identity::ProducerVerificationContext {
            actor: ActorId::account(controller_account.clone()),
            verification_method: controller_device_method.clone(),
            public_key: arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                bytes: controller_device_key.verifying_key().to_bytes().to_vec(),
            },
            digest_suite: arkret_canonical::DigestSuite::Sha256,
        };
        let submission =
            arkret_identity::VerifiedSubmission::verify(pair.body, |_| Ok(producer.clone()))?;
        let paired = controller_authority
            .agent_key_pair(&submission)
            .await
            .context("pairing/accept-key")?;
        ensure!(
            paired.authorize_event_ref == authorization,
            "pair outcome names another authorization"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let signer_commit = loop {
            let status: AgentRuntimeApprovalStatusOutcome = open
                .agent_runtime_approval_status(&AgentRuntimeApprovalStatusRequestBody {
                    pairing_request_id: request_id.clone(),
                    pairing_code: NonEmptyString::new(code).map_err(anyhow::Error::msg)?,
                    agent_id: agent_id.clone(),
                })
                .await
                .context("pairing/observe-key")?;
            status
                .validate_signer_evidence_delivery()
                .context("pairing/signer-evidence")?;
            if status.authorized_event_ref.as_ref() == Some(&authorization) {
                let evidence = &status
                    .current_signer_evidence
                    .as_ref()
                    .context("activated key omitted authenticated signer evidence")?
                    .authenticated_signer_evidence;
                let jwk = evidence.public_key_jwk.as_map();
                ensure!(
                    evidence.signer_kind == arkret_models_identity::AuthenticatedSignerKind::Agent
                        && evidence.subject_id == agent_id
                        && evidence.verification_method == identity.verification_method
                        && status.authorized_verification_method.as_ref()
                            == Some(&identity.verification_method)
                        && jwk.get("kty").and_then(Value::as_str) == Some("OKP")
                        && jwk.get("crv").and_then(Value::as_str) == Some("Ed25519")
                        && jwk.get("x").and_then(Value::as_str)
                            == Some(expected_public_key.key.as_str())
                        && status
                            .authorized_public_key_digest
                            .as_ref()
                            .map(|x| x.as_str())
                            == Some(
                                arkret_canonical::canonical::sha256_digest(
                                    runtime_key.verifying_key().as_bytes()
                                )
                                .as_str()
                            ),
                    "activated Agent signer differs from the original frozen key"
                );
                break evidence.authority_commit_id.clone();
            }
            ensure!(
                std::time::Instant::now() < deadline,
                "accepted runtime key activation did not complete"
            );
            tokio::time::sleep(Duration::from_millis(250)).await;
        };
        let committed = controller
            .committed_event_get(&authorization)
            .await
            .context("pairing/read-accepted-key")?;
        ensure!(
            committed.commit().event_ref == authorization
                && committed.commit().commit_id == signer_commit
                && committed.reducer_input() == Some(&original_authorization),
            "PCR authorization read-back changed Event"
        );
        let holder = random_key()?;
        ensure!(
            holder.verifying_key() != runtime_key.verifying_key(),
            "DPoP session key must differ from Agent runtime key"
        );
        let holder = Arc::new(holder);
        let grant_url =
            url::Url::parse(coauth_base)?.join("/_arkret/gate/account/session-grants")?;
        let binding = arkret::dpop::build_dpop_proof(
            &arkret_http_client::DpopProofRequest::new("POST", grant_url.as_str()),
            &holder,
        )?;
        let kickoff = sdk_with_retry(
            http.clone(),
            coauth_base,
            Some(Auth::Dpop(DpopAuth::proof_only({
                let key = holder.clone();
                move |request| {
                    garth::session::dpop::build_http_dpop_proof(request, &key).map_err(|_| {
                        arkret_http_client::Error::Protocol(
                            "Agent session DPoP signing failed".into(),
                        )
                    })
                }
            }))),
            arkret_http_client::RetryConfig::standard(5),
        )?;
        // The immutable provision selection controls mandatory runtime floors.
        // A lower layer cannot suppress selected capabilities. Retain its exact
        // actions; Realm content authority is still independently evaluated.
        let scopes = state.requested_scope.actions.clone();
        ensure!(
            scopes.iter().any(|x| x == "ak.message.create")
                && scopes
                    .iter()
                    .any(|x| x == ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1)
                && scopes
                    .iter()
                    .any(|x| x == ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1),
            "accepted provision did not select the tested runtime operations"
        );
        ensure!(
            arkret_schema::agent_runtime_scope::assess_agent_runtime_scopes(
                &state.requested_scope.actions,
                &state.requested_scope.actions,
                &scopes
            )?
            .is_none(),
            "accepted runtime scope is incomplete"
        );
        let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let request = UnsignedAgentSessionGrantRequest::new(
            agent_id,
            scopes.clone(),
            authorization.clone(),
            SessionGrantAgentScopeRequest {
                realm_ids: vec![],
                strand_ids: vec![],
                track_names: vec![],
            },
            None,
            SessionGrantDpopBindingProof {
                proof_jwt: binding.header_value,
            },
            UnsignedAgentSessionGrantProof {
                challenge: arkret_canonical::base64url_encode(random_key()?.to_bytes()),
                audience_id: controller_account.station_id.clone(),
                issued_at: now,
                expires_at: now + chrono::Duration::minutes(5),
                verification_method: identity.verification_method.clone(),
            },
        )?;
        let transcript = AgentSessionGrantProof {
            proof_kind: AgentSessionGrantProofKind::AgentKeyProof,
            challenge: request.proof.challenge.clone(),
            request_canonical_digest: request.canonical_request_digest()?,
            audience_id: request.proof.audience_id.clone(),
            issued_at: now,
            expires_at: request.proof.expires_at,
            verification_method: identity.verification_method.clone(),
            signature: String::new(),
        };
        let signature = NonEmptyString::new(arkret_canonical::base64url_encode(
            runtime_key
                .sign(&transcript.canonical_signing_bytes()?)
                .to_bytes(),
        ))
        .map_err(anyhow::Error::msg)?;
        let session = SessionEngine::new(kickoff);
        // Initial pairing requests no content resources. A later explicit
        // confirmation uses a fresh challenge and signed issue intent.
        let mut session_request = request.clone();
        // One exact Strand is the complete content resource. Its accepted
        // current determines the governing Realm; a second Realm selector
        // would request an unrepresentable resource union in the flat carrier.
        session_request.agent_scope_request = SessionGrantAgentScopeRequest {
            realm_ids: vec![],
            strand_ids: vec![strand],
            track_names: vec![NonEmptyString::new("discussion").map_err(anyhow::Error::msg)?],
        };
        session
            .login_request(request.attach_signature(signature)?, SystemClock)
            .await
            .context("pairing/issue-session")?;
        let grant = session
            .current_state()
            .context("real Coauth did not issue Agent SessionGrant")?;
        let observation = grant
            .agent_participation_observation(chrono::Utc::now())
            .context("pairing/observe-session")?;
        ensure!(
            grant.account_id == account
                && grant.device_id.is_none()
                && grant.audience_id == controller_account.station_id
                && grant.dpop_jkt.as_deref() == Some(binding.jkt.as_str())
                && observation.agent_key_authorization_ref == authorization
                && observation.verification_method == identity.verification_method
                && grant
                    .granted_scope
                    .iter()
                    .all(|scope| scopes.contains(scope))
                && arkret_schema::agent_runtime_scope::assess_agent_runtime_scopes(
                    &state.requested_scope.actions,
                    &state.requested_scope.actions,
                    &grant.granted_scope,
                )?
                .is_none(),
            "issued session changed the runtime holder or requested scope"
        );
        ensure!(
            grant.granted_scope.iter().all(|token| {
                ServiceOperationId::from_wire(token).is_some()
                    || arkret_schema::capability_action(token)
                        .is_some_and(|descriptor| descriptor.category == "service")
            }),
            "initial pairing session unexpectedly contains content authority"
        );
        let transport = sdk(
            http.clone(),
            station_base,
            Some(Auth::Dpop(DpopAuth::with_dpop_token(
                grant.grant_jwt.clone(),
                {
                    let holder = holder.clone();
                    move |request| {
                        garth::session::dpop::build_http_dpop_proof(request, &holder).map_err(
                            |_| {
                                arkret_http_client::Error::Protocol(
                                    "Agent HTTP DPoP signing failed".into(),
                                )
                            },
                        )
                    }
                },
            ))),
        )?;
        std::fs::create_dir_all(store_root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(store_root, std::fs::Permissions::from_mode(0o700))?;
        }
        let store = FileStore::open(store_root.join("agent.json")).map_err(anyhow::Error::msg)?;
        Ok(Self {
            runtime: ArkretClient::new(transport, store.clone()),
            outbound: OutboundEngine::new(store, SystemClock),
            signer: Ed25519DetachedJwsSigner::new(
                runtime_key.clone(),
                identity.verification_method.as_str(),
            ),
            account,
            controller: controller.clone(),
            authorization,
            issuer: session,
            session_request,
            holder,
            runtime_key,
            http,
            station_base: station_base.to_owned(),
            grant_url: grant_url.to_string(),
        })
    }

    /// A new signed issue intent follows explicit content authorization; refresh
    /// never expands the predecessor service session's immutable ceiling.
    pub async fn issue_current_content_session(&mut self) -> Result<()> {
        let old = self
            .issuer
            .current_state()
            .context("runtime session missing")?;
        let mut request = self.session_request.clone();
        let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        request.proof.challenge = arkret_canonical::base64url_encode(random_key()?.to_bytes());
        request.proof.issued_at = now;
        request.proof.expires_at = now + chrono::Duration::minutes(5);
        let binding = arkret::dpop::build_dpop_proof(
            &arkret_http_client::DpopProofRequest::new("POST", &self.grant_url),
            &self.holder,
        )?;
        request.dpop_binding_proof = SessionGrantDpopBindingProof {
            proof_jwt: binding.header_value,
        };
        let transcript = AgentSessionGrantProof {
            proof_kind: AgentSessionGrantProofKind::AgentKeyProof,
            challenge: request.proof.challenge.clone(),
            request_canonical_digest: request.canonical_request_digest()?,
            audience_id: request.proof.audience_id.clone(),
            issued_at: request.proof.issued_at,
            expires_at: request.proof.expires_at,
            verification_method: request.proof.verification_method.clone(),
            signature: String::new(),
        };
        let signature = NonEmptyString::new(arkret_canonical::base64url_encode(
            self.runtime_key
                .sign(&transcript.canonical_signing_bytes()?)
                .to_bytes(),
        ))
        .map_err(anyhow::Error::msg)?;
        self.issuer
            .login_request(request.attach_signature(signature)?, SystemClock)
            .await?;
        let grant = self
            .issuer
            .current_state()
            .context("content session missing")?;
        ensure!(
            grant.grant_id != old.grant_id
                && grant
                    .granted_scope
                    .iter()
                    .any(|scope| scope == "ak.message.create")
                && grant
                    .granted_scope
                    .iter()
                    .all(|scope| self.session_request.requested_scope.contains(scope)),
            "fresh content issue must remain within the accepted request and provide its write action"
        );
        let holder = self.holder.clone();
        let transport = sdk(
            self.http.clone(),
            &self.station_base,
            Some(Auth::Dpop(DpopAuth::with_dpop_token(
                grant.grant_jwt.clone(),
                move |request| {
                    garth::session::dpop::build_http_dpop_proof(request, &holder).map_err(|_| {
                        arkret_http_client::Error::Protocol("Agent HTTP DPoP signing failed".into())
                    })
                },
            ))),
        )?;
        self.runtime = ArkretClient::new(transport, self.runtime.store().clone());
        Ok(())
    }

    /// Queue and submit an original Agent-signed SDK Message, then compare the
    /// exact committed read-back. A refusal stays a refusal with public codes only.
    pub async fn prepare_message(
        &self,
        realm: RealmId,
        strand: StrandId,
        body: &str,
    ) -> Result<EventId> {
        let payload = serde_json::from_value::<
            <arkret_wire::event_spec::MessageCreate as arkret_event_draft::EventSpec>::Payload,
        >(
            json!({"strand_id":strand,"track_name":"discussion","content":{"kind":"ak.content.text","body":body}}),
        )?;
        let authored =
            arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::MessageCreate>::new(
                ScopeRef::Realm { realm_id: realm },
                ActorId::account(self.account.clone()),
                payload,
            )?
            .author_with_digest_suite(chrono::Utc::now(), arkret_canonical::DigestSuite::Sha256)?;
        let frozen = garth::MessageAuthoringSession::from_authored_event(authored)?
            .sign(&self.signer, SignEventOptions::default())?;
        let submission = frozen.into_queued_submission();
        let expected = submission.event_id.clone();
        self.outbound.enqueue(submission).await?;
        Ok(expected)
    }

    pub async fn submit_message(&self, expected: EventId) -> Result<Value> {
        let snapshot = self.outbound.snapshot().await?;
        let retained = snapshot
            .items
            .iter()
            .find(|x| x.event_id() == &expected)
            .context("original queued Agent Message is unavailable")?;
        let original = retained.submission.primary_event().clone();
        ensure!(
            original.event_id == expected
                && original.actor_id.as_account_id() == Some(&self.account),
            "queued Agent intent does not match the original runtime"
        );
        match self
            .outbound
            .submit_next(
                self.runtime.authority(),
                &Default::default(),
                |request| async move {
                    let context = arkret_identity::ProducerVerificationContext {
                        actor: ActorId::account(self.account.clone()),
                        verification_method: DidUrl::new(
                            arkret_signatures::EventSigner::verification_method(&self.signer)
                                .to_owned(),
                        )
                        .map_err(str::to_owned)?,
                        public_key: arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                            bytes: self.signer.verifying_key().as_bytes().to_vec(),
                        },
                        digest_suite: arkret_canonical::DigestSuite::Sha256,
                    };
                    arkret_identity::VerifiedSubmission::verify(request, |_| Ok(context.clone()))
                        .map_err(|error| error.to_string())
                },
            )
            .await?
        {
            OutboundEngineOutcome::Committed { item, .. } if item.event_id() == &expected => {
                // This narrow grant delegates writing only. The original
                // authenticated controller reads the accepted Agent bytes;
                // runtime submission still uses the real Agent session/key.
                let view = self.controller.committed_event_get(&expected).await?;
                ensure!(
                    view.commit() == item.commit().context("queue lost accepted Commit")?,
                    "Agent read-back changed accepted Commit"
                );
                ensure!(
                    view.reducer_input() == Some(&original),
                    "Agent read-back changed signed Event"
                );
                Ok(json!({"event_id":expected,"commit_id":view.commit().commit_id,"accepted":true}))
            }
            OutboundEngineOutcome::Rejected { reason_code, .. } => {
                let code = arkret_wire::ErrorCode::from_wire(&reason_code)
                    .map(|c| c.as_str())
                    .unwrap_or("unregistered_refusal");
                Ok(json!({"event_id":expected,"accepted":false,"registered_code":code}))
            }
            OutboundEngineOutcome::Failed { problem, .. } => {
                let code = problem
                    .as_ref()
                    .and_then(|p| p.error_code())
                    .map(|c| c.as_str())
                    .unwrap_or("local_or_unregistered_failure");
                Ok(
                    json!({"event_id":expected,"accepted":false,"registered_code":code,"http_status":problem.map(|p|p.status)}),
                )
            }
            _ => anyhow::bail!("Agent runtime did not reach a definitive requested Event outcome"),
        }
    }
}
