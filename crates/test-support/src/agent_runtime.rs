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
    ArkretClient, FileStore, OutboundEngine, OutboundEngineOutcome, QueuedSubmission,
    SessionEngine, SystemClock,
};
use serde_json::{Value, json};

pub struct AgentRuntimeHandle {
    runtime: ArkretClient<SdkClient, FileStore>,
    outbound: OutboundEngine<FileStore, SystemClock>,
    signer: Ed25519DetachedJwsSigner,
    account: AccountId,
    controller: SdkClient,
    pub authorization: EventId,
}

fn random_key() -> Result<SigningKey> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).context("obtain runtime key OS entropy")?;
    Ok(SigningKey::from_bytes(&seed))
}

fn sdk(http: reqwest::Client, base: &str, auth: Option<Auth>) -> Result<SdkClient> {
    let endpoint = url::Url::parse(base)?;
    let mut builder = SdkClient::builder(endpoint.clone()).http_client(http);
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
    pub async fn pair(
        http: reqwest::Client,
        station_base: &str,
        coauth_base: &str,
        controller: &SdkClient,
        controller_account: &AccountId,
        controller_device_method: &DidUrl,
        controller_device_key: &SigningKey,
        agent_id: DidCoreId,
        realm: RealmId,
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
            .map_err(|_| anyhow::anyhow!("Agent controller current read failed"))?;
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
        let bootstrap: AgentPairingBootstrap = open
            .post(
                "/_arkret/open/agent-pairing/resolve",
                &AgentPairingResolveRequestBody {
                    pairing_token: arkret_canonical::base64url_encode(serde_json::to_vec(
                        &json!({"r":request_id,"c":code}),
                    )?),
                },
            )
            .await?;
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
            .post(
                "/_arkret/open/agent-pairing/runtime-key-requests",
                &approval_request.body,
            )
            .await?;
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
        let paired = controller.agent_key_pair(&pair.body).await?;
        ensure!(
            paired.authorize_event_ref == authorization,
            "pair outcome names another authorization"
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let signer_commit = loop {
            let status: AgentRuntimeApprovalStatusOutcome = open
                .post(
                    "/_arkret/open/agent-pairing/runtime-key-requests/status",
                    &AgentRuntimeApprovalStatusRequestBody {
                        pairing_request_id: request_id.clone(),
                        pairing_code: NonEmptyString::new(code).map_err(anyhow::Error::msg)?,
                        agent_id: agent_id.clone(),
                    },
                )
                .await?;
            status.validate_signer_evidence_delivery()?;
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
        let committed = controller.committed_event_get(&authorization).await?;
        ensure!(
            committed.commit().event_ref == authorization
                && committed.commit().commit_id == signer_commit
                && committed.reducer_input() == Some(&original_authorization),
            "PCR authorization read-back changed Event"
        );
        let describe = open.describe().await?;
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
        let kickoff = sdk(
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
                realm_ids: vec![realm],
                strand_ids: vec![strand],
                track_names: vec![NonEmptyString::new("discussion").map_err(anyhow::Error::msg)?],
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
        session
            .login_request(request.attach_signature(signature)?, SystemClock)
            .await?;
        let grant = session
            .current_state()
            .context("real Coauth did not issue Agent SessionGrant")?;
        let observation = grant.agent_participation_observation(chrono::Utc::now())?;
        ensure!(
            grant.account_id == account
                && grant.device_id.is_none()
                && grant.audience_id == controller_account.station_id
                && grant.dpop_jkt.as_deref() == Some(binding.jkt.as_str())
                && observation.agent_key_authorization_ref == authorization
                && observation.verification_method == identity.verification_method
                && scopes
                    .iter()
                    .all(|scope| grant.granted_scope.contains(scope))
                && grant
                    .granted_scope
                    .iter()
                    .all(|scope| scopes.contains(scope)),
            "issued session changed the runtime holder or requested scope"
        );
        let transport = sdk(
            http,
            station_base,
            Some(Auth::Dpop(DpopAuth::with_dpop_token(
                grant.grant_jwt.clone(),
                move |request| {
                    garth::session::dpop::build_http_dpop_proof(request, &holder).map_err(|_| {
                        arkret_http_client::Error::Protocol("Agent HTTP DPoP signing failed".into())
                    })
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
                runtime_key,
                identity.verification_method.as_str(),
            ),
            account,
            controller: controller.clone(),
            authorization,
        })
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
            .submit_next(self.runtime.authority(), &Default::default())
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
