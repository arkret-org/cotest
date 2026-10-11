//! A live Agent from provision to runtime session on one Station
//! (`key-management.md` sections 3.6.1 and 3.6.3).
//!
//! The controller publishes the Agent's PCR-independent `did:webvh`
//! inception, prepares the provision, freezes the Agent PCR genesis locally,
//! commits the controller-signed `ak.agent.provision` (the Station writes the
//! four provision typed results), submits the genesis separately (admitted by
//! reverse lookup of the forward declaration), publishes the continuous DID
//! binding update and completes the provision with a pairing handle. The
//! runtime submits its key candidate with proof of possession, the controller
//! approves it with the exact `ak.agent.key.authorize` and a requested-scope
//! disclosure, and the Station activates the runtime once that Event's Agent
//! PCR Commit is accepted. The Account Authority then binds an Agent runtime
//! SessionGrant to the accepted key authorization, and the runtime reads its
//! recipient queue with it.
//!
//! [`AgentRuntimeSession::establish`] is the reusable fixture: every later
//! Agent scenario starts from the session it returns.

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use arkret::{ArkretMlsIdentity, ArkretMlsSigner};
use arkret_models_collaboration::agent_operations::{
    AgentKeyPairOutcome, AgentPairingBootstrap, AgentProvisionCommitPhase,
    AgentProvisionCommitRequestBody, AgentProvisionOutcome, AgentProvisionPreparePhase,
    AgentProvisionPrepareRequestBody, AgentProvisionRequestBody, AgentRuntimeApprovalOutcome,
    AgentRuntimeApprovalStatusOutcome, AgentRuntimeApprovalStatusRequestBody,
    agent_key_pairing_request_binding_digest,
};
use arkret_models_collaboration::agent_scope::AgentRequestedScopeDisclosure;
use arkret_models_collaboration::events_payloads::agent::{
    AgentKeyApprovalEvidence, AgentKeyApprovalEvidenceKind, AgentKeyAuthorizePayload, AgentKeyScope,
};
use arkret_models_collaboration::governance::agent_membership_cascade::AgentControllerMembershipBinding;
use arkret_models_collaboration::governance::membership_invite::MembershipPayload;
use arkret_models_crypto::{
    KeyPackagesClaimRequestBody, KeyPackagesUploadOutcome, MlsEndpointIdentity,
};
use arkret_wire::{
    AccountId, ActorId, AuthorityCommitStatus, AuthoritySubmitOutcome, Did, DidCoreId, DidUrl,
    Event, EventId, IdempotencyKey, NonEmptyString, OpaqueLocalId, ProtocolOperationId, RealmId,
    RequestId, SchemaId, ScopeRef, ServiceOperationId,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use ed25519_dalek::{Signer as _, SigningKey};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ArkretServer, TestActorClient, TestServerGroup, expect_json};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::human_device_producer_live::{database, standard_client, station_env};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;

const GROUP: &str = "agent-runtime-session";
const CONTROLLER_LABEL: &str = "agent-controller";
const CONTROLLER_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002301";
const RUNTIME_FRAGMENT: &str = "agent-runtime-1";

/// The service operations the fixture Agent may ever use: its recipient
/// queue, its sender queue and the actor-private Events it authors for its
/// controller. No
/// interactive or E2EE capability is selected, so no floor applies.
fn runtime_operations() -> [&'static str; 4] {
    [
        ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1,
        ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_ACK_V1,
        ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_SEND_V1,
        ServiceOperationId::SELF_ACTOR_PRIVATE_EVENTS_COMMAND_SUBMIT_V1,
    ]
}

fn requested_scope(operations: &[&str]) -> Result<AgentKeyScope> {
    Ok(serde_json::from_value(json!({
        "actions": operations,
        "resources": operations
            .iter()
            .map(|operation| json!({"kind": "operation", "operation": operation}))
            .collect::<Vec<_>>()
    }))?)
}

/// A fresh UUIDv7-shaped token for identifiers the fixture mints.
fn unique_uuid7() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let millis = u64::try_from(Utc::now().timestamp_millis()).unwrap_or_default();
    let tail = NEXT.fetch_add(1, Ordering::Relaxed) ^ u64::from(std::process::id());
    format!(
        "{:08x}-{:04x}-7{:03x}-8{:03x}-{:012x}",
        millis >> 16,
        millis & 0xffff,
        (tail >> 48) & 0xfff,
        (tail >> 36) & 0xfff,
        tail & 0xffff_ffff_ffff
    )
}

/// Sign an authored Event with an Ed25519 key under `method`.
fn sign(authored: arkret_wire::AuthoredEvent, method: &DidUrl, seed: [u8; 32]) -> Result<Event> {
    let (controller, _) = method
        .as_str()
        .split_once('#')
        .context("a verification method is a DID URL")?;
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        seed,
        Did::new(controller.to_owned())?,
        method.clone(),
    );
    let mut authored = authored;
    let created_at = authored.created_at;
    arkret::signatures::sign_event(
        &mut authored,
        &signer,
        arkret::signatures::SignEventOptions::new().with_created_at(created_at),
    )?;
    Ok(authored.into_event())
}

/// Submit one DID log operation to the Station that hosts the DID.
async fn submit_did_operation(
    server: &ArkretServer,
    body: &arkret_models_identity::identity::DidOperationSubmitRequestBody,
) -> Result<()> {
    let accepted = expect_json(
        server
            .http()
            .post(server.url("/_arkret/root/identity/submit-did-operation"))
            .json(body),
        StatusCode::OK,
    )
    .await?;
    ensure!(
        matches!(accepted["status"].as_str(), Some("accepted" | "duplicate")),
        "the Agent DID operation was not accepted: {accepted}"
    );
    Ok(())
}

async fn provision(
    controller: &TestActorClient,
    body: &AgentProvisionRequestBody,
    status: StatusCode,
) -> Result<AgentProvisionOutcome> {
    Ok(serde_json::from_value(
        expect_json(controller.post("/_arkret/self/agents").json(body), status).await?,
    )?)
}

/// One provisioned, founded and paired Agent whose runtime holds an Agent
/// SessionGrant bound to its accepted key authorization.
pub struct AgentRuntimeSession {
    pub controller_account: AccountId,
    pub agent_did: Did,
    pub agent_account: AccountId,
    pub agent_pcr: RealmId,
    pub delegation: DidUrl,
    pub runtime_key: SigningKey,
    pub verification_method: DidUrl,
    pub key_authorization: EventId,
    /// The runtime's authenticated client.
    pub runtime: TestActorClient,
}

impl AgentRuntimeSession {
    /// Provision an Agent of `controller` on `server`, found its PCR, pair a
    /// runtime key and open its session through `coauth`.
    pub async fn establish(
        server: &ArkretServer,
        coauth: &MockCoauthIntrospectionServer,
        controller: &TestActorClient,
        controller_account: &AccountId,
        label: &str,
    ) -> Result<Self> {
        Self::establish_with_operations(
            server,
            coauth,
            controller,
            controller_account,
            label,
            &runtime_operations(),
        )
        .await
    }

    pub async fn establish_with_operations(
        server: &ArkretServer,
        coauth: &MockCoauthIntrospectionServer,
        controller: &TestActorClient,
        controller_account: &AccountId,
        label: &str,
        operations: &[&str],
    ) -> Result<Self> {
        let principal = controller
            .principal
            .as_ref()
            .context("the controller carries its provisioned principal")?;
        let station = server.service_id().clone();
        let device_method = DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
            .map_err(anyhow::Error::msg)?;
        let device_seed = principal.device_signing_key.to_bytes();

        // The controller's recovery policy is a provisioning prerequisite.
        publish_recovery_policy(
            controller,
            controller_account,
            principal,
            &device_method,
            server.trust_domain(),
        )
        .await?;

        // 1. The PCR-independent inception, controller-signed.
        let local_id = format!("{label}-{}", unique_uuid7());
        let root_seed: [u8; 32] = arkret_canonical::sha256_bytes(local_id.as_bytes());
        let binding_seed: [u8; 32] =
            arkret_canonical::sha256_bytes(format!("{local_id}:binding").as_bytes());
        let successor_seed: [u8; 32] =
            arkret_canonical::sha256_bytes(format!("{local_id}:successor").as_bytes());
        let endpoint = url::Url::parse(&server.url("/"))?;
        let inception = arkret_signatures::webvh::prepare_agent_inception(
            &arkret_signatures::webvh::AgentInceptionInput {
                principal_endpoint: &endpoint,
                local_id: &local_id,
                controller_principal_id: &controller_account.principal_id,
                // WebVH entries carry second-granularity versionTime and each
                // entry must be strictly later than its predecessor.
                version_time: Utc::now() - chrono::Duration::seconds(5),
                root_seed: &root_seed,
                next_root_public_key_multibase:
                    &arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                        SigningKey::from_bytes(&binding_seed)
                            .verifying_key()
                            .as_bytes(),
                    ),
            },
        )?;
        submit_did_operation(server, &inception.submit_body).await?;
        let agent_did = Did::new(inception.did.clone())?;

        // 2. Prepare pins the accepted inception.
        let scope = requested_scope(operations)?;
        let operation_id = ProtocolOperationId::new(format!("ak:operation:{}", unique_uuid7()))
            .map_err(anyhow::Error::msg)?;
        let idempotency_key = IdempotencyKey::new(unique_uuid7()).map_err(anyhow::Error::msg)?;
        let slug = label.to_owned();
        let prepared = provision(
            controller,
            &AgentProvisionRequestBody::Prepare(AgentProvisionPrepareRequestBody {
                phase: AgentProvisionPreparePhase::Prepare,
                operation_id: operation_id.clone(),
                idempotency_key: idempotency_key.clone(),
                did: agent_did.clone(),
                slug: slug.clone(),
                requested_scope: scope.clone(),
                pairing_ttl_ms: None,
                controller_station_id: station.clone(),
            }),
            StatusCode::OK,
        )
        .await?;
        let AgentProvisionOutcome::AwaitingControllerEvent(prepared) = prepared else {
            bail!("prepare must await the controller-authored provision");
        };
        ensure!(
            prepared.initial_resolution.did == agent_did
                && prepared.initial_resolution.version_id == inception.version_id,
            "prepare did not pin the submitted inception"
        );
        let agent_id = prepared.agent_id.clone();
        let agent_account = AccountId::new(agent_id.clone(), station.clone());
        let delegation = prepared.controller_authorization_ref.clone();
        let requested_scope_digest = arkret_signatures::agent::agent_requested_scope_digest(
            &agent_id,
            &controller_account.principal_id,
            &scope,
        )?;

        // 3. The controller freezes the Agent PCR genesis locally.
        let genesis = sign(
            arkret_bootstrap::build_agent_pcr_create(arkret_bootstrap::AgentPcrCreateEventInput {
                payload: arkret_bootstrap::AgentPcrCreatePayloadInput {
                    agent_id: agent_id.clone(),
                    governance_station_id: station.clone(),
                    initial_resolution: prepared.initial_resolution.clone(),
                    genesis_salt: arkret_wire::GenesisSalt::generate()?,
                    trust_domain: server.trust_domain().clone(),
                    initial_join_rule: arkret_wire::JoinRule::Closed,
                    initial_history_access: arkret_wire::HistoryAccess::SinceJoin,
                    initial_discoverability: arkret_wire::Discoverability::Secret,
                },
                executed_by: ActorId::account(controller_account.clone()),
                authorization_ref: arkret_wire::AuthorizationRef::new(delegation.as_str())
                    .map_err(anyhow::Error::msg)?,
                created_at: arkret::canonical::normalize_timestamp_canonical(Utc::now()),
            })?,
            &device_method,
            device_seed,
        )?;
        let agent_pcr = genesis.realm_id.clone();

        // 4. The provision forward-declares that genesis and commits alone.
        let provision_event = sign(
            arkret_bootstrap::build_agent_provision_intent(
                &controller_account.principal_id,
                &prepared.controller_realm_id,
                &agent_id,
                &agent_pcr,
                &delegation,
                &slug,
                &requested_scope_digest,
                arkret_models_identity::handle::HandleVisibility::Private,
                None,
                arkret_bootstrap::AgentProvisionIntentOptions {
                    controller_station_id: station.clone(),
                    created_at: Utc::now(),
                },
            )?,
            &device_method,
            device_seed,
        )?;
        let commit_body = AgentProvisionRequestBody::Commit(AgentProvisionCommitRequestBody {
            phase: AgentProvisionCommitPhase::Commit,
            operation_id,
            idempotency_key,
            agent_id: agent_id.clone(),
            did: agent_did.clone(),
            principal_control_realm_id: agent_pcr.clone(),
            slug,
            requested_scope: scope.clone(),
            allocation_handle: prepared.allocation_handle.clone(),
            provision_event: arkret_wire::EventAdmissionSubmission::new(provision_event),
            pairing_ttl_ms: None,
        });
        let awaiting = provision(controller, &commit_body, StatusCode::OK).await?;
        ensure!(
            matches!(awaiting, AgentProvisionOutcome::AwaitingPcrGenesis(_)),
            "an accepted provision awaits its PCR genesis: {awaiting:?}"
        );

        // 5. The genesis is its own submission; the Station finds the declaration by
        //    retype(event_id).
        let founded: AuthoritySubmitOutcome = serde_json::from_value(
            expect_json(
                controller
                    .post("/_arkret/self/events")
                    .json(&arkret_wire::EventAdmissionSubmission::new(genesis.clone())),
                StatusCode::OK,
            )
            .await?,
        )?;
        let AuthoritySubmitOutcome::Accepted { status, commit } = founded else {
            bail!("the Agent PCR genesis was not accepted: {founded:?}");
        };
        ensure!(
            status == AuthorityCommitStatus::Committed
                && commit.realm_id == agent_pcr
                && commit.stream_position == 0,
            "the Agent PCR genesis is not position zero of its own stream"
        );
        let awaiting = provision(controller, &commit_body, StatusCode::OK).await?;
        ensure!(
            matches!(awaiting, AgentProvisionOutcome::AwaitingDidBinding(_)),
            "an accepted genesis awaits the DID binding update: {awaiting:?}"
        );

        // 6. The continuous DID update binds the create-locked tuple.
        let update = arkret_signatures::webvh::prepare_agent_binding_update(
            &arkret_signatures::webvh::AgentBindingUpdateInput {
                did: agent_did.as_str(),
                local_id: &local_id,
                previous_entries: std::slice::from_ref(&inception.log_entry),
                version_time: Utc::now(),
                current_root_seed: &binding_seed,
                next_root_public_key_multibase:
                    &arkret_canonical::ed25519_pubkey_to_did_key_multibase(
                        SigningKey::from_bytes(&successor_seed)
                            .verifying_key()
                            .as_bytes(),
                    ),
                controller_principal_id: &controller_account.principal_id,
                principal_control_realm_id: &agent_pcr,
                requested_scope_digest: &requested_scope_digest,
            },
        )?;
        submit_did_operation(server, &update.submit_body).await?;
        let complete = provision(controller, &commit_body, StatusCode::CREATED).await?;
        let AgentProvisionOutcome::Complete(complete) = complete else {
            bail!("the bound Agent completes provisioning: {complete:?}");
        };
        let pairing_code = complete
            .pairing_code
            .clone()
            .context("the complete outcome carries the pairing code")?;
        ensure!(
            pairing_code.len() == 8 && pairing_code.bytes().all(|byte| byte.is_ascii_digit()),
            "the live Station must mint an eight-digit decimal Agent pairing code"
        );

        // 7. The runtime resolves its pairing handle and submits its key.
        let pairing_token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({
            "r": complete.pairing_request_id,
            "c": pairing_code,
        }))?);
        let bootstrap: AgentPairingBootstrap = serde_json::from_value(
            expect_json(
                server
                    .http()
                    .post(server.url("/_arkret/open/agent-pairing/resolve"))
                    .json(
                        &arkret_models_collaboration::agent_operations::AgentPairingResolveRequestBody {
                            pairing_token,
                        },
                    ),
                StatusCode::OK,
            )
            .await?,
        )?;
        let runtime_identity = bootstrap
            .validated_runtime_identity()
            .map_err(anyhow::Error::msg)?
            .clone();
        ensure!(
            runtime_identity.controller_account_id == *controller_account,
            "the pairing runtime identity names another controller"
        );
        let verification_method = runtime_identity.verification_method.clone();
        let runtime_seed: [u8; 32] =
            arkret_canonical::sha256_bytes(format!("{local_id}:{RUNTIME_FRAGMENT}").as_bytes());
        let runtime_key = SigningKey::from_bytes(&runtime_seed);
        let builder =
            arkret_signatures::agent::RuntimeKeyRequestBuilder::new_with_verification_method(
                &runtime_key,
                bootstrap.clone(),
                &verification_method,
            );
        let approval_request = builder.build_approval_request()?;
        let approval: AgentRuntimeApprovalOutcome = serde_json::from_value(
            expect_json(
                server
                    .http()
                    .post(server.url("/_arkret/open/agent-pairing/runtime-key-requests"))
                    .json(&approval_request.body),
                StatusCode::OK,
            )
            .await?,
        )?;

        // 8. The controller approves the exact candidate.
        let runtime_key_binding_digest =
            arkret_models_collaboration::agent_scope::agent_runtime_key_binding_digest(
                &agent_id,
                &bootstrap.pairing_request_id,
                &verification_method,
                &approval_request.body.public_key,
                None,
            )?;
        let request_digest = agent_key_pairing_request_binding_digest(
            ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1,
            &controller_account.principal_id,
            &agent_id,
            &bootstrap.pairing_request_id,
            &approval.approval_request_id,
            complete.expires_at,
            &station,
            &runtime_key_binding_digest,
        )?;
        let key_id =
            NonEmptyString::new(verification_method.as_str()).map_err(anyhow::Error::msg)?;
        let authorization = AgentKeyAuthorizePayload {
            agent_id: agent_id.clone(),
            key_id,
            verification_method: verification_method.clone(),
            public_key: approval_request.body.public_key.clone(),
            accountable_principal_id: controller_account.principal_id.clone(),
            agent_key_scope: scope.clone(),
            audience: vec![station.to_string()],
            issued_at: arkret::canonical::normalize_timestamp_canonical(Utc::now()),
            expires_at: None,
            approval_evidence: AgentKeyApprovalEvidence {
                kind: AgentKeyApprovalEvidenceKind::PairingRequest,
                evidence_ref: None,
                request_canonical_digest: Some(request_digest),
                pairing_request_id: Some(bootstrap.pairing_request_id.clone()),
                approved_by: Some(controller_account.principal_id.clone()),
            },
            supersedes: Vec::new(),
            revocation_check_ref: None,
            runtime_attestation: None,
        };
        let authorize = sign(
            arkret_event_draft::build_agent_key_authorize_intent(
                &authorization,
                ScopeRef::Realm {
                    realm_id: agent_pcr.clone(),
                },
                ActorId::account(agent_account.clone()),
                ActorId::account(controller_account.clone()),
                delegation.clone(),
                Utc::now(),
            )?
            .author_with_digest_suite(arkret::canonical::DigestSuite::Sha256)?,
            &device_method,
            device_seed,
        )?;
        let disclosure = requested_scope_disclosure(
            controller_account,
            (device_method.clone(), device_seed),
            &agent_id,
            &station,
            &bootstrap.pairing_request_id,
            &scope,
        )?;
        let pair_request = builder.build_key_pair_request(
            approval.approval_request_id.clone(),
            disclosure,
            authorize.clone(),
        )?;
        let paired: AgentKeyPairOutcome = serde_json::from_value(
            expect_json(
                controller
                    .post("/_arkret/gate/account/agent-key-pair")
                    .header("idempotency-key", authorize.event_id.as_str())
                    .json(&pair_request.body),
                StatusCode::OK,
            )
            .await?,
        )?;
        ensure!(
            paired.authorize_event_ref == authorize.event_id,
            "the pairing outcome names another authorization"
        );

        // 9. Activation follows the accepted Commit.
        wait_for_activation(
            server,
            &bootstrap,
            &pairing_code,
            &agent_id,
            &authorize.event_id,
        )
        .await?;

        let committed: arkret_wire::CommittedEventView = serde_json::from_value(
            expect_json(
                controller.get(&format!(
                    "/_arkret/self/committed-events/{}",
                    authorize.event_id
                )),
                StatusCode::OK,
            )
            .await?,
        )?;
        committed.validate_shape()?;
        ensure!(
            committed.commit().event_ref == authorize.event_id
                && committed.reducer_input() == Some(&authorize),
            "the controller must resolve the exact committed Agent authorization"
        );

        // 10. The Account Authority binds the runtime's SessionGrant.
        let grant = crate::scenarios::bridge_contracts::session_grant::mock_session_grant_jwt(
            agent_id.as_str(),
            verification_method.as_str(),
            station.as_str(),
        );
        coauth.bind_agent_runtime_grant(
            &grant,
            agent_id.as_str(),
            authorize.event_id.as_str(),
            verification_method.as_str(),
            &runtime_key.verifying_key(),
            operations,
        )?;
        let runtime = server.client_with_agent_runtime_grant(
            agent_did.as_str(),
            RUNTIME_FRAGMENT,
            grant,
            runtime_key.clone(),
        )?;
        Ok(Self {
            controller_account: controller_account.clone(),
            agent_did,
            agent_account,
            agent_pcr,
            delegation,
            runtime_key,
            verification_method,
            key_authorization: authorize.event_id,
            runtime,
        })
    }
}

/// Publish a one-device recovery policy for the controller.
async fn publish_recovery_policy(
    controller: &TestActorClient,
    controller_account: &AccountId,
    principal: &crate::harness::ProvisionedTestPrincipal,
    device_method: &DidUrl,
    trust_domain: &arkret_wire::TrustDomainId,
) -> Result<()> {
    use ed25519_dalek::Signer as _;

    let policy_id = format!("ak:policy:{}", unique_uuid7());
    let mut policy: arkret_models_crypto::RecoveryPolicy = serde_json::from_value(json!({
        "schema": "ak.schema.recovery_policy.v1",
        "policy_id": policy_id,
        "account_id": controller_account,
        "version": 1,
        "supersedes_id": null,
        "trust_domain": trust_domain,
        "issued_at": arkret_canonical::format_timestamp_canonical(
            arkret::canonical::normalize_timestamp_canonical(Utc::now())
        ),
        "auth_data": {
            "verification_method": device_method,
            "signature_algorithm": "Ed25519",
            "signature": "AA"
        },
        "methods": [{"kind": "did_root"}]
    }))?;
    let transcript = arkret_models_crypto::recovery_policy_signature_transcript_bytes(&policy)?;
    policy.auth_data.signature =
        arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            principal.device_signing_key.sign(&transcript).to_bytes(),
        ))
        .map_err(anyhow::Error::msg)?;
    let event = sign(
        arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            arkret_wire::test_support::raw_event_for_actor_at(
                arkret_wire::EventKind::PolicySet.as_str(),
                ScopeRef::Realm {
                    realm_id: principal.pcr_realm_id.clone(),
                },
                ActorId::account(controller_account.clone()),
                json!({"policy_id": policy_id, "value": policy}),
                arkret::canonical::normalize_timestamp_canonical(Utc::now()),
            )?,
            arkret::canonical::DigestSuite::Sha256,
        )?,
        device_method,
        principal.device_signing_key.to_bytes(),
    )?;
    let response = controller
        .post("/_arkret/root/identity/recovery-policy")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &arkret_wire::EventAdmissionSubmission::new(event),
        )?)
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::OK,
        "the controller recovery policy was not accepted: {} {}",
        response.status(),
        response.text().await.unwrap_or_default()
    );
    Ok(())
}

/// The controller's authenticated private disclosure of the Agent's
/// requested scope to this Station's pairing operation, signed by the
/// controller's active device.
fn requested_scope_disclosure(
    controller_account: &AccountId,
    (signing_method, signing_seed): (DidUrl, [u8; 32]),
    agent_id: &DidCoreId,
    station: &DidCoreId,
    pairing_request_id: &OpaqueLocalId,
    scope: &AgentKeyScope,
) -> Result<AgentRequestedScopeDisclosure> {
    let issued_at = arkret::canonical::normalize_timestamp_canonical(Utc::now());
    let uuid = pairing_request_id
        .as_str()
        .strip_prefix("agent_pairing_request:")
        .context("pairing request id carries its uuid")?;
    let mut disclosure = AgentRequestedScopeDisclosure {
        schema: SchemaId::AgentRequestedScopeDisclosureV1,
        request_id: RequestId::new(format!("ak:request:{uuid}"))?,
        agent_id: agent_id.clone(),
        controller_principal_id: controller_account.principal_id.clone(),
        requested_scope: scope.clone(),
        verifier_id: station.clone(),
        audience: NonEmptyString::new(ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY_V1)
            .map_err(anyhow::Error::msg)?,
        challenge: NonEmptyString::new(pairing_request_id.as_str()).map_err(anyhow::Error::msg)?,
        issued_at,
        expires_at: issued_at + chrono::Duration::seconds(240),
        proofs: Vec::new(),
    };
    let mut proof = arkret_wire::PayloadProof {
        kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
        verification_method: signing_method,
        payload_digest: disclosure.payload_digest()?,
        created_at: issued_at,
        domain: None,
        audience: None,
        proof_purpose: None,
        jws: String::new(),
    };
    proof.jws = arkret_signatures::sign_ed25519_detached_jws(
        &SigningKey::from_bytes(&signing_seed),
        &disclosure.canonical_proof_binding_bytes(&proof)?,
    )?;
    disclosure.proofs.push(proof);
    disclosure.validate()?;
    Ok(disclosure)
}

/// Poll the runtime's open status until the pairing reports the exact
/// authorization active.
async fn wait_for_activation(
    server: &ArkretServer,
    bootstrap: &AgentPairingBootstrap,
    pairing_code: &str,
    agent_id: &DidCoreId,
    authorization: &EventId,
) -> Result<()> {
    let request = AgentRuntimeApprovalStatusRequestBody {
        pairing_request_id: bootstrap.pairing_request_id.clone(),
        pairing_code: NonEmptyString::new(pairing_code).map_err(anyhow::Error::msg)?,
        agent_id: agent_id.clone(),
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status: AgentRuntimeApprovalStatusOutcome = serde_json::from_value(
            expect_json(
                server
                    .http()
                    .post(server.url("/_arkret/open/agent-pairing/runtime-key-requests/status"))
                    .json(&request),
                StatusCode::OK,
            )
            .await?,
        )?;
        if status.authorized_event_ref.as_ref() == Some(authorization) {
            ensure!(
                status.current_signer_evidence.is_some(),
                "an active pairing delivers its current signer evidence"
            );
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "the accepted key authorization never activated the runtime: {status:?}"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// An Agent is provisioned, founded, paired and reads its recipient queue
/// with its runtime SessionGrant; the controller's own queue read stays a
/// human-device read.
/// The live admission half of `ak.vector.agent.longevity_no_expiry.v1`.
/// A provisioned Agent and a Service receive the same indefinite grants at
/// every risk tier, without fetching either subject's display profile.
pub async fn run_agent_capability_longevity_live() -> Result<()> {
    let scenario = "agent-capability-longevity";
    let Some(database) = database(scenario)? else {
        return Ok(());
    };
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        scenario,
        &[station_env(&database.connect_url, &coauth)],
    )
    .await?
    else {
        return skip_or_fail(scenario, "prebuilt Coland unavailable");
    };
    let station = group.server(0);
    let (controller, controller_account) =
        standard_client(station, &coauth, CONTROLLER_LABEL, CONTROLLER_DEVICE).await?;
    let mut operations = runtime_operations().to_vec();
    operations.extend(["ak.event.read", "ak.message.create", "ak.realm.admin"]);
    let agent = AgentRuntimeSession::establish_with_operations(
        station,
        &coauth,
        &controller,
        &controller_account,
        "longevity-agent",
        &operations,
    )
    .await?;
    let created = controller.create_realm_with(json!({
        "title": "Grant Longevity Realm", "summary": "Indefinite grants at every risk tier",
        "public": false, "join_rule": "public", "plaintext_visible_services": [station.service_id()]
    })).await?;
    let realm = RealmId::new(
        created["realm_id"]
            .as_str()
            .context("longevity Realm id")?
            .to_owned(),
    )?;
    let controller_generation = EventId::new(
        created["event_response"]["commits"]
            .as_array()
            .and_then(|commits| commits.last())
            .and_then(|commit| commit["event_ref"].as_str())
            .context("longevity creator membership generation")?
            .to_owned(),
    )?;
    let mut joined = MembershipPayload::join(
        realm.clone(),
        ActorId::account(agent.agent_account.clone()),
        "controller joins its Agent for grant admission",
    );
    joined.agent_controller_binding = Some(AgentControllerMembershipBinding {
        controller_account_id: controller_account.clone(),
        controller_membership_generation_ref: controller_generation,
        controller_terminal_event_ref: None,
    });
    controller
        .submit_event(realm.as_str(), "ak.member.state", joined.to_value()?)
        .await?;
    let subjects = [
        ("Agent", ActorId::account(agent.agent_account)),
        ("Service", ActorId::service(station.service_id().clone())),
    ];
    for (label, subject) in subjects {
        for action in ["ak.event.read", "ak.message.create", "ak.realm.admin"] {
            let grant = arkret_models_collaboration::events_payloads::CapabilityGrantCreateBody {
                schema: SchemaId::CAPABILITY_V1.to_owned(),
                realm_id: Some(realm.clone()),
                issuer_id: ActorId::account(controller_account.clone()),
                subject: arkret_models_collaboration::governance::grant_constraint::CapabilitySubject::Actor(subject.clone()),
                actions: vec![action.to_owned()],
                resources: vec![serde_json::from_value(json!({
                    "kind": "realm", "realm_id": realm, "match_scope": "realm_wide"
                }))?],
                constraints: Vec::new(),
                issuer_authority_refs: vec![arkret::IssuerAuthorityRef::RealmRoot {
                    realm_id: realm.clone(),
                    authority_event_ref: realm.event_id(),
                    authority_generation: 0,
                }],
                issued_at: Utc::now(),
            };
            let payload =
                arkret_models_collaboration::events_payloads::CapabilityGrantPayload { grant };
            let outcome: AuthoritySubmitOutcome = serde_json::from_value(
                controller
                    .submit_event(
                        realm.as_str(),
                        arkret_wire::EventKind::CapabilityGrant.as_str(),
                        serde_json::to_value(payload)?,
                    )
                    .await?,
            )?;
            ensure!(
                matches!(
                    outcome,
                    AuthoritySubmitOutcome::Accepted {
                        status: AuthorityCommitStatus::Committed,
                        ..
                    }
                ),
                "indefinite Realm-wide {action} grant to {label} was not committed: {outcome:?}"
            );
            eprintln!("agent longevity: indefinite Realm-wide {action} grant to {label} committed");
        }
    }
    Ok(())
}

pub async fn run_agent_runtime_session_live() -> Result<()> {
    let Some(database) = database(GROUP)? else {
        return Ok(());
    };
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[station_env(&database.connect_url, &coauth)],
    )
    .await?
    else {
        return skip_or_fail(GROUP, "prebuilt Coland unavailable");
    };
    let station = group.server(0);
    let (controller, controller_account) =
        standard_client(station, &coauth, CONTROLLER_LABEL, CONTROLLER_DEVICE).await?;
    let agent = AgentRuntimeSession::establish(
        station,
        &coauth,
        &controller,
        &controller_account,
        "runtime-agent",
    )
    .await?;
    ensure!(
        agent.agent_account.station_id == controller_account.station_id,
        "the Agent account lives on its controller's Station"
    );
    let queue = expect_json(
        agent.runtime.get("/_arkret/self/device_messages"),
        StatusCode::OK,
    )
    .await?;
    ensure!(
        queue
            .get("deliveries")
            .is_some_and(serde_json::Value::is_array),
        "the Agent runtime reads its recipient queue: {queue}"
    );

    // The controller pauses the Agent through the lifecycle unit; the paused
    // runtime's session no longer authenticates until it is resumed.
    let paused = agent
        .transition(&controller, &controller_account, AgentTransition::Pause)
        .await?;
    ensure!(
        paused == arkret_models_collaboration::agent_operations::AgentLifecycleState::Paused,
        "pause did not commit the paused status"
    );
    let refused = agent
        .runtime
        .get("/_arkret/self/device_messages")
        .send()
        .await?;
    ensure!(
        refused.status() == StatusCode::UNAUTHORIZED,
        "a paused Agent's session still reads its queue: {}",
        refused.status()
    );
    let resumed = agent
        .transition(&controller, &controller_account, AgentTransition::Resume)
        .await?;
    ensure!(
        resumed == arkret_models_collaboration::agent_operations::AgentLifecycleState::Active,
        "resume did not commit the active status"
    );
    expect_json(
        agent.runtime.get("/_arkret/self/device_messages"),
        StatusCode::OK,
    )
    .await?;

    // The Agent sends to its controller's device as an Agent endpoint.
    let principal = controller
        .principal
        .as_ref()
        .context("the controller carries its provisioned principal")?;
    let device_message_id = format!("ak:device_message:{}", unique_uuid7());
    let send = crate::harness::device_message_send_request(
        principal.did.as_str(),
        principal.device_id.as_str(),
        &device_message_id,
        "ak.mls.application",
        crate::harness::encrypted_envelope("ak.mls.application", "YWdlbnQtdG8tY29udHJvbGxlcg"),
        Utc::now() + chrono::Duration::hours(1),
    )?;
    let sent = expect_json(
        agent
            .runtime
            .post("/_arkret/self/device_messages")
            .header("Idempotency-Key", unique_uuid7())
            .json(&send),
        StatusCode::OK,
    )
    .await?;
    ensure!(
        sent["delivered"][controller_account.principal_id.as_str()][principal.device_id.as_str()]["status"]
            == "delivered",
        "the Agent's device message was not delivered: {sent}"
    );
    let inbox = expect_json(
        controller.get("/_arkret/self/device_messages"),
        StatusCode::OK,
    )
    .await?;
    ensure!(
        inbox["deliveries"].as_array().is_some_and(|deliveries| {
            deliveries.iter().any(|delivery| {
                delivery.to_string().contains(device_message_id.as_str())
                    && delivery
                        .to_string()
                        .contains(agent.key_authorization.as_str())
            })
        }),
        "the controller's queue lacks the Agent-sent message with its key authorization: {inbox}"
    );

    // The controller revokes the runtime key; the session ends with it.
    let revoke = sign(
        arkret_event_draft::build_agent_key_revoke_intent(
            &arkret_models_collaboration::events_payloads::agent::AgentKeyRevokePayload {
                agent_id: agent.agent_account.principal_id.clone(),
                key_id: NonEmptyString::new(agent.verification_method.as_str())
                    .map_err(anyhow::Error::msg)?,
                revoked_by: controller_account.principal_id.clone(),
                revoked_at: arkret::canonical::normalize_timestamp_canonical(Utc::now()),
                reason: None,
            },
            ScopeRef::Realm {
                realm_id: agent.agent_pcr.clone(),
            },
            ActorId::account(agent.agent_account.clone()),
            ActorId::account(controller_account.clone()),
            agent.delegation.clone(),
            Utc::now(),
        )?
        .author_with_digest_suite(arkret::canonical::DigestSuite::Sha256)?,
        &DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
            .map_err(anyhow::Error::msg)?,
        principal.device_signing_key.to_bytes(),
    )?;
    let revoked: AuthoritySubmitOutcome = serde_json::from_value(
        expect_json(
            controller
                .post("/_arkret/self/events")
                .json(&arkret_wire::EventAdmissionSubmission::new(revoke)),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(
            revoked,
            AuthoritySubmitOutcome::Accepted {
                status: AuthorityCommitStatus::Committed,
                ..
            }
        ),
        "the key revocation was not committed: {revoked:?}"
    );
    let ended = agent
        .runtime
        .get("/_arkret/self/device_messages")
        .send()
        .await?;
    ensure!(
        ended.status() == StatusCode::UNAUTHORIZED,
        "a revoked key's session still reads its queue: {}",
        ended.status()
    );
    Ok(())
}

/// An Agent publishes with its own current key after restoring persisted MLS
/// identity state; a Device branch cannot be smuggled through that session.
pub async fn run_agent_keypackage_upload_live() -> Result<()> {
    let group_name = "agent-keypackage-upload";
    let Some(database) = database(group_name)? else {
        return Ok(());
    };
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        group_name,
        &[station_env(&database.connect_url, &coauth)],
    )
    .await?
    else {
        return skip_or_fail(group_name, "prebuilt Coland unavailable");
    };
    let station = group.server(0);
    let (controller, controller_account) =
        standard_client(station, &coauth, "mls-agent-controller", CONTROLLER_DEVICE).await?;
    let operations = [
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE_V1,
        ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
        ServiceOperationId::SELF_REALM_STATE_SNAPSHOT_READ_MANIFEST_HEAD_V1,
        ServiceOperationId::SELF_MLS_READ_ROSTER_AUTHORITY_V1,
        ServiceOperationId::SELF_MLS_READ_GROUP_STATE_MATERIAL_V1,
        ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT_V1,
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM_V1,
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_READ_CLAIM_V1,
        ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME_V1,
        ServiceOperationId::SELF_DEVICE_MESSAGES_READ_LIST_V1,
        ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_ACK_V1,
        "ak.message.create",
    ];
    let completed_operations =
        arkret_schema::agent_runtime_scope::complete_agent_runtime_scope(operations)?;
    let operations = completed_operations
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let agent = AgentRuntimeSession::establish_with_operations(
        station,
        &coauth,
        &controller,
        &controller_account,
        "mls-agent",
        &operations,
    )
    .await?;
    let actor = ActorId::account(agent.agent_account.clone());
    let identity = ArkretMlsIdentity::new_agent(
        actor.clone(),
        agent.verification_method.clone(),
        agent.key_authorization.clone(),
        ArkretMlsSigner::from_ed25519_signing_key(agent.runtime_key.clone()),
    )?;
    let keypackage = identity.key_package_record()?;
    let add_keypackage = identity.key_package_record()?;
    let snapshot_file = tempfile::NamedTempFile::new()?;
    std::fs::write(snapshot_file.path(), identity.export_private_state()?)?;
    let restored = ArkretMlsIdentity::restore_from_private_state(
        actor,
        MlsEndpointIdentity::agent_runtime(
            agent.agent_account.principal_id.clone(),
            agent.verification_method.clone(),
            agent.key_authorization.clone(),
        )?,
        &std::fs::read(snapshot_file.path())?,
    )?;
    let upload = restored.signed_key_packages_upload_request(
        &[keypackage.clone(), add_keypackage.clone()],
        agent.verification_method.as_str(),
        None,
    )?;
    let outcome: KeyPackagesUploadOutcome = serde_json::from_value(
        expect_json(
            agent
                .runtime
                .post("/_arkret/self/keys/keypackages/upload")
                .json(&upload),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        outcome.accepted == 2
            && outcome
                .key_package_refs
                .contains(&keypackage.keypackage_ref.to_string())
            && outcome
                .key_package_refs
                .contains(&add_keypackage.keypackage_ref.to_string()),
        "Agent KeyPackage was not published: {outcome:?}"
    );
    let mut wrong_branch = serde_json::to_value(&upload)?;
    let object = wrong_branch
        .as_object_mut()
        .context("typed upload is an object")?;
    object.remove("agent_verification_method");
    object.remove("agent_key_authorize_event_id");
    object.insert("device_id".to_owned(), json!(CONTROLLER_DEVICE));
    let rejected = agent
        .runtime
        .post("/_arkret/self/keys/keypackages/upload")
        .json(&wrong_branch)
        .send()
        .await?;
    ensure!(
        matches!(
            rejected.status(),
            StatusCode::FORBIDDEN | StatusCode::UNPROCESSABLE_ENTITY
        ),
        "Agent session accepted a Device KeyPackage branch: {}",
        rejected.status()
    );
    let mut wrong_method = serde_json::to_value(&upload)?;
    wrong_method["agent_verification_method"] =
        json!(format!("{}#another-runtime-key", agent.agent_did));
    let rejected = agent
        .runtime
        .post("/_arkret/self/keys/keypackages/upload")
        .json(&wrong_method)
        .send()
        .await?;
    ensure!(
        matches!(
            rejected.status(),
            StatusCode::FORBIDDEN | StatusCode::UNPROCESSABLE_ENTITY
        ),
        "Agent KeyPackage upload accepted another runtime method: {}",
        rejected.status()
    );
    let realm_id = agent.agent_pcr.clone();
    let mls_group_id = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    }
    .canonical_mls_group_id()?;
    let signed_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let claim_id = arkret_canonical::sha256_bytes(unique_uuid7().as_bytes());
    let mut claim: KeyPackagesClaimRequestBody = serde_json::from_value(json!({
        "claim_request_id": URL_SAFE_NO_PAD.encode(&claim_id[..16]),
        "target_agent_id": agent.agent_account.principal_id,
        "target_agent_verification_method": agent.verification_method,
        "target_agent_key_authorize_event_id": agent.key_authorization,
        "intended_realm_id": realm_id,
        "mls_group_id": mls_group_id,
        "claim_purpose": "realm_membership",
        "required_capabilities": ["ak.content.v1"],
        "expires_at": arkret_canonical::format_timestamp_canonical(signed_at + chrono::Duration::minutes(4)),
        "target_keypackage_ref": keypackage.keypackage_ref,
        "service_binding": {
            "source_id": station.service_id(),
            "destination_id": station.service_id(),
        },
        "requester_authorization": {
            "kind": "agent",
            "verification_method": agent.verification_method,
            "requester_agent_id": agent.agent_account.principal_id,
            "agent_key_authorize_event_id": agent.key_authorization,
            "signed_at": arkret_canonical::format_timestamp_canonical(signed_at),
            "signature": {
                "kid": agent.verification_method,
                "signature_algorithm": "Ed25519",
                "sig": "AA"
            }
        }
    }))?;
    let signing_input = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &claim.unsigned_request(),
        &claim.service_binding,
        &claim.requester_authorization,
    )?;
    let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Agent { signature, .. } =
        &mut claim.requester_authorization
    else {
        unreachable!("the fixture builds an Agent claim")
    };
    signature.sig = arkret_wire::Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(agent.runtime_key.sign(&signing_input).to_bytes()),
    )
    .map_err(anyhow::Error::msg)?;
    let rejected = agent
        .runtime
        .post("/_arkret/self/keys/keypackages/claim")
        .header("content-type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(&claim)?)
        .send()
        .await?;
    let rejected_status = rejected.status();
    let rejected_body = rejected.text().await?;
    ensure!(
        rejected_status == StatusCode::FORBIDDEN,
        "Agent claimed into an unjoined Realm: {rejected_status} {rejected_body}",
    );

    // A controller already joined to an ordinary Realm can author the
    // Agent's explicit membership Event with the exact controller generation.
    let created = controller
        .create_realm_with(json!({
            "title": "Agent membership admission",
            "summary": "Agent membership admission",
            "public": false,
            "join_rule": "public",
            "plaintext_visible_services": [station.service_id()]
        }))
        .await?;
    let joined_realm = RealmId::new(
        created["realm_id"]
            .as_str()
            .context("created Realm id")?
            .to_owned(),
    )?;
    let controller_generation = EventId::new(
        created["event_response"]["commits"]
            .as_array()
            .and_then(|commits| commits.last())
            .and_then(|commit| commit["event_ref"].as_str())
            .context("creator join Commit event ref")?
            .to_owned(),
    )?;
    let strand_id = controller.default_strand_id(joined_realm.as_str())?;
    let mut agent_join = MembershipPayload::join(
        joined_realm.clone(),
        ActorId::account(agent.agent_account.clone()),
        "controller joins its active Agent",
    );
    agent_join.agent_controller_binding = Some(AgentControllerMembershipBinding {
        controller_account_id: controller_account.clone(),
        controller_membership_generation_ref: controller_generation,
        controller_terminal_event_ref: None,
    });
    let mut wrong_controller = agent_join.clone();
    wrong_controller
        .agent_controller_binding
        .as_mut()
        .context("Agent join binding")?
        .controller_account_id = agent.agent_account.clone();
    let forged = controller
        .author_event(
            joined_realm.as_str(),
            "ak.member.state",
            wrong_controller.to_value()?,
        )
        .await?;
    let refused = controller
        .post("/_arkret/self/events")
        .header("content-type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &crate::publication::initial_submission(forged, "")?,
        )?)
        .send()
        .await?;
    let status = refused.status();
    let body = refused.text().await?;
    ensure!(
        matches!(status, StatusCode::FORBIDDEN | StatusCode::CONFLICT)
            && (body.contains("agent_controller_binding_invalid") || body.contains("controller")),
        "wrong controller admitted an Agent join: {status} {body}"
    );
    let mut wrong_generation = agent_join.clone();
    wrong_generation
        .agent_controller_binding
        .as_mut()
        .context("Agent join binding")?
        .controller_membership_generation_ref = EventId::new(
        created["event_response"]["commits"][0]["event_ref"]
            .as_str()
            .context("Realm create Event ref")?
            .to_owned(),
    )?;
    let forged = controller
        .author_event(
            joined_realm.as_str(),
            "ak.member.state",
            wrong_generation.to_value()?,
        )
        .await?;
    let refused = controller
        .post("/_arkret/self/events")
        .header("content-type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &crate::publication::initial_submission(forged, "")?,
        )?)
        .send()
        .await?;
    let status = refused.status();
    let body = refused.text().await?;
    ensure!(
        matches!(status, StatusCode::FORBIDDEN | StatusCode::CONFLICT)
            && (body.contains("agent_controller_binding_invalid")
                || body.contains("bound joined generation")),
        "wrong controller generation admitted an Agent join: {status} {body}"
    );
    let join_event = controller
        .author_event(
            joined_realm.as_str(),
            "ak.member.state",
            agent_join.to_value()?,
        )
        .await?;
    let joined: AuthoritySubmitOutcome = serde_json::from_value(
        expect_json(
            controller
                .post("/_arkret/self/events")
                .header("content-type", "application/json")
                .body(arkret_canonical::canonical_json_bytes(
                    &crate::publication::initial_submission(join_event.clone(), "")?,
                )?),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(joined, AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Committed,
            commit,
        } if commit.event_ref == join_event.event_id),
        "controller's Agent join was not committed"
    );
    claim.claim_request_id = arkret_wire::Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(&arkret_canonical::sha256_bytes(unique_uuid7().as_bytes())[..16]),
    )
    .map_err(anyhow::Error::msg)?;
    claim.intended_realm_id = joined_realm.clone();
    claim.mls_group_id = ScopeRef::Realm {
        realm_id: joined_realm.clone(),
    }
    .canonical_mls_group_id()?;
    let signing_input = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &claim.unsigned_request(),
        &claim.service_binding,
        &claim.requester_authorization,
    )?;
    let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Agent { signature, .. } =
        &mut claim.requester_authorization
    else {
        unreachable!("the fixture builds an Agent claim")
    };
    signature.sig = arkret_wire::Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(agent.runtime_key.sign(&signing_input).to_bytes()),
    )
    .map_err(anyhow::Error::msg)?;
    let claimed = agent
        .runtime
        .post("/_arkret/self/keys/keypackages/claim")
        .header("content-type", "application/json")
        .body(arkret_canonical::canonical_json_bytes(&claim)?)
        .send()
        .await?;
    let claim_status = claimed.status();
    let claim_body = claimed.text().await?;
    ensure!(
        claim_status == StatusCode::OK,
        "joined Agent self-claim was refused: {claim_status} {claim_body}"
    );

    // The joined controller claims another Agent KeyPackage for an MLS Add.
    // Its signed authorization and target are distinct from the Agent's
    // earlier self claim, while both point at the same accepted binding.
    let controller_principal = controller
        .principal
        .as_ref()
        .context("controller carries its provisioned principal")?;
    let controller_method = DidUrl::new(format!(
        "{}#{}",
        controller_principal.did, controller_principal.device_id
    ))
    .map_err(anyhow::Error::msg)?;
    let mut controller_claim = claim.clone();
    controller_claim.claim_request_id = arkret_wire::Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(&arkret_canonical::sha256_bytes(unique_uuid7().as_bytes())[..16]),
    )
    .map_err(anyhow::Error::msg)?;
    controller_claim.target_keypackage_ref = Some(serde_json::from_value(json!(
        add_keypackage.keypackage_ref
    ))?);
    controller_claim.requester_account_id = Some(controller_account.clone());
    controller_claim.requester_authorization = serde_json::from_value(json!({
        "kind": "device",
        "verification_method": controller_method,
        "requester_device_id": controller_principal.device_id,
        "device_authorize_event_id": controller_principal.founding_authorize_event_id,
        "signed_at": arkret_canonical::format_timestamp_canonical(Utc::now()),
        "signature": {
            "kid": controller_method,
            "signature_algorithm": "Ed25519",
            "sig": "AA"
        }
    }))?;
    let signing_input = arkret_models_crypto::keypackage_claim_authorization_signing_bytes(
        &controller_claim.unsigned_request(),
        &controller_claim.service_binding,
        &controller_claim.requester_authorization,
    )?;
    let arkret_models_crypto::PeerKeyPackageRequesterAuthorization::Device { signature, .. } =
        &mut controller_claim.requester_authorization
    else {
        unreachable!("the fixture builds a Device claim")
    };
    signature.sig = arkret_wire::Base64UrlString::new(
        URL_SAFE_NO_PAD.encode(
            controller_principal
                .device_signing_key
                .sign(&signing_input)
                .to_bytes(),
        ),
    )
    .map_err(anyhow::Error::msg)?;
    let (status, response) =
        crate::scenarios::mls_lifecycle_live::post_claim(&controller, &controller_claim).await?;
    ensure!(
        status == StatusCode::OK,
        "joined controller could not claim Agent KeyPackage: {status} {}",
        String::from_utf8_lossy(&response)
    );
    let outcome: arkret_models_crypto::KeyPackagesClaimOutcome = serde_json::from_slice(&response)?;
    ensure!(
        outcome.claims.len() == 1,
        "controller claim selected an unexpected set: {outcome:?}"
    );
    let add_claim = outcome.claims[0].clone();
    ensure!(
        add_claim.agent_id.as_ref() == Some(&agent.agent_account.principal_id)
            && add_claim.agent_verification_method.as_ref() == Some(&agent.verification_method)
            && add_claim.agent_key_authorize_event_id.as_ref() == Some(&agent.key_authorization)
            && add_claim.keypackage_ref == add_keypackage.keypackage_ref.to_string(),
        "controller claim did not select the Agent's exact accepted key binding: {add_claim:?}"
    );

    let scope = ScopeRef::Realm {
        realm_id: joined_realm.clone(),
    };
    let controller_identity = ArkretMlsIdentity::new_human_device(
        ActorId::account(controller_account.clone()),
        controller_principal.device_id.clone(),
        ArkretMlsSigner::from_ed25519_signing_key(controller_principal.device_signing_key.clone()),
    )?;
    let genesis_binding = arkret::MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mut controller_group =
        controller_identity.create_group_with_governance_binding(&scope, &genesis_binding)?;
    controller_group.install_local_creator_binding(
        ActorId::account(controller_account.clone()),
        Some(controller_principal.founding_authorize_event_id.clone()),
    )?;
    let leaves = controller_group.verified_leaf_bindings()?;
    let [creator] = leaves.as_slice() else {
        bail!("Genesis requires exactly one verified controller leaf");
    };
    ensure!(
        creator.leaf_index == 0 && creator.actor_id == ActorId::account(controller_account.clone())
    );
    let creator_leaf_authority =
        arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority {
            leaf_signature_key_b64u: creator.signature_key.clone(),
            endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
                device_id: controller_principal.device_id.clone(),
            },
            authorization_event_ref: creator
                .device_authorize_event_id
                .clone()
                .context("Genesis controller leaf lacks accepted device authorization")?,
        };
    creator_leaf_authority.validate()?;
    let (group_info, tree) = controller_group.public_group_state_bytes()?;
    let group_info_ref = crate::scenarios::mls_lifecycle_live::upload_public_blob(
        &controller,
        &joined_realm,
        &group_info,
    )
    .await?;
    let tree_ref =
        crate::scenarios::mls_lifecycle_live::upload_public_blob(&controller, &joined_realm, &tree)
            .await?;
    let genesis = controller
        .author_event(
            joined_realm.as_str(),
            "ak.mls.genesis",
            crate::scenarios::mls_lifecycle_live::canonical(json!({
                "cipher_suite": crate::scenarios::mls_lifecycle_live::ACTIVE_SUITE,
                "group_info_ref": group_info_ref,
                "ratchet_tree_ref": tree_ref,
                "governance_binding": genesis_binding,
                "creator_leaf_authority": creator_leaf_authority,
                "created_at": arkret_canonical::format_timestamp_canonical(Utc::now()),
            }))?,
        )
        .await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &controller,
        &controller_account,
        CONTROLLER_DEVICE,
        &genesis,
    )
    .await?;

    let add_binding = arkret::MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(genesis.event_id.clone()),
        0,
        1,
        0,
    )?;
    let mut add_record = add_keypackage.clone();
    add_record.keypackage = add_claim.keypackage.clone();
    add_record.keypackage_ref = arkret_wire::Hash::new(add_claim.keypackage_ref.clone())?;
    add_record.capabilities = add_claim.capabilities.clone();
    add_record.state = arkret_models_crypto::MlsKeyPackageState::Claimed;
    add_record.claim_id = Some(add_claim.claim_id.clone());
    add_record.expires_at = Some(add_claim.expires_at);
    let add = controller_group.add_member_with_governance_binding(&add_record, &add_binding)?;
    let commit_payload =
        arkret::MlsCommitPayload::new(genesis.event_id.clone(), 0, &add.commit, add_binding)?;
    let commit_event = controller
        .author_event(
            joined_realm.as_str(),
            "ak.mls.commit",
            crate::scenarios::mls_lifecycle_live::canonical(serde_json::to_value(
                &commit_payload,
            )?)?,
        )
        .await?;
    let mut welcome = arkret_wire::MlsWelcomeDelivery {
        welcome_id: arkret_wire::MlsWelcomeDeliveryId::new_v7_at(
            u64::try_from(Utc::now().timestamp_millis()).unwrap_or_default(),
        ),
        realm_id: joined_realm.clone(),
        effective_scope: scope.clone(),
        commit_event_ref: commit_event.event_id.clone(),
        recipient_actor_id: ActorId::account(agent.agent_account.clone()),
        recipient_endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::AgentRuntime {
            verification_method: agent.verification_method.clone(),
        },
        keypackage_claim_ref: add.welcome.keypackage_claim_ref.clone(),
        ciphertext_b64: add.welcome.ciphertext_b64.clone(),
        producer_proof: arkret_wire::DetachedObjectSignature {
            context: arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
            signature_algorithm: arkret_wire::DetachedSignatureAlgorithm::Ed25519,
            verification_method: controller_method.clone(),
            signed_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            created_at: Utc::now(),
            sig: arkret_wire::Base64UrlString::new("AA".to_owned()).map_err(anyhow::Error::msg)?,
        },
    };
    let mut unsigned = serde_json::to_value(&welcome)?;
    unsigned
        .as_object_mut()
        .context("Welcome is an object")?
        .remove("producer_proof");
    welcome.producer_proof = arkret_signatures::detached_object::sign_detached_object(
        &unsigned,
        arkret_wire::DetachedSignatureContext::MlsWelcomeDelivery,
        controller_method,
        arkret_canonical::normalize_timestamp_canonical(Utc::now()),
        &controller_principal.device_signing_key,
    )?;
    welcome.validate_shape()?;
    let submission =
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::MlsCommit(
            arkret_wire::MlsCommitSubmission {
                commit_event: commit_event.clone(),
                welcomes: vec![welcome.clone()],
                idempotency_key: arkret_wire::UuidV7::new(unique_uuid7().parse()?)?,
            },
        );
    submission.validate()?;
    let (status, result) =
        crate::scenarios::mls_lifecycle_live::post_json(&controller, &submission).await?;
    ensure!(
        status == StatusCode::OK,
        "Agent Add Commit refused: {status} {result}"
    );
    let result: AuthoritySubmitOutcome = serde_json::from_value(result)?;
    ensure!(
        matches!(result, AuthoritySubmitOutcome::Accepted { status: AuthorityCommitStatus::Committed, commit } if commit.event_ref == commit_event.event_id),
        "Agent Add Commit was not committed"
    );
    let accepted = crate::scenarios::mls_lifecycle_live::accepted_full_view(
        &controller,
        &commit_event.event_id,
    )
    .await?;
    let base = arkret_wire::MlsGroupCurrent {
        effective_scope: scope,
        genesis_event_ref: genesis.event_id.clone(),
        cipher_suite: arkret_wire::NonEmptyString::new(
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        )
        .unwrap(),
        current_mls_commit_event_ref: genesis.event_id.clone(),
        epoch: 0,
        current_key_access_revision: 0,
        covered_key_access_revision: 0,
        public_tree_ref: arkret_wire::BlobRef::new(tree_ref)?,
    };
    ensure!(
        controller_group.install_accepted_commit(&accepted, &base)? == 1,
        "controller Add Commit not installed"
    );
    let (queued, ack_token) =
        crate::scenarios::mls_lifecycle_live::recipient_welcomes(&agent.runtime).await?;
    ensure!(
        queued == vec![welcome.clone()],
        "Agent queue did not receive exact Welcome: {queued:?}"
    );
    let mut agent_group =
        arkret::ArkretMlsGroup::join_from_verified_welcome_delivery(restored, &welcome, &accepted)?;
    ensure!(agent_group.epoch() == 1, "Agent did not install epoch 1");
    // Exercise the same independently verified complete roster used by native
    // runtimes. Joining OpenMLS alone cannot authenticate the founder's leaf.
    let http = agent.runtime.sdk();
    let roster_request = arkret::MlsMemberRosterAuthorityReadRequestBody {
        realm_id: joined_realm.clone(),
        effective_scope: welcome.effective_scope.clone(),
        mls_group_id: welcome.effective_scope.canonical_mls_group_id()?,
        target_commit_event_ref: commit_event.event_id.clone(),
        target_epoch: 1,
        caller_actor_id: ActorId::account(agent.agent_account.clone()),
        cursor: None,
    };
    let page = http.self_mls_roster_authority(&roster_request).await?;
    ensure!(
        page.roster.next_cursor.is_none() && page.roster.records.len() == 2,
        "Agent must receive the complete Genesis and Add roster"
    );
    let peer = arkret::verify_mls_member_roster_authority_pages(
        std::slice::from_ref(&page),
        &roster_request,
    )?;
    let material_request =
        arkret::mls_roster_genesis_material_request(&peer, &page.roster.manifest);
    let material = http
        .self_mls_group_state_material(&material_request)
        .await?;
    arkret::install_verified_mls_self_roster_bindings(
        &mut agent_group,
        &[page],
        &roster_request,
        &material,
    )
    .map_err(anyhow::Error::msg)?;
    ensure!(
        agent_group.verified_leaf_bindings()?.len() == 2,
        "complete roster did not bind both the founder and Agent leaves"
    );
    let scan = arkret::StreamScanRequest {
        realm_id: joined_realm.clone(),
        stream_ref: arkret::CommitStreamRef::from_scope(&welcome.effective_scope, None)?,
        direction: arkret::StreamScanDirection::After(None),
        limit: 200,
    };
    let scanned = http.scan_commit_stream(&scan).await?;
    ensure!(
        scanned
            .committed_events
            .iter()
            .any(|row| row.commit().event_ref == commit_event.event_id),
        "Agent stream scan did not return its accepted Add Commit"
    );
    agent
        .runtime
        .post("/_arkret/self/device_messages/ack")
        .json(
            &arkret_models_collaboration::device_messages::DeviceMessagesAckRequestBody {
                ack_token,
            },
        )
        .send()
        .await?
        .error_for_status()?;

    let receipt = arkret_models_crypto::RecipientMlsDurableReceipt {
        domain: arkret_wire::NonEmptyString::new(
            arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1.to_owned(),
        )
        .map_err(anyhow::Error::msg)?,
        claim_request_id: controller_claim.claim_request_id.clone(),
        key_package_ref: arkret_wire::NonEmptyString::new(add_claim.keypackage_ref.clone())
            .map_err(anyhow::Error::msg)?,
        recipient: arkret_models_crypto::RecipientMlsDurableSigner::Agent {
            recipient_agent_id: agent.agent_account.principal_id.clone(),
            recipient_agent_verification_method: agent.verification_method.clone(),
            agent_key_authorize_event_id: agent.key_authorization.clone(),
        },
        recipient_id: station.service_id().clone(),
        realm_id: joined_realm.clone(),
        mls_group_id: controller_claim.mls_group_id.clone(),
        mls_epoch: 1,
        welcome_ref: welcome.welcome_id.clone(),
        welcome_digest: welcome.durable_receipt_digest()?,
        durable_at: Utc::now(),
        signature: arkret_models_crypto::KeyOperationSignature {
            kid: arkret_wire::NonEmptyString::new(agent.verification_method.to_string())
                .map_err(anyhow::Error::msg)?,
            signature_algorithm: None,
            sig: arkret_wire::Base64UrlString::new("AA".to_owned()).map_err(anyhow::Error::msg)?,
        },
    };
    let mut wrong_binding = receipt.clone();
    wrong_binding.claim_request_id = claim.claim_request_id.clone();
    let wrong_binding = identity.sign_recipient_mls_durable_receipt(wrong_binding)?;
    let wrong_consume = identity.signed_key_packages_consume_request(
        arkret_wire::KeypackageClaimId::new(add_claim.claim_id.clone())?,
        wrong_binding,
    )?;
    let (status, result) = crate::scenarios::mls_lifecycle_live::post_json_at(
        &agent.runtime,
        "/_arkret/self/keys/keypackages/consume",
        &wrong_consume,
    )
    .await?;
    ensure!(
        matches!(status, StatusCode::CONFLICT | StatusCode::FORBIDDEN),
        "Agent consume accepted another claim's receipt binding: {status} {result}"
    );

    let receipt = identity.sign_recipient_mls_durable_receipt(receipt)?;
    let consume = identity.signed_key_packages_consume_request(
        arkret_wire::KeypackageClaimId::new(add_claim.claim_id.clone())?,
        receipt,
    )?;
    let (status, result) = crate::scenarios::mls_lifecycle_live::post_json_at(
        &controller,
        "/_arkret/self/keys/keypackages/consume",
        &consume,
    )
    .await?;
    ensure!(
        matches!(status, StatusCode::FORBIDDEN | StatusCode::NOT_FOUND),
        "the controller consumed its Agent's KeyPackage claim: {status} {result}"
    );
    let (status, result) = crate::scenarios::mls_lifecycle_live::post_json_at(
        &agent.runtime,
        "/_arkret/self/keys/keypackages/consume",
        &consume,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "Agent durable consume refused: {status} {result}"
    );
    let first_consume = result;
    let (status, replay) = crate::scenarios::mls_lifecycle_live::post_json_at(
        &agent.runtime,
        "/_arkret/self/keys/keypackages/consume",
        &consume,
    )
    .await?;
    ensure!(
        status == StatusCode::OK && replay == first_consume,
        "exact Agent receipt replay must preserve the original result: {status} {replay}"
    );
    let mut changed_receipt = consume.recipient_durable_receipt.clone();
    changed_receipt.durable_at += chrono::Duration::milliseconds(1);
    let changed_receipt = identity.sign_recipient_mls_durable_receipt(changed_receipt)?;
    let changed_consume = identity.signed_key_packages_consume_request(
        arkret_wire::KeypackageClaimId::new(add_claim.claim_id.clone())?,
        changed_receipt,
    )?;
    let (status, _) = crate::scenarios::mls_lifecycle_live::post_json_at(
        &agent.runtime,
        "/_arkret/self/keys/keypackages/consume",
        &changed_consume,
    )
    .await?;
    ensure!(
        status == StatusCode::CONFLICT,
        "a regenerated Agent receipt changed the original consume: {status}"
    );

    // Ordinary encrypted replies use the runtime leaf, while historical signer
    // authorization remains in the independent Agent PCR.
    let header = arkret::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/vnd.arkret.message+json",
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        welcome.effective_scope.clone(),
        arkret_wire::EventKind::MessageCreate.as_str(),
        1,
        commit_event.event_id.clone(),
        agent_group.local_content_sender_domain()?,
        arkret::EventContentRoutingContext::None,
    )?;
    let plaintext =
        arkret::canonical::canonical_json_bytes(&arkret::ContentBlock::text("Agent reply"))?;
    let sealed =
        arkret::MessageCrypto::encrypt(&mut agent_group, "agent-reply", header, &plaintext)?;
    let reply = actor_private_event(
        arkret_wire::EventKind::MessageCreate,
        &agent.agent_account,
        &joined_realm,
        json!({"strand_id": strand_id, "track_name": "discussion", "encrypted_content": sealed.payload.to_envelope()?}),
        &agent.verification_method,
        agent.runtime_key.to_bytes(),
    )?;
    // Resolve the controller's current selection before isolating missing
    // message authority. A session overlay is not this action-time selection.
    let selection = arkret::ParticipationReplaceRequestBody {
        target_scope: arkret::ParticipationScope::Realm {
            realm_id: joined_realm.clone(),
        },
        selection: arkret::ParticipationBits {
            reply_message: true,
            ..arkret::ParticipationBits::NONE
        },
        expected_version: 0,
    };
    let selected = controller
        .sdk()
        .agent_participation_replace(agent.agent_account.principal_id.as_str(), &selection)
        .await?;
    ensure!(
        selected
            .agent_participation_entries
            .iter()
            .any(|entry| entry.scope == selection.target_scope
                && entry.selection == selection.selection
                && entry.version == 1),
        "controller current reply selection was not installed"
    );
    // Shared replies require the controller's accepted Public mode as well as
    // current participation. The initial Private mode does not grant sharing.
    let public_mode = arkret_models_collaboration::agent_interaction::AgentInteractionSetPayload {
        agent_account_id: agent.agent_account.clone(),
        controller_account_id: controller_account.clone(),
        interaction_mode:
            arkret_models_collaboration::agent_interaction::AgentInteractionMode::Public,
        expected_revision: None,
    };
    controller
        .submit_event(
            joined_realm.as_str(),
            arkret_wire::EventKind::AgentInteractionSet.as_str(),
            serde_json::to_value(public_mode)?,
        )
        .await?;
    let (status, result) = crate::scenarios::mls_lifecycle_live::post_json_at(
        &agent.runtime,
        "/_arkret/self/events",
        &crate::publication::initial_submission(reply.clone(), "")?,
    )
    .await?;
    ensure!(
        status == StatusCode::FORBIDDEN
            && result["type"] == "https://arkret.org/problems/capability_denied",
        "membership alone authorized an ordinary Agent reply: {status} {result}"
    );
    let absent = expect_json(
        controller.get(&format!(
            "/_arkret/self/committed-events/{}",
            reply.event_id
        )),
        StatusCode::NOT_FOUND,
    )
    .await?;
    ensure!(
        absent["type"] == "https://arkret.org/problems/not_found",
        "a refused Agent reply must leave no accepted Commit: {absent}"
    );
    controller
        .grant_realm_actions_to(
            joined_realm.as_str(),
            agent.agent_did.as_str(),
            &["ak.message.create"],
        )
        .await?;
    let (status, result) = crate::scenarios::mls_lifecycle_live::post_json_at(
        &agent.runtime,
        "/_arkret/self/events",
        &crate::publication::initial_submission(reply.clone(), "")?,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "ordinary Agent reply refused: {status} {result}"
    );
    let accepted =
        crate::scenarios::mls_lifecycle_live::accepted_full_view(&controller, &reply.event_id)
            .await?;
    ensure!(
        accepted.event == reply,
        "Station changed the signed Agent reply"
    );
    let target = arkret::CommittedEventRef {
        event_id: accepted.event.event_id.clone(),
        commit_id: accepted.commit.commit_id.clone(),
        stream_ref: accepted.commit.stream_ref.clone(),
        stream_position: accepted.commit.stream_position,
    };
    let query = arkret::SignerKeysQueryRequestBody {
        request_id: RequestId::new(format!("ak:request:{}", unique_uuid7()))?,
        realm_id: joined_realm.clone(),
        recipient_account_id: controller_account.clone(),
        queries: vec![arkret::SignerKeyQuerySelector::HistoricalEvent {
            sender: arkret::HistoricalSignerKeyQuerySender::Agent {
                actor: ActorId::account(agent.agent_account.clone()),
                verification_method: agent.verification_method.clone(),
                committed_event_ref: target,
            },
        }],
    };
    let evidence = controller.sdk().signer_keys_query(&query).await?;
    evidence.validate_for_request(&query)?;
    let [arkret::SignerKeyQueryOutcome::HistoricalResolved { key, .. }] =
        evidence.results.as_slice()
    else {
        bail!(
            "the accepted ordinary Agent reply lacks exact historical signer evidence: {evidence:?}"
        );
    };
    ensure!(
        key.authorization_ref.event_id == agent.key_authorization
            && key.authorization_ref.stream_ref.realm_id() == &agent.agent_pcr,
        "historical Agent evidence replaced its independent PCR authorization"
    );
    ensure!(
        arkret::base64url_decode(key.public_key_b64u.as_str().as_bytes())?
            == agent.runtime_key.verifying_key().to_bytes()
    );
    let proof = accepted
        .event
        .producer_proof
        .as_ref()
        .context("accepted reply producer proof")?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &arkret_signatures::EventProofBuilder::new().envelope_bytes(&accepted.event)?,
        &accepted.event.actor_id,
        &arkret_signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: arkret::base64url_decode(key.public_key_b64u.as_str().as_bytes())?,
        },
        arkret::canonical::DigestSuite::Sha256,
    )?;
    let received: arkret::EncryptedEnvelope = serde_json::from_value(
        accepted
            .event
            .payload
            .get("encrypted_content")
            .context("accepted reply ciphertext")?
            .clone(),
    )?;
    let sender = arkret::mls_basic_credential_identity(accepted.event.actual_signer())?;
    let header = received.reconstruct_pre_encryption_header(
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        accepted.event.scope_ref.clone(),
        accepted.event.kind.as_str(),
        std::str::from_utf8(&sender)?,
        None,
    )?;
    let received =
        arkret::mls::encrypted_envelope_to_payload_with_verified_header(&received, header)?;
    ensure!(controller_group.decrypt_payload(&received)? == plaintext);
    let frozen_key = key.clone();
    let mut wrong_query = query.clone();
    let arkret::SignerKeyQuerySelector::HistoricalEvent {
        sender:
            arkret::HistoricalSignerKeyQuerySender::Agent {
                committed_event_ref,
                ..
            },
    } = &mut wrong_query.queries[0]
    else {
        unreachable!()
    };
    committed_event_ref.stream_position += 1;
    let unavailable = controller.sdk().signer_keys_query(&wrong_query).await?;
    unavailable.validate_for_request(&wrong_query)?;
    ensure!(
        matches!(
            unavailable.results.as_slice(),
            [arkret::SignerKeyQueryOutcome::Unavailable { .. }]
        ),
        "historical Agent lookup accepted a substituted target coordinate"
    );
    agent
        .transition(&controller, &controller_account, AgentTransition::Pause)
        .await?;
    let historical = controller.sdk().signer_keys_query(&query).await?;
    historical.validate_for_request(&query)?;
    let [arkret::SignerKeyQueryOutcome::HistoricalResolved { key, .. }] =
        historical.results.as_slice()
    else {
        bail!("pausing a runtime erased its accepted historical proof");
    };
    ensure!(
        key == &frozen_key,
        "historical Agent signer query used the later PCR state"
    );
    // The receiving Station must also publish its durable franking carrier
    // using this original Agent cut, even after the runtime is paused.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let stream = controller
            .sdk()
            .scan_commit_stream_to_head(
                joined_realm.clone(),
                arkret::CommitStreamRef::Realm {
                    realm_id: joined_realm.clone(),
                },
                Some(accepted.commit.stream_position),
                100,
            )
            .await?;
        let proofs = stream
            .committed_events
            .iter()
            .filter_map(arkret::CommittedEventView::reducer_input)
            .filter(|event| {
                event.kind == arkret_wire::EventKind::ModerationFrankingProof
                    && event.payload["event_id"] == reply.event_id.as_str()
            })
            .collect::<Vec<_>>();
        if let [proof] = proofs.as_slice() {
            ensure!(proof.actor_id == ActorId::service(station.service_id().clone()));
            ensure!(proof.payload["realm_id"] == joined_realm.as_str());
            ensure!(proof.payload["received_by"] == station.service_id().as_str());
            break;
        }
        ensure!(
            proofs.is_empty(),
            "Agent receipt published duplicate franking carriers"
        );
        ensure!(
            Instant::now() < deadline,
            "accepted Agent reply has no durable franking carrier"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

/// A controller-authored Agent lifecycle transition.
#[derive(Clone, Copy)]
pub enum AgentTransition {
    Pause,
    Resume,
}

impl AgentRuntimeSession {
    /// Commit one lifecycle transition through the controller's operation and
    /// return the status its covering Commit established.
    pub async fn transition(
        &self,
        controller: &TestActorClient,
        controller_account: &AccountId,
        transition: AgentTransition,
    ) -> Result<arkret_models_collaboration::agent_operations::AgentLifecycleState> {
        let principal = controller
            .principal
            .as_ref()
            .context("the controller carries its provisioned principal")?;
        let device_method = DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
            .map_err(anyhow::Error::msg)?;
        let at = arkret::canonical::normalize_timestamp_canonical(Utc::now());
        let scope = ScopeRef::Realm {
            realm_id: self.agent_pcr.clone(),
        };
        let agent = ActorId::account(self.agent_account.clone());
        let executor = ActorId::account(controller_account.clone());
        let (intent, path) = match transition {
            AgentTransition::Pause => (
                arkret_event_draft::build_agent_pause_intent(
                    agent,
                    executor,
                    scope,
                    self.delegation.clone(),
                    None,
                    at,
                )?,
                "pause",
            ),
            AgentTransition::Resume => (
                arkret_event_draft::build_agent_resume_intent(
                    agent,
                    executor,
                    scope,
                    self.delegation.clone(),
                    at,
                )?,
                "resume",
            ),
        };
        let event = sign(
            intent.author_with_digest_suite(arkret::canonical::DigestSuite::Sha256)?,
            &device_method,
            principal.device_signing_key.to_bytes(),
        )?;
        let submission = arkret_wire::EventAdmissionSubmission::new(event.clone());
        let body = match transition {
            AgentTransition::Pause => serde_json::to_value(
                arkret_models_collaboration::agent_operations::AgentPauseRequestBody {
                    reason: None,
                    lifecycle_event: submission,
                },
            )?,
            AgentTransition::Resume => serde_json::to_value(
                arkret_models_collaboration::agent_operations::AgentResumeRequestBody {
                    lifecycle_event: submission,
                },
            )?,
        };
        let outcome: arkret_models_collaboration::agent_operations::AgentLifecycleOutcome =
            serde_json::from_value(
                expect_json(
                    controller
                        .post(&format!(
                            "/_arkret/self/agents/{}/{path}",
                            self.agent_account.principal_id
                        ))
                        .json(&body),
                    StatusCode::OK,
                )
                .await?,
            )?;
        let committed = controller
            .sdk()
            .committed_event_get(&event.event_id)
            .await?;
        committed.validate_shape()?;
        ensure!(
            committed.commit().event_ref == event.event_id
                && committed.commit().stream_ref
                    == (arkret_wire::CommitStreamRef::Realm {
                        realm_id: self.agent_pcr.clone(),
                    })
                && committed.reducer_input() == Some(&event),
            "the controller must resolve the exact lifecycle Event and its Agent PCR Commit"
        );
        Ok(outcome.status)
    }
}

const CONTROLLER_FOUNDING_HPKE_KEY: &str = "z6LSCotestFederationHpkeKey";

/// One actor-private Event of `kind` by `actor`, signed under `method`.
fn actor_private_event(
    kind: arkret_wire::EventKind,
    actor: &AccountId,
    realm_id: &RealmId,
    payload: serde_json::Value,
    method: &DidUrl,
    seed: [u8; 32],
) -> Result<Event> {
    sign(
        arkret_wire::AuthoredEvent::finalize_with_digest_suite(
            arkret_wire::test_support::raw_event_for_actor_at(
                kind.as_str(),
                ScopeRef::Realm {
                    realm_id: realm_id.clone(),
                },
                ActorId::account(actor.clone()),
                payload,
                arkret::canonical::normalize_timestamp_canonical(Utc::now()),
            )?,
            arkret::canonical::DigestSuite::Sha256,
        )?,
        method,
        seed,
    )
}

async fn submit_actor_private(
    client: &TestActorClient,
    event: &Event,
) -> Result<reqwest::Response> {
    Ok(client
        .post("/_arkret/self/actor-private-events")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(arkret_canonical::canonical_json_bytes(
            &arkret_wire::ActorPrivateEventSubmitRequestBody {
                event: event.clone(),
            },
        )?)
        .send()
        .await?)
}

async fn expect_code(response: reqwest::Response, status: StatusCode, code: &str) -> Result<()> {
    let actual = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or_default();
    let problem_type = format!("https://arkret.org/problems/{code}");
    ensure!(
        actual == status && body["type"].as_str() == Some(problem_type.as_str()),
        "expected {status} {code}, got {actual} {body}"
    );
    Ok(())
}

/// The actor-private Agent kinds from a real Agent runtime session: the
/// Agent's action request and draft proposal are admitted into its
/// controller's private store, the controller rejects the request, a draft
/// whose HPKE recipient is not bound to the controller device's current key
/// is `param_invalid`, and a request already past its expiry is
/// `failed_precondition`.
pub async fn run_agent_actor_private_events_live() -> Result<()> {
    let group_name = "agent-actor-private-events";
    let Some(database) = database(group_name)? else {
        return Ok(());
    };
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        group_name,
        &[station_env(&database.connect_url, &coauth)],
    )
    .await?
    else {
        return skip_or_fail(group_name, "prebuilt Coland unavailable");
    };
    let station = group.server(0);
    let (controller, controller_account) =
        standard_client(station, &coauth, "private-controller", CONTROLLER_DEVICE).await?;
    let agent = AgentRuntimeSession::establish(
        station,
        &coauth,
        &controller,
        &controller_account,
        "private-agent",
    )
    .await?;
    let principal = controller
        .principal
        .as_ref()
        .context("the controller carries its provisioned principal")?;
    let device_method = DidUrl::new(format!("{}#{}", principal.did, principal.device_id))
        .map_err(anyhow::Error::msg)?;
    let runtime_seed = agent.runtime_key.to_bytes();
    let now = arkret::canonical::normalize_timestamp_canonical(Utc::now());
    let stamp = |at: chrono::DateTime<Utc>| arkret_canonical::format_timestamp_canonical(at);
    let target = json!({"kind": "realm", "realm_id": agent.agent_pcr});

    // The Agent asks its controller to approve an action.
    let request = actor_private_event(
        arkret_wire::EventKind::AgentActionRequest,
        &agent.agent_account,
        &agent.agent_pcr,
        json!({
            "request_id": format!("request-{}", unique_uuid7()),
            "agent_id": agent.agent_account.principal_id,
            "controller_account_id": controller_account,
            "proposed_action": "ak.message.create",
            "target": target,
            "request_canonical_digest": format!("sha256:{}", "6".repeat(64)),
            "expires_at": stamp(now + chrono::Duration::hours(1)),
            "created_at": stamp(now)
        }),
        &agent.verification_method,
        runtime_seed,
    )?;
    let accepted = submit_actor_private(&agent.runtime, &request).await?;
    ensure!(
        accepted.status() == StatusCode::OK,
        "the Agent's action request was not admitted: {} {}",
        accepted.status(),
        accepted.text().await.unwrap_or_default()
    );
    let replay = submit_actor_private(&agent.runtime, &request).await?;
    ensure!(
        replay.status() == StatusCode::OK,
        "an exact retry of the Agent's request is not its first outcome"
    );

    // The controller rejects it from its own device.
    let request_id = request.payload["request_id"].clone();
    let reject = actor_private_event(
        arkret_wire::EventKind::AgentActionReject,
        &controller_account,
        &principal.pcr_realm_id,
        json!({
            "rejection_id": format!("rejection-{}", unique_uuid7()),
            "request_id": request_id,
            "agent_id": agent.agent_account.principal_id,
            "rejected_at": stamp(now)
        }),
        &device_method,
        principal.device_signing_key.to_bytes(),
    )?;
    let rejected = submit_actor_private(&controller, &reject).await?;
    ensure!(
        rejected.status() == StatusCode::OK,
        "the controller's rejection was not admitted: {} {}",
        rejected.status(),
        rejected.text().await.unwrap_or_default()
    );

    // The Agent proposes a draft sealed to the controller's device.
    let draft = |recipient_digest: String| {
        actor_private_event(
            arkret_wire::EventKind::AgentDraftPropose,
            &agent.agent_account,
            &agent.agent_pcr,
            json!({
                "draft_id": format!("draft-{}", unique_uuid7()),
                "agent_id": agent.agent_account.principal_id,
                "controller_account_id": controller_account,
                "proposed_action": "ak.message.create",
                "target": target,
                "content_digest": format!("sha256:{}", "1".repeat(64)),
                "content_handoff": {
                    "scheme": "ak.hpke_x25519_aead_chacha20poly1305.v1",
                    "recipients": [{
                        "recipient_device_id": principal.device_id,
                        "recipient_hpke_key_digest": recipient_digest,
                        "enc": URL_SAFE_NO_PAD.encode([7u8; 32]),
                        "ciphertext": URL_SAFE_NO_PAD.encode([9u8; 48]),
                        "ciphertext_digest": arkret_canonical::sha256_digest([9u8; 48])
                    }]
                },
                "expires_at": stamp(now + chrono::Duration::hours(1)),
                "created_at": stamp(now)
            }),
            &agent.verification_method,
            runtime_seed,
        )
    };
    let proposed = submit_actor_private(
        &agent.runtime,
        &draft(arkret_canonical::sha256_digest(
            CONTROLLER_FOUNDING_HPKE_KEY.as_bytes(),
        ))?,
    )
    .await?;
    ensure!(
        proposed.status() == StatusCode::OK,
        "the Agent's draft proposal was not admitted: {} {}",
        proposed.status(),
        proposed.text().await.unwrap_or_default()
    );

    // A recipient digest that is not the device's current HPKE key.
    expect_code(
        submit_actor_private(
            &agent.runtime,
            &draft(format!("sha256:{}", "2".repeat(64)))?,
        )
        .await?,
        StatusCode::BAD_REQUEST,
        "param_invalid",
    )
    .await?;

    // A request whose expiry has already passed.
    let expired = actor_private_event(
        arkret_wire::EventKind::AgentActionRequest,
        &agent.agent_account,
        &agent.agent_pcr,
        json!({
            "request_id": format!("request-{}", unique_uuid7()),
            "agent_id": agent.agent_account.principal_id,
            "controller_account_id": controller_account,
            "proposed_action": "ak.message.create",
            "target": target,
            "request_canonical_digest": format!("sha256:{}", "6".repeat(64)),
            "expires_at": stamp(now - chrono::Duration::minutes(1)),
            "created_at": stamp(now - chrono::Duration::minutes(2))
        }),
        &agent.verification_method,
        runtime_seed,
    )?;
    expect_code(
        submit_actor_private(&agent.runtime, &expired).await?,
        StatusCode::CONFLICT,
        "failed_precondition",
    )
    .await?;
    Ok(())
}
