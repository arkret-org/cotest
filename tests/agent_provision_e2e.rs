//! Personal AI Agent provisioning -> pairing -> lifecycle, driven live against
//! a spawned soland in development mode (AKP-0008, spec_section_11 live leg).
//!
//! Exercises controller-authored provisioning through the public agent HTTP
//! surface. The test obtains server-allocated coordinates, asks the SDK to
//! build and sign the closed Event pair, then commits that pair through the
//! ordinary admission pipeline:
//!   1. `ak.self.agent.command.provision` prepare + commit -> active lifecycle intent with a
//!      `pending_runtime_key` runtime_state + pairing (key-management.md §3.6.1).
//!   2. `ak.gate.account.command.pair_agent_key` -> durable `ak.agent.key.authorize`, status ->
//!      `active` without changing Realm grants.
//!   3. grant attach / detach -> durable `ak.capability.grant` / `ak.capability.revoke`.
//!   4. pause / resume / deactivate -> durable lifecycle events flip status.
//!
//! `ArkretServer::spawn` builds / locates the sibling `soland` binary and runs
//! it in development mode. Controller-owned Event and payload proof authoring
//! remains client-side and is provided only by the shared SDK.
//!
//! Legacy mutation endpoints that cannot carry controller-signed Events are
//! covered as fail-closed compatibility surfaces.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use arkret_canonical as canonical;
use arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase;
use arkret_crypto::DeviceTrustBinding;
use arkret_http_client::{Auth, Client as SdkClient, ClientBuilder, Error as ArkretError};
use arkret_identifiers::{BackupId, BackupSeriesId, DeviceId, Did, PolicyId, TypedTrustDomainId};
use arkret_models_collaboration::event_sync::{
    EventsFrontierAccountClientState, EventsFrontierView,
};
use arkret_models_collaboration::events_payloads::SignatureMaterial;
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizePayload, DeviceCrossSigningBinding, DeviceListUpdatePayload,
    DeviceOrPrincipalRef,
};
use arkret_models_crypto::{
    BackupKind, KeyBackup, KeyBackupAead, KeyBackupAeadName, KeyBackupAuthData,
    KeyBackupContentItem, KeyBackupDomainSeparation, KeyBackupDomainSeparationAad,
    KeyBackupEncryption, KeyBackupFrontierRef, KeyBackupRecipientMethod,
    KeyBackupSignatureAlgorithm, ManagedFrontierRef, ManagedPrincipalBinding, RecoveryHpkeSuite,
    RecoveryKeyAgreementAlgorithm, RecoveryKeyAgreementEntry, RecoveryKeyAgreementUse,
    RecoveryKeyEntry, RecoveryKeySignatureAlgorithm, RecoveryPolicy, RecoveryPolicyAuthData,
    RecoveryPolicyRef, RecoveryProofKind, RecoveryPublicationAuthorizationRule,
    RecoverySessionCreateRequestBody, RecoverySessionProofSubmitRequestBody, RecoverySessionState,
    SessionState,
};
use arkret_models_identity::artifacts_device_identity::{
    CrossSigningPublish, KeyFormat, PublishedKey, SubordinateSignedKey, SubordinateSignedKeyBinding,
};
use arkret_models_identity::did_document::principal_control_realm_id;
use arkret_wire::{
    AuthoritySetIssuer, AuthoritySetIssuerRole, Base64UrlString, DidUrl, EventKind, NonEmptyString,
    OpaqueLocalId, RECOVERY_POLICY_SIGNATURE_TYPE, SchemaId, ServiceOperationId,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeDelta, Timelike as _, Utc};
use cotest::harness::{
    ArkretServer, create_realm_with_signing_seed, dev_login, event_envelope, eventually,
    expect_api_error, expect_json, refresh_event_proof_with_signing_seed, register_account,
};
use ed25519_dalek::{Signer as _, SigningKey};
use reqwest::StatusCode;
use serde_json::{Value, json};
use serial_test::serial;

const ALICE_DID: &str =
    "did:webvh:QmPgnKLR8FfoCkXfTYK1eB5Q9rUT3Uws4b9mLKRRWwQRnr:cotest-agent.example:webvh:alice";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000a901";
const TRUST_DOMAIN: &str = "ak:trust_domain:soland.local";
const RECOVERY_POLICY_SIGNED_FIELDS: [&str; 12] = [
    "schema",
    "policy_id",
    "principal_id",
    "version",
    "trust_domain",
    "allowed_proof_kinds",
    "publication_authorization_rules",
    "recovery_keys",
    "recovery_key_agreements",
    "supersedes",
    "issued_at",
    "expires_at",
];
const TEST_DEVICE_ALGORITHMS: [&str; 2] = ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"];
const TEST_DEVICE_HPKE_KEY: &str = "z6LSCotestAgentDeviceHpkeKey";
const RECOVERY_POLICY_ID: &str = "ak:policy:019a0000-0000-7000-8000-00000000a901";
const RECOVERY_REPLACEMENT_DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000a902";
const RECOVERY_WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
static NEXT_AGENT_BACKUP: AtomicUsize = AtomicUsize::new(1);
type AgentBackupPointer = (u64, Vec<String>);

static AGENT_BACKUP_POINTERS: LazyLock<Mutex<HashMap<String, AgentBackupPointer>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static CONTROLLER_SEAL_BASES: LazyLock<Mutex<HashMap<String, arkret::SealBasis>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static CONTROLLER_SEALS: LazyLock<Mutex<HashMap<String, arkret::Seal>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static MANAGED_AGENT_PCR_SEALS: LazyLock<Mutex<HashMap<String, arkret::Seal>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn non_empty(value: impl Into<String>) -> Result<NonEmptyString> {
    NonEmptyString::new(value).map_err(anyhow::Error::msg)
}

fn did_url(value: impl Into<String>) -> Result<DidUrl> {
    DidUrl::new(value).map_err(anyhow::Error::msg)
}

fn opaque_local_id(value: impl Into<String>) -> Result<OpaqueLocalId> {
    OpaqueLocalId::new(value).map_err(anyhow::Error::msg)
}

fn base64_url(value: impl Into<String>) -> Result<Base64UrlString> {
    Base64UrlString::new(value).map_err(anyhow::Error::msg)
}

fn controller_verification_method() -> DidUrl {
    DidUrl::new(format!("{ALICE_DID}#cotest")).expect("controller DID URL is well-formed")
}

/// `{ALICE_DID}#{ALICE_DEVICE}` — the device DID URL every controller-signed
/// fixture Event in this file signs under.
fn alice_device_verification_method() -> DidUrl {
    DidUrl::new(format!("{ALICE_DID}#{ALICE_DEVICE}")).expect("Alice device DID URL is well-formed")
}

fn test_agent_requested_scope() -> arkret::AgentKeyScope {
    let service_actions = agent_runtime_service_actions();
    arkret::AgentKeyScope {
        actions: service_actions
            .into_iter()
            .chain(["ak.event.read", "ak.message.create", "ak.reaction.add"])
            .map(ToOwned::to_owned)
            .collect(),
        resources: service_actions
            .into_iter()
            .map(|operation| arkret::AgentKeyScopeResource {
                kind: arkret::AgentKeyScopeResourceKind::Operation,
                realm_id: None,
                resource_ref: None,
                schema_ref: None,
                operation: Some(operation.to_owned()),
                service_id: None,
            })
            .collect(),
        constraints: Vec::new(),
    }
}

fn agent_runtime_service_actions() -> [&'static str; 8] {
    [
        "ak.self.events.stream.subscribe",
        "ak.self.events.query.scan",
        "ak.self.events.command.submit",
        "ak.self.keys.keypackages.upload.create",
        "ak.self.keys.keypackages.command.consume",
        "ak.self.keys.keypackages.command.revoke",
        "ak.self.device_messages.query.list",
        "ak.self.device_messages.command.ack",
    ]
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn agent_provision_pair_lifecycle_e2e() -> Result<()> {
    let server = ArkretServer::spawn("agent-provision-e2e").await?;
    let token = register_account(&server, ALICE_DID, "@cotest-agent-alice", ALICE_DEVICE)
        .await
        .context("register agent controller account")?;
    prepare_agent_controller_recovery(&server, &token)
        .await
        .context("prepare agent controller recovery")?;

    // 1-2. provision -> active intent with pending_runtime_key + pairing material -> ready.
    let agent_did = provision_and_pair_agent(&server, &token, "Summary Assistant", "summary")
        .await
        .context("provision and pair agent")?;
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");

    advance_event_sequence(
        ALICE_DID,
        "ak:realm:01999999-0000-7000-8000-000000000000",
        32,
    );
    let realm_id = create_realm_with_signing_seed(
        &server,
        &token,
        ALICE_DID,
        "Sidecar profile projection",
        [21_u8; 32],
    )
    .await?;
    eventually(
        "Sidecar Realm bootstrap Seal",
        Duration::from_secs(30),
        Duration::from_millis(250),
        || async {
            let response = server
                .http()
                .get(server.url("/_arkret/self/events/frontier"))
                .query(&[("realm_id", realm_id.as_str())])
                .bearer_auth(&token)
                .send()
                .await?;
            if !response.status().is_success() {
                return Err(anyhow!(
                    "Sidecar Realm frontier is not materialized yet: {}",
                    response.text().await?
                ));
            }
            let state: EventsFrontierAccountClientState = response.json().await?;
            if !matches!(state.frontier, EventsFrontierView::RealmSeal(_)) {
                return Err(anyhow!("Sidecar Realm returned the wrong frontier variant"));
            }
            Ok(())
        },
    )
    .await?;
    let strand_id = realm_id.replace("ak:realm:", "ak:strand:");
    let actor_client = server.client_with_token(ALICE_DID, ALICE_DEVICE, token.clone())?;
    grant_controller_strand_create(&server, &token, &actor_client, &realm_id).await?;
    let mut strand_event = actor_client
        .author_event(
            &realm_id,
            "ak.strand.create",
            json!({
                "object": {
                    "id": strand_id,
                    "schema": "ak.schema.strand.v1",
                    "realm_id": realm_id,
                    "tracks": {"discussion": {"enabled": true, "is_primary": true}},
                    "created_by": ALICE_DID,
                    "created_at": "2026-05-02T00:00:00.000Z",
                    "metadata": {"title": "Sidecar context"}
                }
            }),
        )
        .await?;
    refresh_event_proof_with_signing_seed(&mut strand_event, [21_u8; 32])?;
    let strand_event: arkret::Event = serde_json::from_value(strand_event)?;
    let strand_submission = actor_client
        .sdk()
        .prepare_initial_submissions(std::slice::from_ref(&strand_event))
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("Sidecar Strand submission is missing"))?;
    let strand = actor_client.sdk().events_submit(&strand_submission).await?;
    assert!(strand.accepted.contains(&strand_event.event_id));

    let controller = bearer_sdk_client(&server, &token)?;
    let sidecar = controller
        .agent_sidecar_ensure(&arkret::AgentSidecarEnsureRequestBody {
            controller_id: arkret::Did::new(ALICE_DID)?,
            addressed_agent_ids: Vec::new(),
            context_ref: arkret::AgentSidecarContextRef::strand(
                arkret::RealmId::new(realm_id.clone())?,
                arkret::StrandId::new(strand_id)?,
            ),
        })
        .await
        .context("ensure agent sidecar")?;
    assert!(sidecar.ok, "live Sidecar ensure must succeed");
    assert!(sidecar.sidecar_id.as_str().starts_with("ak:sidecar:"));
    assert_eq!(
        sidecar.access_readiness,
        arkret::AgentSidecarAccessReadiness::KeyMaterialPending,
        "ensure must not report ready before a controller-authored MLS genesis exists"
    );
    let sidecar_view = controller.agent_sidecar_get(&sidecar.sidecar_id).await?;
    assert_eq!(sidecar_view.sidecar.id, sidecar.sidecar_id);
    assert_eq!(
        sidecar_view.access_readiness,
        arkret::AgentSidecarAccessReadiness::KeyMaterialPending
    );
    assert!(sidecar_view.effective_agent_ids.is_empty());
    expect_sdk_api_error(
        controller
            .circle_get(sidecar_view.sidecar.backing_circle_id.as_str())
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )?;
    let ordinary_circles = controller.circle_list(&realm_id).await?;
    assert!(
        ordinary_circles
            .circles
            .iter()
            .all(|circle| circle.circle_id != sidecar_view.sidecar.backing_circle_id),
        "ordinary Circle list must not enumerate Sidecar backing Circles"
    );

    // The legacy command surface has no client-supplied Event parameter. It
    // must fail closed instead of letting the server impersonate the
    // controller; callers must submit a controller-signed SDK Event.
    let attach = controller
        .agent_grant_attach(
            &agent_did,
            &arkret::AgentGrantAttachRequestBody {
                grant: arkret::CapabilityGrant {
                    id: arkret::GrantId::new("ak:grant:01964137-0000-7000-8000-000000000010")?,
                    schema: "ak.schema.capability.v1".to_owned(),
                    realm_id: Some(arkret::RealmId::new(realm_id.clone())?),
                    issuer: arkret::Did::new(ALICE_DID)?,
                    subject: arkret::CapabilitySubject::Did(arkret::Did::new(agent_did.clone())?),
                    actions: vec!["ak.event.read".to_owned()],
                    capability_action_registry_digest: None,
                    resources: vec![serde_json::from_value(json!({
                        "kind": "realm",
                        "realm_id": realm_id
                    }))?],
                    constraints: Vec::new(),
                    issuer_authority_refs: vec![arkret::IssuerAuthorityRef::RealmRoot {
                        realm_id: arkret_identifiers::RealmId::new(realm_id.to_string())?,
                        cell_ref: "ak:cell:ak.component.realm.authority_root.v1:null".to_owned(),
                        controller_epoch_at_issuance: 0,
                        authority_generation: 0,
                    }],
                    issued_at: Utc::now(),
                    not_before: None,
                    expires_at: None,
                    updated_by: None,
                    updated_at: None,
                    revoked_by: None,
                    revoked_at: None,
                    proofs: vec![arkret::PayloadProof {
                        kind: "detached_jws".to_owned(),
                        alg: "EdDSA".to_owned(),
                        verification_method: controller_verification_method(),
                        payload_digest: arkret::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
                        created_at: Utc::now(),
                        domain: None,
                        audience: None,
                        proof_purpose: Some(arkret::PayloadProofPurpose::IssuerAttestation),
                        jws: "header..signature".to_owned(),
                    }],
                    authority_depth: None,
                    authority_root_refs: Vec::new(),
                },
            },
        )
        .await;
    expect_sdk_api_error(
        attach,
        StatusCode::NOT_IMPLEMENTED,
        "controller_signed_event_required",
    )?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn cross_signing_recovery_session_creates_durable_transaction() -> Result<()> {
    let restart_database_url = std::env::var("COTEST_A_SOLAND_DATABASE_URL").ok();
    let mut server = if let Some(database_url) = restart_database_url.as_deref() {
        ArkretServer::spawn_with_database_url(
            "cross-signing-recovery-transaction-e2e",
            database_url,
            // Typed failpoint: let the first old backup delete commit, then
            // fail the rest of this attempt so the retry has to resume from
            // durable progress. See soland `crates/http/src/failpoints.rs`.
            &[(
                "SOLAND_FAILPOINTS",
                "backup_series_erase_durable_step=fail_after_durable_steps:1",
            )],
        )
        .await?
    } else {
        ArkretServer::spawn("cross-signing-recovery-transaction-e2e").await?
    };
    let token = register_account(&server, ALICE_DID, "@cotest-recovery-alice", ALICE_DEVICE)
        .await
        .context("register recovery principal")?;
    prepare_agent_controller_recovery(&server, &token)
        .await
        .context("prepare A-model recovery authority")?;

    let session_body = RecoverySessionCreateRequestBody {
        principal_id: Did::new(ALICE_DID.to_owned())?,
        requesting_device_id: DeviceId::new(RECOVERY_REPLACEMENT_DEVICE.to_owned())?,
        trust_domain: TypedTrustDomainId::new(TRUST_DOMAIN.to_owned())?,
        expected_recovery_policy_ref: Some(RecoveryPolicyRef {
            policy_id: PolicyId::new(RECOVERY_POLICY_ID.to_owned())?,
            policy_version: 1,
        }),
    };
    let session_value = expect_json(
        server
            .http()
            .post(server.url("/_arkret/root/identity/recovery-sessions"))
            .bearer_auth(&token)
            .json(&session_body),
        StatusCode::CREATED,
    )
    .await?;
    let session: RecoverySessionState = serde_json::from_value(session_value)?;
    assert_eq!(session.state, SessionState::Pending);
    assert_eq!(session.ssk_generation, Some(1));

    let material = recovery_key_material()?;
    let recovery_secret_ref = format!("{ALICE_DID}#recovery-proof-1");
    let proof = arkret_crypto::identity_root::build_recovery_unlock_proof(
        &session,
        &recovery_secret_ref,
        &material,
    )?;
    let verified = expect_json(
        server
            .http()
            .post(server.url(&format!(
                "/_arkret/root/identity/recovery-sessions/{}/proofs",
                session.recovery_session_id
            )))
            .bearer_auth(&token)
            .json(&RecoverySessionProofSubmitRequestBody { proof }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(verified["state"], "verified");
    let proof_digest = serde_json::from_value(
        verified
            .pointer("/proof_summary/proof_digest")
            .cloned()
            .ok_or_else(|| anyhow!("verified session omitted proof digest: {verified}"))?,
    )?;
    let verified_session: RecoverySessionState = serde_json::from_value(
        expect_json(
            server
                .http()
                .get(server.url(&format!(
                    "/_arkret/root/identity/recovery-sessions/{}",
                    session.recovery_session_id
                )))
                .bearer_auth(&token),
            StatusCode::OK,
        )
        .await?,
    )?;

    let request = live_cross_signing_recovery_create_request(
        &server,
        &token,
        &verified_session,
        proof_digest,
    )
    .await?;
    let first = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/security-transactions"))
            .bearer_auth(&token)
            .json(&request),
        StatusCode::OK,
    )
    .await?;
    let replay = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/security-transactions"))
            .bearer_auth(&token)
            .json(&request),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(first, replay);
    assert_eq!(first["kind"], "recovery");
    assert_eq!(first["state"], "pending");
    assert_eq!(first["next_required_step"], "submit_authorize_unit");
    assert_eq!(
        first["binding"]["recovery_session_id"],
        session.recovery_session_id.as_str()
    );
    let continue_request = json!({
        "request_digest": first["request_digest"],
        "prepared_plan_digest": first["prepared_plan_digest"],
        "expected_next_step": "submit_authorize_unit"
    });
    let continue_path = format!(
        "/_arkret/self/security-transactions/{}/continue",
        first["transaction_id"]
            .as_str()
            .ok_or_else(|| anyhow!("recovery transaction omitted transaction_id: {first}"))?
    );
    let replacement_token = dev_login(&server, ALICE_DID, RECOVERY_REPLACEMENT_DEVICE).await?;
    let first_authorized = expect_json(
        server
            .http()
            .post(server.url(&continue_path))
            .bearer_auth(&replacement_token)
            .json(&continue_request),
        StatusCode::OK,
    )
    .await?;
    if restart_database_url.is_some() {
        server
            .restart_external_process()
            .await
            .context("restart A-model coordinator after authorize acceptance")?;
    }
    let authorized_replay = expect_json(
        server
            .http()
            .post(server.url(&continue_path))
            .bearer_auth(&replacement_token)
            .json(&continue_request),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(first_authorized, authorized_replay);
    let authorized = authorized_replay;
    assert_eq!(authorized["state"], "awaiting_device_attestation");
    assert_eq!(authorized["next_required_step"], "issue_terminal_receipt");
    assert_eq!(
        authorized["accepted_steps"].as_array().map(Vec::len),
        Some(1)
    );
    let mut conflicting_continue = continue_request;
    conflicting_continue["request_digest"] = json!(format!("sha256:{}", "0".repeat(64)));
    expect_api_error(
        server
            .http()
            .post(server.url(&continue_path))
            .bearer_auth(&replacement_token)
            .json(&conflicting_continue),
        StatusCode::CONFLICT,
        "duplicate_conflict",
    )
    .await?;
    let authorized_resource: arkret_wire::SecurityTransaction = serde_json::from_value(authorized)?;
    let replacement_signer = inkson::event_signer::build_ed25519_signer_with_verification_method(
        [25_u8; 32],
        ALICE_DID,
        format!("{ALICE_DID}#{RECOVERY_REPLACEMENT_DEVICE}"),
    );
    let terminal_request = inkson::fresh_device_recovery::sign_terminal_receipt_continue(
        &authorized_resource,
        inkson::fresh_device_recovery::RecoveryTerminalObservation {
            policy_id: verified_session.policy_id.clone(),
            policy_version: verified_session.policy_version,
            trust_domain: verified_session.trust_domain.clone(),
            proof_summary: serde_json::from_value(serde_json::to_value(
                verified_session
                    .proof_summary
                    .clone()
                    .ok_or_else(|| anyhow!("verified recovery session omitted proof summary"))?,
            )?)?,
            backup_classes_unlocked: Vec::new(),
            welcome_count: 0,
            welcome_realm_summary: None,
            started_at: verified_session.created_at,
            completed_at: Utc::now(),
        },
        &replacement_signer,
    )?;
    let first_completed = expect_json(
        server
            .http()
            .post(server.url(&continue_path))
            .bearer_auth(&replacement_token)
            .json(&terminal_request),
        StatusCode::OK,
    )
    .await?;
    if restart_database_url.is_some() {
        server
            .restart_external_process()
            .await
            .context("restart A-model coordinator after terminal acceptance")?;
    }
    let completed_replay = expect_json(
        server
            .http()
            .post(server.url(&continue_path))
            .bearer_auth(&replacement_token)
            .json(&terminal_request),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(first_completed, completed_replay);
    let completed = completed_replay;
    assert_eq!(completed["state"], "completed");
    assert!(completed["next_required_step"].is_null());
    assert_eq!(
        completed["accepted_steps"].as_array().map(Vec::len),
        Some(2)
    );
    let fetched = expect_json(
        server
            .http()
            .get(server.url(&format!(
                "/_arkret/self/security-transactions/{}",
                completed["transaction_id"]
                    .as_str()
                    .ok_or_else(|| anyhow!("completed transaction omitted id: {completed}"))?
            )))
            .bearer_auth(&replacement_token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(completed, fetched);
    let mut conflicting_terminal = serde_json::to_value(&terminal_request)?;
    conflicting_terminal["client_attestation"]["artifact"]["welcome_count"] = json!(1);
    expect_api_error(
        server
            .http()
            .post(server.url(&continue_path))
            .bearer_auth(&replacement_token)
            .json(&conflicting_terminal),
        StatusCode::CONFLICT,
        "duplicate_conflict",
    )
    .await?;
    let completed_session = expect_json(
        server
            .http()
            .get(server.url(&format!(
                "/_arkret/root/identity/recovery-sessions/{}",
                verified_session.recovery_session_id
            )))
            .bearer_auth(&replacement_token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(completed_session["state"], "completed");
    assert_eq!(
        completed_session["transaction_id"],
        completed["transaction_id"]
    );
    if restart_database_url.is_some() {
        run_security_rotation_restart_matrix(&mut server, &replacement_token, &replacement_signer)
            .await?;
    }
    assert_recovery_public_artifacts_contain_no_secret_material(
        &[
            serde_json::to_value(&request)?,
            first,
            serde_json::to_value(&terminal_request)?,
            completed,
            completed_session,
        ],
        &material,
        server.service_log_contents()?.as_deref(),
    )?;
    Ok(())
}

async fn run_security_rotation_restart_matrix(
    server: &mut ArkretServer,
    token: &str,
    signer: &inkson::event_signer::InksonEventSigner,
) -> Result<()> {
    use arkret_models_crypto::{
        BackupSeriesEraseRequestBody, BackupSeriesEraseStatus, ClientStepAttestationArtifact,
        SecurityRotationLocalCommit, TypedClientStepAttestation,
        TypedSecurityTransactionContinueRequest,
    };
    use arkret_wire::{
        AuthorizationLeaseIssueIntent, AuthorizationLeaseIssueOutcome,
        AuthorizationLeaseIssueRequest, BackupRotationKind, CLIENT_STEP_ATTESTATION_SIGNED_FIELDS,
        ClientStepAttestationAuthData, LeaseBasisRef, RiskTier, SecurityTransactionBinding,
        SecurityTransactionCreateRequest, SecurityTransactionState, SecurityTransactionStep,
    };

    let principal = Did::new(ALICE_DID.to_owned())?;
    let current_device = DeviceId::new(RECOVERY_REPLACEMENT_DEVICE.to_owned())?;
    let control_realm = principal_control_realm_id(&principal);
    let mut sdk = bearer_sdk_client(server, token)?;
    let frontier = match sdk
        .events_frontier(
            &arkret_models_collaboration::event_sync::EventsFrontierSelector::RealmSeal {
                realm_id: arkret::RealmId::new(control_realm.clone())?,
            },
        )
        .await?
        .frontier
    {
        arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(frontier) => {
            frontier
        }
        _ => {
            return Err(anyhow!(
                "principal-control frontier was not a Realm Seal view"
            ));
        }
    };
    let mut actor_events = sdk
        .events_query_all_pages(&control_realm)
        .await?
        .events
        .into_iter()
        .filter(|event| event.actor_id == principal)
        .collect::<Vec<_>>();
    actor_events.sort_by_key(|event| event.actor_seq);
    let previous = actor_events
        .last()
        .map(|event| vec![event.event_id.clone()])
        .unwrap_or_default();
    let first_seq = actor_events.last().map_or(1, |event| event.actor_seq + 1);

    let old_secret = build_rotation_backup(
        signer,
        BackupKind::SecretStorage,
        "ak:backup:019fb200-0000-7000-8000-000000000001",
        "ak:backup_series:019fb200-0000-7000-8000-000000000011",
        b"old encrypted secret-storage material",
    )?;
    let old_mls = build_rotation_backup(
        signer,
        BackupKind::MlsHistory,
        "ak:backup:019fb200-0000-7000-8000-000000000002",
        "ak:backup_series:019fb200-0000-7000-8000-000000000012",
        b"old encrypted MLS material",
    )?;
    for backup in [&old_secret, &old_mls] {
        expect_json(
            server
                .http()
                .put(server.url(&format!("/_arkret/self/keys/backups/{}", backup.backup_id)))
                .bearer_auth(token)
                .json(backup),
            StatusCode::OK,
        )
        .await?;
    }
    let new_secret = build_rotation_backup(
        signer,
        BackupKind::SecretStorage,
        "ak:backup:019fb200-0000-7000-8000-000000000003",
        "ak:backup_series:019fb200-0000-7000-8000-000000000013",
        b"new encrypted secret-storage material",
    )?;
    let new_mls = build_rotation_backup(
        signer,
        BackupKind::MlsHistory,
        "ak:backup:019fb200-0000-7000-8000-000000000004",
        "ak:backup_series:019fb200-0000-7000-8000-000000000014",
        b"new encrypted MLS material",
    )?;

    let mut revoke = arkret::Event::new(
        EventKind::DEVICE_REVOKE,
        arkret::ScopeRef::Realm {
            realm_id: arkret::RealmId::new(control_realm.clone())?,
        },
        principal.clone(),
        first_seq,
        arkret::Hlc::new(format!(
            "{:012x}-0001-a13f9c2e",
            canonical_now().timestamp_millis()
        ))?,
        serde_json::to_value(
            arkret_models_collaboration::events_payloads::device_identity::DeviceRevokePayload {
                principal_id: principal.clone(),
                device_id: DeviceId::new(ALICE_DEVICE.to_owned())?,
                revoked_by: DeviceOrPrincipalRef::DeviceId(current_device.clone()),
                revoked_at: canonical_now(),
                reason: arkret_models_collaboration::events_payloads::device_identity::DeviceRevocationReason::new(
                    "device_lost".to_owned(),
                )
                .map_err(anyhow::Error::msg)?,
                proof: None,
            },
        )?,
    )?;
    revoke.prev_refs = previous;
    revoke.seal_basis = Some(frontier.seal_basis());
    sign_rotation_event(&mut revoke, signer)?;

    let secret_pointer = build_rotation_pointer_event(
        signer,
        &frontier,
        BackupRotationKind::SecretStorage,
        &old_secret,
        &new_secret,
        first_seq + 1,
        vec![revoke.event_id.clone()],
    )?;
    let mls_pointer = build_rotation_pointer_event(
        signer,
        &frontier,
        BackupRotationKind::MlsHistory,
        &old_mls,
        &new_mls,
        first_seq + 2,
        vec![secret_pointer.event_id.clone()],
    )?;
    let proposal_key = SigningKey::from_bytes(&[25_u8; 32]);
    let proposal_verification_method =
        did_url(format!("{ALICE_DID}#{RECOVERY_REPLACEMENT_DEVICE}"))?;
    let proposal_notary = arkret_wire::notary::NotaryValue::single_did(principal.clone());
    let revoke_submission = prepare_initial_submission_for_notary(
        &sdk,
        &revoke,
        &proposal_key,
        &proposal_verification_method,
        &proposal_notary,
    )
    .await
    .context("prepare rotation revoke publication evidence")?;
    let secret_submission = prepare_initial_submission_for_notary(
        &sdk,
        &secret_pointer,
        &proposal_key,
        &proposal_verification_method,
        &proposal_notary,
    )
    .await
    .context("prepare secret-storage pointer publication evidence")?;
    let mls_submission = prepare_initial_submission_for_notary(
        &sdk,
        &mls_pointer,
        &proposal_key,
        &proposal_verification_method,
        &proposal_notary,
    )
    .await
    .context("prepare MLS pointer publication evidence")?;
    let transaction_id =
        arkret::TransactionId::new("ak:transaction:019fb200-0000-7000-8000-000000000021")?;
    let create = inkson::fresh_device_recovery::SecurityRotationDraft {
        transaction_id: transaction_id.clone(),
        principal_id: principal.clone(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
        revoke_submission: arkret::EventsSubmitBatchRequestBody {
            events: vec![revoke_submission],
        },
        new_secret_commitment: arkret::Hash::new(canonical::sha256_digest(
            b"rotation-new-secret-commitment",
        ))?,
        backup_rotations: vec![
            inkson::fresh_device_recovery::SecurityRotationBackupDraft {
                backup_kind: BackupRotationKind::SecretStorage,
                previous_series_id: old_secret.series_id.clone(),
                new_series_id: new_secret.series_id.clone(),
                new_backup_bodies: vec![serde_json::to_value(&new_secret)?],
                active_series_submission: arkret::EventsSubmitBatchRequestBody {
                    events: vec![secret_submission],
                },
                old_backups: vec![backup_ref(&old_secret)?],
            },
            inkson::fresh_device_recovery::SecurityRotationBackupDraft {
                backup_kind: BackupRotationKind::MlsHistory,
                previous_series_id: old_mls.series_id.clone(),
                new_series_id: new_mls.series_id.clone(),
                new_backup_bodies: vec![serde_json::to_value(&new_mls)?],
                active_series_submission: arkret::EventsSubmitBatchRequestBody {
                    events: vec![mls_submission],
                },
                old_backups: vec![backup_ref(&old_mls)?],
            },
        ],
    }
    .into_create_request(Did::new(server.service_id().to_owned())?)?;
    let mut transaction = sdk
        .create_security_transaction(&SecurityTransactionCreateRequest::SecurityRotation(create))
        .await
        .context("create security rotation transaction")?;
    let fixed_request_digest = transaction.request_digest.clone();
    let fixed_plan_digest = transaction.prepared_plan_digest.clone();

    for step in [
        SecurityTransactionStep::Revoke,
        SecurityTransactionStep::UploadNewMaterial,
        SecurityTransactionStep::SwitchAuthoritativePointer,
    ] {
        assert_eq!(transaction.next_required_step, Some(step));
        let request = TypedSecurityTransactionContinueRequest {
            request_digest: fixed_request_digest.clone(),
            prepared_plan_digest: fixed_plan_digest.clone(),
            expected_next_step: step,
            client_attestation: None,
            participant_request: None,
        };
        let first = sdk
            .continue_security_transaction(&transaction_id, &request)
            .await
            .with_context(|| format!("continue rotation {step:?} before restart"))?;
        server.restart_external_process().await?;
        sdk = bearer_sdk_client(server, token)?;
        let replay = sdk
            .continue_security_transaction(&transaction_id, &request)
            .await
            .with_context(|| format!("replay rotation {step:?} after restart"))?;
        assert_eq!(
            serde_json::to_value(&first)?,
            serde_json::to_value(&replay)?,
            "{step:?} response-loss replay changed the first durable outcome"
        );
        transaction = replay;
    }
    assert_eq!(
        transaction.next_required_step,
        Some(SecurityTransactionStep::EraseOldMaterial)
    );
    let backups_before_erase = sdk.list_all_key_backups().await?;
    for backup in [&old_secret, &old_mls] {
        assert!(
            backups_before_erase
                .iter()
                .any(|candidate| candidate.backup_id == backup.backup_id),
            "old backup {} was deleted before the erase step",
            backup.backup_id
        );
    }

    let SecurityTransactionBinding::SecurityRotation(binding) = transaction.binding.clone() else {
        return Err(anyhow!("rotation transaction returned a recovery binding"));
    };
    let erase_frontier = match sdk
        .events_frontier(
            &arkret_models_collaboration::event_sync::EventsFrontierSelector::RealmSeal {
                realm_id: arkret::RealmId::new(control_realm.clone())?,
            },
        )
        .await?
        .frontier
    {
        arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(frontier) => {
            frontier
        }
        _ => {
            return Err(anyhow!(
                "principal-control frontier was not a Realm Seal view"
            ));
        }
    };
    let lease_request = AuthorizationLeaseIssueRequest {
        events: Vec::new(),
        intents: vec![AuthorizationLeaseIssueIntent {
            scope_ref: arkret::ScopeRef::Realm {
                realm_id: arkret::RealmId::new(control_realm.clone())?,
            },
            action: "ak.keys.backup_series.erase".to_owned(),
            authorization_rule_id: "realm_admission".to_owned(),
            risk_tier: RiskTier::High,
            basis_ref: LeaseBasisRef::Seal(erase_frontier.seal_id),
        }],
    };
    let lease_value = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/authorization-leases"))
            .bearer_auth(token)
            .header("Idempotency-Key", "rotation-erase-lease")
            .json(&lease_request),
        StatusCode::OK,
    )
    .await
    .context("issue old-backup erase authorization lease")?;
    let lease_outcome: AuthorizationLeaseIssueOutcome = serde_json::from_value(lease_value)?;
    lease_outcome.validate_against_request(&lease_request)?;
    let erase_request = BackupSeriesEraseRequestBody {
        transaction_id: transaction_id.clone(),
        transaction_request_digest: fixed_request_digest.clone(),
        prepared_plan_digest: fixed_plan_digest.clone(),
        erase_confirmation_digest: binding.erase_confirmation_digest.clone(),
        series: binding.backup_rotations.clone(),
        authorization_lease: lease_outcome.authorization_leases[0].clone(),
        cba_proof_bundles: Vec::new(),
    };
    let partial = sdk
        .erase_backup_series(&erase_request)
        .await
        .context("erase old backup series with injected partial failure")?;
    assert_eq!(partial.status, BackupSeriesEraseStatus::Partial);
    assert_eq!(
        partial
            .series_results
            .iter()
            .flat_map(|result| &result.erased_backups)
            .count(),
        1
    );
    server.restart_external_process().await?;
    sdk = bearer_sdk_client(server, token)?;
    let erased = sdk.erase_backup_series(&erase_request).await?;
    assert_eq!(erased.status, BackupSeriesEraseStatus::Complete);
    let erased_replay = sdk.erase_backup_series(&erase_request).await?;
    assert_eq!(erased, erased_replay);
    transaction = sdk.get_security_transaction(&transaction_id).await?;
    assert_eq!(
        transaction.next_required_step,
        Some(SecurityTransactionStep::LocalCommit)
    );

    let commit = SecurityRotationLocalCommit {
        schema: SchemaId::SECURITY_ROTATION_LOCAL_COMMIT_V1.to_owned(),
        transaction_id: transaction_id.clone(),
        transaction_request_digest: fixed_request_digest.clone(),
        prepared_plan_digest: fixed_plan_digest.clone(),
        local_commit_digest: binding.local_commit_digest.clone(),
        erase_confirmation_digest: binding.erase_confirmation_digest.clone(),
        device_id: current_device,
        committed_at: Utc::now(),
    };
    let artifact = ClientStepAttestationArtifact::SecurityRotationLocalCommit(commit);
    let mut attestation = TypedClientStepAttestation {
        step: SecurityTransactionStep::LocalCommit,
        output_ref: binding.local_commit_digest.as_str().to_owned(),
        transaction_id: transaction_id.clone(),
        transaction_request_digest: fixed_request_digest.clone(),
        prepared_plan_digest: fixed_plan_digest.clone(),
        attestation_digest: arkret::Hash::new(canonical::canonical_sha256(&artifact)?)?,
        artifact,
        auth_data: ClientStepAttestationAuthData {
            verification_method: DidUrl::new(format!("{ALICE_DID}#{RECOVERY_REPLACEMENT_DEVICE}"))
                .map_err(anyhow::Error::msg)?,
            alg: "EdDSA".to_owned(),
            signature: String::new(),
            signed_fields: CLIENT_STEP_ATTESTATION_SIGNED_FIELDS
                .iter()
                .map(ToString::to_string)
                .collect(),
        },
    };
    attestation.auth_data.signature =
        URL_SAFE_NO_PAD.encode(signer.sign_raw(&attestation.signing_bytes()?)?);
    let commit_request = TypedSecurityTransactionContinueRequest {
        request_digest: fixed_request_digest,
        prepared_plan_digest: fixed_plan_digest,
        expected_next_step: SecurityTransactionStep::LocalCommit,
        client_attestation: Some(attestation),
        participant_request: None,
    };
    let first_complete = sdk
        .continue_security_transaction(&transaction_id, &commit_request)
        .await?;
    server.restart_external_process().await?;
    sdk = bearer_sdk_client(server, token)?;
    let complete_replay = sdk
        .continue_security_transaction(&transaction_id, &commit_request)
        .await?;
    assert_eq!(
        serde_json::to_value(&first_complete)?,
        serde_json::to_value(&complete_replay)?
    );
    assert_eq!(complete_replay.state, SecurityTransactionState::Completed);
    assert_eq!(complete_replay.accepted_steps.len(), 5);
    let backups_after_commit = sdk.list_all_key_backups().await?;
    for backup in [&old_secret, &old_mls] {
        assert!(
            backups_after_commit
                .iter()
                .all(|candidate| candidate.backup_id != backup.backup_id),
            "old backup {} survived completed rotation",
            backup.backup_id
        );
    }
    for backup in [&new_secret, &new_mls] {
        assert!(
            backups_after_commit
                .iter()
                .any(|candidate| candidate.backup_id == backup.backup_id),
            "new backup {} disappeared during rotation",
            backup.backup_id
        );
    }
    Ok(())
}

fn backup_ref(backup: &KeyBackup) -> Result<arkret_wire::BackupObjectRef> {
    Ok(arkret_wire::BackupObjectRef {
        backup_id: backup.backup_id.clone(),
        ciphertext_digest: arkret::Hash::new(backup.ciphertext_digest.clone())?,
    })
}

fn build_rotation_backup(
    signer: &inkson::event_signer::InksonEventSigner,
    kind: BackupKind,
    backup_id: &str,
    series_id: &str,
    ciphertext: &[u8],
) -> Result<KeyBackup> {
    let created_at = canonical_now();
    let item_kind = match kind {
        BackupKind::SecretStorage => "recovery_secret",
        BackupKind::MlsHistory => "mls_group_state",
        BackupKind::DidRecovery => return Err(anyhow!("rotation excludes did_recovery")),
    };
    let mut backup = KeyBackup {
        backup_id: BackupId::new(backup_id.to_owned())?,
        actor_id: Did::new(ALICE_DID.to_owned())?,
        device_id: Some(DeviceId::new(RECOVERY_REPLACEMENT_DEVICE.to_owned())?),
        backup_kind: kind,
        mixed_secret_storage: false,
        backup_version: "kb_rotation_1".to_owned(),
        created_at,
        updated_at: None,
        expires_at: None,
        encryption: KeyBackupEncryption {
            recipient_method: KeyBackupRecipientMethod::SecretStorageKey,
            recipient_key_ref: Some("rotation-test-ssk".to_owned()),
            kdf: None,
            aead: KeyBackupAead {
                name: KeyBackupAeadName::Xchacha20Poly1305,
                aead_profile: Some("ak.aead.xchacha20_poly1305.v1".to_owned()),
                nonce_salt: None,
                nonce: Some(base64_url("cm90YXRpb24tdGVzdC1ub25jZQ")?),
                enc: None,
                extra: Default::default(),
            },
            key_commitment: None,
            hpke_suite: None,
            extra: Default::default(),
        },
        domain_separation: KeyBackupDomainSeparation {
            hkdf_info: format!(
                "arkret-key-backup/{}/rotation/v1",
                match kind {
                    BackupKind::SecretStorage => "secret_storage",
                    BackupKind::MlsHistory => "mls_history",
                    BackupKind::DidRecovery => unreachable!(),
                }
            ),
            subdomain: "rotation".to_owned(),
            aead_aad: KeyBackupDomainSeparationAad {
                schema: "ak.schema.key_backup.v1".to_owned(),
                actor_id: Did::new(ALICE_DID.to_owned())?,
                device_id: Some(RECOVERY_REPLACEMENT_DEVICE.to_owned()),
                backup_kind: kind,
                backup_version: "kb_rotation_1".to_owned(),
                created_at,
                item_kinds: vec![item_kind.to_owned()],
                managed_principal_bindings: Vec::new(),
                recipient_method: Some(KeyBackupRecipientMethod::SecretStorageKey),
                recipient_key_ref: Some("rotation-test-ssk".to_owned()),
                extra: Default::default(),
            },
            extra: Default::default(),
        },
        contents: vec![KeyBackupContentItem {
            item_kind: item_kind.to_owned(),
            realm_id: None,
            managed_principal_binding: None,
            mls_group_id: (kind == BackupKind::MlsHistory).then(|| "rotation-group".to_owned()),
            epoch: (kind == BackupKind::MlsHistory).then_some(1),
            first_event_id: None,
            last_event_id: None,
            secret_id: (kind == BackupKind::SecretStorage).then(|| "rotation-secret".to_owned()),
            secret_version: (kind == BackupKind::SecretStorage).then_some(1),
            extra: Default::default(),
        }],
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        ciphertext_digest: canonical::sha256_digest(ciphertext),
        plaintext_commitment: None,
        auth_data: Some(KeyBackupAuthData {
            device_id: DeviceId::new(RECOVERY_REPLACEMENT_DEVICE.to_owned())?,
            verification_method: DidUrl::new(format!("{ALICE_DID}#{RECOVERY_REPLACEMENT_DEVICE}"))
                .map_err(anyhow::Error::msg)?,
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            signature: base64_url("cGVuZGluZw")?,
            ssk_generation: std::num::NonZeroU64::new(1),
            device_authorize_event_id: None,
            signed_fields: [
                "backup_id",
                "actor_id",
                "backup_kind",
                "backup_version",
                "series_id",
                "series_seq",
                "supersedes",
                "encryption",
                "domain_separation",
                "contents",
                "ciphertext_digest",
            ]
            .iter()
            .map(ToString::to_string)
            .collect(),
            extra: Default::default(),
        }),
        retention: None,
        series_id: BackupSeriesId::new(series_id.to_owned())?,
        series_seq: 0,
        supersedes: None,
        supersedes_digest: None,
        frontier_ref: None,
        recovery_policy_ref: None,
        extra: Default::default(),
    };
    let mut unsigned = serde_json::to_value(&backup)?;
    unsigned["auth_data"]
        .as_object_mut()
        .context("rotation backup auth_data is not an object")?
        .remove("signature");
    backup.auth_data.as_mut().unwrap().signature = base64_url(
        URL_SAFE_NO_PAD.encode(signer.sign_raw(&canonical::canonical_json_bytes(&unsigned)?)?),
    )?;
    Ok(backup)
}

fn sign_rotation_event(
    event: &mut arkret::Event,
    signer: &inkson::event_signer::InksonEventSigner,
) -> Result<()> {
    signer.sign_envelope(event)?;
    Ok(())
}

fn build_rotation_pointer_event(
    signer: &inkson::event_signer::InksonEventSigner,
    frontier: &arkret::RealmSealFrontierView,
    kind: arkret_wire::BackupRotationKind,
    old_backup: &KeyBackup,
    new_backup: &KeyBackup,
    actor_seq: u64,
    prev_refs: Vec<arkret::EventId>,
) -> Result<arkret::Event> {
    let wire_kind = match kind {
        arkret_wire::BackupRotationKind::SecretStorage => "secret_storage",
        arkret_wire::BackupRotationKind::MlsHistory => "mls_history",
    };
    let signed_fields = [
        "schema",
        "actor_id",
        "backup_kind",
        "active_series_id",
        "series_pointer_version",
        "previous_series_ids",
        "frontier_ref",
        "issued_at",
    ];
    let mut payload = json!({
        "schema": "ak.schema.key_backup_active_series.v1",
        "actor_id": ALICE_DID,
        "backup_kind": wire_kind,
        "active_series_id": new_backup.series_id,
        "series_pointer_version": 1,
        "previous_series_ids": [old_backup.series_id],
        "frontier_ref": {
            "frontier_digest": frontier.control_event_set_root,
            "seal_ref": frontier.seal_id,
            "ssk_generation": 1
        },
        "issued_at": canonical::format_timestamp_canonical(canonical_now()),
        "auth_data": {
            "verification_method": format!("{ALICE_DID}#{RECOVERY_REPLACEMENT_DEVICE}"),
            "signature_algorithm": "Ed25519",
            "signature": "pending",
            "signed_fields": signed_fields,
            "ssk_generation": 1
        }
    });
    let mut unsigned = payload.clone();
    unsigned["auth_data"]
        .as_object_mut()
        .context("rotation pointer auth_data is not an object")?
        .remove("signature");
    payload["auth_data"]["signature"] = json!(
        URL_SAFE_NO_PAD.encode(signer.sign_raw(&canonical::canonical_json_bytes(&unsigned)?)?)
    );
    let mut event = arkret::Event::new(
        EventKind::KEY_BACKUP_ACTIVE_SERIES,
        arkret::ScopeRef::Realm {
            realm_id: arkret::RealmId::new(principal_control_realm_id(&Did::new(
                ALICE_DID.to_owned(),
            )?))?,
        },
        Did::new(ALICE_DID.to_owned())?,
        actor_seq,
        arkret::Hlc::new(format!(
            "{:012x}-{:04x}-a13f9c2e",
            canonical_now().timestamp_millis(),
            actor_seq
        ))?,
        payload,
    )?;
    event.prev_refs = prev_refs;
    event.seal_basis = Some(frontier.seal_basis());
    sign_rotation_event(&mut event, signer)?;
    Ok(event)
}

/// `ak.self.agent.command.renew_pairing` (decision 0007): an expired pairing
/// renews IN PLACE on the same agent principal. The renewed handle is fresh
/// and single-use, the dead handle stays permanently unresolvable, and the
/// renewed pairing completes to `active` without provisioning a replacement.
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn agent_pairing_renewal_e2e() -> Result<()> {
    let server = ArkretServer::spawn("agent-pairing-renewal-e2e").await?;
    let token = register_account(&server, ALICE_DID, "@cotest-agent-alice", ALICE_DEVICE).await?;
    prepare_agent_controller_recovery(&server, &token).await?;
    let controller = bearer_sdk_client(&server, &token)?;

    // Provision with a 1 ms pairing window so the handle is already dead.
    let prov = provision_agent(&server, &token, "Renewal Assistant", "renewal", Some(1)).await?;
    let agent_did = prov.agent_id.to_string();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    // Two orthogonal axes (key-management.md §3.6.1): pairing expiry is not a
    // lifecycle transition — the intent stays active while the derived
    // runtime_state falls to pairing_expired on first observation.
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");
    assert_eq!(
        agent_runtime_state(&server, &token, &agent_did).await?,
        "pairing_expired"
    );

    // Renewal only rotates short-lived pairing material; it does not author a
    // controller-owned domain Event. The principal and accepted Event refs stay
    // unchanged until the runtime completes the renewed pairing.
    let renewed = controller
        .agent_renew_pairing(&agent_did, &arkret::AgentRenewPairingRequestBody::default())
        .await?;
    assert_eq!(renewed.agent_id.to_string(), agent_did, "same principal");
    assert_ne!(renewed.pairing_request_id, prov.pairing_request_id);
    assert_ne!(renewed.pairing_code, prov.pairing_code);
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");
    assert_eq!(
        agent_runtime_state(&server, &token, &agent_did).await?,
        "pending_runtime_key"
    );

    let stale = pair_agent_runtime_key(&server, &token, &prov).await;
    assert!(stale.is_err(), "expired pairing handle must remain dead");
    let paired = pair_agent_runtime_key(&server, &token, &renewed).await?;
    assert!(!paired.authorized_event_ref.as_str().is_empty());
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");
    assert_eq!(
        agent_runtime_state(&server, &token, &agent_did).await?,
        "ready"
    );

    // Active-intent runtime replacement: no forced pause and no resume. The
    // agent stays active throughout, runtime_state projects replacing while the
    // handle is open, and completing the pairing atomically supersedes the old
    // key without changing the lifecycle intent (key-management.md §3.6.1).
    let replacement = controller
        .agent_renew_pairing(&agent_did, &arkret::AgentRenewPairingRequestBody::default())
        .await?;
    assert_eq!(replacement.agent_id.to_string(), agent_did);
    assert_ne!(replacement.pairing_request_id, renewed.pairing_request_id);
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");
    assert_eq!(
        agent_runtime_state(&server, &token, &agent_did).await?,
        "replacing"
    );
    let stale = pair_agent_runtime_key(&server, &token, &renewed).await;
    assert!(stale.is_err(), "superseded pairing handle must remain dead");
    let replaced =
        pair_agent_runtime_key_as(&server, &token, &replacement, "runtime-key-2").await?;
    assert_ne!(replaced.authorized_event_ref, paired.authorized_event_ref);
    // No resume required: the active agent immediately serves with the new key.
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");
    assert_eq!(
        agent_runtime_state(&server, &token, &agent_did).await?,
        "ready"
    );

    // Compromise path: the controller explicitly pauses, then replaces. The
    // intent stays paused across the replacement and requires an explicit
    // resume; pause/resume never interlock with the open handle.
    pause_agent_runtime(&server, &token, &replacement).await?;
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "paused");
    let paused_replacement = controller
        .agent_renew_pairing(&agent_did, &arkret::AgentRenewPairingRequestBody::default())
        .await?;
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "paused");
    assert_eq!(
        agent_runtime_state(&server, &token, &agent_did).await?,
        "replacing"
    );
    let paused_replaced =
        pair_agent_runtime_key_as(&server, &token, &paused_replacement, "runtime-key-3").await?;
    assert_ne!(
        paused_replaced.authorized_event_ref,
        replaced.authorized_event_ref
    );
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "paused");
    assert_eq!(
        agent_runtime_state(&server, &token, &agent_did).await?,
        "ready"
    );
    resume_agent_runtime(&server, &token, &paused_replacement).await?;
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");

    // Replacement handle expiry is non-destructive: the intent, the existing key
    // and grants all survive and runtime_state returns to ready.
    let short_lived = controller
        .agent_renew_pairing(
            &agent_did,
            &arkret::AgentRenewPairingRequestBody {
                pairing_ttl_ms: Some(1),
            },
        )
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");
    assert_eq!(
        agent_runtime_state(&server, &token, &agent_did).await?,
        "ready"
    );
    assert!(
        pair_agent_runtime_key_as(&server, &token, &short_lived, "runtime-key-4")
            .await
            .is_err(),
        "expired replacement handle must remain dead"
    );
    Ok(())
}

/// AKP-0008 runtime-side approval status poll
/// (`ak.open.agent_pairing.query.runtime_key_request_status`): the runtime
/// learns the controller decision after submitting a runtime key request
/// (arkret-work 2026-07-10-agent-runtime-approval-status-closure acceptance #5).
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn agent_runtime_key_request_status_poll_e2e() -> Result<()> {
    let server = ArkretServer::spawn("agent-approval-status-e2e").await?;
    let token = register_account(&server, ALICE_DID, "@cotest-agent-alice", ALICE_DEVICE).await?;
    prepare_agent_controller_recovery(&server, &token).await?;
    let controller = bearer_sdk_client(&server, &token)?;
    let prov =
        provision_agent(&server, &token, "Status Poll Assistant", "statuspoll", None).await?;
    let agent_did = prov.agent_id.to_string();
    let status_body =
        arkret_models_collaboration::agent_operations::AgentRuntimeApprovalStatusRequestBody {
            pairing_request_id: prov.pairing_request_id.clone(),
            pairing_code: prov
                .pairing_code
                .clone()
                .ok_or_else(|| anyhow!("pairing_code missing"))?,
            agent_id: prov.agent_id.clone(),
        };

    // 1. Open pairing, nothing submitted yet: pending without an approval_request_id or any
    //    authorized binding.
    let status = controller
        .agent_runtime_approval_status(&status_body)
        .await?;
    assert_eq!(status.retry_after, Some(Duration::from_secs(1)));
    // Two orthogonal axes (key-management.md §3.6.1): the bootstrapping agent's
    // lifecycle intent is active; the derived runtime_state is pending_runtime_key.
    assert_eq!(
        status.status,
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
    );
    assert_eq!(
        status.runtime_state,
        arkret_models_collaboration::agent_operations::AgentRuntimeState::PendingRuntimeKey
    );
    assert!(status.approval_request_id.is_none());
    assert!(status.authorized_event_ref.is_none());
    assert!(status.authorized_public_key_digest.is_none());

    // 2. Runtime submits the open approval request; the poll echoes its id.
    let approval_request = build_runtime_approval_request(&server, &prov)?;
    let submitted = controller
        .agent_runtime_approval_request(&approval_request)
        .await?;
    assert!(submitted.ok);
    let status = controller
        .agent_runtime_approval_status(&status_body)
        .await?;
    assert_eq!(
        status.status,
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
    );
    assert_eq!(
        status.runtime_state,
        arkret_models_collaboration::agent_operations::AgentRuntimeState::PendingRuntimeKey
    );
    assert_eq!(
        status.approval_request_id.as_deref(),
        Some(submitted.approval_request_id.as_str())
    );

    // 3. Anti-enumeration: a wrong pairing_code is indistinguishable from an unknown
    //    pairing_request_id.
    let wrong_code =
        arkret_models_collaboration::agent_operations::AgentRuntimeApprovalStatusRequestBody {
            pairing_code: "00000000".to_owned(),
            ..status_body.clone()
        };
    expect_sdk_api_error(
        controller.agent_runtime_approval_status(&wrong_code).await,
        StatusCode::NOT_FOUND,
        "not_found",
    )?;

    // 4. Controller approves; the poll flips to active and hands the runtime the exact key binding
    //    the controller authorized.
    let pair = pair_agent_runtime_key(&server, &token, &prov).await?;
    let status = controller
        .agent_runtime_approval_status(&status_body)
        .await?;
    assert_eq!(
        status.status,
        arkret_models_collaboration::agent_operations::AgentLifecycleState::Active
    );
    assert_eq!(
        status.runtime_state,
        arkret_models_collaboration::agent_operations::AgentRuntimeState::Ready
    );
    assert!(status.approval_request_id.is_none());
    assert_eq!(
        status.authorized_event_ref.as_ref().map(|id| id.as_str()),
        Some(pair.authorized_event_ref.as_str())
    );
    let signing_key = runtime_signing_key();
    let verification_method = format!("{agent_did}#runtime-key-1");
    let builder = runtime_key_request_builder(&server, &prov, &signing_key)?
        .verification_method(verification_method.clone());
    assert_eq!(
        status.authorized_verification_method.as_deref(),
        Some(verification_method.as_str())
    );
    let local_digest = builder.public_key_digest()?;
    assert_eq!(
        status.authorized_public_key_digest.as_deref(),
        Some(local_digest.as_str())
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn agent_pairing_waits_for_current_pcr_recovery_without_consuming_handle() -> Result<()> {
    let server = ArkretServer::spawn("agent-pcr-recovery-gate-e2e").await?;
    let token = register_account(&server, ALICE_DID, "@cotest-agent-alice", ALICE_DEVICE).await?;
    prepare_agent_controller_recovery(&server, &token).await?;
    let controller = bearer_sdk_client(&server, &token)?;
    let provisioned = provision_agent(
        &server,
        &token,
        "Recovery Gate Assistant",
        "recoverygate",
        None,
    )
    .await?;

    // Establish the Agent PCR frontier, but deliberately omit the
    // controller-owned managed-PCR recovery backup that must cover it.
    ensure_agent_pcr_mls(&server, &token, &provisioned).await?;
    let body =
        build_agent_key_pair_request_as(&server, &token, &provisioned, "runtime-key-recovery-gate")
            .await?;

    expect_sdk_api_error(
        controller.agent_key_pair(&body).await,
        StatusCode::PRECONDITION_FAILED,
        "agent_pcr_recovery_not_ready",
    )?;
    // A rejected recovery gate must not consume the pairing: the lifecycle
    // intent stays active and the derived runtime_state stays pending_runtime_key
    // (key-management.md §3.6.1).
    assert_eq!(
        agent_status(&server, &token, provisioned.agent_id.as_str()).await?,
        "active",
        "a rejected recovery gate must not change the lifecycle intent"
    );
    assert_eq!(
        agent_runtime_state(&server, &token, provisioned.agent_id.as_str()).await?,
        "pending_runtime_key",
        "a rejected recovery gate must not activate or consume the pairing"
    );

    // Publishing the current backup does not advance the Agent PCR frontier,
    // so the exact same controller-signed request and pairing handle must now
    // succeed.
    prepare_agent_pcr_recovery(&server, &token, &provisioned).await?;
    let outcome = controller.agent_key_pair(&body).await?;
    assert_eq!(
        outcome.authorized_event_ref, body.authorize_event.event.event_id,
        "the retry must accept the original authorization event"
    );
    assert_eq!(
        agent_status(&server, &token, provisioned.agent_id.as_str()).await?,
        "active"
    );
    let recovery = bearer_sdk_client(&server, &token)?
        .agent_get(provisioned.agent_id.as_str())
        .await?
        .key_state
        .ok_or_else(|| anyhow!("managed Agent key_state is missing"))?
        .pcr_recovery;
    assert!(
        matches!(recovery, arkret::AgentPcrRecoveryState::Ready { .. }),
        "an accepted but not-yet-Sealed pairing Event must not move the managed PCR frontier: \
         {recovery:?}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn agent_participation_selection_is_persisted_without_server_authored_event() -> Result<()> {
    let service_name = "agent-live-e2e";
    let server = ArkretServer::spawn(service_name).await?;
    let token = register_account(&server, ALICE_DID, "@cotest-agent-alice", ALICE_DEVICE).await?;
    prepare_agent_controller_recovery(&server, &token).await?;

    let realm_id = principal_control_realm_id(&Did::new(ALICE_DID.to_owned())?);
    let agent_did = provision_and_pair_agent(&server, &token, "Reply Assistant", "reply").await?;

    let controller = bearer_sdk_client(&server, &token)?;
    let participation = controller
        .agent_participation_replace(
            &agent_did,
            &arkret::AgentParticipationReplaceRequestBody {
                scope: arkret::AgentParticipationScope::Realm {
                    realm_id: arkret::RealmId::new(realm_id)?,
                },
                selection: arkret::AgentParticipation {
                    reply: true,
                    accept_third_party_mention: false,
                    act_on_behalf: false,
                },
            },
        )
        .await?;
    assert!(participation.ok);
    assert_eq!(participation.entries.len(), 1);
    assert!(participation.entries[0].selection.reply);
    Ok(())
}

async fn prepare_agent_controller_recovery(server: &ArkretServer, token: &str) -> Result<()> {
    let principal_id = Did::new(ALICE_DID.to_owned())?;
    let device_id = DeviceId::new(ALICE_DEVICE.to_owned())?;
    let control_realm_id = principal_control_realm_id(&principal_id);
    let typed_control_realm_id = arkret::RealmId::new(control_realm_id.clone())?;
    let trust_domain = TypedTrustDomainId::new(TRUST_DOMAIN.to_owned())?;

    let psk = SigningKey::from_bytes(&[21_u8; 32]);
    let ssk = SigningKey::from_bytes(&[22_u8; 32]);
    let usk = SigningKey::from_bytes(&[23_u8; 32]);
    let device_key = SigningKey::from_bytes(&[24_u8; 32]);
    let root_key = SigningKey::from_bytes(&[32_u8; 32]);
    let enrollment_authority_key = SigningKey::from_bytes(&[17_u8; 32]);
    let enrollment_authority_public =
        ed25519_pubkey_to_did_key_multibase(enrollment_authority_key.verifying_key().as_bytes());
    let enrollment_authority_verification_method =
        did_url(format!("{ALICE_DID}#device-enrollment-authority"))?;
    let next_root = SigningKey::from_bytes(&[33_u8; 32]);
    let next_root_public =
        ed25519_pubkey_to_did_key_multibase(next_root.verifying_key().as_bytes());
    let principal_endpoint = reqwest::Url::parse("https://cotest-agent.example")?;
    let prepared_inception =
        arkret::webvh::prepare_principal_inception(&arkret::webvh::PrincipalInceptionInput {
            principal_endpoint: &principal_endpoint,
            local_id: "alice",
            also_known_as: &["acct:alice@cotest-agent.example".to_owned()],
            version_time: "2026-06-17T00:00:00.000Z".parse()?,
            root_seed: &[32_u8; 32],
            next_root_public_key_multibase: &next_root_public,
            enrollment: arkret::webvh::PrincipalEnrollmentDelegation::SelfAuthority {
                principal_signing_public_key_multibase: &ed25519_pubkey_to_did_key_multibase(
                    psk.verifying_key().as_bytes(),
                ),
                enrollment_public_key_multibase: &enrollment_authority_public,
                principal_signing_fragment: Some("cotest"),
                enrollment_fragment: Some("device-enrollment-authority"),
            },
        })?;
    if prepared_inception.did != ALICE_DID {
        return Err(anyhow!(
            "fixed controller DID drifted: expected {ALICE_DID}, got {}",
            prepared_inception.did
        ));
    }
    let submitted_inception = expect_json(
        server
            .http()
            .post(server.url("/_arkret/root/identity/submit-did-operation"))
            .json(&prepared_inception.submit_body),
        StatusCode::OK,
    )
    .await?;
    if submitted_inception["did"].as_str() != Some(ALICE_DID) {
        return Err(anyhow!(
            "controller DID inception response drifted: {submitted_inception}"
        ));
    }
    let psk_kid = controller_verification_method();
    let ssk_kid = format!("{ALICE_DID}#cotest-ssk");
    let usk_kid = format!("{ALICE_DID}#cotest-usk");
    let control_created_at = canonical_now();
    let control_timestamp_hex = format!("{:012x}", control_created_at.timestamp_millis());
    let root_public_key = ed25519_pubkey_to_did_key_multibase(root_key.verifying_key().as_bytes());
    let root_did = Did::new(format!("did:key:{root_public_key}"))?;
    let root_verification_method = did_url(prepared_inception.root_verification_method.clone())?;
    let root_signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        [32_u8; 32],
        root_did,
        root_verification_method.clone(),
    );
    let event_verification_method = controller_verification_method();
    let mut bootstrap_create = arkret_bootstrap::build_self_principal_pcr_create(
        arkret_bootstrap::SelfPrincipalPcrCreateInput {
            principal_id: principal_id.clone(),
            realm_id: typed_control_realm_id.clone(),
            trust_domain: trust_domain.clone(),
            did_inception_ref: arkret::EventRef::new(
                prepared_inception.version_id.clone(),
                arkret_bootstrap::DID_INCEPTION_REF_ROLE,
            ),
            capability_action_registry_digest: arkret::current_capability_action_registry_digest()?,
            event_id: arkret::EventId::new(
                "ak:event:01904100-0000-7000-8000-00000000a910".to_owned(),
            )?,
            created_at: control_created_at,
            hlc: arkret::Hlc::new(format!("{control_timestamp_hex}-0000-a13f9c2e"))?,
        },
        &cotest::publication::project_cells,
    )?;
    arkret::signatures::sign_event(
        &mut bootstrap_create,
        &root_signer,
        &root_verification_method,
        arkret::signatures::SignEventOptions::new().with_created_at(control_created_at),
    )?;

    let device_public_key =
        ed25519_pubkey_to_did_key_multibase(device_key.verifying_key().as_bytes());
    let enrollment_authorization_ref =
        non_empty(format!("{ALICE_DID}#device-enrollment-authority"))?;
    let bootstrap_authorize_payload = DeviceAuthorizePayload {
        principal_id: principal_id.clone(),
        device_id: device_id.clone(),
        device_public_key: non_empty(device_public_key.clone())?,
        hpke_key: non_empty(TEST_DEVICE_HPKE_KEY)?,
        algorithms: TEST_DEVICE_ALGORITHMS
            .into_iter()
            .map(non_empty)
            .collect::<Result<Vec<_>>>()?,
        device_key_algorithm: Some(non_empty("EdDSA")?),
        authorized_by: DeviceOrPrincipalRef::Did(principal_id.clone()),
        scopes: None,
        not_before: control_created_at,
        expires_at: None,
        device_signature: None,
        proof: None,
        cross_signing_binding: None,
        enrollment_authority_binding: Some(arkret::DeviceEnrollmentAuthorityBinding {
            kind: arkret::DeviceEnrollmentAuthorityBindingKind::ServiceAttested,
            authority_did: principal_id.clone(),
            authorization_ref: enrollment_authorization_ref.clone(),
        }),
        recovery_session_id: None,
    };
    let mut bootstrap_authorize = arkret::Event::new_with_id_at(
        arkret::EventId::new("ak:event:01904100-0000-7000-8000-00000000a911".to_owned())?,
        EventKind::DEVICE_AUTHORIZE,
        arkret_wire::ScopeRef::Realm {
            realm_id: typed_control_realm_id.clone(),
        },
        principal_id.clone(),
        1,
        arkret::Hlc::new(format!("{control_timestamp_hex}-0001-a13f9c2e"))?,
        serde_json::to_value(bootstrap_authorize_payload)?,
        control_created_at,
    )?;
    bootstrap_authorize.prev_refs = vec![bootstrap_create.event_id.clone()];
    bootstrap_authorize.executed_by = Some(principal_id.clone());
    bootstrap_authorize.authorization_ref = Some(enrollment_authorization_ref.to_string());
    let enrollment_authority_signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        [17_u8; 32],
        principal_id.clone(),
        enrollment_authority_verification_method.clone(),
    );
    arkret::signatures::sign_event(
        &mut bootstrap_authorize,
        &enrollment_authority_signer,
        &enrollment_authority_verification_method,
        arkret::signatures::SignEventOptions::new().with_created_at(control_created_at),
    )?;
    let sdk = bearer_sdk_client(server, token)?;
    let bootstrap_submissions = sdk
        .prepare_initial_submissions(&[bootstrap_create.clone(), bootstrap_authorize.clone()])
        .await
        .context("issue principal bootstrap publication evidence")?;
    let bootstrap_submit = sdk
        .events_submit_batch(&bootstrap_submissions)
        .await
        .context("submit principal bootstrap unit")?;
    if !bootstrap_submit
        .accepted
        .contains(&bootstrap_create.event_id)
        || !bootstrap_submit
            .accepted
            .contains(&bootstrap_authorize.event_id)
    {
        return Err(anyhow!(
            "SDK principal bootstrap unit was not accepted: {bootstrap_submit:?}"
        ));
    }
    let seal_signer = arkret_signatures::Ed25519PayloadSigner::new(
        device_key.clone(),
        principal_id.clone(),
        alice_device_verification_method(),
    );
    let controller_seal = arkret_bootstrap::build_self_principal_bootstrap_seal(
        &bootstrap_create,
        &bootstrap_authorize,
        arkret::Hlc::new(format!("{control_timestamp_hex}-0002-a13f9c2e"))?,
        &seal_signer,
        &cotest::publication::project_cells,
    )?;
    let seal_outcome = bearer_sdk_client(server, token)?
        .events_submit_seal(&controller_seal)
        .await?;
    if seal_outcome.seal_id != controller_seal.id {
        return Err(anyhow!(
            "controller PCR Seal id changed at admission: expected {}, got {}",
            controller_seal.id,
            seal_outcome.seal_id
        ));
    }
    let controller_seal_basis = controller_seal.seal_basis();
    CONTROLLER_SEAL_BASES
        .lock()
        .expect("controller Seal basis lock")
        .insert(server.url("/"), controller_seal_basis.clone());
    let controller_frontier = managed_agent_frontier(server, token, &control_realm_id)
        .await?
        .context("principal bootstrap Seal frontier is available")?;

    let key_record = |kid: String, key: &SigningKey| PublishedKey {
        kid: DidUrl::new(kid).unwrap(),
        alg: NonEmptyString::new("EdDSA").unwrap(),
        public_key: NonEmptyString::new(ed25519_pubkey_to_did_key_multibase(
            key.verifying_key().as_bytes(),
        ))
        .unwrap(),
        key_format: KeyFormat::Multibase,
    };
    let ssk_record = key_record(ssk_kid.clone(), &ssk);
    let usk_record = key_record(usk_kid, &usk);
    let mut cross_signing = CrossSigningPublish {
        principal_id: principal_id.clone(),
        trust_domain: trust_domain.clone(),
        principal_signing_key: key_record(psk_kid.as_str().to_owned(), &psk),
        self_signing_key: SubordinateSignedKey {
            kid: ssk_record.kid,
            alg: ssk_record.alg,
            public_key: ssk_record.public_key,
            key_format: ssk_record.key_format,
            binding: SubordinateSignedKeyBinding {
                verification_method: psk_kid.clone(),
                alg: non_empty("EdDSA")?,
                signature: non_empty("pending")?,
            },
        },
        user_signing_key: SubordinateSignedKey {
            kid: usk_record.kid,
            alg: usk_record.alg,
            public_key: usk_record.public_key,
            key_format: usk_record.key_format,
            binding: SubordinateSignedKeyBinding {
                verification_method: psk_kid,
                alg: non_empty("EdDSA")?,
                signature: non_empty("pending")?,
            },
        },
        expected_previous_generation: 0,
        generation: std::num::NonZeroU64::new(1).unwrap(),
        issued_at: canonical_now(),
    };
    cross_signing.self_signing_key.binding.signature = non_empty(sign_ed25519_b64url(
        &psk,
        &cross_signing.self_signing_binding_input()?,
    ))?;
    cross_signing.user_signing_key.binding.signature = non_empty(sign_ed25519_b64url(
        &psk,
        &cross_signing.user_signing_binding_input()?,
    ))?;
    let actor_frontier =
        managed_agent_actor_frontier(server, token, ALICE_DID, &control_realm_id).await?;
    let first_actor_seq = actor_frontier.next_actor_seq;
    let mut cross_signing_event = arkret_event_draft::build_cross_signing_publish_event_at(
        arkret_wire::ScopeRef::Realm {
            realm_id: typed_control_realm_id.clone(),
        },
        principal_id.clone(),
        first_actor_seq,
        arkret::Hlc::new(format!(
            "{control_timestamp_hex}-{:04x}-a13f9c2e",
            first_actor_seq & 0xffff
        ))?,
        cross_signing,
        control_created_at,
    )?;
    cross_signing_event.prev_refs = actor_frontier.frontier_event_ids;
    cross_signing_event.seal_basis = Some(controller_seal_basis.clone());
    let cross_signing_event_id = cross_signing_event.event_id.clone();
    let algorithms = TEST_DEVICE_ALGORITHMS.map(str::to_owned).to_vec();
    let cross_signing_binding = DeviceCrossSigningBinding {
        verification_method: did_url(ssk_kid.to_owned())?,
        alg: non_empty("EdDSA")?,
        ssk_generation: std::num::NonZeroU64::new(1).unwrap(),
        signature: base64_url(sign_ed25519_b64url(
            &ssk,
            &DeviceTrustBinding::canonical_input(
                &principal_id,
                &device_id,
                &device_public_key,
                TEST_DEVICE_HPKE_KEY,
                &algorithms,
                1,
            )?,
        ))?,
    };
    let mut device_authorize = DeviceAuthorizePayload {
        principal_id: principal_id.clone(),
        device_id: device_id.clone(),
        device_public_key: non_empty(device_public_key)?,
        hpke_key: non_empty(TEST_DEVICE_HPKE_KEY)?,
        algorithms: algorithms
            .into_iter()
            .map(non_empty)
            .collect::<Result<Vec<_>>>()?,
        device_key_algorithm: Some(non_empty("EdDSA")?),
        authorized_by: DeviceOrPrincipalRef::DeviceId(device_id),
        scopes: None,
        not_before: canonical_now(),
        expires_at: None,
        device_signature: Some(SignatureMaterial::NonEmptyString(non_empty("pending")?)),
        proof: None,
        cross_signing_binding: Some(cross_signing_binding),
        enrollment_authority_binding: None,
        recovery_session_id: None,
    };
    device_authorize.device_signature = Some(SignatureMaterial::NonEmptyString(non_empty(
        sign_ed25519_b64url(
            &device_key,
            &device_authorize.device_possession_signature_input()?,
        ),
    )?));
    let device_actor_seq = first_actor_seq + 1;
    let mut device_authorize_event = arkret_event_draft::build_device_authorize_event_at(
        arkret_wire::ScopeRef::Realm {
            realm_id: typed_control_realm_id,
        },
        principal_id.clone(),
        device_actor_seq,
        arkret::Hlc::new(format!(
            "{control_timestamp_hex}-{:04x}-a13f9c2e",
            device_actor_seq & 0xffff
        ))?,
        device_authorize,
        control_created_at,
    )?;
    device_authorize_event.prev_refs = vec![cross_signing_event_id.clone()];
    device_authorize_event.seal_basis = Some(controller_seal_basis.clone());
    let device_authorize_event_id = device_authorize_event.event_id.clone();
    let issued_at = canonical_now();
    let signed_fields = RECOVERY_POLICY_SIGNED_FIELDS.map(str::to_owned).to_vec();
    let recovery_material = recovery_key_material()?;
    let (recovery_verification_method, recovery_public_key_multibase) =
        recovery_signing_key_material(&recovery_material)?;
    let recovery_key_agreement_ref = did_url(format!("{ALICE_DID}#backup-hpke-1"))?;
    let mut policy = RecoveryPolicy {
        schema: "ak.schema.recovery_policy.v1".to_owned(),
        policy_id: PolicyId::new(RECOVERY_POLICY_ID.to_owned())?,
        principal_id,
        version: 1,
        supersedes: None,
        trust_domain,
        allowed_proof_kinds: vec![RecoveryProofKind::RecoveryUnlock],
        publication_authorization_rules: vec![RecoveryPublicationAuthorizationRule {
            rule_id: "recovery_unlock".to_owned(),
            proof_kind: RecoveryProofKind::RecoveryUnlock,
            issuer_role: AuthoritySetIssuerRole::IdentityRecovery,
            allowed_actions: vec!["ak.device.reanchor".to_owned()],
            issuers: vec![AuthoritySetIssuer {
                verification_method: recovery_verification_method.clone(),
            }],
            threshold: 1,
        }],
        threshold: None,
        device_quorum: None,
        trusted_recovery_services: None,
        recovery_keys: Some(vec![RecoveryKeyEntry {
            verification_method: recovery_verification_method,
            public_key_multibase: recovery_public_key_multibase,
            key_agreement_ref: recovery_key_agreement_ref.clone(),
            alg: RecoveryKeySignatureAlgorithm::Ed25519,
            not_before: issued_at - TimeDelta::minutes(1),
            expires_at: issued_at + TimeDelta::days(365),
            revoked_at: None,
        }]),
        recovery_key_agreements: Some(vec![RecoveryKeyAgreementEntry {
            key_agreement_ref: recovery_key_agreement_ref,
            alg: RecoveryKeyAgreementAlgorithm::X25519,
            public_key_multibase: non_empty(
                recovery_material.backup_hpke_public_key_multikey.clone(),
            )?,
            hpke_suites: vec![RecoveryHpkeSuite::X25519ChaCha20Poly1305],
            usage: RecoveryKeyAgreementUse::BackupHpke,
            not_before: issued_at - TimeDelta::minutes(1),
            expires_at: issued_at + TimeDelta::days(365),
            revoked_at: None,
        }]),
        approval_requirement: None,
        audit: None,
        issued_at,
        not_before: None,
        expires_at: Some(issued_at + TimeDelta::days(365)),
        auth_data: RecoveryPolicyAuthData {
            verification_method: alice_device_verification_method(),
            signature_algorithm: "Ed25519".to_owned(),
            signature: "pending".to_owned(),
            signed_fields: signed_fields.clone(),
        },
        extra: arkret_wire::XExtensionMap::default(),
    };
    let policy_value = serde_json::to_value(&policy)?;
    let signed_payload = RECOVERY_POLICY_SIGNED_FIELDS
        .into_iter()
        .map(|field| {
            policy_value
                .get(field)
                .cloned()
                .map(|value| (field.to_owned(), value))
                .ok_or_else(|| anyhow!("recovery policy missing signed field {field}"))
        })
        .collect::<Result<serde_json::Map<String, Value>>>()?;
    let transcript = json!({
        "type": RECOVERY_POLICY_SIGNATURE_TYPE,
        "signed_fields": signed_fields,
        "payload": signed_payload,
    });
    policy.auth_data.signature =
        sign_ed25519_b64url(&device_key, &canonical::canonical_json_bytes(&transcript)?);

    let policy_created_at = canonical_now();
    let policy_timestamp_hex = format!("{:012x}", policy_created_at.timestamp_millis());
    let policy_payload = arkret_models_crypto::RecoveryPolicySetPayload {
        policy_id: policy.policy_id.clone(),
        value: policy,
    };
    let mut policy_event = arkret::Event::new_with_id_at(
        arkret::EventId::new("ak:event:01904100-0000-7000-8000-00000000a912".to_owned())?,
        EventKind::POLICY_SET,
        arkret_wire::ScopeRef::Realm {
            realm_id: arkret::RealmId::new(&control_realm_id)?,
        },
        Did::new(ALICE_DID.to_owned())?,
        2,
        arkret::Hlc::new(format!("{policy_timestamp_hex}-{:04x}-a13f9c2e", 2))?,
        serde_json::to_value(policy_payload)?,
        policy_created_at,
    )?;
    policy_event.prev_refs = vec![bootstrap_authorize.event_id.clone()];
    policy_event.seal_basis = Some(controller_seal_basis);
    arkret::signatures::sign_event(
        &mut policy_event,
        &seal_signer,
        &alice_device_verification_method(),
        arkret::signatures::SignEventOptions::new().with_created_at(policy_created_at),
    )?;
    let policy_submission = prepare_controller_initial_submission(
        &sdk,
        &policy_event,
        &psk,
        &event_verification_method,
    )
    .await?;
    let policy_submit = sdk.events_submit(&policy_submission).await?;
    if !policy_submit.accepted.contains(&policy_event.event_id) {
        return Err(anyhow!(
            "SDK recovery-policy Event was not accepted: {policy_submit:?}"
        ));
    }
    let mut policy_seal_hlc = arkret::HlcGenerator::new(
        &control_realm_id,
        ALICE_DEVICE,
        b"cotest-controller-recovery-policy-seal",
    );
    let policy_seal = arkret_bootstrap::build_self_principal_first_successor_seal(
        &bootstrap_create,
        &bootstrap_authorize,
        &policy_event,
        &controller_frontier,
        policy_seal_hlc.generate(),
        &seal_signer,
        &cotest::publication::project_cells,
    )?;
    let policy_seal_outcome = sdk.events_submit_seal(&policy_seal).await?;
    if policy_seal_outcome.seal_id != policy_seal.id {
        return Err(anyhow!(
            "recovery-policy Seal id changed at admission: expected {}, got {}",
            policy_seal.id,
            policy_seal_outcome.seal_id
        ));
    }
    let policy_request =
        arkret_models_crypto::RecoveryPolicyPublishRequest::from(policy_submission);
    let response = server
        .http()
        .post(server.url("/_arkret/root/identity/recovery-policy"))
        .bearer_auth(token)
        .json(&policy_request)
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    if !matches!(status, StatusCode::OK | StatusCode::CREATED) {
        return Err(anyhow!("recovery policy publish returned {status}: {body}"));
    }

    let policy_seal_basis = policy_seal.seal_basis();
    cross_signing_event.actor_seq = 3;
    cross_signing_event.prev_refs = vec![policy_event.event_id.clone()];
    cross_signing_event.seal_basis = Some(policy_seal_basis.clone());
    cross_signing_event.hlc = Some(arkret::Hlc::new(format!(
        "{control_timestamp_hex}-0003-a13f9c2e"
    ))?);
    arkret::signatures::sign_event(
        &mut cross_signing_event,
        &seal_signer,
        &alice_device_verification_method(),
        arkret::signatures::SignEventOptions::new().with_created_at(control_created_at),
    )?;
    let cross_signing_submission = prepare_controller_initial_submission(
        &sdk,
        &cross_signing_event,
        &psk,
        &event_verification_method,
    )
    .await
    .context("issue cross-signing publication evidence")?;
    let cross_signing_submit = sdk
        .events_submit(&cross_signing_submission)
        .await
        .context("submit cross-signing publish")?;
    if !cross_signing_submit
        .accepted
        .contains(&cross_signing_event_id)
    {
        return Err(anyhow!(
            "SDK cross-signing Event was not accepted: {cross_signing_submit:?}"
        ));
    }

    device_authorize_event.actor_seq = 4;
    device_authorize_event.prev_refs = vec![cross_signing_event_id];
    device_authorize_event.seal_basis = Some(policy_seal_basis);
    device_authorize_event.hlc = Some(arkret::Hlc::new(format!(
        "{control_timestamp_hex}-0004-a13f9c2e"
    ))?);
    arkret::signatures::sign_event(
        &mut device_authorize_event,
        &seal_signer,
        &alice_device_verification_method(),
        arkret::signatures::SignEventOptions::new().with_created_at(control_created_at),
    )?;
    let device_authorize_submission = prepare_controller_initial_submission(
        &sdk,
        &device_authorize_event,
        &psk,
        &event_verification_method,
    )
    .await
    .context("issue current-device authorization publication evidence")?;
    let device_authorize_submit = sdk
        .events_submit(&device_authorize_submission)
        .await
        .context("submit current-device authorization")?;
    if !device_authorize_submit
        .accepted
        .contains(&device_authorize_event_id)
    {
        return Err(anyhow!(
            "SDK device-authorize Event was not accepted: {device_authorize_submit:?}"
        ));
    }
    let control_events = sdk.events_query_all_pages(&control_realm_id).await?.events;
    let mut control_seal_hlc = arkret::HlcGenerator::new(
        &control_realm_id,
        ALICE_DEVICE,
        b"cotest-controller-cross-signing-seal",
    );
    let control_seal = arkret_bootstrap::build_self_principal_event_seal(
        &control_events,
        &policy_seal,
        control_seal_hlc.generate(),
        &seal_signer,
        &cotest::publication::project_cells,
    )?;
    let control_seal_outcome = sdk.events_submit_seal(&control_seal).await?;
    if control_seal_outcome.seal_id != control_seal.id {
        return Err(anyhow!(
            "cross-signing Seal id changed at admission: expected {}, got {}",
            control_seal.id,
            control_seal_outcome.seal_id
        ));
    }
    CONTROLLER_SEALS
        .lock()
        .expect("controller Seal lock")
        .insert(server.url("/"), control_seal);
    Ok(())
}

async fn live_cross_signing_recovery_create_request(
    server: &ArkretServer,
    token: &str,
    session: &RecoverySessionState,
    proof_digest: arkret::Hash,
) -> Result<arkret_wire::SecurityTransactionCreateRequest> {
    let principal = Did::new(ALICE_DID.to_owned())?;
    let replacement_device = DeviceId::new(RECOVERY_REPLACEMENT_DEVICE.to_owned())?;
    let device_key = SigningKey::from_bytes(&[25_u8; 32]);
    let device_public_key =
        ed25519_pubkey_to_did_key_multibase(device_key.verifying_key().as_bytes());
    let ssk_key = SigningKey::from_bytes(&[22_u8; 32]);
    let ssk_verification_method = did_url(format!("{ALICE_DID}#cotest-ssk"))?;
    let algorithms = TEST_DEVICE_ALGORITHMS
        .into_iter()
        .map(non_empty)
        .collect::<Result<Vec<_>>>()?;
    let binding_input = DeviceTrustBinding::canonical_input(
        &principal,
        &replacement_device,
        &device_public_key,
        TEST_DEVICE_HPKE_KEY,
        &TEST_DEVICE_ALGORITHMS.map(str::to_owned),
        1,
    )?;
    let mut authorize_payload = DeviceAuthorizePayload {
        principal_id: principal.clone(),
        device_id: replacement_device.clone(),
        device_public_key: non_empty(device_public_key)?,
        hpke_key: non_empty(TEST_DEVICE_HPKE_KEY)?,
        algorithms,
        device_key_algorithm: Some(non_empty("EdDSA")?),
        authorized_by: DeviceOrPrincipalRef::Did(principal.clone()),
        scopes: None,
        not_before: canonical_now(),
        expires_at: None,
        device_signature: None,
        proof: None,
        cross_signing_binding: Some(DeviceCrossSigningBinding {
            verification_method: ssk_verification_method.clone(),
            alg: non_empty("EdDSA")?,
            ssk_generation: std::num::NonZeroU64::new(1).unwrap(),
            signature: Base64UrlString::new(
                URL_SAFE_NO_PAD.encode(ssk_key.sign(&binding_input).to_bytes()),
            )
            .map_err(anyhow::Error::msg)?,
        }),
        enrollment_authority_binding: None,
        recovery_session_id: Some(session.recovery_session_id.clone()),
    };
    authorize_payload.device_signature = Some(SignatureMaterial::NonEmptyString(non_empty(
        URL_SAFE_NO_PAD.encode(
            device_key
                .sign(&authorize_payload.device_possession_signature_input()?)
                .to_bytes(),
        ),
    )?));

    let realm_id = principal_control_realm_id(&principal);
    let frontier = managed_agent_actor_frontier(server, token, ALICE_DID, &realm_id).await?;
    let now = canonical_now();
    let timestamp = format!("{:012x}", now.timestamp_millis());
    let scope_ref = arkret_wire::ScopeRef::Realm {
        realm_id: arkret::RealmId::new(realm_id)?,
    };
    let mut authorize = arkret::Event::new_at(
        EventKind::DEVICE_AUTHORIZE,
        scope_ref.clone(),
        principal.clone(),
        frontier.next_actor_seq,
        arkret::Hlc::new(format!("{timestamp}-0000-a13f9c2e"))?,
        serde_json::to_value(authorize_payload)?,
        now,
    )?;
    authorize.prev_refs = frontier.frontier_event_ids;
    let mut list_update = arkret::Event::new_at(
        EventKind::DEVICE_LIST_UPDATE,
        scope_ref,
        principal.clone(),
        frontier.next_actor_seq + 1,
        arkret::Hlc::new(format!("{timestamp}-0001-a13f9c2e"))?,
        serde_json::to_value(DeviceListUpdatePayload {
            principal_id: principal.clone(),
            changed: Some(vec![replacement_device]),
            left: None,
            device_list_digest: None,
            stream_id: None,
            updated_at: Some(now),
        })?,
        now,
    )?;
    list_update.prev_refs = vec![authorize.event_id.clone()];
    let control_seal = managed_agent_frontier(server, token, authorize.realm_id.as_str())
        .await?
        .ok_or_else(|| anyhow!("recovery principal control Seal frontier is unavailable"))?;
    let seal_basis = control_seal.seal_basis();
    authorize.seal_basis = Some(seal_basis.clone());
    list_update.seal_basis = Some(seal_basis);
    let ssk_signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        [22_u8; 32],
        principal.clone(),
        ssk_verification_method.clone(),
    );
    for event in [&mut authorize, &mut list_update] {
        arkret::signatures::sign_event(
            event,
            &ssk_signer,
            &ssk_verification_method,
            arkret::signatures::SignEventOptions::new().with_created_at(now),
        )?;
    }
    let recovery_signer = inkson::event_signer::build_ed25519_signer_with_verification_method(
        [22_u8; 32],
        ALICE_DID,
        ssk_verification_method.as_str(),
    );
    let authorize_submission =
        inkson::fresh_device_recovery::author_recovery_publication_submission(
            session,
            authorize,
            arkret_models_crypto::RecoveryPublicationAction::DeviceAuthorize,
            &recovery_signer,
            session.requesting_device_id.clone(),
        )?;
    let list_submission = inkson::fresh_device_recovery::author_recovery_publication_submission(
        session,
        list_update,
        arkret_models_crypto::RecoveryPublicationAction::DeviceListUpdate,
        &recovery_signer,
        session.requesting_device_id.clone(),
    )?;
    let request = inkson::fresh_device_recovery::cross_signing_recovery_create_request(
        session,
        proof_digest,
        Did::new(server.service_id().to_owned())?,
        arkret::TransactionId::new(
            "ak:transaction:01975510-0000-7000-8000-0000000000f2".to_owned(),
        )?,
        arkret::ReceiptId::new("ak:receipt:01975510-0000-7000-8000-0000000000f8".to_owned())?,
        std::cmp::min(session.expires_at, Utc::now() + chrono::Duration::hours(1)),
        authorize_submission,
        list_submission,
    )?;
    Ok(arkret_wire::SecurityTransactionCreateRequest::Recovery(
        request,
    ))
}

fn sign_ed25519_b64url(key: &SigningKey, input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(key.sign(input).to_bytes())
}

fn recovery_key_material() -> Result<arkret_crypto::identity_root::IdentityRecoveryKeyMaterial> {
    Ok(
        arkret_crypto::identity_root::derive_identity_recovery_key_material_from_bip39(
            RECOVERY_WORDS,
            "",
            0,
        )?,
    )
}

fn assert_recovery_public_artifacts_contain_no_secret_material(
    artifacts: &[Value],
    material: &arkret_crypto::identity_root::IdentityRecoveryKeyMaterial,
    service_log: Option<&str>,
) -> Result<()> {
    let rendered = artifacts
        .iter()
        .map(serde_json::to_string)
        .collect::<serde_json::Result<Vec<_>>>()?
        .join("\n");
    let mut public_surfaces = vec![("durable HTTP artifacts", rendered.as_str())];
    if let Some(log) = service_log {
        public_surfaces.push(("service log", log));
    }

    let private_values = [
        ("mnemonic", RECOVERY_WORDS.to_owned()),
        ("PRK", URL_SAFE_NO_PAD.encode(material.prk)),
        ("root seed", URL_SAFE_NO_PAD.encode(material.root_seed)),
        (
            "next root seed",
            URL_SAFE_NO_PAD.encode(material.next_root_seed),
        ),
        (
            "recovery proof seed",
            URL_SAFE_NO_PAD.encode(material.recovery_proof_seed),
        ),
        (
            "backup HPKE IKM",
            URL_SAFE_NO_PAD.encode(material.backup_hpke_ikm),
        ),
        (
            "backup HPKE private key",
            URL_SAFE_NO_PAD.encode(material.backup_hpke_serialized_private_key),
        ),
        (
            "replacement signing seed",
            URL_SAFE_NO_PAD.encode([25_u8; 32]),
        ),
    ];
    for (surface_name, surface) in public_surfaces {
        for (secret_name, secret) in &private_values {
            if surface.contains(secret) {
                return Err(anyhow!(
                    "{surface_name} leaked recovery {secret_name} material"
                ));
            }
        }
    }
    Ok(())
}

fn recovery_signing_key_material(
    material: &arkret_crypto::identity_root::IdentityRecoveryKeyMaterial,
) -> Result<(DidUrl, NonEmptyString)> {
    Ok((
        did_url(format!("{ALICE_DID}#recovery-proof-1"))?,
        non_empty(material.recovery_proof_public_key_multikey.clone())?,
    ))
}

fn canonical_now() -> DateTime<Utc> {
    Utc::now()
        .with_nanosecond(0)
        .expect("zero nanoseconds are valid")
}

async fn submit_delegated_agent_event(
    server: &ArkretServer,
    token: &str,
    agent_id: &str,
    realm_id: &str,
    authorization_ref: &str,
    kind: &str,
    payload: Value,
) -> Result<arkret::Event> {
    let mut event = event_envelope(agent_id, realm_id, kind, payload);
    let actor_frontier = managed_agent_actor_frontier(server, token, agent_id, realm_id).await?;
    let actor_seq = actor_frontier.next_actor_seq;
    event["actor_seq"] = json!(actor_seq);
    event["hlc"] = json!(format!("01970e589d21-{:04x}-a13f9c2e", actor_seq & 0xffff));
    event["prev_refs"] = serde_json::to_value(&actor_frontier.frontier_event_ids)?;
    event["executed_by"] = json!(ALICE_DID);
    event["authorization_ref"] = json!(authorization_ref);
    if kind == EventKind::REALM_CREATE {
        if actor_frontier.next_actor_seq != 0 {
            return Err(anyhow!(
                "delegated Realm bootstrap requires an empty actor frontier"
            ));
        }
        event["actor_seq"] = json!(0);
        event["hlc"] = json!("01970e589d21-0001-a13f9c2e");
        event["prev_refs"] = json!([]);
    } else {
        let seal_frontier = managed_agent_frontier(server, token, realm_id)
            .await?
            .ok_or_else(|| anyhow!("delegated Control Move requires an accepted PCR Seal"))?;
        event["seal_basis"] = serde_json::to_value(seal_frontier.seal_basis())?;
    }
    event["proofs"][0]["verification_method"] = json!(controller_verification_method());
    refresh_event_proof_with_signing_seed(&mut event, [21_u8; 32])?;
    let typed_event: arkret::Event = serde_json::from_value(event.clone())?;
    if kind == EventKind::REALM_CREATE {
        arkret_bootstrap::materialize_managed_agent_pcr_control(
            std::slice::from_ref(&typed_event),
            &cotest::publication::project_cells,
        )?;
    } else {
        let sdk = bearer_sdk_client(server, token)?;
        let realm_create = sdk
            .events_query_all_pages(realm_id)
            .await?
            .events
            .into_iter()
            .find(|event| event.kind == EventKind::REALM_CREATE)
            .ok_or_else(|| anyhow!("managed PCR Realm create Event is missing"))?;
        let realm_create_payload = serde_json::to_value(&realm_create.payload)?;
        let notary: arkret_wire::notary::NotaryValue = serde_json::from_value(
            realm_create_payload
                .pointer("/object/notary")
                .cloned()
                .ok_or_else(|| anyhow!("managed PCR Realm notary is missing"))?,
        )?;
        let submission = prepare_initial_submission_for_notary(
            &sdk,
            &typed_event,
            &SigningKey::from_bytes(&[21_u8; 32]),
            &controller_verification_method(),
            &notary,
        )
        .await?;
        let outcome = sdk.events_submit(&submission).await?;
        if !outcome.accepted.contains(&typed_event.event_id) {
            return Err(anyhow!("delegated {kind} was not accepted: {outcome:?}"));
        }
        return Ok(typed_event);
    }
    let body = expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(token)
            .json(&event),
        StatusCode::OK,
    )
    .await?;
    if body["status"] != "accepted" {
        return Err(anyhow!("delegated {kind} was not accepted: {body}"));
    }
    Ok(typed_event)
}

async fn managed_agent_frontier(
    server: &ArkretServer,
    token: &str,
    realm_id: &str,
) -> Result<Option<arkret_models_collaboration::event_sync::RealmSealFrontierView>> {
    let response = server
        .http()
        .get(server.url(&format!(
            "/_arkret/self/events/frontier?realm_id={realm_id}"
        )))
        .bearer_auth(token)
        .send()
        .await?;
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let status = response.status();
    let body = response.text().await?;
    if status == StatusCode::SERVICE_UNAVAILABLE
        && body.contains("\"code\":\"frontier_unavailable\"")
        && (body.contains("no accepted Control Event material")
            || body.contains("no accepted device-signed Seal")
            || body.contains("accepted managed Agent PCR Seal materialization failed"))
    {
        return Ok(None);
    }
    if status != StatusCode::OK {
        return Err(anyhow!("managed Agent frontier returned {status}: {body}"));
    }
    let state: EventsFrontierAccountClientState = serde_json::from_str(&body)?;
    match state.frontier {
        EventsFrontierView::RealmSeal(frontier) => Ok(Some(frontier)),
        EventsFrontierView::RealmActor(_) | EventsFrontierView::ActorAggregate(_) => {
            Err(anyhow!("managed Agent frontier returned a non-Seal view"))
        }
    }
}

async fn managed_agent_actor_frontier(
    server: &ArkretServer,
    token: &str,
    agent_id: &str,
    realm_id: &str,
) -> Result<arkret_models_collaboration::event_sync::RealmActorFrontierView> {
    let response = server
        .http()
        .get(server.url(&format!(
            "/_arkret/self/events/frontier?actor_id={agent_id}&realm_id={realm_id}"
        )))
        .bearer_auth(token)
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    if status != StatusCode::OK {
        return Err(anyhow!(
            "managed Agent actor frontier returned {status}: {body}"
        ));
    }
    let state: EventsFrontierAccountClientState = serde_json::from_str(&body)?;
    match state.frontier {
        EventsFrontierView::RealmActor(frontier) => {
            frontier.validate()?;
            Ok(frontier)
        }
        EventsFrontierView::RealmSeal(_) | EventsFrontierView::ActorAggregate(_) => Err(anyhow!(
            "managed Agent actor frontier returned the wrong frontier variant"
        )),
    }
}

fn managed_agent_seal_basis(server: &ArkretServer, realm_id: &str) -> Result<arkret::SealBasis> {
    let seal_key = format!("{}|{realm_id}", server.base_url());
    MANAGED_AGENT_PCR_SEALS
        .lock()
        .expect("managed Agent PCR Seal lock")
        .get(&seal_key)
        .map(arkret::Seal::seal_basis)
        .ok_or_else(|| anyhow!("managed Agent PCR Seal basis is missing"))
}

async fn pause_agent_runtime<P: PairingOutcome>(
    server: &ArkretServer,
    token: &str,
    pairing: &P,
) -> Result<()> {
    let agent_id = pairing.agent_id().clone();
    let realm_id = pairing.principal_control_realm_id().clone();
    let frontier =
        managed_agent_actor_frontier(server, token, agent_id.as_str(), realm_id.as_str()).await?;
    let actor_seq = frontier.next_actor_seq;
    let changed_at = canonical_now();
    let mut event = arkret_event_draft::build_agent_pause_event(
        agent_id.clone(),
        Did::new(ALICE_DID.to_owned())?,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        did_url(pairing.controller_authorization_ref())?,
        Some("runtime_replacement".to_owned()),
        actor_seq,
        arkret::Hlc::new(format!("01970e589d21-{:04x}-a13f9c2e", actor_seq & 0xffff))?,
        changed_at,
    )?;
    event.prev_refs = frontier.frontier_event_ids;
    event.seal_basis = Some(managed_agent_seal_basis(server, realm_id.as_str())?);
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        [21_u8; 32],
        Did::new(ALICE_DID.to_owned())?,
        controller_verification_method(),
    );
    arkret::signatures::sign_event(
        &mut event,
        &signer,
        &controller_verification_method(),
        arkret::signatures::SignEventOptions::new().with_created_at(changed_at),
    )?;
    let lifecycle_event =
        prepare_managed_agent_submission(server, token, realm_id.as_str(), &event).await?;
    let outcome = bearer_sdk_client(server, token)?
        .agent_pause(
            agent_id.as_str(),
            &arkret::AgentPauseRequestBody {
                reason: Some("runtime_replacement".to_owned()),
                lifecycle_event,
            },
        )
        .await?;
    if outcome.status.as_wire_str() != "paused" {
        return Err(anyhow!(
            "Agent pause returned {}",
            outcome.status.as_wire_str()
        ));
    }
    Ok(())
}

async fn resume_agent_runtime<P: PairingOutcome>(
    server: &ArkretServer,
    token: &str,
    pairing: &P,
) -> Result<()> {
    let agent_id = pairing.agent_id().clone();
    let realm_id = pairing.principal_control_realm_id().clone();
    let frontier =
        managed_agent_actor_frontier(server, token, agent_id.as_str(), realm_id.as_str()).await?;
    let actor_seq = frontier.next_actor_seq;
    let changed_at = canonical_now();
    let mut event = arkret_event_draft::build_agent_resume_event(
        agent_id.clone(),
        Did::new(ALICE_DID.to_owned())?,
        arkret_wire::ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        did_url(pairing.controller_authorization_ref())?,
        None,
        actor_seq,
        arkret::Hlc::new(format!("01970e589d21-{:04x}-a13f9c2e", actor_seq & 0xffff))?,
        changed_at,
    )?;
    event.prev_refs = frontier.frontier_event_ids;
    event.seal_basis = Some(managed_agent_seal_basis(server, realm_id.as_str())?);
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        [21_u8; 32],
        Did::new(ALICE_DID.to_owned())?,
        controller_verification_method(),
    );
    arkret::signatures::sign_event(
        &mut event,
        &signer,
        &controller_verification_method(),
        arkret::signatures::SignEventOptions::new().with_created_at(changed_at),
    )?;
    let lifecycle_event =
        prepare_managed_agent_submission(server, token, realm_id.as_str(), &event).await?;
    let outcome = bearer_sdk_client(server, token)?
        .agent_resume(
            agent_id.as_str(),
            &arkret::AgentResumeRequestBody {
                sidecar_exposure_ack: None,
                lifecycle_event,
            },
        )
        .await?;
    if outcome.status.as_wire_str() != "active" {
        return Err(anyhow!(
            "Agent resume returned {}",
            outcome.status.as_wire_str()
        ));
    }
    Ok(())
}

async fn move_event_after_actor_frontier(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
    event: &mut Value,
) -> Result<()> {
    let realm_id = event["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow!("event realm_id missing before actor-frontier move"))?;
    let frontier = managed_agent_actor_frontier(server, token, actor_id, realm_id).await?;
    let actor_seq = frontier.next_actor_seq;
    event["actor_seq"] = json!(actor_seq);
    event["hlc"] = json!(format!("01970e589d21-{:04x}-a13f9c2e", actor_seq & 0xffff));
    event["prev_refs"] = serde_json::to_value(frontier.frontier_event_ids)?;
    refresh_event_proof_with_signing_seed(event, [21_u8; 32])?;
    Ok(())
}

async fn ensure_agent_pcr_mls<P: PairingOutcome>(
    server: &ArkretServer,
    token: &str,
    provisioned: &P,
) -> Result<(
    arkret_models_collaboration::event_sync::RealmSealFrontierView,
    String,
)> {
    let agent_id = provisioned.agent_id().as_str();
    let realm_id = provisioned.principal_control_realm_id().as_str();
    let group_id = format!("ak:mls_group:{}", realm_id.trim_start_matches("ak:realm:"));
    let stale_seal_ref = bearer_sdk_client(server, token)?
        .agent_get(agent_id)
        .await?
        .key_state
        .and_then(|state| match state.pcr_recovery {
            arkret::AgentPcrRecoveryState::Stale {
                managed_frontier_ref,
                ..
            } => Some(managed_frontier_ref.seal_ref),
            _ => None,
        });
    let mut frontier_before = managed_agent_frontier(server, token, realm_id).await?;
    let mut mls_created = false;
    if frontier_before.is_none() {
        let existing_events = bearer_sdk_client(server, token)?
            .events_query_all_pages(realm_id)
            .await?
            .events;
        let realm_create_event_id = match existing_events
            .iter()
            .find(|event| event.kind == EventKind::REALM_CREATE)
        {
            Some(event) => event.event_id.clone(),
            None => submit_delegated_agent_event(
                server,
                token,
                agent_id,
                realm_id,
                provisioned.controller_authorization_ref(),
                "ak.realm.create",
                json!({
                    "object": {
                        "id": realm_id,
                        "schema": "ak.schema.realm.v1",
                        "title": "Managed Agent Principal Control Realm",
                        "summary": "Controller-managed E2EE continuity for a Native Personal Agent",
                        "created_by": agent_id,
                        "trust_domain": TRUST_DOMAIN,
                        "schema_refs": [
                            "ak.schema.realm.v1",
                            "ak.profile.principal_control_realm.v1"
                        ],
                        "fields": {"purpose": "principal_control"},
                        "default_discoverability": "invite_only",
                        "default_join_rule": "invite",
                        "history_visibility": "restricted",
                        // `realm.schema.json` is closed and declares neither
                        // `history_sharing_policy` nor
                        // `plaintext_visible_services`. A managed Agent PCR
                        // satisfies `restricted` through the profile-fixed
                        // baseline in `ak.profile.principal_control_realm.v1`
                        // (realm-and-space.md §2.8.1), which is why its
                        // single-Event genesis needs no policy Event — and could
                        // not emit one, since the kind is absent from the PCR
                        // event-kind allowlist.
                        "encryption_profile": "mls_rfc9420",
                        "content_encryption_floor": "e2ee_required",
                        "metadata_encryption_floor": "e2ee_required",
                        "security_class": "high_assurance",
                        "federation_policy": "restricted",
                        "notary_profile": "single_did",
                        "digest_algorithm": "sha256",
                        "notary": {
                            "kind": "single_did",
                            "did": agent_id,
                            "recovery_members": [ALICE_DID],
                            "controller_organization": ALICE_DID,
                            "recovery_controller_organizations": [ALICE_DID]
                        },
                        "capability_action_registry_digest":
                            arkret::current_capability_action_registry_digest()
                                .expect("embedded capability-action registry"),
                        "created_at": "2026-05-02T00:00:00.000Z"
                    }
                }),
            )
            .await?
            .event_id,
        };
        let seal_key = format!("{}|{realm_id}", server.base_url());
        let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
            [24_u8; 32],
            Did::new(ALICE_DID.to_owned())?,
            alice_device_verification_method(),
        );
        let mut hlc =
            arkret::HlcGenerator::new(realm_id, ALICE_DEVICE, b"cotest-managed-agent-pcr-seal");
        let client = bearer_sdk_client(server, token)?;
        let realm_events = client.events_query_all_pages(realm_id).await?.events;
        let genesis_seal = arkret_bootstrap::build_managed_agent_pcr_event_seal(
            &realm_events,
            None,
            hlc.generate(),
            &signer,
            &cotest::publication::project_cells,
        )?;
        let outcome = client.events_submit_seal(&genesis_seal).await?;
        if outcome.seal_id != genesis_seal.id {
            return Err(anyhow!(
                "managed Agent PCR genesis Seal id changed at admission: expected {}, got {}",
                genesis_seal.id,
                outcome.seal_id
            ));
        }
        MANAGED_AGENT_PCR_SEALS
            .lock()
            .expect("managed Agent PCR Seal lock")
            .insert(seal_key, genesis_seal.clone());
        frontier_before = managed_agent_frontier(server, token, realm_id).await?;

        if !existing_events
            .iter()
            .any(|event| event.kind == EventKind::MLS_GENESIS)
        {
            submit_delegated_agent_event(
                server,
                token,
                agent_id,
                realm_id,
                provisioned.controller_authorization_ref(),
                "ak.mls.genesis",
                json!({
                    "mls_group_id": group_id,
                    "effective_scope": {"kind": "realm", "realm_id": realm_id},
                    "epoch": 0,
                    "creator_principal_id": agent_id,
                    "creator_device_id": ALICE_DEVICE,
                    "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
                    "group_info_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
                    "ratchet_tree_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
                    "governance_binding": {
                        "binding_version": 1,
                        "encoding_profile": "cbor-deterministic-rfc8949-v1",
                        "realm_id": realm_id,
                        "effective_scope": {"kind": "realm", "realm_id": realm_id},
                        "mls_group_id": group_id,
                        "previous_epoch": 0,
                        "next_epoch": 0,
                        "membership_frontier": [realm_create_event_id],
                        "covered_seal_refs": [genesis_seal.id],
                        "policy_root": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                        "capability_root": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
                        "discussion_metadata_digest": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
                        "binding_profile": "ak.profile.mls_governance_binding.full.v1",
                        "reducer_profile": "ak.reducer.v1"
                    },
                    "created_at": "2026-05-02T00:00:01.000Z"
                }),
            )
            .await?;
            mls_created = true;
        }
    }
    let seal_needs_advancing = mls_created
        || stale_seal_ref.as_deref()
            == frontier_before
                .as_ref()
                .map(|frontier| frontier.seal_id.as_str());
    if seal_needs_advancing {
        let client = bearer_sdk_client(server, token)?;
        let events = client.events_query_all_pages(realm_id).await?.events;
        let seal_key = format!("{}|{realm_id}", server.base_url());
        let predecessor = MANAGED_AGENT_PCR_SEALS
            .lock()
            .expect("managed Agent PCR Seal lock")
            .get(&seal_key)
            .cloned();
        if let (Some(frontier), Some(predecessor)) = (&frontier_before, &predecessor)
            && frontier.seal_id != predecessor.id
        {
            return Err(anyhow!(
                "managed Agent PCR predecessor mismatch: frontier {}, local {}",
                frontier.seal_id,
                predecessor.id
            ));
        }
        let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
            [24_u8; 32],
            Did::new(ALICE_DID.to_owned())?,
            alice_device_verification_method(),
        );
        let mut hlc =
            arkret::HlcGenerator::new(realm_id, ALICE_DEVICE, b"cotest-managed-agent-pcr-seal");
        let seal = arkret_bootstrap::build_managed_agent_pcr_event_seal(
            &events,
            predecessor.as_ref(),
            hlc.generate(),
            &signer,
            &cotest::publication::project_cells,
        )?;
        let outcome = client.events_submit_seal(&seal).await?;
        if outcome.seal_id != seal.id {
            return Err(anyhow!(
                "managed Agent PCR Seal id changed at admission: expected {}, got {}",
                seal.id,
                outcome.seal_id
            ));
        }
        MANAGED_AGENT_PCR_SEALS
            .lock()
            .expect("managed Agent PCR Seal lock")
            .insert(seal_key, seal);
    }
    eventually(
        "managed Agent PCR Seal coverage",
        Duration::from_secs(30),
        Duration::from_millis(250),
        || {
            let stale_seal_ref = stale_seal_ref.clone();
            async move {
                let frontier = managed_agent_frontier(server, token, realm_id)
                    .await?
                    .ok_or_else(|| anyhow!("managed Agent PCR has no Seal"))?;
                if frontier.control_event_set_root.as_str()
                    == "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                {
                    return Err(anyhow!("managed Agent PCR still has an empty Genesis Seal"));
                }
                if stale_seal_ref.as_deref() == Some(frontier.seal_id.as_str()) {
                    return Err(anyhow!("managed Agent PCR Seal has not advanced yet"));
                }
                Ok(())
            }
        },
    )
    .await?;
    let frontier = managed_agent_frontier(server, token, realm_id)
        .await?
        .ok_or_else(|| anyhow!("managed Agent PCR has no Seal after MLS genesis"))?;
    Ok((frontier, group_id))
}

async fn prepare_agent_pcr_recovery<P: PairingOutcome>(
    server: &ArkretServer,
    token: &str,
    provisioned: &P,
) -> Result<()> {
    let existing_recovery = bearer_sdk_client(server, token)?
        .agent_get(provisioned.agent_id().as_str())
        .await?
        .key_state
        .ok_or_else(|| anyhow!("managed Agent key_state is missing"))?
        .pcr_recovery;
    if matches!(
        existing_recovery,
        arkret::AgentPcrRecoveryState::Ready { .. }
    ) {
        return Ok(());
    }
    let (frontier, group_id) = ensure_agent_pcr_mls(server, token, provisioned).await?;
    let sequence = NEXT_AGENT_BACKUP.fetch_add(1, Ordering::Relaxed);
    let backup_id = BackupId::new(format!("ak:backup:019a0000-0000-7000-8000-{sequence:012x}"))?;
    let series_id = BackupSeriesId::new(format!(
        "ak:backup_series:019a0000-0000-7000-8001-{sequence:012x}"
    ))?;
    let pointer_key = format!("{}|{}", server.base_url(), provisioned.agent_id());
    let (series_pointer_version, previous_series_ids) = {
        let pointers = AGENT_BACKUP_POINTERS.lock().expect("backup pointer lock");
        pointers
            .get(&pointer_key)
            .map(|(version, series_ids)| (version + 1, series_ids.clone()))
            .unwrap_or_else(|| (1, Vec::new()))
    };
    let managed_frontier_ref = ManagedFrontierRef {
        frontier_digest: frontier.control_event_set_root.clone(),
        seal_ref: frontier.seal_id.as_str().to_owned(),
        mls_epoch: 0,
    };
    let binding = ManagedPrincipalBinding {
        managed_principal_id: provisioned.agent_id().clone(),
        controller_id: Did::new(ALICE_DID.to_owned())?,
        principal_control_realm_id: provisioned.principal_control_realm_id().clone(),
        authorization_ref: provisioned.controller_authorization_ref().to_owned(),
        managed_frontier_ref,
    };
    let created_at = canonical_now();
    let recipient_key_ref = format!("{ALICE_DID}#backup-hpke-1");
    let device_key = SigningKey::from_bytes(&[24_u8; 32]);
    let device_multibase =
        ed25519_pubkey_to_did_key_multibase(device_key.verifying_key().as_bytes());
    let signed_fields = [
        "backup_id",
        "actor_id",
        "backup_kind",
        "backup_version",
        "series_id",
        "series_seq",
        "encryption",
        "domain_separation",
        "contents",
        "ciphertext_digest",
        "frontier_ref",
        "recovery_policy_ref",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    let mut backup = KeyBackup {
        backup_id: backup_id.clone(),
        actor_id: Did::new(ALICE_DID.to_owned())?,
        device_id: Some(DeviceId::new(ALICE_DEVICE.to_owned())?),
        backup_kind: BackupKind::MlsHistory,
        mixed_secret_storage: false,
        backup_version: "kb_1".to_owned(),
        created_at,
        updated_at: None,
        expires_at: None,
        encryption: KeyBackupEncryption {
            recipient_method: KeyBackupRecipientMethod::RecoveryPublicKey,
            recipient_key_ref: Some(recipient_key_ref.clone()),
            kdf: None,
            aead: KeyBackupAead {
                name: KeyBackupAeadName::Chacha20Poly1305,
                aead_profile: Some("ak.aead.chacha20_poly1305.v1".to_owned()),
                nonce_salt: None,
                nonce: None,
                enc: Some(
                    Base64UrlString::new("Y290ZXN0LW1hbmFnZWQtYWdlbnQtcGNy")
                        .map_err(|error| anyhow!(error))?,
                ),
                extra: Default::default(),
            },
            key_commitment: None,
            hpke_suite: None,
            extra: Default::default(),
        },
        domain_separation: KeyBackupDomainSeparation {
            hkdf_info: "arkret-key-backup/mls_history/managed_agent_pcr/v1".to_owned(),
            subdomain: "managed_agent_pcr".to_owned(),
            aead_aad: KeyBackupDomainSeparationAad {
                schema: "ak.schema.key_backup.v1".to_owned(),
                actor_id: Did::new(ALICE_DID.to_owned())?,
                device_id: Some(ALICE_DEVICE.to_owned()),
                backup_kind: BackupKind::MlsHistory,
                backup_version: "kb_1".to_owned(),
                created_at,
                item_kinds: vec!["mls_group_state".to_owned()],
                managed_principal_bindings: vec![binding.clone()],
                recipient_method: Some(KeyBackupRecipientMethod::RecoveryPublicKey),
                recipient_key_ref: Some(recipient_key_ref.clone()),
                extra: Default::default(),
            },
            extra: Default::default(),
        },
        contents: vec![KeyBackupContentItem {
            item_kind: "mls_group_state".to_owned(),
            realm_id: Some(provisioned.principal_control_realm_id().clone()),
            managed_principal_binding: Some(binding),
            mls_group_id: Some(group_id),
            epoch: Some(0),
            first_event_id: None,
            last_event_id: None,
            secret_id: None,
            secret_version: None,
            extra: Default::default(),
        }],
        ciphertext: "Y290ZXN0LW1hbmFnZWQtYWdlbnQtcGNyLXN0YXRl".to_owned(),
        ciphertext_digest:
            "sha256:2108421084217842908421084210842121084210842178429084210842108421".to_owned(),
        plaintext_commitment: None,
        auth_data: Some(KeyBackupAuthData {
            device_id: DeviceId::new(ALICE_DEVICE.to_owned())?,
            verification_method: DidUrl::new(format!(
                "did:key:{device_multibase}#{device_multibase}"
            ))
            .map_err(|error| anyhow!(error))?,
            signature_algorithm: KeyBackupSignatureAlgorithm::Ed25519,
            signature: Base64UrlString::new("AA").map_err(|error| anyhow!(error))?,
            ssk_generation: std::num::NonZeroU64::new(1),
            device_authorize_event_id: None,
            signed_fields,
            extra: Default::default(),
        }),
        retention: None,
        series_id: series_id.clone(),
        series_seq: 0,
        supersedes: None,
        supersedes_digest: None,
        frontier_ref: Some(KeyBackupFrontierRef {
            frontier_digest: frontier.control_event_set_root.clone(),
            seal_ref: Some(frontier.seal_id.as_str().to_owned()),
            generation: arkret::KeyBackupFrontierGeneration::SskGeneration(
                std::num::NonZeroU64::new(1).expect("non-zero generation"),
            ),
        }),
        recovery_policy_ref: Some(RecoveryPolicyRef {
            policy_id: PolicyId::new(RECOVERY_POLICY_ID.to_owned())?,
            policy_version: 1,
        }),
        extra: Default::default(),
    };
    let mut unsigned = serde_json::to_value(&backup)?;
    unsigned["auth_data"]
        .as_object_mut()
        .ok_or_else(|| anyhow!("key backup auth_data did not serialize as an object"))?
        .remove("signature");
    backup
        .auth_data
        .as_mut()
        .expect("auth_data present")
        .signature = Base64UrlString::new(sign_ed25519_b64url(
        &device_key,
        &canonical::canonical_json_bytes(&unsigned)?,
    ))
    .map_err(|error| anyhow!(error))?;
    let put = expect_json(
        server
            .http()
            .put(server.url(&format!(
                "/_arkret/self/keys/backups/{}",
                backup_id.as_str()
            )))
            .bearer_auth(token)
            .header("Idempotency-Key", format!("agent-pcr-{backup_id}"))
            .json(&backup),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(put["status"], "accepted");

    let controller_realm = principal_control_realm_id(&Did::new(ALICE_DID.to_owned())?);
    let controller_frontier =
        match managed_agent_frontier(server, token, controller_realm.as_str()).await? {
            Some(frontier) => frontier,
            None => {
                let basis = CONTROLLER_SEAL_BASES
                    .lock()
                    .expect("controller Seal basis lock")
                    .get(&server.url("/"))
                    .cloned()
                    .ok_or_else(|| {
                        anyhow!("controller principal-control stream has no accepted Seal")
                    })?;
                arkret_models_collaboration::event_sync::RealmSealFrontierView::new(
                    arkret::RealmId::new(controller_realm)?,
                    basis
                        .leaves
                        .first()
                        .cloned()
                        .ok_or_else(|| anyhow!("controller Seal basis has no leaf"))?,
                    basis.control_event_set_root,
                    basis.state_root,
                    arkret_models_collaboration::event_sync::ControlGovernanceHealth::healthy(),
                    None,
                )
            }
        };
    let mut active_series = json!({
        "schema": "ak.schema.key_backup_active_series.v1",
        "actor_id": ALICE_DID,
        "backup_kind": "mls_history",
        "active_series_id": series_id,
        "series_pointer_version": series_pointer_version,
        "previous_series_ids": previous_series_ids,
        "frontier_ref": {
            "frontier_digest": controller_frontier.control_event_set_root,
            "seal_ref": controller_frontier.seal_id,
            "ssk_generation": 1
        },
        "issued_at": arkret::canonical::format_timestamp_canonical(canonical_now()),
        "auth_data": {
            "verification_method": format!("{ALICE_DID}#{ALICE_DEVICE}"),
            "signature_algorithm": "Ed25519",
            "signature": "pending",
            "signed_fields": [
                "schema",
                "actor_id",
                "backup_kind",
                "active_series_id",
                "series_pointer_version",
                "previous_series_ids",
                "frontier_ref",
                "issued_at"
            ],
            "ssk_generation": 1
        }
    });
    let mut unsigned_active_series = active_series.clone();
    unsigned_active_series["auth_data"]
        .as_object_mut()
        .ok_or_else(|| anyhow!("active series auth_data did not serialize as an object"))?
        .remove("signature");
    active_series["auth_data"]["signature"] = Value::String(sign_ed25519_b64url(
        &device_key,
        &canonical::canonical_json_bytes(&unsigned_active_series)?,
    ));
    let active_series_verification_method = alice_device_verification_method();
    let mut active_series_event =
        cotest::harness::event_envelope_with_signing_seed_and_verification_method(
            ALICE_DID,
            principal_control_realm_id(&Did::new(ALICE_DID.to_owned())?).as_str(),
            "ak.key_backup.active_series",
            active_series,
            [24_u8; 32],
            &active_series_verification_method,
        );
    move_event_after_actor_frontier(server, token, ALICE_DID, &mut active_series_event).await?;
    let controller_realm_id = principal_control_realm_id(&Did::new(ALICE_DID.to_owned())?);
    let controller_frontier = managed_agent_frontier(server, token, &controller_realm_id)
        .await?
        .ok_or_else(|| anyhow!("controller PCR Seal frontier is missing"))?;
    active_series_event["seal_basis"] = serde_json::to_value(controller_frontier.seal_basis())?;
    refresh_event_proof_with_signing_seed(&mut active_series_event, [24_u8; 32])?;
    let active_series_event: arkret::Event = serde_json::from_value(active_series_event)?;
    let sdk = bearer_sdk_client(server, token)?;
    let submission = prepare_controller_initial_submission(
        &sdk,
        &active_series_event,
        &SigningKey::from_bytes(&[21_u8; 32]),
        &controller_verification_method(),
    )
    .await?;
    let outcome = sdk.events_submit(&submission).await?;
    if !outcome.accepted.contains(&active_series_event.event_id) {
        return Err(anyhow!(
            "active backup series Event was not accepted: {outcome:?}"
        ));
    }
    let previous_seal = CONTROLLER_SEALS
        .lock()
        .expect("controller Seal lock")
        .get(&server.url("/"))
        .cloned()
        .ok_or_else(|| anyhow!("controller principal-control stream has no accepted Seal"))?;
    let control_events = sdk
        .events_query_all_pages(controller_realm_id.as_str())
        .await?
        .events;
    let seal_signer = arkret_signatures::Ed25519PayloadSigner::new(
        SigningKey::from_bytes(&[24_u8; 32]),
        Did::new(ALICE_DID.to_owned())?,
        alice_device_verification_method(),
    );
    let mut seal_hlc = arkret::HlcGenerator::new(
        controller_realm_id.as_str(),
        ALICE_DEVICE,
        b"cotest-controller-active-series-seal",
    );
    let active_series_seal = arkret_bootstrap::build_self_principal_event_seal(
        &control_events,
        &previous_seal,
        seal_hlc.generate(),
        &seal_signer,
        &cotest::publication::project_cells,
    )?;
    let seal_outcome = sdk.events_submit_seal(&active_series_seal).await?;
    if seal_outcome.seal_id != active_series_seal.id {
        return Err(anyhow!(
            "active-series Seal id changed at admission: expected {}, got {}",
            active_series_seal.id,
            seal_outcome.seal_id
        ));
    }
    CONTROLLER_SEAL_BASES
        .lock()
        .expect("controller Seal basis lock")
        .insert(server.url("/"), active_series_seal.seal_basis());
    CONTROLLER_SEALS
        .lock()
        .expect("controller Seal lock")
        .insert(server.url("/"), active_series_seal);
    eventually(
        "managed Agent PCR recovery projection",
        Duration::from_secs(30),
        Duration::from_millis(250),
        || async {
            let recovery = bearer_sdk_client(server, token)?
                .agent_get(provisioned.agent_id().as_str())
                .await?
                .key_state
                .ok_or_else(|| anyhow!("managed Agent key_state is missing"))?
                .pcr_recovery;
            if !matches!(recovery, arkret::AgentPcrRecoveryState::Ready { .. }) {
                return Err(anyhow!(
                    "managed Agent PCR recovery is not ready: {recovery:?}"
                ));
            }
            Ok(())
        },
    )
    .await?;
    AGENT_BACKUP_POINTERS
        .lock()
        .expect("backup pointer lock")
        .entry(pointer_key)
        .and_modify(|(version, series_ids)| {
            *version = series_pointer_version;
            series_ids.push(series_id.to_string());
        })
        .or_insert_with(|| (series_pointer_version, vec![series_id.to_string()]));
    Ok(())
}

/// Complete the controller-owned two-phase provisioning protocol. All
/// canonical payloads, nested proof transcripts, effects and Event envelopes
/// come from `arkret-bootstrap`; this fixture only supplies live frontier stamps
/// and transports the typed requests.
async fn provision_agent(
    server: &ArkretServer,
    token: &str,
    display_name: &str,
    slug: &str,
    pairing_ttl_ms: Option<u64>,
) -> Result<arkret::AgentProvisionComplete> {
    let client = bearer_sdk_client(server, token)?;
    let requested_scope = test_agent_requested_scope();
    let prepared = client
        .agent_provision(&arkret::AgentProvisionRequestBody::Prepare {
            display_name: Some(display_name.to_owned()),
            slug: slug.to_owned(),
            avatar_blob_ref: None,
            requested_scope: requested_scope.clone(),
            pairing_ttl_ms,
        })
        .await
        .context("prepare agent provision")?;
    let (
        agent_id,
        principal_control_realm_id,
        controller_realm_id,
        controller_authorization_ref,
        requested_scope_digest,
    ) = match prepared {
        arkret::AgentProvisionOutcome::AwaitingControllerEvents {
            agent_id,
            principal_control_realm_id,
            controller_realm_id,
            controller_authorization_ref,
            requested_scope_digest,
        } => (
            agent_id,
            principal_control_realm_id,
            controller_realm_id,
            controller_authorization_ref,
            requested_scope_digest,
        ),
        unexpected => {
            return Err(anyhow!(
                "agent provision prepare returned an unexpected outcome: {unexpected:?}"
            ));
        }
    };
    let controller_id = arkret::Did::new(ALICE_DID.to_owned())?;
    let expected_scope_digest = arkret_signatures::agent::agent_requested_scope_digest(
        &agent_id,
        &controller_id,
        &requested_scope,
    )?;
    if requested_scope_digest != expected_scope_digest {
        return Err(anyhow!(
            "agent provision prepare returned a mismatched requested_scope_digest"
        ));
    }

    let actor_frontier =
        managed_agent_actor_frontier(server, token, ALICE_DID, controller_realm_id.as_str())
            .await?;
    let actor_seq = actor_frontier.next_actor_seq;
    let now = DateTime::<Utc>::from_timestamp(Utc::now().timestamp(), 0)
        .ok_or_else(|| anyhow!("current timestamp is outside the wire range"))?;
    let timestamp_hex = format!("{:012x}", now.timestamp_millis());
    let verification_method = controller_verification_method();
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        [21_u8; 32],
        controller_id.clone(),
        verification_method.clone(),
    );
    let mut events = arkret_bootstrap::build_agent_provision_event_drafts(
        &controller_id,
        &controller_realm_id,
        &agent_id,
        slug,
        arkret_bootstrap::AgentProvisionEventDraftOptions {
            created_at: now,
            accountability_actor_seq: actor_seq,
            accountability_hlc: arkret::Hlc::new(format!(
                "{timestamp_hex}-{:04x}-a13f9c2e",
                actor_seq & 0xffff
            ))?,
            selector_actor_seq: actor_seq + 1,
            selector_hlc: arkret::Hlc::new(format!(
                "{timestamp_hex}-{:04x}-a13f9c2e",
                (actor_seq + 1) & 0xffff
            ))?,
        },
        &signer,
    )?;
    events.accountability_grant.prev_refs = actor_frontier.frontier_event_ids;
    events.selector_claim.prev_refs = vec![events.accountability_grant.event_id.clone()];
    let realm_seal_basis = CONTROLLER_SEAL_BASES
        .lock()
        .expect("controller Seal basis lock")
        .get(&server.url("/"))
        .cloned()
        .ok_or_else(|| anyhow!("controller Realm Seal basis is missing"))?;
    let device_verification_method = alice_device_verification_method();
    let device_event_signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        [24_u8; 32],
        controller_id.clone(),
        device_verification_method.clone(),
    );
    for event in [&mut events.accountability_grant, &mut events.selector_claim] {
        event.seal_basis = Some(realm_seal_basis.clone());
        event.proofs.clear();
        arkret::signatures::sign_event(
            event,
            &device_event_signer,
            &device_verification_method,
            arkret::signatures::SignEventOptions::new().with_created_at(now),
        )?;
    }
    let provision_event_ids = [
        events.accountability_grant.event_id.clone(),
        events.selector_claim.event_id.clone(),
    ];
    let accountability_grant = prepare_controller_initial_submission(
        &client,
        &events.accountability_grant,
        &SigningKey::from_bytes(&[21_u8; 32]),
        &verification_method,
    )
    .await
    .context("prepare accountability publication evidence")?;
    let selector_claim = prepare_controller_initial_submission(
        &client,
        &events.selector_claim,
        &SigningKey::from_bytes(&[21_u8; 32]),
        &verification_method,
    )
    .await
    .context("prepare selector publication evidence")?;
    let commit = arkret::AgentProvisionRequestBody::Commit {
        agent_id,
        principal_control_realm_id,
        display_name: Some(display_name.to_owned()),
        slug: slug.to_owned(),
        avatar_blob_ref: None,
        requested_scope,
        provision_events: Box::new(arkret::AgentProvisionEvents {
            accountability_grant,
            selector_claim,
        }),
        pairing_ttl_ms,
    };
    let committed = client
        .agent_provision(&commit)
        .await
        .context("commit agent provision")?;
    let retried = client
        .agent_provision(&commit)
        .await
        .context("retry agent provision commit")?;
    if serde_json::to_value(&committed)? != serde_json::to_value(&retried)? {
        return Err(anyhow!(
            "an exact agent provision Commit retry returned a different outcome"
        ));
    }
    let replayed = expect_json(
        server
            .http()
            .get(server.url("/_arkret/self/events"))
            .bearer_auth(token)
            .query(&[("actors", ALICE_DID), ("limit", "100")]),
        StatusCode::OK,
    )
    .await?;
    for event_id in provision_event_ids {
        let event = replayed["events"]
            .as_array()
            .and_then(|events| {
                events
                    .iter()
                    .find(|event| event["event_id"].as_str() == Some(event_id.as_str()))
            })
            .cloned()
            .ok_or_else(|| anyhow!("provision Event {event_id} was not persisted for replay"))?;
        let event: arkret::Event = serde_json::from_value(event)?;
        event.validate_proof_bindings().map_err(|error| {
            anyhow!("replayed provision Event {event_id} failed SDK proof verification: {error}")
        })?;
        let public_key = arkret::signatures::PublicKeyMaterial::Ed25519Raw {
            bytes: SigningKey::from_bytes(&[24_u8; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        };
        let canonical_bytes = arkret::canonical::canonical_json_bytes(&event.digest_payload()?)?;
        arkret::signatures::verify_eddsa_detached_jws_proof(
            event
                .proofs
                .first()
                .ok_or_else(|| anyhow!("replayed provision Event {event_id} has no proof"))?,
            &canonical_bytes,
            &event.actor_id,
            &public_key,
        )?;
    }
    match committed {
        arkret::AgentProvisionOutcome::Complete { outcome } => {
            if outcome.controller_authorization_ref != controller_authorization_ref {
                return Err(anyhow!(
                    "agent provision commit changed controller_authorization_ref"
                ));
            }
            Ok(outcome)
        }
        unexpected => Err(anyhow!(
            "agent provision commit returned an unexpected outcome: {unexpected:?}"
        )),
    }
}

async fn provision_and_pair_agent(
    server: &ArkretServer,
    token: &str,
    display_name: &str,
    slug: &str,
) -> Result<String> {
    let prov = provision_agent(server, token, display_name, slug, None)
        .await
        .context("provision agent")?;
    let agent_did = prov.agent_id.to_string();
    assert!(prov.pairing_code.is_some(), "pairing_code present");
    assert_eq!(
        agent_status(server, token, &agent_did)
            .await
            .context("read pending agent status")?,
        "active"
    );
    assert_eq!(
        agent_runtime_state(server, token, &agent_did)
            .await
            .context("read pending agent runtime_state")?,
        "pending_runtime_key"
    );

    let pair = pair_agent_runtime_key(server, token, &prov)
        .await
        .context("pair agent runtime key")?;
    assert!(
        !pair.authorized_event_ref.as_str().is_empty(),
        "authorized_event_ref present"
    );
    assert_eq!(
        agent_status(server, token, &agent_did)
            .await
            .context("read active agent status")?,
        "active"
    );
    Ok(agent_did)
}

/// Deterministic local runtime key material shared by the pairing and the
/// approval-status tests: verification method, Ed25519 signing key, and the
/// spec-shape OKP public key JWK.
fn runtime_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[13_u8; 32])
}

fn runtime_signing_key_for_fragment(fragment: &str) -> SigningKey {
    match fragment {
        "runtime-key-1" => runtime_signing_key(),
        "runtime-key-2" => SigningKey::from_bytes(&[14_u8; 32]),
        "runtime-key-3" => SigningKey::from_bytes(&[15_u8; 32]),
        _ => SigningKey::from_bytes(&[16_u8; 32]),
    }
}

trait PairingOutcome {
    fn agent_id(&self) -> &arkret::Did;
    fn principal_control_realm_id(&self) -> &arkret::RealmId;
    fn controller_authorization_ref(&self) -> &str;
    fn pairing_request_id(&self) -> &str;
    fn pairing_code(&self) -> Option<&str>;
    fn expires_at(&self) -> chrono::DateTime<Utc>;
}

macro_rules! impl_pairing_outcome {
    ($type:ty) => {
        impl PairingOutcome for $type {
            fn agent_id(&self) -> &arkret::Did {
                &self.agent_id
            }

            fn principal_control_realm_id(&self) -> &arkret::RealmId {
                &self.principal_control_realm_id
            }

            fn controller_authorization_ref(&self) -> &str {
                &self.controller_authorization_ref
            }

            fn pairing_request_id(&self) -> &str {
                &self.pairing_request_id
            }

            fn pairing_code(&self) -> Option<&str> {
                self.pairing_code.as_deref()
            }

            fn expires_at(&self) -> chrono::DateTime<Utc> {
                self.expires_at
            }
        }
    };
}

impl_pairing_outcome!(arkret::AgentProvisionComplete);
impl_pairing_outcome!(arkret::AgentRenewPairingOutcome);

fn runtime_key_request_builder<'a, P: PairingOutcome>(
    server: &ArkretServer,
    provisioned: &P,
    signing_key: &'a SigningKey,
) -> Result<arkret_signatures::agent::RuntimeKeyRequestBuilder<'a>> {
    let pairing_code = provisioned
        .pairing_code()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("pairing_code missing"))?;
    let service_id = arkret::Did::new(server.service_id().to_owned())?;
    let proof_expires_at = std::cmp::min(
        provisioned.expires_at(),
        canonical_now() + chrono::Duration::minutes(4),
    );
    Ok(arkret_signatures::agent::RuntimeKeyRequestBuilder::new(
        signing_key,
        arkret::AgentPairingBootstrap {
            arkret_base_url: server.base_url().to_string(),
            service_id,
            agent_id: provisioned.agent_id().clone(),
            pairing_request_id: opaque_local_id(provisioned.pairing_request_id())?,
            pairing_code,
            pairing_expires_at: provisioned.expires_at(),
        },
    )
    .proof_expires_at(proof_expires_at))
}

/// Build the open `agent_runtime_approval_request_body` a runtime submits to
/// `POST /_arkret/open/agent-pairing/runtime-key-requests`, from the same key
/// material as [`pair_agent_runtime_key`].
fn build_runtime_approval_request<P: PairingOutcome>(
    server: &ArkretServer,
    provisioned: &P,
) -> Result<arkret::AgentRuntimeApprovalRequestBody> {
    let signing_key = runtime_signing_key();
    Ok(
        runtime_key_request_builder(server, provisioned, &signing_key)?
            .verification_method(format!("{}#runtime-key-1", provisioned.agent_id()))
            .build_approval_request()?
            .body,
    )
}

async fn pair_agent_runtime_key<P: PairingOutcome>(
    server: &ArkretServer,
    token: &str,
    provisioned: &P,
) -> Result<arkret::AgentKeyPairOutcome> {
    pair_agent_runtime_key_as(server, token, provisioned, "runtime-key-1").await
}

/// [`pair_agent_runtime_key`] with an explicit verification-method fragment.
/// Runtime replacement re-pairing uses a distinct fragment so the new key is
/// a distinct key id and the pair completion supersedes the old one.
async fn pair_agent_runtime_key_as<P: PairingOutcome>(
    server: &ArkretServer,
    token: &str,
    provisioned: &P,
    fragment: &str,
) -> Result<arkret::AgentKeyPairOutcome> {
    prepare_agent_pcr_recovery(server, token, provisioned).await?;
    let body = build_agent_key_pair_request_as(server, token, provisioned, fragment).await?;
    // `agent_key_pair` drives `ak.gate.account.command.pair_agent_key`, bound to
    // `POST /_arkret/gate/account/agent-key-pair`: the controller submits the
    // durable `ak.agent.key.authorize` event that clears `pending_runtime_key`.
    Ok(bearer_sdk_client(server, token)?
        .agent_key_pair(&body)
        .await?)
}

async fn build_agent_key_pair_request_as<P: PairingOutcome>(
    server: &ArkretServer,
    token: &str,
    provisioned: &P,
    fragment: &str,
) -> Result<arkret::AgentKeyPairRequestBody> {
    build_agent_key_pair_request_with_controller_vm(
        server,
        token,
        provisioned,
        fragment,
        &controller_verification_method(),
        [21_u8; 32],
    )
    .await
}

async fn build_agent_key_pair_request_with_controller_vm<P: PairingOutcome>(
    server: &ArkretServer,
    token: &str,
    provisioned: &P,
    fragment: &str,
    controller_vm: &DidUrl,
    controller_signing_seed: [u8; 32],
) -> Result<arkret::AgentKeyPairRequestBody> {
    let agent_did = provisioned.agent_id().to_string();
    let pairing_request_id = provisioned.pairing_request_id();
    let pairing_code = provisioned
        .pairing_code()
        .ok_or_else(|| anyhow!("pairing_code missing"))?;
    let pairing_expires_at = provisioned.expires_at();
    let agent_id = provisioned.agent_id().clone();
    let controller_id = arkret::Did::new(ALICE_DID.to_owned())
        .map_err(|err| anyhow!("alice did invalid: {err}"))?;
    let signing_key = runtime_signing_key_for_fragment(fragment);
    let verification_method = format!("{agent_did}#{fragment}");
    let builder = runtime_key_request_builder(server, provisioned, &signing_key)?
        .verification_method(verification_method.clone());
    let approval_request = builder.build_approval_request()?.body;
    bearer_sdk_client(server, token)?
        .agent_runtime_approval_request(&approval_request)
        .await?;
    let runtime_public_key_digest = builder.public_key_digest()?;
    let pairing_binding_digest =
        arkret_models_collaboration::agent_operations::agent_key_pairing_request_binding_digest(
            arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
            &controller_id,
            &agent_id,
            &approval_request.pairing_request_id,
            pairing_code,
            pairing_expires_at,
            &arkret::Did::new(server.service_id().to_owned())?,
            &approval_request
                .proof_of_possession
                .runtime_key_binding_digest,
            &approval_request.proof_of_possession,
        )?;
    let issued_at = canonical_now();
    let expires_at = std::cmp::min(pairing_expires_at, issued_at + chrono::Duration::minutes(4));
    let authorize_event_id = arkret::EventId::new(arkret::new_prefixed_uuid7("ak:event:"))?;
    let signing_key_binding = arkret_signatures::agent_evidence::build_agent_signing_key_binding(
        agent_id.clone(),
        arkret::NonEmptyString::new(verification_method.clone())
            .map_err(|reason| anyhow!(reason))?,
        arkret::DidUrl::new(verification_method.clone()).map_err(|reason| anyhow!(reason))?,
        signing_key.verifying_key().to_bytes(),
        authorize_event_id.clone(),
        issued_at,
        Some(expires_at),
        controller_id.clone(),
        controller_vm.clone(),
        &SigningKey::from_bytes(&controller_signing_seed),
    )
    .map_err(|reason| anyhow!(reason.as_str()))?;
    let signing_key_binding_digest =
        arkret_signatures::agent_evidence::agent_signing_key_binding_digest(&signing_key_binding)
            .map_err(|reason| anyhow!(reason.as_str()))?;
    let authorize_payload = arkret::AgentKeyAuthorizePayload {
        agent_id: agent_id.clone(),
        key_id: non_empty(verification_method.clone())?,
        verification_method: did_url(verification_method.clone())?,
        public_key_digest: runtime_public_key_digest,
        signing_key_binding_digest,
        accountable_principal_id: controller_id.clone(),
        agent_key_scope: test_agent_requested_scope(),
        audience: vec![server.service_id().to_owned()],
        issued_at,
        expires_at: Some(expires_at),
        approval_evidence: arkret::AgentKeyApprovalEvidence {
            kind: arkret::AgentKeyApprovalEvidenceKind::PairingRequest,
            evidence_ref: None,
            request_canonical_digest: Some(pairing_binding_digest),
            pairing_request_id: Some(opaque_local_id(pairing_request_id)?),
            approved_by: Some(controller_id.clone()),
        },
        supersedes: bearer_sdk_client(server, token)?
            .agent_get(agent_did.as_str())
            .await?
            .key_state
            .map(|state| {
                state
                    .active_authorizations
                    .into_iter()
                    .map(|authorization| arkret::AgentKeySupersession {
                        key_id: authorization.key_id,
                        authorized_event_ref: authorization.authorized_event_ref,
                    })
                    .collect()
            })
            .unwrap_or_default(),
        revocation_check_ref: None,
        runtime_attestation: None,
    };
    let controller_signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        controller_signing_seed,
        controller_id.clone(),
        controller_vm.clone(),
    );
    let actor_frontier = managed_agent_actor_frontier(
        server,
        token,
        agent_did.as_str(),
        provisioned.principal_control_realm_id().as_str(),
    )
    .await?;
    let actor_seq = actor_frontier.next_actor_seq;
    let mut authorize_event = arkret_event_draft::build_agent_key_authorize_event(
        &authorize_payload,
        authorize_event_id,
        arkret_wire::ScopeRef::Realm {
            realm_id: provisioned.principal_control_realm_id().clone(),
        },
        agent_id.clone(),
        controller_id.clone(),
        did_url(provisioned.controller_authorization_ref())?,
        actor_seq,
        arkret::Hlc::new(format!("01970e589d21-{:04x}-a13f9c2e", actor_seq & 0xffff))?,
    )?;
    authorize_event.prev_refs = actor_frontier.frontier_event_ids;
    authorize_event.seal_basis = Some(managed_agent_seal_basis(
        server,
        provisioned.principal_control_realm_id().as_str(),
    )?);
    authorize_event.created_at = canonical_now();
    authorize_event.proofs.clear();
    arkret::signatures::sign_event(
        &mut authorize_event,
        &controller_signer,
        controller_vm,
        arkret::signatures::SignEventOptions::new().with_created_at(canonical_now()),
    )?;
    let sdk = bearer_sdk_client(server, token)?;
    let realm_create = sdk
        .events_query_all_pages(provisioned.principal_control_realm_id().as_str())
        .await?
        .events
        .into_iter()
        .find(|event| event.kind == EventKind::REALM_CREATE)
        .ok_or_else(|| anyhow!("managed PCR Realm create Event is missing"))?;
    let realm_create_payload = serde_json::to_value(&realm_create.payload)?;
    let notary: arkret_wire::notary::NotaryValue = serde_json::from_value(
        realm_create_payload
            .pointer("/object/notary")
            .cloned()
            .ok_or_else(|| anyhow!("managed PCR Realm notary is missing"))?,
    )?;
    let authorize_submission = prepare_initial_submission_for_notary(
        &sdk,
        &authorize_event,
        &SigningKey::from_bytes(&controller_signing_seed),
        controller_vm,
        &notary,
    )
    .await?;
    let disclosure_issued_at = canonical_now();
    let requested_scope = test_agent_requested_scope();
    let requested_scope_digest = arkret_signatures::agent::agent_requested_scope_digest(
        &agent_id,
        &controller_id,
        &requested_scope,
    )?;
    let pairing_request_uuid = pairing_request_id
        .strip_prefix("agent_pairing_request:")
        .ok_or_else(|| anyhow!("pairing_request_id has an invalid prefix"))?;
    let mut requested_scope_disclosure = arkret::AgentRequestedScopeDisclosure {
        schema: SchemaId::AGENT_REQUESTED_SCOPE_DISCLOSURE_V1.to_owned(),
        request_id: arkret::RequestId::new(format!("ak:request:{pairing_request_uuid}"))?,
        agent_id,
        controller_id,
        requested_scope,
        requested_scope_digest,
        verifier_did: arkret::Did::new(server.service_id().to_owned())?,
        audience: arkret::NonEmptyString::new(
            ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
        )
        .map_err(|reason| anyhow!(reason))?,
        challenge: arkret::NonEmptyString::new(pairing_request_id)
        .map_err(|reason| anyhow!(reason))?,
        issued_at: disclosure_issued_at,
        expires_at: disclosure_issued_at + chrono::Duration::minutes(5),
        proofs: vec![arkret::Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: controller_vm.clone(),
            event_digest: arkret::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            created_at: disclosure_issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "eyJhbGciOiJFZERTQSJ9..AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ".to_owned(),
        }],
    };
    requested_scope_disclosure.proofs[0].event_digest =
        requested_scope_disclosure.payload_digest()?;
    Ok(builder
        .build_key_pair_request(
            requested_scope_disclosure,
            signing_key_binding,
            authorize_submission,
        )?
        .body)
}

async fn agent_status(server: &ArkretServer, token: &str, agent_did: &str) -> Result<String> {
    let list = bearer_sdk_client(server, token)?.agent_list().await?;
    let status = list
        .agents
        .iter()
        .find(|agent| agent.agent_id.as_str() == agent_did)
        .map(|agent| {
            serde_json::to_value(agent.status)
                .ok()
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
                .unwrap_or_default()
        })
        .unwrap_or_default();
    Ok(status)
}

/// The derived runtime readiness axis (key-management.md §3.6.1), orthogonal to
/// the lifecycle intent returned by [`agent_status`].
async fn agent_runtime_state(
    server: &ArkretServer,
    token: &str,
    agent_did: &str,
) -> Result<String> {
    let list = bearer_sdk_client(server, token)?.agent_list().await?;
    let runtime_state = list
        .agents
        .iter()
        .find(|agent| agent.agent_id.as_str() == agent_did)
        .map(|agent| {
            serde_json::to_value(agent.runtime_state)
                .ok()
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
                .unwrap_or_default()
        })
        .unwrap_or_default();
    Ok(runtime_state)
}

async fn prepare_controller_initial_submission(
    sdk: &SdkClient,
    event: &arkret::Event,
    signing_key: &SigningKey,
    verification_method: &DidUrl,
) -> Result<arkret_wire::EventInitialSubmission> {
    let notary = arkret_wire::notary::NotaryValue::single_did(event.actor_id.clone());
    prepare_initial_submission_for_notary(sdk, event, signing_key, verification_method, &notary)
        .await
}

async fn prepare_managed_agent_submission(
    server: &ArkretServer,
    token: &str,
    realm_id: &str,
    event: &arkret::Event,
) -> Result<arkret_wire::EventInitialSubmission> {
    let sdk = bearer_sdk_client(server, token)?;
    let realm_create = sdk
        .events_query_all_pages(realm_id)
        .await?
        .events
        .into_iter()
        .find(|candidate| candidate.kind == EventKind::REALM_CREATE)
        .ok_or_else(|| anyhow!("managed PCR Realm create Event is missing"))?;
    let realm_create_payload = serde_json::to_value(&realm_create.payload)?;
    let notary: arkret_wire::notary::NotaryValue = serde_json::from_value(
        realm_create_payload
            .pointer("/object/notary")
            .cloned()
            .ok_or_else(|| anyhow!("managed PCR Realm notary is missing"))?,
    )?;
    prepare_initial_submission_for_notary(
        &sdk,
        event,
        &SigningKey::from_bytes(&[21_u8; 32]),
        &controller_verification_method(),
        &notary,
    )
    .await
}

async fn grant_controller_strand_create(
    server: &ArkretServer,
    token: &str,
    actor_client: &cotest::harness::TestActorClient,
    realm_id: &str,
) -> Result<()> {
    let grant_id = arkret::GrantId::new(arkret::new_prefixed_uuid7("ak:grant:"))?;
    let issued_at = canonical_now();
    let mut grant = arkret::CapabilityGrant {
        id: grant_id.clone(),
        schema: "ak.schema.capability.v1".to_owned(),
        realm_id: Some(arkret::RealmId::new(realm_id.to_owned())?),
        issuer: Did::new(ALICE_DID.to_owned())?,
        subject: arkret::CapabilitySubject::Did(Did::new(ALICE_DID.to_owned())?),
        actions: vec!["ak.strand.create".to_owned()],
        capability_action_registry_digest: Some(
            arkret::current_capability_action_registry_digest()?
        ),
        resources: vec![serde_json::from_value(json!({
            "kind": "realm",
            "realm_id": realm_id,
            "match_scope": "realm_wide"
        }))?],
        constraints: Vec::new(),
        issuer_authority_refs: vec![arkret::IssuerAuthorityRef::RealmRoot {
            realm_id: arkret_identifiers::RealmId::new(realm_id.to_string())?,
            cell_ref: "ak:cell:ak.component.realm.authority_root.v1:null".to_owned(),
            controller_epoch_at_issuance: 0,
            authority_generation: 0,
        }],
        issued_at,
        not_before: None,
        expires_at: None,
        updated_by: None,
        updated_at: None,
        revoked_by: None,
        revoked_at: None,
        proofs: Vec::new(),
        authority_depth: None,
        authority_root_refs: Vec::new(),
    };
    let mut proof = arkret::PayloadProof {
        kind: "detached_jws".to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: controller_verification_method(),
        payload_digest: grant.payload_digest()?,
        created_at: issued_at,
        domain: None,
        audience: None,
        proof_purpose: Some(arkret::PayloadProofPurpose::IssuerAttestation),
        jws: String::new(),
    };
    proof.jws = arkret_signatures::sign_eddsa_detached_jws(
        &SigningKey::from_bytes(&[21_u8; 32]),
        &grant.canonical_proof_binding_bytes(&proof)?,
    )?;
    grant.proofs.push(proof);
    let mut event_value = actor_client
        .author_event(
            realm_id,
            "ak.capability.grant",
            json!({
                "grant_id": grant_id,
                "grant": grant
            }),
        )
        .await?;
    refresh_event_proof_with_signing_seed(&mut event_value, [21_u8; 32])?;
    let event: arkret::Event = serde_json::from_value(event_value)?;
    let submission = actor_client
        .sdk()
        .prepare_initial_submissions(std::slice::from_ref(&event))
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("controller Strand-create capability submission is missing"))?;
    let outcome = actor_client.sdk().events_submit(&submission).await?;
    if !outcome.accepted.contains(&event.event_id) {
        return Err(anyhow!(
            "controller Strand-create capability was not accepted: {outcome:?}"
        ));
    }
    let predecessor_seal = event
        .seal_basis
        .as_ref()
        .and_then(|basis| basis.leaves.first())
        .cloned()
        .ok_or_else(|| anyhow!("capability Event has no predecessor Seal"))?;
    eventually(
        "controller Strand-create capability Seal",
        Duration::from_secs(30),
        Duration::from_millis(250),
        || async {
            let response = server
                .http()
                .get(server.url("/_arkret/self/events/frontier"))
                .query(&[("realm_id", realm_id)])
                .bearer_auth(token)
                .send()
                .await?;
            if !response.status().is_success() {
                return Err(anyhow!("capability Seal frontier is not ready"));
            }
            let state: EventsFrontierAccountClientState = response.json().await?;
            let EventsFrontierView::RealmSeal(frontier) = state.frontier else {
                return Err(anyhow!("capability Seal returned the wrong frontier"));
            };
            if frontier.seal_id == predecessor_seal {
                return Err(anyhow!("capability Event is not sealed yet"));
            }
            Ok(())
        },
    )
    .await
}

async fn prepare_initial_submission_for_notary(
    sdk: &SdkClient,
    event: &arkret::Event,
    signing_key: &SigningKey,
    verification_method: &DidUrl,
    notary: &arkret_wire::notary::NotaryValue,
) -> Result<arkret_wire::EventInitialSubmission> {
    let request = arkret_wire::AuthorizationLeaseIssueRequest {
        events: vec![event.clone()],
        intents: Vec::new(),
    };
    let request_key = arkret_wire::new_prefixed_uuid7("lease-");
    let options = arkret_http_client::ClientRequestOptions::new()
        .request_id(request_key.clone())
        .idempotency_key(request_key);
    let lease = sdk
        .issue_authorization_leases(&request, &options)
        .await?
        .authorization_leases
        .into_iter()
        .next()
        .context("authorization lease issuer returned no lease")?;

    let policy = arkret_wire::ControlProposalDecisionPolicy::default();
    let received_at = canonical_now();
    let proposal_digest = arkret_identifiers::Hash::new(event.event_digest()?)?;
    let authority_set_ref = arkret_identifiers::Hash::new(canonical::canonical_sha256(notary)?)?;
    let mut member_receipt = arkret_wire::ProposalMemberReceipt {
        realm_id: event.realm_id.clone(),
        proposal_digest: proposal_digest.clone(),
        received_at,
        decision_due_at: received_at + policy.decision_window,
        absolute_due_at: received_at + policy.absolute_horizon,
        authority_set_ref: authority_set_ref.clone(),
        signature: arkret_wire::PayloadSignature {
            alg: "EdDSA".to_owned(),
            verification_method: verification_method.clone(),
            extra: Default::default(),
            payload_digest: arkret_identifiers::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            created_at: received_at,
            jws: String::new(),
        },
    };
    let signing_bytes = member_receipt.canonical_bytes_for_signature()?;
    member_receipt.signature.payload_digest = member_receipt.member_receipt_digest()?;
    member_receipt.signature.jws =
        arkret_signatures::jws::sign_jws_ed25519(&signing_bytes, signing_key)
            .map_err(anyhow::Error::msg)?;
    let control_proposal_receipt = arkret_wire::ControlProposalReceipt {
        kind: arkret_wire::ControlProposalReceiptKind::ProposalReceipt,
        realm_id: event.realm_id.clone(),
        proposal_digest,
        received_at,
        decision_due_at: received_at + policy.decision_window,
        absolute_due_at: received_at + policy.absolute_horizon,
        defer_count: 0,
        authority_set_ref,
        member_receipts: vec![member_receipt],
    };
    control_proposal_receipt.validate_structural(policy)?;
    let submission = arkret_wire::EventInitialSubmission {
        event: event.clone(),
        authorization_lease: lease,
        cba_proof_bundles: Vec::new(),
        control_proposal_receipt: Some(control_proposal_receipt),
    };
    submission.validate_structural()?;
    Ok(submission)
}

fn bearer_sdk_client(server: &ArkretServer, token: &str) -> Result<SdkClient> {
    Ok(ClientBuilder::new(server.base_url())
        .allow_insecure_localhost()
        .auth(Auth::Bearer(token.to_owned()))
        .build()?)
}

fn expect_sdk_api_error<T>(
    result: arkret_http_client::Result<T>,
    status: StatusCode,
    code: &str,
) -> Result<()> {
    match result {
        Err(ArkretError::Api {
            status: actual_status,
            error,
        }) => {
            assert_eq!(
                actual_status,
                status.as_u16(),
                "expected SDK API status {status}, got {actual_status}: {error:?}"
            );
            assert_eq!(
                error.code(),
                code,
                "expected SDK API error code {code}, got {error:?}"
            );
            Ok(())
        }
        Err(error) => Err(anyhow!(
            "expected SDK API error {status}/{code}, got {error}"
        )),
        Ok(_) => Err(anyhow!(
            "expected SDK API error {status}/{code}, got success"
        )),
    }
}

fn advance_event_sequence(actor: &str, realm_id: &str, count: usize) {
    for _ in 0..count {
        let _ = event_envelope(
            actor,
            realm_id,
            "ak.message.create",
            json!({"body": "sequence padding"}),
        );
    }
}
