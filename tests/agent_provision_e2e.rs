//! Personal AI Agent provisioning -> pairing -> lifecycle, driven live against
//! a spawned soland in development mode (AKP-0008, spec_section_11 live leg).
//!
//! Exercises controller-authored provisioning through the public agent HTTP
//! surface. The test obtains server-allocated coordinates, asks the SDK to
//! build and sign the closed Event pair, then commits that pair through the
//! ordinary admission pipeline:
//!   1. `ak.self.agent.command.provision` prepare + commit -> `pending_runtime_key` + pairing.
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
use arkret_core::{
    BackupClass, BackupId, BackupSeriesId, Base64UrlString, CrossSigningPublish,
    DeviceAuthorizePayload, DeviceCrossSigningBinding, DeviceId, DeviceOrPrincipalRef, Did, DidUrl,
    EventsFrontierAccountClientState, EventsFrontierView, KeyBackup, KeyBackupAead,
    KeyBackupAeadName, KeyBackupAuthData, KeyBackupContentItem, KeyBackupDomainSeparation,
    KeyBackupDomainSeparationAad, KeyBackupEncryption, KeyBackupFrontierRef,
    KeyBackupRecipientMethod, KeyBackupSignatureAlgorithm, KeyFormat, ManagedFrontierRef,
    ManagedPrincipalBinding, NonEmptyString, PolicyId, PublishedKey, RecoveryHpkeSuite,
    RecoveryKeyAgreementAlgorithm, RecoveryKeyAgreementEntry, RecoveryKeyAgreementUse,
    RecoveryKeyEntry, RecoveryKeySignatureAlgorithm, RecoveryPolicy, RecoveryPolicyAuthData,
    RecoveryPolicyRef, RecoveryProofKind, SignatureMaterial, SubordinateSignedKey,
    SubordinateSignedKeyBinding, TypedTrustDomainId, canonical,
    ed25519_pubkey_to_did_key_multibase, principal_control_realm_id,
};
use arkret_crypto::DeviceTrustBinding;
use arkret_http_client::{Auth, Client as SdkClient, ClientBuilder, Error as ArkretError};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, TimeDelta, Timelike as _, Utc};
use cotest::harness::{
    ArkretServer, create_realm_with_signing_seed, event_envelope, eventually, expect_json,
    refresh_event_proof_with_signing_seed, register_account, submit_event_with_signing_seed,
};
use ed25519_dalek::{Signer as _, SigningKey};
use reqwest::StatusCode;
use serde_json::{Value, json};
use serial_test::serial;

const ALICE_DID: &str =
    "did:webvh:QmPgnKLR8FfoCkXfTYK1eB5Q9rUT3Uws4b9mLKRRWwQRnr:cotest-agent.example:webvh:alice";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000a901";
const TRUST_DOMAIN: &str = "ak:trust_domain:soland.local";
const RECOVERY_POLICY_SIGNATURE_TYPE: &str = "ak.identity.recovery_policy.signature.v1";
const RECOVERY_POLICY_SIGNED_FIELDS: [&str; 11] = [
    "schema",
    "policy_id",
    "principal_id",
    "version",
    "trust_domain",
    "allowed_proof_kinds",
    "recovery_keys",
    "recovery_key_agreements",
    "supersedes",
    "issued_at",
    "expires_at",
];
const TEST_DEVICE_ALGORITHMS: [&str; 2] = ["ak.hpke_x25519_aead_chacha20poly1305.v1", "ak.mls.v1"];
const TEST_DEVICE_HPKE_KEY: &str = "z6LSCotestAgentDeviceHpkeKey";
const RECOVERY_POLICY_ID: &str = "ak:policy:019a0000-0000-7000-8000-00000000a901";
static NEXT_AGENT_BACKUP: AtomicUsize = AtomicUsize::new(1);
type AgentBackupPointer = (u64, Vec<String>);

static AGENT_BACKUP_POINTERS: LazyLock<Mutex<HashMap<String, AgentBackupPointer>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static CONTROLLER_SEAL_BASES: LazyLock<Mutex<HashMap<String, arkret::SealBasis>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static MANAGED_AGENT_PCR_SEALS: LazyLock<Mutex<HashMap<String, arkret::Seal>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn non_empty(value: impl Into<String>) -> Result<NonEmptyString> {
    NonEmptyString::new(value).map_err(anyhow::Error::msg)
}

fn did_url(value: impl Into<String>) -> Result<DidUrl> {
    DidUrl::new(value).map_err(anyhow::Error::msg)
}

fn base64_url(value: impl Into<String>) -> Result<Base64UrlString> {
    Base64UrlString::new(value).map_err(anyhow::Error::msg)
}

fn controller_verification_method() -> String {
    format!("{ALICE_DID}#cotest")
}

fn test_agent_requested_scope() -> arkret::AgentKeyScope {
    let service_actions = [
        "ak.self.events.stream.subscribe",
        "ak.self.events.query.scan",
        "ak.self.events.command.submit",
    ];
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

    // 1-2. provision -> pending_runtime_key + pairing material -> active.
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
    let strand_id = realm_id.replace("ak:realm:", "ak:strand:");
    let strand = submit_event_with_signing_seed(
        &server,
        &token,
        ALICE_DID,
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
        StatusCode::OK,
        [21_u8; 32],
    )
    .await?;
    assert_eq!(strand["status"], "accepted");

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
                    parent_grant_id: None,
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
    // Lazy expiry flips the projected status on first observation.
    assert_eq!(
        agent_status(&server, &token, &agent_did).await?,
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
    assert_eq!(
        agent_status(&server, &token, &agent_did).await?,
        "pending_runtime_key"
    );

    let stale = pair_agent_runtime_key(&server, &token, &prov).await;
    assert!(stale.is_err(), "expired pairing handle must remain dead");
    let paired = pair_agent_runtime_key(&server, &token, &renewed).await?;
    assert!(!paired.authorized_event_ref.as_str().is_empty());
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");

    // Runtime replacement requires an explicit pause. Pairing supersedes the
    // old runtime key while the principal stays paused until an explicit resume.
    pause_agent_runtime(&server, &token, &renewed).await?;
    let replacement = controller
        .agent_renew_pairing(&agent_did, &arkret::AgentRenewPairingRequestBody::default())
        .await?;
    assert_eq!(replacement.agent_id.to_string(), agent_did);
    assert_ne!(replacement.pairing_request_id, renewed.pairing_request_id);
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "paused");
    let stale = pair_agent_runtime_key(&server, &token, &renewed).await;
    assert!(stale.is_err(), "superseded pairing handle must remain dead");
    let replaced =
        pair_agent_runtime_key_as(&server, &token, &replacement, "runtime-key-2").await?;
    assert_ne!(replaced.authorized_event_ref, paired.authorized_event_ref);
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "paused");
    resume_agent_runtime(&server, &token, &replacement).await?;
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");

    pause_agent_runtime(&server, &token, &replacement).await?;
    let short_lived = controller
        .agent_renew_pairing(
            &agent_did,
            &arkret::AgentRenewPairingRequestBody {
                pairing_ttl_ms: Some(1),
            },
        )
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "paused");
    assert!(
        pair_agent_runtime_key_as(&server, &token, &short_lived, "runtime-key-3")
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
    let status_body = arkret::models::AgentRuntimeApprovalStatusRequestBody {
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
    assert_eq!(
        status.status,
        arkret::models::AgentStatus::PendingRuntimeKey
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
        arkret::models::AgentStatus::PendingRuntimeKey
    );
    assert_eq!(
        status.approval_request_id.as_deref(),
        Some(submitted.approval_request_id.as_str())
    );

    // 3. Anti-enumeration: a wrong pairing_code is indistinguishable from an unknown
    //    pairing_request_id.
    let wrong_code = arkret::models::AgentRuntimeApprovalStatusRequestBody {
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
    assert_eq!(status.status, arkret::models::AgentStatus::Active);
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
    assert_eq!(
        agent_status(&server, &token, provisioned.agent_id.as_str()).await?,
        "pending_runtime_key",
        "a rejected recovery gate must not activate or consume the pairing"
    );

    // Publishing the current backup does not advance the Agent PCR frontier,
    // so the exact same controller-signed request and pairing handle must now
    // succeed.
    prepare_agent_pcr_recovery(&server, &token, &provisioned).await?;
    let outcome = controller.agent_key_pair(&body).await?;
    assert_eq!(
        outcome.authorized_event_ref, body.authorize_event.event_id,
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
async fn agent_legacy_participation_command_fails_closed_e2e() -> Result<()> {
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
        .await;
    expect_sdk_api_error(
        participation,
        StatusCode::NOT_IMPLEMENTED,
        "controller_signed_event_required",
    )?;
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
        format!("{ALICE_DID}#device-enrollment-authority");
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
    let root_verification_method = prepared_inception.root_verification_method.clone();
    let root_signer = arkret_signatures::Ed25519MoveSigner::from_did_key_seed(
        [32_u8; 32],
        root_did,
        root_verification_method.clone(),
    );
    let event_verification_method = controller_verification_method();
    let event_signer = arkret_signatures::Ed25519MoveSigner::from_did_key_seed(
        [21_u8; 32],
        principal_id.clone(),
        event_verification_method.clone(),
    );

    let mut bootstrap_create = arkret::identity::build_self_principal_pcr_create(
        arkret::identity::SelfPrincipalPcrCreateInput {
            principal_id: principal_id.clone(),
            realm_id: typed_control_realm_id.clone(),
            trust_domain: trust_domain.clone(),
            did_inception_ref: arkret::EventRef::new(
                prepared_inception.version_id.clone(),
                arkret::identity::DID_INCEPTION_REF_ROLE,
            ),
            event_id: arkret::EventId::new(
                "ak:event:01904100-0000-7000-8000-00000000a910".to_owned(),
            )?,
            created_at: control_created_at,
            hlc: arkret::Hlc::new(format!("{control_timestamp_hex}-0000-a13f9c2e"))?,
        },
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
        arkret::events::EventKind::DEVICE_AUTHORIZE,
        typed_control_realm_id.clone(),
        principal_id.clone(),
        1,
        arkret::Hlc::new(format!("{control_timestamp_hex}-0001-a13f9c2e"))?,
        serde_json::to_value(bootstrap_authorize_payload)?,
        control_created_at,
    )?;
    bootstrap_authorize.prev_refs = vec![bootstrap_create.event_id.clone()];
    bootstrap_authorize.executed_by = Some(principal_id.clone());
    bootstrap_authorize.authorization_ref = Some(enrollment_authorization_ref.to_string());
    let enrollment_authority_signer = arkret_signatures::Ed25519MoveSigner::from_did_key_seed(
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
    let bootstrap_submit = bearer_sdk_client(server, token)?
        .events_submit_batch(&[bootstrap_create.clone(), bootstrap_authorize.clone()])
        .await?;
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
    let seal_signer = arkret_signatures::Ed25519MoveSigner::new(
        device_key.clone(),
        principal_id.clone(),
        format!("{ALICE_DID}#{ALICE_DEVICE}"),
    );
    let controller_seal = arkret::identity::build_self_principal_bootstrap_seal(
        &bootstrap_create,
        &bootstrap_authorize,
        arkret::Hlc::new(format!("{control_timestamp_hex}-0002-a13f9c2e"))?,
        &seal_signer,
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

    let key_record = |kid: String, key: &SigningKey| PublishedKey {
        kid: NonEmptyString::new(kid).unwrap(),
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
        principal_signing_key: key_record(psk_kid.clone(), &psk),
        self_signing_key: SubordinateSignedKey {
            kid: ssk_record.kid,
            alg: ssk_record.alg,
            public_key: ssk_record.public_key,
            key_format: ssk_record.key_format,
            binding: SubordinateSignedKeyBinding {
                verification_method: non_empty(psk_kid.clone())?,
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
                verification_method: non_empty(psk_kid)?,
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
    let first_actor_seq = actor_frontier.actor_seq + 1;
    let mut cross_signing_event = arkret::build_cross_signing_publish_event_at(
        typed_control_realm_id.clone(),
        principal_id.clone(),
        first_actor_seq,
        arkret::Hlc::new(format!(
            "{control_timestamp_hex}-{:04x}-a13f9c2e",
            first_actor_seq & 0xffff
        ))?,
        cross_signing,
        control_created_at,
    )?;
    cross_signing_event.prev_refs = actor_frontier.event_id.into_iter().collect();
    cross_signing_event.seal_basis = Some(controller_seal_basis.clone());
    arkret::signatures::sign_event(
        &mut cross_signing_event,
        &event_signer,
        &event_verification_method,
        arkret::signatures::SignEventOptions::new().with_created_at(control_created_at),
    )?;
    let cross_signing_event_id = cross_signing_event.event_id.clone();
    let cross_signing_submit = bearer_sdk_client(server, token)?
        .events_submit(&cross_signing_event)
        .await?;
    if !cross_signing_submit
        .accepted
        .contains(&cross_signing_event_id)
    {
        return Err(anyhow!(
            "SDK cross-signing Event was not accepted: {cross_signing_submit:?}"
        ));
    }

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
    let mut device_authorize_event = arkret::build_device_authorize_event_at(
        typed_control_realm_id,
        principal_id.clone(),
        device_actor_seq,
        arkret::Hlc::new(format!(
            "{control_timestamp_hex}-{:04x}-a13f9c2e",
            device_actor_seq & 0xffff
        ))?,
        device_authorize,
        control_created_at,
    )?;
    device_authorize_event.prev_refs = vec![cross_signing_event_id];
    device_authorize_event.seal_basis = Some(controller_seal_basis);
    arkret::signatures::sign_event(
        &mut device_authorize_event,
        &event_signer,
        &event_verification_method,
        arkret::signatures::SignEventOptions::new().with_created_at(control_created_at),
    )?;
    let device_authorize_event_id = device_authorize_event.event_id.clone();
    let device_authorize_submit = bearer_sdk_client(server, token)?
        .events_submit(&device_authorize_event)
        .await?;
    if !device_authorize_submit
        .accepted
        .contains(&device_authorize_event_id)
    {
        return Err(anyhow!(
            "SDK device-authorize Event was not accepted: {device_authorize_submit:?}"
        ));
    }

    eventually(
        "controller device authorization projection",
        Duration::from_secs(30),
        Duration::from_millis(250),
        || async {
            let response = server
                .http()
                .get(server.url("/_arkret/self/account/viewer"))
                .bearer_auth(token)
                .send()
                .await?;
            if response.status() != StatusCode::OK {
                return Err(anyhow!("account viewer returned {}", response.status()));
            }
            let body: Value = response.json().await?;
            let active = body["devices"].as_array().is_some_and(|devices| {
                devices.iter().any(|device| {
                    device["device_id"] == ALICE_DEVICE && device["status"] == "active"
                })
            });
            if active {
                Ok(())
            } else {
                Err(anyhow!("controller device is not active yet: {body}"))
            }
        },
    )
    .await?;

    let issued_at = canonical_now();
    let signed_fields = RECOVERY_POLICY_SIGNED_FIELDS.map(str::to_owned).to_vec();
    let (recovery_verification_method, recovery_public_key_multibase) =
        recovery_signing_key_material()?;
    let recovery_key_agreement_ref = did_url(format!("{ALICE_DID}#backup-hpke-1"))?;
    let mut policy = RecoveryPolicy {
        schema: "ak.schema.recovery_policy.v1".to_owned(),
        policy_id: PolicyId::new(RECOVERY_POLICY_ID.to_owned())?,
        principal_id,
        version: 1,
        supersedes: None,
        trust_domain,
        allowed_proof_kinds: vec![RecoveryProofKind::RecoveryUnlock],
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
            public_key_multibase: non_empty("z6LSriWhVBzW9Vz2PvqbieSz7Aa2hPLzTKJuDwXTMKFeomeW")?,
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
            verification_method: format!("{ALICE_DID}#{ALICE_DEVICE}"),
            signature_algorithm: "Ed25519".to_owned(),
            signature: "pending".to_owned(),
            signed_fields: signed_fields.clone(),
        },
        extra: arkret_core::XExtensionMap::default(),
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

    let response = server
        .http()
        .post(server.url("/_arkret/root/identity/recovery-policy"))
        .bearer_auth(token)
        .json(&policy)
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    if !matches!(status, StatusCode::OK | StatusCode::CREATED) {
        return Err(anyhow!("recovery policy publish returned {status}: {body}"));
    }
    Ok(())
}

fn sign_ed25519_b64url(key: &SigningKey, input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(key.sign(input).to_bytes())
}

fn recovery_signing_key_material() -> Result<(DidUrl, NonEmptyString)> {
    let recovery_key = SigningKey::from_bytes(&[25_u8; 32]);
    let multibase = ed25519_pubkey_to_did_key_multibase(recovery_key.verifying_key().as_bytes());
    Ok((
        did_url(format!("{ALICE_DID}#recovery-proof-1"))?,
        non_empty(multibase)?,
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
    let actor_seq = actor_frontier.actor_seq + 1;
    event["actor_seq"] = json!(actor_seq);
    event["hlc"] = json!(format!("01970e589d21-{:04x}-a13f9c2e", actor_seq & 0xffff));
    event["prev_refs"] = actor_frontier
        .event_id
        .as_ref()
        .map(|event_id| json!([event_id]))
        .unwrap_or_else(|| json!([]));
    event["executed_by"] = json!(ALICE_DID);
    event["authorization_ref"] = json!(authorization_ref);
    if kind == arkret::events::EventKind::REALM_CREATE {
        let typed_realm_id = arkret::RealmId::new(realm_id.to_owned())?;
        if actor_frontier.actor_seq != 0 {
            return Err(anyhow!(
                "delegated Realm bootstrap requires an empty actor frontier"
            ));
        }
        event["actor_seq"] = json!(1);
        event["hlc"] = json!("01970e589d21-0001-a13f9c2e");
        event["prev_refs"] = json!([]);
        event["effects"] = serde_json::to_value(vec![
            arkret::identity::managed_agent_principal_control_create_effect(&typed_realm_id, 1)?,
        ])?;
    }
    event["proofs"][0]["verification_method"] = json!(controller_verification_method());
    refresh_event_proof_with_signing_seed(&mut event, [21_u8; 32])?;
    let typed_event: arkret::Event = serde_json::from_value(event.clone())?;
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
) -> Result<Option<arkret_core::RealmSealFrontierView>> {
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
        EventsFrontierView::RealmSealView(frontier) => Ok(Some(frontier)),
        EventsFrontierView::Actor(_) => Err(anyhow!("managed Agent frontier returned actor view")),
    }
}

async fn managed_agent_actor_frontier(
    server: &ArkretServer,
    token: &str,
    agent_id: &str,
    realm_id: &str,
) -> Result<arkret_core::ActorFrontierView> {
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
        EventsFrontierView::Actor(frontier) => {
            frontier.validate()?;
            Ok(frontier)
        }
        EventsFrontierView::RealmSealView(_) => {
            Err(anyhow!("managed Agent actor frontier returned Realm view"))
        }
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
    let actor_seq = frontier.actor_seq + 1;
    let changed_at = canonical_now();
    let mut event = arkret::agent::build_agent_pause_event(
        agent_id.clone(),
        Did::new(ALICE_DID.to_owned())?,
        realm_id.clone(),
        pairing.controller_authorization_ref(),
        Some("runtime_replacement".to_owned()),
        actor_seq,
        arkret::Hlc::new(format!("01970e589d21-{:04x}-a13f9c2e", actor_seq & 0xffff))?,
        changed_at,
    )?;
    event.prev_refs = frontier.event_id.into_iter().collect();
    event.seal_basis = Some(managed_agent_seal_basis(server, realm_id.as_str())?);
    let signer = arkret_signatures::Ed25519MoveSigner::from_did_key_seed(
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
    let outcome = bearer_sdk_client(server, token)?
        .agent_pause(
            agent_id.as_str(),
            &arkret::AgentPauseRequestBody {
                reason: Some("runtime_replacement".to_owned()),
                lifecycle_event: event,
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
    let actor_seq = frontier.actor_seq + 1;
    let changed_at = canonical_now();
    let mut event = arkret::agent::build_agent_resume_event(
        agent_id.clone(),
        Did::new(ALICE_DID.to_owned())?,
        realm_id.clone(),
        pairing.controller_authorization_ref(),
        None,
        actor_seq,
        arkret::Hlc::new(format!("01970e589d21-{:04x}-a13f9c2e", actor_seq & 0xffff))?,
        changed_at,
    )?;
    event.prev_refs = frontier.event_id.into_iter().collect();
    event.seal_basis = Some(managed_agent_seal_basis(server, realm_id.as_str())?);
    let signer = arkret_signatures::Ed25519MoveSigner::from_did_key_seed(
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
    let outcome = bearer_sdk_client(server, token)?
        .agent_resume(
            agent_id.as_str(),
            &arkret::AgentResumeRequestBody {
                sidecar_exposure_ack: None,
                lifecycle_event: event,
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
    let actor_seq = frontier.actor_seq + 1;
    event["actor_seq"] = json!(actor_seq);
    event["hlc"] = json!(format!("01970e589d21-{:04x}-a13f9c2e", actor_seq & 0xffff));
    event["prev_refs"] = frontier
        .event_id
        .map(|event_id| json!([event_id]))
        .unwrap_or_else(|| json!([]));
    refresh_event_proof_with_signing_seed(event, [21_u8; 32])?;
    Ok(())
}

async fn ensure_agent_pcr_mls<P: PairingOutcome>(
    server: &ArkretServer,
    token: &str,
    provisioned: &P,
) -> Result<(arkret_core::RealmSealFrontierView, String)> {
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
    let frontier_before = managed_agent_frontier(server, token, realm_id).await?;
    if frontier_before.is_none() {
        let existing_events = bearer_sdk_client(server, token)?
            .events_query_all_pages(realm_id)
            .await?
            .events;
        let realm_create_event_id = match existing_events
            .iter()
            .find(|event| event.kind == arkret::events::EventKind::REALM_CREATE)
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
                        "history_sharing_policy": {
                            "version": 1,
                            "default_key_share": "deny",
                            "pre_join_history": "deny",
                            "allowed_key_sources": ["key_backup"],
                            "allowed_receiver_states": ["active_member"],
                            "audit": {
                                "share_audit_event_required": true,
                                "access_audit_required": true
                            }
                        },
                        "encryption_profile": "mls_rfc9420",
                        "content_encryption_floor": "e2ee_required",
                        "metadata_encryption_floor": "e2ee_required",
                        "plaintext_visible_services": [],
                        "security_class": "high_assurance",
                        "federation_policy": "restricted",
                        "notary_profile": "single_did",
                        "digest_algorithm": "sha256",
                        "notary": {
                            "type": "single_did",
                            "did": agent_id,
                            "recovery_members": [ALICE_DID],
                            "controller_organization": ALICE_DID,
                            "recovery_controller_organizations": [ALICE_DID]
                        },
                        "created_at": "2026-05-02T00:00:00.000Z"
                    }
                }),
            )
            .await?
            .event_id,
        };
        if !existing_events
            .iter()
            .any(|event| event.kind == arkret::events::EventKind::MLS_GENESIS)
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
        }
    }
    let seal_needs_advancing = frontier_before.is_none()
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
        let signer = arkret_signatures::Ed25519MoveSigner::from_did_key_seed(
            [24_u8; 32],
            Did::new(ALICE_DID.to_owned())?,
            format!("{ALICE_DID}#{ALICE_DEVICE}"),
        );
        let mut hlc =
            arkret::HlcGenerator::new(realm_id, ALICE_DEVICE, b"cotest-managed-agent-pcr-seal");
        let seal = arkret::identity::build_managed_agent_pcr_event_seal(
            &events,
            predecessor.as_ref(),
            hlc.generate(),
            &signer,
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
        "backup_class",
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
        backup_class: BackupClass::MlsHistory,
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
                backup_class: BackupClass::MlsHistory,
                backup_version: "kb_1".to_owned(),
                created_at,
                item_types: vec!["mls_group_state".to_owned()],
                managed_principal_bindings: vec![binding.clone()],
                recipient_method: Some(KeyBackupRecipientMethod::RecoveryPublicKey),
                recipient_key_ref: Some(recipient_key_ref.clone()),
                extra: Default::default(),
            },
            extra: Default::default(),
        },
        contents: vec![KeyBackupContentItem {
            item_type: "mls_group_state".to_owned(),
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
                arkret_core::RealmSealFrontierView {
                    realm_id: arkret::RealmId::new(controller_realm)?,
                    seal_id: basis
                        .leaves
                        .first()
                        .cloned()
                        .ok_or_else(|| anyhow!("controller Seal basis has no leaf"))?,
                    control_event_set_root: basis.control_event_set_root,
                    state_root: basis.state_root,
                    hlc: None,
                }
            }
        };
    let mut active_series = json!({
        "schema": "ak.schema.key_backup_active_series.v1",
        "actor_id": ALICE_DID,
        "backup_class": "mls_history",
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
            "verification_method": format!("did:key:{device_multibase}#{device_multibase}"),
            "signature_algorithm": "Ed25519",
            "signature": "pending",
            "signed_fields": [
                "schema",
                "actor_id",
                "backup_class",
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
    let mut active_series_event = event_envelope(
        ALICE_DID,
        principal_control_realm_id(&Did::new(ALICE_DID.to_owned())?).as_str(),
        "ak.key_backup.active_series",
        active_series,
    );
    move_event_after_actor_frontier(server, token, ALICE_DID, &mut active_series_event).await?;
    expect_json(
        server
            .http()
            .post(server.url("/_arkret/self/events"))
            .bearer_auth(token)
            .json(&active_series_event),
        StatusCode::OK,
    )
    .await?;
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
/// come from `arkret::agent`; this fixture only supplies live frontier stamps
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
    let expected_scope_digest =
        arkret::agent_requested_scope_digest(&agent_id, &controller_id, &requested_scope)?;
    if requested_scope_digest != expected_scope_digest {
        return Err(anyhow!(
            "agent provision prepare returned a mismatched requested_scope_digest"
        ));
    }

    let actor_frontier =
        managed_agent_actor_frontier(server, token, ALICE_DID, controller_realm_id.as_str())
            .await?;
    let actor_seq = actor_frontier.actor_seq + 1;
    let now = DateTime::<Utc>::from_timestamp(Utc::now().timestamp(), 0)
        .ok_or_else(|| anyhow!("current timestamp is outside the wire range"))?;
    let timestamp_hex = format!("{:012x}", now.timestamp_millis());
    let verification_method = controller_verification_method();
    let signer = arkret_signatures::Ed25519MoveSigner::from_did_key_seed(
        [21_u8; 32],
        controller_id.clone(),
        verification_method.clone(),
    );
    let mut events = arkret::agent::build_agent_provision_event_drafts(
        &controller_id,
        &controller_realm_id,
        &agent_id,
        slug,
        arkret::agent::AgentProvisionEventDraftOptions {
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
    events.accountability_grant.prev_refs = actor_frontier.event_id.into_iter().collect();
    events.selector_claim.prev_refs = vec![events.accountability_grant.event_id.clone()];
    let realm_seal_basis = CONTROLLER_SEAL_BASES
        .lock()
        .expect("controller Seal basis lock")
        .get(&server.url("/"))
        .cloned()
        .ok_or_else(|| anyhow!("controller Realm Seal basis is missing"))?;
    for event in [&mut events.accountability_grant, &mut events.selector_claim] {
        event.seal_basis = Some(realm_seal_basis.clone());
        arkret::signatures::sign_event(
            event,
            &signer,
            &verification_method,
            arkret::signatures::SignEventOptions::new().with_created_at(now),
        )?;
    }
    let provision_event_ids = [
        events.accountability_grant.event_id.clone(),
        events.selector_claim.event_id.clone(),
    ];
    let commit = arkret::AgentProvisionRequestBody::Commit {
        agent_id,
        principal_control_realm_id,
        display_name: Some(display_name.to_owned()),
        slug: slug.to_owned(),
        avatar_blob_ref: None,
        requested_scope,
        provision_events: Box::new(events),
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
            bytes: SigningKey::from_bytes(&[21_u8; 32])
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
) -> Result<arkret::agent::RuntimeKeyRequestBuilder<'a>> {
    let pairing_code = provisioned
        .pairing_code()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("pairing_code missing"))?;
    let service_id = arkret::Did::new(server.service_id().to_owned())?;
    let proof_expires_at =
        chrono::DateTime::parse_from_rfc3339("2999-01-01T00:00:00.000Z")?.with_timezone(&Utc);
    Ok(arkret::agent::RuntimeKeyRequestBuilder::new(
        signing_key,
        arkret::AgentPairingBootstrap {
            arkret_base_url: server.base_url().to_string(),
            service_id,
            agent_id: provisioned.agent_id().clone(),
            pairing_request_id: provisioned.pairing_request_id().to_owned(),
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
    let agent_did = provisioned.agent_id().to_string();
    let pairing_request_id = provisioned.pairing_request_id();
    let pairing_code = provisioned
        .pairing_code()
        .ok_or_else(|| anyhow!("pairing_code missing"))?;
    let pairing_expires_at =
        arkret::canonical::format_timestamp_canonical(provisioned.expires_at());
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
    let pairing_binding_digest = arkret::agent_key_pairing_request_binding_digest(
        &controller_id,
        &agent_id,
        &verification_method,
        &runtime_public_key_digest,
        pairing_request_id,
        pairing_code,
        &pairing_expires_at,
        server.service_id(),
    )?;
    let authorize_payload = arkret::AgentKeyAuthorizePayload {
        agent_id: agent_id.clone(),
        key_id: verification_method.clone(),
        verification_method: verification_method.clone(),
        public_key_digest: Some(runtime_public_key_digest),
        accountable_principal_id: controller_id.clone(),
        agent_key_scope: test_agent_requested_scope(),
        audience: vec![server.service_id().to_owned()],
        issued_at: canonical_now(),
        expires_at: Some(
            chrono::DateTime::parse_from_rfc3339("2999-01-01T00:00:00.000Z")?.with_timezone(&Utc),
        ),
        approval_evidence: arkret::AgentKeyApprovalEvidence {
            kind: arkret::AgentKeyApprovalEvidenceKind::PairingRequest,
            evidence_ref: None,
            request_canonical_digest: Some(pairing_binding_digest),
            pairing_request_id: Some(pairing_request_id.to_owned()),
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
    let controller_signer = arkret_signatures::Ed25519MoveSigner::from_did_key_seed(
        [21_u8; 32],
        controller_id.clone(),
        controller_verification_method(),
    );
    let actor_frontier = managed_agent_actor_frontier(
        server,
        token,
        agent_did.as_str(),
        provisioned.principal_control_realm_id().as_str(),
    )
    .await?;
    let actor_seq = actor_frontier.actor_seq + 1;
    let mut authorize_event = arkret::agent::build_agent_key_authorize_event(
        &authorize_payload,
        provisioned.principal_control_realm_id().clone(),
        agent_id.clone(),
        controller_id.clone(),
        provisioned.controller_authorization_ref(),
        actor_seq,
        arkret::Hlc::new(format!("01970e589d21-{:04x}-a13f9c2e", actor_seq & 0xffff))?,
    )?;
    authorize_event.prev_refs = actor_frontier.event_id.into_iter().collect();
    authorize_event.created_at = canonical_now();
    authorize_event.proofs.clear();
    arkret::signatures::sign_event(
        &mut authorize_event,
        &controller_signer,
        &controller_verification_method(),
        arkret::signatures::SignEventOptions::new().with_created_at(canonical_now()),
    )?;
    let disclosure_issued_at = canonical_now();
    let requested_scope = test_agent_requested_scope();
    let requested_scope_digest =
        arkret::agent_requested_scope_digest(&agent_id, &controller_id, &requested_scope)?;
    let pairing_request_uuid = pairing_request_id
        .strip_prefix("agent_pairing_request:")
        .ok_or_else(|| anyhow!("pairing_request_id has an invalid prefix"))?;
    let mut requested_scope_disclosure = arkret::AgentRequestedScopeDisclosure {
        schema: arkret::AGENT_REQUESTED_SCOPE_DISCLOSURE_SCHEMA.to_owned(),
        request_id: arkret::RequestId::new(format!("ak:request:{pairing_request_uuid}"))?,
        agent_id,
        controller_id,
        requested_scope,
        requested_scope_digest,
        verifier_did: arkret::Did::new(server.service_id().to_owned())?,
        audience: arkret::NonEmptyString::new(
            arkret::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
        )
        .map_err(|reason| anyhow!(reason))?,
        challenge: arkret::NonEmptyString::new(pairing_request_id)
        .map_err(|reason| anyhow!(reason))?,
        issued_at: disclosure_issued_at,
        expires_at: disclosure_issued_at + chrono::Duration::minutes(5),
        proofs: vec![arkret::Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: controller_verification_method(),
            event_digest: arkret::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            created_at: disclosure_issued_at,
            domain: None,
            audience: None,
            jws: "eyJhbGciOiJFZERTQSJ9..AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ".to_owned(),
        }],
    };
    requested_scope_disclosure.proofs[0].event_digest =
        requested_scope_disclosure.payload_digest()?;
    Ok(builder
        .build_key_pair_request(requested_scope_disclosure, authorize_event)?
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
