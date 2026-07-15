//! Personal AI Agent provisioning -> pairing -> lifecycle, driven live against
//! a spawned soland in development mode (AKP-0008, spec_section_11 live leg).
//!
//! Exercises the dev-mode server-authored fan-out (architecture option B) end
//! to end through the public agent HTTP surface:
//!   1. `ak.self.agent.command.provision` -> `pending_runtime_key` + pairing.
//!   2. `ak.gate.account.command.pair_agent_key` -> durable `ak.agent.key.authorize`, status ->
//!      `active` without changing Realm grants.
//!   3. grant attach / detach -> durable `ak.capability.grant` / `ak.capability.revoke`.
//!   4. pause / resume / deactivate -> durable lifecycle events flip status.
//!
//! `ArkretServer::spawn` builds / locates the sibling `soland` binary and runs
//! it in development mode. The agent endpoints internally author their durable
//! fan-out events, so this test needs no client-side event signing.
//!
//! The second test also drives the cross-service session leg by presenting a
//! DPoP-bound `agent_key_proof` session grant and backing soland with a local
//! introspection service.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};
use arkret_core::{
    BackupClass, BackupId, BackupSeriesId, Base64UrlString, CrossSigningPublish,
    DeviceAuthorizePayload, DeviceCrossSigningBinding, DeviceId, DeviceOrPrincipalRef, Did, DidUrl,
    Error as ArkretError, EventsFrontierAccountClientState, EventsFrontierView,
    EventsSubscribeFrameKind, KeyBackup, KeyBackupAead, KeyBackupAeadName, KeyBackupAuthData,
    KeyBackupContentItem, KeyBackupDomainSeparation, KeyBackupDomainSeparationAad,
    KeyBackupEncryption, KeyBackupFrontierRef, KeyBackupRecipientMethod,
    KeyBackupSignatureAlgorithm, KeyFormat, ManagedFrontierRef, ManagedPrincipalBinding,
    NonEmptyString, PolicyId, PublishedKey, RecoveryHpkeSuite, RecoveryKeyAgreementAlgorithm,
    RecoveryKeyAgreementEntry, RecoveryKeyAgreementUse, RecoveryKeyEntry,
    RecoveryKeySignatureAlgorithm, RecoveryPolicy, RecoveryPolicyAuthData, RecoveryPolicyRef,
    RecoveryProofKind, SignatureMaterial, SubordinateSignedKey, SubordinateSignedKeyBinding,
    TypedTrustDomainId, canonical, ed25519_pubkey_to_did_key_multibase, principal_control_realm_id,
};
use arkret_crypto::DeviceTrustBinding;
use arkret_http_client::{Auth, Client as SdkClient, ClientBuilder, EventsSubscribeOptions};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, SecondsFormat, TimeDelta, Timelike as _, Utc};
use cotest::harness::{
    ArkretServer, add_member, create_realm, event_envelope, eventually, expect_json,
    refresh_event_proof, register_account, submit_event,
};
use cotest::scenarios::_helpers::mock_http::{self, MockServer};
use ed25519_dalek::{Signer as _, SigningKey};
use reqwest::StatusCode;
use salvo::affix_state;
use salvo::prelude::{Depot, Json, Request, Response, Router, handler};
use serde_json::{Value, json};
use serial_test::serial;
use sha2::{Digest, Sha256};

const ALICE_DID: &str = "did:key:z6MktojHN9D8obak7C9wjpTzCRrdE5zC6cxt5ANUFnQskgbs";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000a901";
const AGENT_SESSION_GRANT: &str = "cotest.agent.session.grant";
const INTROSPECTION_BEARER: &str = "cotest-introspection-bearer";
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
static AGENT_BACKUP_POINTERS: LazyLock<Mutex<HashMap<String, (u64, Vec<String>)>>> =
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
    let token = register_account(&server, ALICE_DID, "@cotest-agent-alice", ALICE_DEVICE).await?;
    prepare_agent_controller_recovery(&server, &token).await?;

    // 1-2. provision -> pending_runtime_key + pairing material -> active.
    let agent_did =
        provision_and_pair_agent(&server, &token, "Summary Assistant", "summary").await?;
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");

    advance_event_sequence(
        ALICE_DID,
        "ak:realm:01999999-0000-7000-8000-000000000000",
        32,
    );
    let realm_id = create_realm(&server, &token, ALICE_DID, "Sidecar profile projection").await?;
    let strand_id = realm_id.replace("ak:realm:", "ak:strand:");
    let strand = submit_event(
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
                "created_at": "2026-05-02T00:00:00Z",
                "metadata": {"title": "Sidecar context"}
            }
        }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(strand["status"], "accepted");

    let controller = bearer_sdk_client(&server, &token)?;
    let sidecar = controller
        .agent_sidecar_thread_ensure(&arkret::AgentSidecarThreadEnsureRequestBody {
            controller_id: arkret::Did::new(ALICE_DID)?,
            addressed_agent_ids: Vec::new(),
            context_ref: arkret::AgentSidecarContextRef::strand(
                arkret::RealmId::new(realm_id.clone())?,
                arkret::StrandId::new(strand_id)?,
            ),
        })
        .await?;
    assert!(sidecar.ok, "live Sidecar ensure must succeed");
    expect_sdk_api_error(
        controller
            .circle_get(sidecar.private_circle_id.as_str())
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    )?;
    let ordinary_circles = controller.circle_list(&realm_id).await?;
    assert!(
        ordinary_circles
            .circles
            .iter()
            .all(|circle| circle.circle_id != sidecar.private_circle_id),
        "ordinary Circle list must not enumerate Sidecar-profile Circles"
    );

    // 3. grant attach/detach must materialize into the authz projection.
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
                        verification_method: format!("{ALICE_DID}#cotest"),
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
        .await?;
    let grant_id = attach.grant_id.to_string();
    let effective_after_attach = effective_grants(&server, &token, &realm_id, &agent_did).await?;
    assert!(
        grant_exists_in(&effective_after_attach, &grant_id),
        "attached grant must appear in effective grants: {effective_after_attach}"
    );

    let grant_id = arkret::GrantId::new(grant_id)?;
    let detach = controller.agent_grant_detach(&agent_did, &grant_id).await?;
    assert!(detach.ok, "grant detach must succeed");
    let effective_after_detach = effective_grants(&server, &token, &realm_id, &agent_did).await?;
    assert!(
        !grant_exists_in(&effective_after_detach, grant_id.as_str()),
        "detached grant must disappear from effective grants: {effective_after_detach}"
    );

    // 4. lifecycle transitions land durable events + flip projected status.
    for (path, expect) in [
        ("pause", "paused"),
        ("resume", "active"),
        ("deactivate", "deactivated"),
    ] {
        let outcome = match path {
            "pause" => {
                controller
                    .agent_pause(&agent_did, &arkret::AgentPauseRequestBody { reason: None })
                    .await?
            }
            "resume" => {
                controller
                    .agent_resume(
                        &agent_did,
                        &arkret::AgentResumeRequestBody {
                            sidecar_exposure_ack: None,
                        },
                    )
                    .await?
            }
            "deactivate" => {
                controller
                    .agent_deactivate(
                        &agent_did,
                        &arkret::AgentDeactivateRequestBody { reason: None },
                    )
                    .await?
            }
            _ => unreachable!(),
        };
        assert!(outcome.ok, "lifecycle {path} must succeed");
        assert_eq!(
            agent_status(&server, &token, &agent_did).await?,
            expect,
            "status after {path}"
        );
    }

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
    let prov = controller
        .agent_provision(&arkret::AgentProvisionRequestBody {
            display_name: Some("Renewal Assistant".to_owned()),
            slug: "renewal".to_owned(),
            avatar_blob_ref: None,
            requested_scope: test_agent_requested_scope(),
            accountability: None,
            pairing_ttl_ms: Some(1),
        })
        .await?;
    let agent_did = prov.agent_id.to_string();
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    // Lazy expiry flips the projected status on first observation.
    assert_eq!(
        agent_status(&server, &token, &agent_did).await?,
        "pairing_expired"
    );

    // Renewal: same principal, fresh handle, status back to pending.
    let renewed = controller
        .agent_renew_pairing(&agent_did, &arkret::AgentRenewPairingRequestBody::default())
        .await?;
    assert_eq!(renewed.agent_id.to_string(), agent_did, "same principal");
    assert_ne!(
        renewed.pairing_request_id, prov.pairing_request_id,
        "renewed pairing_request_id must be fresh"
    );
    assert!(
        renewed.pairing_code.is_some(),
        "renewed pairing_code present"
    );
    assert_ne!(
        renewed.pairing_code, prov.pairing_code,
        "renewed pairing_code must be fresh"
    );
    assert_eq!(
        agent_status(&server, &token, &agent_did).await?,
        "pending_runtime_key"
    );

    // The dead handle must stay unresolvable: pairing with the ORIGINAL
    // provision tuple fails even though the agent is pending again.
    let stale = pair_agent_runtime_key(&server, &token, &prov).await;
    assert!(
        stale.is_err(),
        "pairing with the expired handle must fail after renewal"
    );
    assert_eq!(
        agent_status(&server, &token, &agent_did).await?,
        "pending_runtime_key"
    );

    // The renewed handle completes pairing to active on the same principal.
    let pair = pair_agent_runtime_key(&server, &token, &renewed).await?;
    assert!(
        !pair.authorized_event_ref.as_str().is_empty(),
        "authorized_event_ref present"
    );
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");

    // Runtime replacement re-pairing (key-management §3.6.1): renewing an
    // ACTIVE agent is allowed, is NOT a state transition, and never touches
    // existing keys or grants until the new pairing completes.
    let replacement = controller
        .agent_renew_pairing(&agent_did, &arkret::AgentRenewPairingRequestBody::default())
        .await?;
    assert_eq!(
        replacement.agent_id.to_string(),
        agent_did,
        "same principal"
    );
    assert_ne!(
        replacement.pairing_request_id, renewed.pairing_request_id,
        "replacement pairing_request_id must be fresh"
    );
    assert_eq!(
        agent_status(&server, &token, &agent_did).await?,
        "active",
        "replacement re-pairing must not change agent status"
    );

    // A dead handle stays unresolvable and previously-keyed agents never
    // fall back to pairing_expired.
    let stale = pair_agent_runtime_key(&server, &token, &renewed).await;
    assert!(
        stale.is_err(),
        "pairing with the superseded handle must fail"
    );
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");

    // Completing the replacement pairing with a DISTINCT runtime key keeps
    // the agent active and supersedes the prior key in the same accepted
    // fan-out (reason=superseded_by_repairing).
    let replaced =
        pair_agent_runtime_key_as(&server, &token, &replacement, "runtime-key-2").await?;
    assert!(
        !replaced.authorized_event_ref.as_str().is_empty(),
        "replacement authorized_event_ref present"
    );
    assert_ne!(
        replaced.authorized_event_ref, pair.authorized_event_ref,
        "replacement authorization is a fresh event"
    );
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");

    // Replacement handle expiry has zero side effects: open a 1 ms handle,
    // let it die, and the agent stays active (never pairing_expired).
    let short_lived = controller
        .agent_renew_pairing(
            &agent_did,
            &arkret::AgentRenewPairingRequestBody {
                pairing_ttl_ms: Some(1),
            },
        )
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert_eq!(
        agent_status(&server, &token, &agent_did).await?,
        "active",
        "an expired replacement handle must not touch agent state"
    );
    let expired = pair_agent_runtime_key_as(&server, &token, &short_lived, "runtime-key-3").await;
    assert!(expired.is_err(), "expired replacement handle must be dead");
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "active");
    Ok(())
}

/// AKP-0008 runtime-side approval status poll
/// (`ak.open.agent_pairing.query.runtime_key_request_status`): the runtime
/// learns the controller decision after submitting a runtime key request
/// (cotask 2026-07-10-agent-runtime-approval-status-closure acceptance #5).
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn agent_runtime_key_request_status_poll_e2e() -> Result<()> {
    let server = ArkretServer::spawn("agent-approval-status-e2e").await?;
    let token = register_account(&server, ALICE_DID, "@cotest-agent-alice", ALICE_DEVICE).await?;
    prepare_agent_controller_recovery(&server, &token).await?;
    let controller = bearer_sdk_client(&server, &token)?;
    let prov = controller
        .agent_provision(&arkret::AgentProvisionRequestBody {
            display_name: Some("Status Poll Assistant".to_owned()),
            slug: "statuspoll".to_owned(),
            avatar_blob_ref: None,
            requested_scope: test_agent_requested_scope(),
            accountability: None,
            pairing_ttl_ms: None,
        })
        .await?;
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
    let provisioned = controller
        .agent_provision(&arkret::AgentProvisionRequestBody {
            display_name: Some("Recovery Gate Assistant".to_owned()),
            slug: "recoverygate".to_owned(),
            avatar_blob_ref: None,
            requested_scope: test_agent_requested_scope(),
            accountability: None,
            pairing_ttl_ms: None,
        })
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
    eventually(
        "pairing advances the Agent PCR beyond its pre-commit recovery tail",
        Duration::from_secs(30),
        Duration::from_millis(250),
        || async {
            let recovery = bearer_sdk_client(&server, &token)?
                .agent_get(provisioned.agent_id.as_str())
                .await?
                .key_state
                .ok_or_else(|| anyhow!("managed Agent key_state is missing"))?
                .pcr_recovery;
            if !matches!(recovery, arkret::AgentPcrRecoveryState::Stale { .. }) {
                return Err(anyhow!(
                    "post-pairing Agent PCR recovery is not stale: {recovery:?}"
                ));
            }
            Ok(())
        },
    )
    .await?;
    prepare_agent_pcr_recovery(&server, &token, &provisioned).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn agent_key_proof_session_reply_and_revoke_live_e2e() -> Result<()> {
    let service_name = "agent-live-e2e";
    let holder = AgentSessionHolder::new();
    let mock = MockIntrospection::spawn(
        format!("did:web:{service_name}.cotest.local"),
        holder.cnf_jkt.clone(),
        holder.public_jwk.to_string(),
    )
    .await?;
    let introspection_url = mock.url();
    let server = ArkretServer::spawn_with_env(
        service_name,
        &[
            (
                "SOLAND_SESSION_GRANT_INTROSPECTION_URL",
                introspection_url.as_str(),
            ),
            (
                "SOLAND_SESSION_GRANT_INTROSPECTION_BEARER",
                INTROSPECTION_BEARER,
            ),
        ],
    )
    .await?;
    mock.set_service_id(server.service_id().to_owned());
    let token = register_account(&server, ALICE_DID, "@cotest-agent-alice", ALICE_DEVICE).await?;
    prepare_agent_controller_recovery(&server, &token).await?;

    let realm_id = create_realm(&server, &token, ALICE_DID, "Agent reply live e2e").await?;
    let agent_did = provision_and_pair_agent(&server, &token, "Reply Assistant", "reply").await?;
    mock.set_subject(agent_did.clone());
    advance_event_sequence(ALICE_DID, &realm_id, 32);
    add_member(&server, &token, ALICE_DID, &realm_id, &agent_did).await?;

    let controller = bearer_sdk_client(&server, &token)?;
    let participation = controller
        .agent_participation_replace(
            &agent_did,
            &arkret::AgentParticipationReplaceRequestBody {
                scope: arkret::AgentParticipationScope::Realm {
                    realm_id: arkret::RealmId::new(realm_id.clone())?,
                },
                selection: arkret::AgentParticipation {
                    reply: true,
                    accept_third_party_mention: false,
                    act_on_behalf: false,
                },
            },
        )
        .await?;
    assert!(participation.ok, "participation set must succeed");
    assert!(
        participation
            .entries
            .first()
            .is_some_and(|entry| entry.effective.reply),
        "effective reply bit must be enabled"
    );

    // The agent reply targets the realm's default Strand (the message envelope
    // derives `strand_id` from the realm id). soland's agent-reply participation
    // gate resolves the message scope through the projected Strand, so the
    // Strand must exist first — create it as the realm owner.
    let default_strand_id = realm_id.replace("ak:realm:", "ak:strand:");
    let strand = submit_event(
        &server,
        &token,
        ALICE_DID,
        &realm_id,
        "ak.strand.create",
        json!({
            "object": {
                "id": default_strand_id,
                "schema": "ak.schema.strand.v1",
                "realm_id": realm_id,
                "tracks": {"discussion": {"enabled": true, "is_primary": true}},
                "created_by": ALICE_DID,
                "created_at": "2026-05-02T00:00:00Z",
                "metadata": {"title": "Agent reply strand"}
            }
        }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(strand["status"], "accepted");

    // AKP-0016 §5.2: every agent-originated Event carries an auditable
    // `agent_context` whose `authorization_ref` MUST resolve to an active
    // capability grant for the agent IN THE EVENT'S REALM, with an action
    // covering the operation's canonical kind. Grant the agent `ak.message.create`
    // in the reply Realm so the reply's agent_context references a real grant.
    let agent_grant_id = "ak:grant:01999999-0000-7000-8000-0000000000c1";
    let agent_grant = submit_event(
        &server,
        &token,
        ALICE_DID,
        &realm_id,
        "ak.capability.grant",
        json!({
            "grant_id": agent_grant_id,
            "grant": {
                "id": agent_grant_id,
                "schema": "ak.schema.capability.v1",
                "realm_id": realm_id,
                "issuer": ALICE_DID,
                "subject": agent_did,
                "actions": ["ak.message.create"],
                "resources": [{"kind": "realm", "realm_id": realm_id}],
                "constraints": [],
                "issued_at": "2026-05-02T00:00:00Z",
                "proofs": [{
                    "kind": "detached_jws",
                    "alg": "EdDSA",
                    "verification_method": format!("{ALICE_DID}#cotest"),
                    "payload_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                    "created_at": "2026-05-02T00:00:00Z",
                    "jws": "a..b"
                }]
            }
        }),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(agent_grant["status"], "accepted");

    let agent_message = event_envelope(
        &agent_did,
        &realm_id,
        "ak.message.create",
        json!({
            "body": "agent_key_proof live reply",
            "content": {"body": "agent_key_proof live reply"},
            "agent_context": {
                "agent_id": agent_did,
                "operator_or_controller": ALICE_DID,
                "execution_purpose": "reply",
                "authorization_ref": agent_grant_id,
            },
        }),
    );
    let agent_client = agent_session_client(&server, &holder)?;
    let accepted = agent_client
        .events_submit(&event_from_value(&agent_message)?)
        .await?;
    assert_eq!(
        accepted
            .accepted
            .first()
            .map(|event_id| event_id.to_string())
            .as_deref(),
        agent_message["event_id"].as_str(),
        "agent-authored message must be accepted"
    );
    assert!(
        mock.requests() >= 1,
        "agent submit must use the introspection service"
    );

    let agent_event_id = agent_message["event_id"]
        .as_str()
        .expect("agent message event_id")
        .to_owned();
    let scan = agent_client
        .events_query(&realm_id, None, None, None, Some(50))
        .await?;
    assert!(
        scan.events
            .iter()
            .any(|event| event.event_id.to_string() == agent_event_id),
        "DPoP-bound agent scan must include accepted reply event {agent_event_id}: {scan:?}"
    );

    // Catch-up replay now requires an `after` cursor (the old
    // include-history-from-genesis stream semantics are gone), so cover the
    // agent streaming surface with the live leg instead: subscribe first,
    // submit another agent-authored event, and expect its live frame.
    let mut stream = agent_client
        .events_subscribe_frames(&EventsSubscribeOptions::new().realm(realm_id.clone()))
        .await?;
    let live_message = event_envelope(
        &agent_did,
        &realm_id,
        "ak.message.create",
        json!({
            "body": "agent_key_proof live stream",
            "content": {"body": "agent_key_proof live stream"},
            "agent_context": {
                "agent_id": agent_did,
                "operator_or_controller": ALICE_DID,
                "execution_purpose": "reply",
                "authorization_ref": agent_grant_id,
            },
        }),
    );
    let live_event_id = live_message["event_id"]
        .as_str()
        .expect("live message event_id")
        .to_owned();
    let accepted_live = agent_client
        .events_submit(&event_from_value(&live_message)?)
        .await?;
    assert_eq!(
        accepted_live
            .accepted
            .first()
            .map(|event_id| event_id.to_string())
            .as_deref(),
        Some(live_event_id.as_str()),
        "agent live message must be accepted"
    );
    let mut saw_live_event = false;
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while let Some(frame) = stream.next_frame().await? {
            if frame.kind == EventsSubscribeFrameKind::Event
                && serde_json::to_string(&frame)
                    .is_ok_and(|frame_json| frame_json.contains(&live_event_id))
            {
                saw_live_event = true;
                break;
            }
        }
        Ok::<_, anyhow::Error>(())
    })
    .await
    .map_err(|_| anyhow!("agent stream did not deliver live event {live_event_id} within 15s"))??;
    assert!(
        saw_live_event,
        "DPoP-bound agent stream must deliver the accepted live event {live_event_id}"
    );

    let paused = controller
        .agent_pause(
            &agent_did,
            &arkret::AgentPauseRequestBody {
                reason: Some("cotest live e2e pause".to_owned()),
            },
        )
        .await?;
    assert!(paused.ok, "pause must succeed");
    assert_eq!(agent_status(&server, &token, &agent_did).await?, "paused");

    let mut after_pause = event_envelope(
        &agent_did,
        &realm_id,
        "ak.message.create",
        json!({
            "body": "agent_key_proof after pause",
            "content": {"body": "agent_key_proof after pause"},
            "agent_context": {
                "agent_id": agent_did,
                "operator_or_controller": ALICE_DID,
                "execution_purpose": "reply",
                "authorization_ref": agent_grant_id,
            },
        }),
    );
    move_event_after_actor_frontier(&server, &token, &agent_did, &mut after_pause).await?;
    expect_sdk_api_error(
        agent_client
            .events_submit(&event_from_value(&after_pause)?)
            .await,
        StatusCode::PRECONDITION_FAILED,
        "agent_paused",
    )?;

    let deactivated = controller
        .agent_deactivate(
            &agent_did,
            &arkret::AgentDeactivateRequestBody {
                reason: Some("cotest live e2e".to_owned()),
            },
        )
        .await?;
    assert!(deactivated.ok, "deactivate must succeed");
    assert_eq!(
        agent_status(&server, &token, &agent_did).await?,
        "deactivated"
    );

    let mut after_deactivate = event_envelope(
        &agent_did,
        &realm_id,
        "ak.message.create",
        json!({
            "body": "agent_key_proof after deactivate",
            "content": {"body": "agent_key_proof after deactivate"},
            "agent_context": {
                "agent_id": agent_did,
                "operator_or_controller": ALICE_DID,
                "execution_purpose": "reply",
                "authorization_ref": agent_grant_id,
            },
        }),
    );
    move_event_after_actor_frontier(&server, &token, &agent_did, &mut after_deactivate).await?;
    expect_sdk_api_error(
        agent_client
            .events_submit(&event_from_value(&after_deactivate)?)
            .await,
        StatusCode::PRECONDITION_FAILED,
        "agent_deactivated",
    )?;

    mock.set_active(false);
    let after_revoke = event_envelope(
        &agent_did,
        &realm_id,
        "ak.message.create",
        json!({
            "body": "agent_key_proof after revoke",
            "content": {"body": "agent_key_proof after revoke"},
        }),
    );
    expect_sdk_api_error(
        agent_client
            .events_submit(&event_from_value(&after_revoke)?)
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthenticated",
    )?;
    assert!(
        mock.requests() >= 2,
        "write after revoke must force fresh introspection"
    );

    Ok(())
}

async fn prepare_agent_controller_recovery(server: &ArkretServer, token: &str) -> Result<()> {
    let principal_id = Did::new(ALICE_DID.to_owned())?;
    let device_id = DeviceId::new(ALICE_DEVICE.to_owned())?;
    let control_realm_id = principal_control_realm_id(&principal_id);
    let trust_domain = TypedTrustDomainId::new(TRUST_DOMAIN.to_owned())?;

    let psk = SigningKey::from_bytes(&[21_u8; 32]);
    let ssk = SigningKey::from_bytes(&[22_u8; 32]);
    let usk = SigningKey::from_bytes(&[23_u8; 32]);
    let device_key = SigningKey::from_bytes(&[24_u8; 32]);
    let psk_kid = ALICE_DID.to_owned();
    let ssk_kid = format!("{ALICE_DID}#cotest-ssk");
    let usk_kid = format!("{ALICE_DID}#cotest-usk");

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
    submit_event(
        server,
        token,
        ALICE_DID,
        control_realm_id.as_str(),
        "ak.cross_signing.publish",
        serde_json::to_value(&cross_signing)?,
        StatusCode::OK,
    )
    .await?;

    let device_public_key =
        ed25519_pubkey_to_did_key_multibase(device_key.verifying_key().as_bytes());
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
    submit_event(
        server,
        token,
        ALICE_DID,
        control_realm_id.as_str(),
        "ak.device.authorize",
        serde_json::to_value(&device_authorize)?,
        StatusCode::OK,
    )
    .await?;

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
) -> Result<String> {
    let mut event = event_envelope(agent_id, realm_id, kind, payload);
    event["executed_by"] = json!(ALICE_DID);
    event["authorization_ref"] = json!(authorization_ref);
    event["proofs"][0]["verification_method"] = json!(format!("{ALICE_DID}#cotest"));
    refresh_event_proof(&mut event);
    let event_id = event["event_id"]
        .as_str()
        .ok_or_else(|| anyhow!("delegated event_id missing"))?
        .to_owned();
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
    Ok(event_id)
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
    if status != StatusCode::OK {
        return Err(anyhow!("managed Agent frontier returned {status}: {body}"));
    }
    let state: EventsFrontierAccountClientState = serde_json::from_str(&body)?;
    match state.frontier {
        EventsFrontierView::RealmSealView(frontier) => Ok(Some(frontier)),
        EventsFrontierView::Actor(_) => Err(anyhow!("managed Agent frontier returned actor view")),
    }
}

async fn managed_agent_actor_seq(
    server: &ArkretServer,
    token: &str,
    agent_id: &str,
) -> Result<u64> {
    let response = server
        .http()
        .get(server.url(&format!(
            "/_arkret/self/events/frontier?actor_id={agent_id}"
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
        EventsFrontierView::Actor(frontier) => Ok(frontier.actor_seq),
        EventsFrontierView::RealmSealView(_) => {
            Err(anyhow!("managed Agent actor frontier returned Realm view"))
        }
    }
}

async fn move_event_after_actor_frontier(
    server: &ArkretServer,
    token: &str,
    actor_id: &str,
    event: &mut Value,
) -> Result<()> {
    let original_actor_seq = event["actor_seq"].as_u64().unwrap_or_default();
    let frontier_actor_seq = managed_agent_actor_seq(server, token, actor_id).await?;
    // Lifecycle commands author a bounded fan-out of Agent control events. On
    // deactivation the controller also loses visibility of the terminal Agent
    // PCR frontier, so a rejection probe needs headroom beyond both its local
    // sequence and the last caller-visible frontier.
    let actor_seq = original_actor_seq.max(frontier_actor_seq) + 32;
    event["actor_seq"] = json!(actor_seq);
    event["hlc"] = json!(format!("01970e589d21-{:04x}-a13f9c2e", actor_seq & 0xffff));
    refresh_event_proof(event);
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
    if managed_agent_frontier(server, token, realm_id)
        .await?
        .is_none()
    {
        let realm_create_event_id = submit_delegated_agent_event(
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
                    "created_at": "2026-05-02T00:00:00Z"
                }
            }),
        )
        .await?;
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
                "created_at": "2026-05-02T00:00:01Z"
            }),
        )
        .await?;
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
                device_id: ALICE_DEVICE.to_owned(),
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
            ssk_generation: Some(1),
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

    let mut active_series = json!({
        "schema": "ak.schema.key_backup_active_series.v1",
        "actor_id": ALICE_DID,
        "backup_class": "mls_history",
        "active_series_id": series_id,
        "series_pointer_version": series_pointer_version,
        "previous_series_ids": previous_series_ids,
        "frontier_ref": {
            "frontier_digest": frontier.control_event_set_root,
            "seal_ref": frontier.seal_id,
            "ssk_generation": 1
        },
        "issued_at": canonical_now(),
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
    submit_event(
        server,
        token,
        ALICE_DID,
        principal_control_realm_id(&Did::new(ALICE_DID.to_owned())?).as_str(),
        "ak.key_backup.active_series",
        active_series,
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

async fn provision_and_pair_agent(
    server: &ArkretServer,
    token: &str,
    display_name: &str,
    slug: &str,
) -> Result<String> {
    let controller = bearer_sdk_client(server, token)?;
    let prov = controller
        .agent_provision(&arkret::AgentProvisionRequestBody {
            display_name: Some(display_name.to_owned()),
            slug: slug.to_owned(),
            avatar_blob_ref: None,
            requested_scope: test_agent_requested_scope(),
            accountability: None,
            pairing_ttl_ms: None,
        })
        .await?;
    let agent_did = prov.agent_id.to_string();
    assert!(prov.pairing_code.is_some(), "pairing_code present");
    assert_eq!(
        agent_status(server, token, &agent_did).await?,
        "pending_runtime_key"
    );

    let pair = pair_agent_runtime_key(server, token, &prov).await?;
    assert!(
        !pair.authorized_event_ref.as_str().is_empty(),
        "authorized_event_ref present"
    );
    assert_eq!(agent_status(server, token, &agent_did).await?, "active");
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

impl_pairing_outcome!(arkret::AgentProvisionOutcome);
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
    let pairing_expires_at = provisioned
        .expires_at()
        .to_rfc3339_opts(SecondsFormat::Millis, true);
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
            chrono::DateTime::parse_from_rfc3339("2999-01-01T00:00:00Z")?.with_timezone(&Utc),
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
    let controller_signer = arkret::Ed25519MoveSigner::from_did_key_seed(
        [21_u8; 32],
        controller_id.clone(),
        format!("{ALICE_DID}#cotest"),
    );
    let actor_seq = managed_agent_actor_seq(server, token, agent_did.as_str()).await? + 1;
    let mut authorize_event = arkret::agent::build_agent_key_authorize_event(
        &authorize_payload,
        provisioned.principal_control_realm_id().clone(),
        agent_id,
        controller_id,
        provisioned.controller_authorization_ref(),
        actor_seq,
        arkret::Hlc::new(format!("01970e589d21-{:04x}-a13f9c2e", actor_seq & 0xffff))?,
    )?;
    authorize_event.created_at = canonical_now();
    authorize_event.proofs.clear();
    arkret::signatures::sign_event(
        &mut authorize_event,
        &controller_signer,
        &format!("{ALICE_DID}#cotest"),
        arkret::signatures::SignEventOptions::new().with_created_at(canonical_now()),
    )?;
    Ok(builder.build_key_pair_request(authorize_event)?.body)
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

async fn effective_grants(
    server: &ArkretServer,
    token: &str,
    realm_id: &str,
    agent_did: &str,
) -> Result<Value> {
    // A controller may inspect a managed Agent's grants only within a Realm
    // it owns. Query the Realm named by the attached grant; grant attachment
    // deliberately preserves the caller-supplied governed Realm.
    let effective = bearer_sdk_client(server, token)?
        .authz_effective_grants(realm_id, agent_did, None)
        .await?;
    Ok(serde_json::to_value(effective)?)
}

fn grant_exists_in(effective: &Value, grant_id: &str) -> bool {
    effective["grants"].as_array().is_some_and(|grants| {
        grants.iter().any(|grant| {
            grant["id"].as_str() == Some(grant_id) || grant["grant_id"].as_str() == Some(grant_id)
        })
    })
}

fn bearer_sdk_client(server: &ArkretServer, token: &str) -> Result<SdkClient> {
    Ok(ClientBuilder::new(server.base_url())
        .allow_insecure_localhost()
        .auth(Auth::Bearer(token.to_owned()))
        .build()?)
}

fn agent_session_client(server: &ArkretServer, holder: &AgentSessionHolder) -> Result<SdkClient> {
    Ok(ClientBuilder::new(server.base_url())
        .allow_insecure_localhost()
        .auth(Auth::Dpop(garth::session::dpop::access_token_auth(
            AGENT_SESSION_GRANT,
            SigningKey::from_bytes(&holder.signing_key.to_bytes()),
        )))
        .build()?)
}

fn event_from_value(value: &Value) -> Result<arkret::Event> {
    Ok(serde_json::from_value(value.clone())?)
}

fn expect_sdk_api_error<T>(
    result: arkret_core::Result<T>,
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

struct AgentSessionHolder {
    signing_key: SigningKey,
    public_jwk: Value,
    cnf_jkt: String,
}

impl AgentSessionHolder {
    fn new() -> Self {
        let secret = [7_u8; 32];
        let signing_key = SigningKey::from_bytes(&secret);
        let public_x = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
        let public_jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": public_x,
        });
        let cnf_jkt =
            jwk_thumbprint_ed25519(public_jwk["x"].as_str().expect("public x must be a string"));
        Self {
            signing_key,
            public_jwk,
            cnf_jkt,
        }
    }
}

fn jwk_thumbprint_ed25519(x: &str) -> String {
    let canonical = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}");
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()))
}

#[derive(Clone)]
struct AgentIntrospectionState {
    active: Arc<AtomicBool>,
    request_count: Arc<AtomicUsize>,
    service_id: Arc<Mutex<String>>,
    subject: Arc<Mutex<Option<String>>>,
    cnf_jkt: String,
    session_public_key: String,
}

struct MockIntrospection {
    url: String,
    active: Arc<AtomicBool>,
    request_count: Arc<AtomicUsize>,
    service_id: Arc<Mutex<String>>,
    subject: Arc<Mutex<Option<String>>>,
    _server: MockServer,
}

impl MockIntrospection {
    async fn spawn(
        service_id: String,
        cnf_jkt: String,
        session_public_key: String,
    ) -> Result<Self> {
        let active = Arc::new(AtomicBool::new(true));
        let request_count = Arc::new(AtomicUsize::new(0));
        let service_id = Arc::new(Mutex::new(service_id));
        let subject = Arc::new(Mutex::new(None));
        let state = AgentIntrospectionState {
            active: Arc::clone(&active),
            request_count: Arc::clone(&request_count),
            service_id: Arc::clone(&service_id),
            subject: Arc::clone(&subject),
            cnf_jkt,
            session_public_key,
        };
        let router = Router::with_path("session-grants/introspect")
            .hoop(affix_state::inject(state))
            .post(agent_introspect);
        let server = mock_http::spawn_mock(router).await?;
        let url = format!("http://{}/session-grants/introspect", server.addr());
        Ok(Self {
            url,
            active,
            request_count,
            service_id,
            subject,
            _server: server,
        })
    }

    fn url(&self) -> String {
        self.url.clone()
    }

    fn requests(&self) -> usize {
        self.request_count.load(Ordering::SeqCst)
    }

    fn set_service_id(&self, service_id: String) {
        if let Ok(mut guard) = self.service_id.lock() {
            *guard = service_id;
        }
    }

    fn set_subject(&self, subject: String) {
        if let Ok(mut guard) = self.subject.lock() {
            *guard = Some(subject);
        }
    }

    fn set_active(&self, active: bool) {
        self.active.store(active, Ordering::SeqCst);
    }
}

#[handler]
async fn agent_introspect(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .get_typed::<AgentIntrospectionState>()
        .expect("agent introspection mock state injected")
        .clone();
    state.request_count.fetch_add(1, Ordering::SeqCst);
    let authorized = req
        .headers()
        .get(salvo::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .to_ascii_lowercase()
                .contains(&format!("bearer {INTROSPECTION_BEARER}"))
        });
    if !authorized {
        res.status_code(salvo::http::StatusCode::UNAUTHORIZED);
        res.render(Json(
            json!({"ok": false, "error": {"errcode": "unauthenticated"}}),
        ));
        return;
    }
    let _body: Value = req.parse_json().await.unwrap_or_else(|_| json!({}));

    let service_id = state
        .service_id
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_else(|_| "did:web:agent-live-e2e.cotest.local".to_owned());
    let subject = state
        .subject
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
        .unwrap_or_else(|| "did:web:agent-unset.example".to_owned());
    let body = if state.active.load(Ordering::SeqCst) {
        json!({
            "active": true,
            "status": "active",
            "proof_required": false,
            "one_time_use_consumed": false,
            "grant": {
                // `SessionGrantIntrospectGrant.id` is a typed `GrantId`
                // (`ak:grant:<uuidv7>`); a bare label fails SDK deserialization
                // and soland reports the introspection response as invalid (503).
                "id": "ak:grant:01964137-0000-7000-8000-000000000a01",
                "issuer": "did:web:coauth.cotest.local",
                "subject": subject,
                "service_account_id": "agent-live-e2e-account",
                "audience": service_id,
                "scopes": [
                    "ak.self.events.stream.subscribe",
                    "ak.self.events.query.scan",
                    "ak.self.events.command.submit",
                    "ak.event.read",
                    "ak.message.create",
                    "ak.reaction.add"
                ],
                "expires_at": "2026-12-31T23:59:59Z",
                "revocation_ref": "ak:session:agent-live-e2e-grant",
                "session_public_key": state.session_public_key,
                "cnf_jkt": state.cnf_jkt,
                "proof_kind": "agent_key_proof",
                "scope_details": {
                    "agent_id": subject,
                    "controller_id": ALICE_DID,
                    "resources": {
                        "realm_refs": ["*"],
                        "strand_refs": []
                    },
                    "constraints": {
                        "allowed_tracks": [],
                        "allowed_data_classes": [],
                        "allowed_endpoints": []
                    },
                    "capability_grant_refs": [],
                    "policy_refs": []
                },
                "freshness_state": "fresh"
            }
        })
    } else {
        json!({
            "active": false,
            "status": "revoked",
            "proof_required": false,
            "one_time_use_consumed": false
        })
    };
    res.render(Json(body));
}
