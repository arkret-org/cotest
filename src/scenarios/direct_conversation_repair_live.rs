//! Two-Soland live closure for durable Direct Conversation Human repair.
//!
//! The state installer is development-only, but it feeds typed Events through
//! the real registry projector/reducer and persists canonical/projected rows.
//! Dispatch, role-scoped Describe resolution, peer relay, evidence checking,
//! and closed-target batch commit all use production handlers and stores.

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::direct_conversation_ops::{
    AcceptedAtServiceBinding, AcceptedAtServiceBindingCore, DidBindingEvidenceKind,
    DidBindingEvidenceReceipt, MultikeyMethodType, PrincipalServiceBindingProofPurpose,
    PrincipalServiceKind, ServiceVerificationMethod,
};
use arkret_models_collaboration::direct_conversation_repair::{
    DirectConversationRepairAuthorization, DirectConversationRepairDispatchRequest,
    DirectConversationRepairEnqueueOutcome,
};
use arkret_models_collaboration::events_payloads::{
    DirectConversationMlsGenerationActivatePayload, DirectConversationMlsGenerationPhase,
    MemberRepairRequestPayload, MemberRepairRequester,
};
use arkret_models_collaboration::objects::direct_conversation::{
    DirectConversationPairKeyParticipant, direct_conversation_main_strand_create_payload,
    direct_conversation_member_join_payload, direct_conversation_pair_key,
    direct_conversation_realm_create_payload,
};
use arkret_models_collaboration::objects::realm::NotaryProfile;
use arkret_models_crypto::KeyPackagesUploadUnsignedRequest;
use arkret_models_identity::{
    ServiceResolutionCarrier, ServiceResolutionRecord, canonical_service_current_record_path,
};
use arkret_wire::notary::NotaryValue;
use arkret_wire::{
    ActorId, AuthorizationRef, Base64UrlString, CoreId, DeviceId, DidUrl, Event, EventId, FullId,
    GenesisSalt, Hash, Hlc, MlsGroupId, NonEmptyString, PrincipalId, ProtocolSignature, ScopeRef,
    ServiceId, StrandId, project_full_id_to_core_id,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::harness::{TestServerGroup, canonical_device_id, expect_json};
use crate::scenarios::identity_test_support::{
    HARNESS_ACCOUNT_AUTHORITY_ORIGIN, actor_did_for_service,
    authorize_device_public_key_with_event_id, harness_account_authority_id,
};

const INSTALL_PATH: &str = "/_arkret/_conformance/direct-repair/install";
const MESSAGES_PATH: &str = "/_arkret/_conformance/direct-repair/messages";
const DEVICE_PATH: &str = "/_arkret/_conformance/device-signing-key";
const DISPATCH_PATH: &str = "/_arkret/self/direct-conversations/repair-dispatch";
const KEYPACKAGE_PATH: &str = "/_arkret/self/keys/keypackages/upload";

struct FixtureEvents {
    events: Vec<Event>,
    pair_key: Hash,
    realm_id: arkret_wire::RealmId,
    main_strand_id: StrandId,
    rejoin_event_id: EventId,
    active_generation_digest: Hash,
}

fn canonical_now() -> DateTime<Utc> {
    DateTime::from_timestamp_millis(Utc::now().timestamp_millis()).expect("current timestamp")
}

fn fixture_events(
    trust_domain: arkret_wire::TypedTrustDomainId,
    requester_full: &FullId,
    requester: &CoreId,
    recipient: &CoreId,
) -> Result<FixtureEvents> {
    let created_at = canonical_now();
    let requester_actor = ActorId::from(requester.clone());
    let recipient_actor = ActorId::from(recipient.clone());
    let pair_key = direct_conversation_pair_key(
        trust_domain.clone(),
        DirectConversationPairKeyParticipant::unmapped(requester_actor.clone()),
        DirectConversationPairKeyParticipant::unmapped(recipient_actor.clone()),
    )?;
    let create_payload = direct_conversation_realm_create_payload(
        GenesisSalt::generate()?,
        trust_domain,
        NotaryProfile::SingleDid,
        NotaryValue::single_did(requester_full.clone()),
        arkret::current_capability_action_registry_digest()?,
        created_at,
    )?;
    let create = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::RealmCreate.as_str(),
        ScopeRef::RealmGenesis,
        requester_actor.clone(),
        10,
        Hlc::new(format!(
            "{:012x}-0000-d1ec7e57",
            created_at.timestamp_millis()
        ))?,
        serde_json::to_value(create_payload)?,
        created_at,
    )?;
    let realm_id = create.realm_id.clone();
    let join = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::MemberState.as_str(),
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        requester_actor.clone(),
        11,
        Hlc::new(format!(
            "{:012x}-0001-d1ec7e57",
            created_at.timestamp_millis()
        ))?,
        direct_conversation_member_join_payload(
            realm_id.clone(),
            recipient_actor,
            arkret_models_identity::DeliveryStatus::Unroutable,
        )
        .to_value()?,
        created_at,
    )?;
    let strand = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::StrandCreate.as_str(),
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        requester_actor.clone(),
        12,
        Hlc::new(format!(
            "{:012x}-0002-d1ec7e57",
            created_at.timestamp_millis()
        ))?,
        serde_json::to_value(direct_conversation_main_strand_create_payload(
            realm_id.clone(),
            requester_actor.clone(),
            created_at,
        ))?,
        created_at,
    )?;
    let main_strand_id = StrandId::from_event_id(&strand.event_id);
    let generation_payload = DirectConversationMlsGenerationActivatePayload {
        pair_key: pair_key.clone(),
        mls_generation: 0,
        phase: DirectConversationMlsGenerationPhase::ProvisionalHistorySend,
        mls_group_id: MlsGroupId::new("ak:mls_group:cotest-direct-repair".to_owned())
            .map_err(anyhow::Error::msg)?,
        genesis_event_ref: create.event_id.clone(),
        selected_group_state_ref: NonEmptyString::new(strand.event_id.to_string())
            .map_err(anyhow::Error::msg)?,
        main_strand_id: main_strand_id.clone(),
        predecessor_active_value_digest: None,
    };
    let generation_value = serde_json::to_value(&generation_payload)?;
    let active_generation_digest =
        Hash::new(arkret_canonical::canonical_sha256(&generation_value)?)?;
    let generation = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::DirectConversationMlsGenerationActivate.as_str(),
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        requester_actor.clone(),
        13,
        Hlc::new(format!(
            "{:012x}-0003-d1ec7e57",
            created_at.timestamp_millis()
        ))?,
        generation_value,
        created_at,
    )?;
    let mut rejoin = arkret_wire::test_support::raw_event_at(
        arkret_wire::EventKind::MemberState.as_str(),
        ScopeRef::Realm {
            realm_id: realm_id.clone(),
        },
        requester_actor.clone(),
        14,
        Hlc::new(format!(
            "{:012x}-0004-d1ec7e57",
            created_at.timestamp_millis()
        ))?,
        direct_conversation_member_join_payload(
            realm_id.clone(),
            requester_actor,
            arkret_models_identity::DeliveryStatus::Unroutable,
        )
        .to_value()?,
        created_at,
    )?;
    rejoin.authorization_ref = Some(
        AuthorizationRef::new("ak.authority.direct_conversation_repair.v1".to_owned())
            .map_err(anyhow::Error::msg)?,
    );
    rejoin.refresh_content_bound_identity()?;
    let rejoin_event_id = rejoin.event_id.clone();
    Ok(FixtureEvents {
        events: vec![create, join, strand, generation, rejoin],
        pair_key,
        realm_id,
        main_strand_id,
        rejoin_event_id,
        active_generation_digest,
    })
}

async fn current_service_record(
    server: &crate::harness::ArkretServer,
) -> Result<(ServiceId, ServiceResolutionRecord)> {
    let full_id = FullId::new(server.service_id().to_owned())?;
    let service_id = ServiceId::from(project_full_id_to_core_id(&full_id)?);
    let record = serde_json::from_value(
        expect_json(
            server
                .http()
                .get(server.url(&canonical_service_current_record_path(&service_id))),
            StatusCode::OK,
        )
        .await?,
    )?;
    Ok((service_id, record))
}

fn accepted_local_binding(
    principal_full: &FullId,
    principal: &CoreId,
    service_record: &ServiceResolutionRecord,
    trust_domain: &str,
    device_id: &DeviceId,
) -> Result<AcceptedAtServiceBinding> {
    let accepted_at = canonical_now();
    let document_digest = Hash::new(arkret_canonical::sha256_digest(
        service_record.record.full_id.as_str().as_bytes(),
    ))?;
    let authority_evidence = DidBindingEvidenceReceipt {
        kind: DidBindingEvidenceKind::AkDidBindingEvidenceV1,
        method: "webvh".to_owned(),
        document_digest: document_digest.clone(),
        method_proofs: Vec::new(),
    };
    let mut core = AcceptedAtServiceBindingCore {
        principal_id: PrincipalId::from(principal.clone()),
        service_id: service_record.record.service_id.clone(),
        trust_domain: trust_domain.to_owned(),
        service_kind: PrincipalServiceKind::PrincipalServer,
        service_verification_method: ServiceVerificationMethod {
            id: service_record.proof.verification_method.clone(),
            controller: service_record.record.full_id.clone(),
            method_type: MultikeyMethodType::Multikey,
            public_key_multibase: "z6MkCotestServiceBindingKey".to_owned(),
        },
        endpoint_origins: vec![service_record.record.base_url.clone()],
        document_digest,
        authority_evidence,
        service_resolution: ServiceResolutionCarrier::Inline {
            inline: service_record.clone(),
        },
        authorization_challenge: Base64UrlString::new("A".repeat(24))
            .map_err(anyhow::Error::msg)?,
        history_head: Some(service_record.record.method_history_head.clone()),
        version_id: Some(service_record.record.version_id.clone()),
        not_before: accepted_at,
        expires_at: Some(accepted_at + ChronoDuration::hours(1)),
        accepted_at,
        predecessor_binding_digest: None,
        binding_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
    };
    core.binding_digest = core.computed_binding_digest()?;
    let principal_method =
        DidUrl::new(format!("{principal_full}#{device_id}")).map_err(anyhow::Error::msg)?;
    let service_input = core.proof_signing_input_bytes(
        PrincipalServiceBindingProofPurpose::ServiceAcceptance,
        &core.service_verification_method.id,
    )?;
    let principal_input = core.proof_signing_input_bytes(
        PrincipalServiceBindingProofPurpose::PrincipalAuthorization,
        &principal_method,
    )?;
    Ok(AcceptedAtServiceBinding {
        principal_id: core.principal_id,
        service_id: core.service_id,
        trust_domain: core.trust_domain,
        service_kind: core.service_kind,
        service_verification_method: core.service_verification_method.clone(),
        endpoint_origins: core.endpoint_origins,
        document_digest: core.document_digest,
        authority_evidence: core.authority_evidence,
        service_resolution: core.service_resolution,
        authorization_challenge: core.authorization_challenge,
        history_head: core.history_head,
        version_id: core.version_id,
        not_before: core.not_before,
        expires_at: core.expires_at,
        accepted_at: core.accepted_at,
        predecessor_binding_digest: core.predecessor_binding_digest,
        binding_digest: core.binding_digest,
        service_acceptance_proof: ProtocolSignature {
            verification_method: core.service_verification_method.id,
            created_at: accepted_at,
            jws: Base64UrlString::new(URL_SAFE_NO_PAD.encode(service_input))
                .map_err(anyhow::Error::msg)?,
        },
        principal_authorization_proof: ProtocolSignature {
            verification_method: principal_method,
            created_at: accepted_at,
            jws: Base64UrlString::new(URL_SAFE_NO_PAD.encode(principal_input))
                .map_err(anyhow::Error::msg)?,
        },
    })
}

async fn install_fixture(
    server: &crate::harness::ArkretServer,
    fixture: &FixtureEvents,
    requester: &CoreId,
    recipient: &CoreId,
    peer_service_id: &ServiceId,
    peer_record: &ServiceResolutionRecord,
    local_binding: Option<&AcceptedAtServiceBinding>,
) -> Result<()> {
    let carrier = ServiceResolutionCarrier::Inline {
        inline: peer_record.clone(),
    };
    let body = json!({
        "events": fixture.events,
        "binding": {
            "pair_key": fixture.pair_key,
            "binding_digest": Hash::new(arkret_canonical::canonical_sha256(&json!({
                "participants": [requester, recipient],
                "realm_id": fixture.realm_id,
                "main_strand_id": fixture.main_strand_id,
            }))?)?,
            "participants_unordered": [requester, recipient],
            "realm_id": fixture.realm_id,
            "main_strand_id": fixture.main_strand_id,
            "binding_event_ref": fixture.events[2].event_id,
        },
        "contacts": [
            {
                "requester": requester,
                "target": recipient,
                "request_event_ref": fixture.events[0].event_id,
                "response_event_ref": fixture.events[1].event_id,
                "peer_service_id": peer_service_id,
                "peer_service_resolution": carrier,
            },
            {
                "requester": recipient,
                "target": requester,
                "request_event_ref": fixture.events[1].event_id,
                "response_event_ref": fixture.events[0].event_id,
                "peer_service_id": peer_service_id,
                "peer_service_resolution": carrier,
            }
        ],
        "local_principal_service_binding": local_binding,
    });
    let outcome = expect_json(
        server.http().post(server.url(INSTALL_PATH)).json(&body),
        StatusCode::OK,
    )
    .await?;
    ensure!(
        outcome["projected_event_count"].as_u64() == Some(4),
        "fixture projection incomplete: {outcome}"
    );
    Ok(())
}

async fn install_device(
    server: &crate::harness::ArkretServer,
    actor: &CoreId,
    device: &DeviceId,
    key: &SigningKey,
) -> Result<()> {
    let multibase = arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase(
        &key.verifying_key().to_bytes(),
    );
    expect_json(
        server.http().post(server.url(DEVICE_PATH)).json(&json!({
            "actor_id": actor,
            "device_id": device,
            "public_key_multibase": multibase,
        })),
        StatusCode::OK,
    )
    .await?;
    Ok(())
}

async fn upload_requester_keypackage(
    server: &crate::harness::ArkretServer,
    token: &str,
    actor: &FullId,
    device_id: &DeviceId,
    device_authorize_event_id: &EventId,
    signing_key: &SigningKey,
) -> Result<NonEmptyString> {
    let keypackage_ref = NonEmptyString::new("ak:mls:keypackage:cotest-direct-repair".to_owned())
        .map_err(anyhow::Error::msg)?;
    let bytes = b"cotest-direct-repair-keypackage";
    let unsigned: KeyPackagesUploadUnsignedRequest = serde_json::from_value(json!({
        "principal_id": actor,
        "device_id": device_id,
        "key_packages": [{
            "keypackage_id": "ak:mls_keypackage:cotest-direct-repair",
            "keypackage_ref": keypackage_ref,
            "keypackage_digest": arkret_canonical::sha256_digest(bytes),
            "key_package": URL_SAFE_NO_PAD.encode(bytes),
            "cipher_suites": ["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
            "capabilities": ["mimi.content.v1", "ak.content.v1"],
            "expires_at": "2100-01-01T00:00:00.000Z",
            "created_at": "2026-08-10T00:00:00.000Z",
            "device_authorize_event_id": device_authorize_event_id,
        }]
    }))?;
    let signature = arkret_signatures::keypackages::sign_keypackages_upload_request(
        &unsigned,
        &format!("{actor}#{device_id}"),
        &signing_key.to_bytes(),
    )?;
    expect_json(
        server
            .http()
            .post(server.url(KEYPACKAGE_PATH))
            .bearer_auth(token)
            .json(&unsigned.into_signed(signature)),
        StatusCode::OK,
    )
    .await?;
    Ok(keypackage_ref)
}

fn signed_dispatch(
    request_id: &str,
    fixture: &FixtureEvents,
    requester: &CoreId,
    device_id: &DeviceId,
    device_authorize_event_id: &EventId,
    keypackage_ref: &NonEmptyString,
    signing_key: &SigningKey,
) -> Result<DirectConversationRepairDispatchRequest> {
    let signed_at = canonical_now();
    let verification_method = DidUrl::new(format!(
        "did:key:{}#{}",
        arkret_canonical::multibase::ed25519_pubkey_to_did_key_multibase(
            &signing_key.verifying_key().to_bytes()
        ),
        device_id
    ))
    .map_err(anyhow::Error::msg)?;
    let mut request = DirectConversationRepairDispatchRequest {
        request_id: Base64UrlString::new(request_id.to_owned()).map_err(anyhow::Error::msg)?,
        content: MemberRepairRequestPayload {
            realm_id: fixture.realm_id.clone(),
            requester_principal_id: requester.clone(),
            requester: MemberRepairRequester::Device {
                requester_device_id: device_id.clone(),
            },
            requester_keypackage_ref: keypackage_ref.clone(),
            observed_active_generation_value_digest: fixture.active_generation_digest.clone(),
            rejoin_event_id: fixture.rejoin_event_id.clone(),
            created_at: signed_at,
        },
        requester_authorization: DirectConversationRepairAuthorization::Device {
            requester_device_id: device_id.clone(),
            verification_method: verification_method.clone(),
            device_authorize_event_id: device_authorize_event_id.clone(),
            signed_at,
            signature: ProtocolSignature {
                verification_method,
                created_at: signed_at,
                jws: Base64UrlString::new("AA".to_owned()).map_err(anyhow::Error::msg)?,
            },
        },
    };
    let signature = signing_key.sign(&request.signing_input()?);
    let DirectConversationRepairAuthorization::Device {
        signature: proof, ..
    } = &mut request.requester_authorization
    else {
        unreachable!()
    };
    proof.jws = Base64UrlString::new(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
        .map_err(anyhow::Error::msg)?;
    request.validate_shape()?;
    Ok(request)
}

async fn observed_messages(
    server: &crate::harness::ArkretServer,
    recipient: &CoreId,
) -> Result<Vec<Value>> {
    let body = expect_json(
        server
            .http()
            .post(server.url(MESSAGES_PATH))
            .json(&json!({"recipient": recipient})),
        StatusCode::OK,
    )
    .await?;
    Ok(body["messages"].as_array().cloned().unwrap_or_default())
}

async fn wait_for_file(path: &Path) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !path.exists() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    ensure!(path.exists(), "chaos breakpoint was not reached");
    Ok(())
}

/// Runs only when two explicitly independent PostgreSQL URLs and a prebuilt
/// Soland binary are available. This keeps the ordinary Cotest lane hermetic
/// while making the durable wire closure reproducible in CI and locally.
pub async fn run_direct_conversation_repair_live() -> Result<()> {
    let Ok(source_database_url) = std::env::var("COTEST_DIRECT_REPAIR_SOURCE_DATABASE_URL") else {
        eprintln!("skipping direct repair live E2E: source PostgreSQL URL is unset");
        return Ok(());
    };
    let Ok(target_database_url) = std::env::var("COTEST_DIRECT_REPAIR_TARGET_DATABASE_URL") else {
        eprintln!("skipping direct repair live E2E: target PostgreSQL URL is unset");
        return Ok(());
    };
    ensure!(
        source_database_url != target_database_url,
        "repair E2E requires two independent persistent databases"
    );
    let temp = TempDir::new()?;
    let control = temp.path().join("target-chaos.json");
    let authority_id = harness_account_authority_id();
    let common = |database_url: String| {
        vec![
            ("DATABASE_URL".to_owned(), database_url),
            (
                "SOLAND_ACCOUNT_AUTHORITY_URL".to_owned(),
                HARNESS_ACCOUNT_AUTHORITY_ORIGIN.to_owned(),
            ),
            (
                "SOLAND_ACCOUNT_AUTHORITY_SERVICE_ID".to_owned(),
                authority_id.clone(),
            ),
        ]
    };
    let source_env = common(source_database_url);
    let mut target_env = common(target_database_url);
    target_env.extend([
        ("SOLAND_ENABLE_TEST_ENDPOINTS".to_owned(), "1".to_owned()),
        (
            "SOLAND_TEST_CHAOS_CONTROL_FILE".to_owned(),
            control.display().to_string(),
        ),
    ]);
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        "direct-repair-live",
        &[source_env, target_env],
    )
    .await?
    else {
        eprintln!("skipping direct repair live E2E: prebuilt Soland binary is unavailable");
        return Ok(());
    };
    let source = group.server(0);
    let target = group.server(1);
    let requester_full = FullId::new(actor_did_for_service(
        source.service_id(),
        "repair-requester",
    )?)?;
    let recipient_full = FullId::new(actor_did_for_service(
        target.service_id(),
        "repair-recipient",
    )?)?;
    let requester = project_full_id_to_core_id(&requester_full)?;
    let recipient = project_full_id_to_core_id(&recipient_full)?;
    let requester_device = DeviceId::new(canonical_device_id("repair-requester-device"))?;
    let recipient_device_a = DeviceId::new(canonical_device_id("repair-recipient-a"))?;
    let recipient_device_b = DeviceId::new(canonical_device_id("repair-recipient-b"))?;
    let requester_key = SigningKey::from_bytes(&[0x71; 32]);
    let recipient_key = SigningKey::from_bytes(&[0x72; 32]);
    let requester_client = source
        .register_client(
            requester_full.as_str(),
            "repair-requester",
            requester_device.as_str(),
        )
        .await?;
    let recipient_client = target
        .register_client(
            recipient_full.as_str(),
            "repair-recipient",
            recipient_device_a.as_str(),
        )
        .await?;
    let requester_authorize = authorize_device_public_key_with_event_id(
        source,
        &requester_client.token,
        requester_full.as_str(),
        requester_device.as_str(),
        &requester_key,
    )
    .await?;
    authorize_device_public_key_with_event_id(
        target,
        &recipient_client.token,
        recipient_full.as_str(),
        recipient_device_a.as_str(),
        &recipient_key,
    )
    .await?;
    install_device(
        target,
        &recipient,
        &recipient_device_b,
        &SigningKey::from_bytes(&[0x73; 32]),
    )
    .await?;
    let (source_service_id, source_record) = current_service_record(source).await?;
    let (target_service_id, target_record) = current_service_record(target).await?;
    let fixture = fixture_events(
        source.trust_domain().clone(),
        &requester_full,
        &requester,
        &recipient,
    )?;
    let target_binding = accepted_local_binding(
        &recipient_full,
        &recipient,
        &target_record,
        target.trust_domain().as_str(),
        &recipient_device_a,
    )?;
    install_fixture(
        source,
        &fixture,
        &requester,
        &recipient,
        &target_service_id,
        &target_record,
        None,
    )
    .await?;
    install_fixture(
        target,
        &fixture,
        &requester,
        &recipient,
        &source_service_id,
        &source_record,
        Some(&target_binding),
    )
    .await?;
    let keypackage_ref = upload_requester_keypackage(
        source,
        &requester_client.token,
        &requester_full,
        &requester_device,
        &requester_authorize,
        &requester_key,
    )
    .await?;

    let request_id = "Q290ZXN0RGlyZWN0UmVwYWlyMDE";
    let request = signed_dispatch(
        request_id,
        &fixture,
        &requester,
        &requester_device,
        &requester_authorize,
        &keypackage_ref,
        &requester_key,
    )?;
    let reached = temp.path().join("post-commit.reached");
    let release = temp.path().join("post-commit.release");
    std::fs::write(
        &control,
        serde_json::to_vec(&json!({
            "breakpoint": "post_direct_repair_commit_pre_response",
            "transaction_id": request_id,
            "delay_ms": 15000,
            "reached_file": reached,
            "release_file": release,
        }))?,
    )?;
    let first = source
        .http()
        .post(source.url(DISPATCH_PATH))
        .bearer_auth(&requester_client.token)
        .timeout(Duration::from_millis(500))
        .json(&request)
        .send();
    ensure!(
        first.await.is_err(),
        "response-loss probe unexpectedly received the response"
    );
    wait_for_file(&reached).await?;
    std::fs::write(&release, b"release")?;
    tokio::time::sleep(Duration::from_millis(250)).await;
    let replay: DirectConversationRepairEnqueueOutcome = serde_json::from_value(
        expect_json(
            source
                .http()
                .post(source.url(DISPATCH_PATH))
                .bearer_auth(&requester_client.token)
                .json(&request),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        replay.validate_shape().is_ok(),
        "repair replay did not return Enqueued"
    );
    let messages = observed_messages(target, &recipient).await?;
    ensure!(
        messages.len() == 2,
        "repair must enqueue once to both current devices: {messages:?}"
    );
    ensure!(
        messages.iter().all(
            |row| row["content"]["content"]["requester_keypackage_ref"].as_str()
                == Some(keypackage_ref.as_str())
        ),
        "repair changed the exact requester KeyPackage ref"
    );
    let replay_again: DirectConversationRepairEnqueueOutcome = serde_json::from_value(
        expect_json(
            source
                .http()
                .post(source.url(DISPATCH_PATH))
                .bearer_auth(&requester_client.token)
                .json(&request),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        replay == replay_again && observed_messages(target, &recipient).await?.len() == 2,
        "exact replay changed outcome bytes or duplicated messages"
    );

    let mut conflicting = request.clone();
    conflicting.content.created_at += ChronoDuration::seconds(1);
    let conflict_response = source
        .http()
        .post(source.url(DISPATCH_PATH))
        .bearer_auth(&requester_client.token)
        .json(&conflicting)
        .send()
        .await?;
    ensure!(
        conflict_response.status() == StatusCode::CONFLICT,
        "same request_id with another digest was not rejected"
    );
    ensure!(
        observed_messages(target, &recipient).await?.len() == 2,
        "digest conflict produced target side effects"
    );

    let race_id = "Q290ZXN0RGlyZWN0UmVwYWlyMDI";
    let race_request = signed_dispatch(
        race_id,
        &fixture,
        &requester,
        &requester_device,
        &requester_authorize,
        &keypackage_ref,
        &requester_key,
    )?;
    let race_reached = temp.path().join("pre-commit.reached");
    let race_release = temp.path().join("pre-commit.release");
    std::fs::write(
        &control,
        serde_json::to_vec(&json!({
            "breakpoint": "pre_direct_repair_device_batch_commit",
            "transaction_id": race_id,
            "delay_ms": 15000,
            "reached_file": race_reached,
            "release_file": race_release,
        }))?,
    )?;
    let race_client = source.http();
    let race_url = source.url(DISPATCH_PATH);
    let race_token = requester_client.token.clone();
    let pending = tokio::spawn(async move {
        race_client
            .post(race_url)
            .bearer_auth(race_token)
            .json(&race_request)
            .send()
            .await
    });
    wait_for_file(&race_reached).await?;
    install_device(
        target,
        &recipient,
        &DeviceId::new(canonical_device_id("repair-recipient-racing"))?,
        &SigningKey::from_bytes(&[0x74; 32]),
    )
    .await?;
    std::fs::write(&race_release, b"release")?;
    let race_response = pending.await.context("join race dispatch")??;
    ensure!(
        !race_response.status().is_success(),
        "changed target snapshot returned Enqueued"
    );
    ensure!(
        observed_messages(target, &recipient).await?.len() == 2,
        "snapshot race partially enqueued a repair batch"
    );
    Ok(())
}
