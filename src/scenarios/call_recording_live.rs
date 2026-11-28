//! Process-native recording composition: real issuer/Station/current/Start/Q/
//! Blob/Service-ready originals plus the actual RTC codec and receiver. The
//! plaintext source is a test recording sample, not a claimed product recorder.

use anyhow::{Context as _, Result, ensure};
use arkret_crypto::call_recording::RecordingStreamOutput;
use arkret_identity::{ProducerVerificationContext, VerifiedProducerEvent, VerifiedRealmCommit};
use arkret_mls::ArkretMlsGroup;
use arkret_models_collaboration::events_payloads::call::*;
use arkret_models_collaboration::mls_group_state_material::*;
use arkret_models_collaboration::objects::blob::{
    BlobStorageEncryption, BlobStorageEncryptionScheme, BlobUploadResponseBody,
};
use arkret_models_crypto::{EncryptedAttachmentKeyRef, MlsGovernanceBindingPayload};
use arkret_wire::{
    Base64UrlString, CallId, CommittedEventFullView, CurrentSelector, CurrentState, Event,
    EventKind, GrantId, MlsGroupValue, RealmId, ScopeRef,
};
use serde_json::{Value, json};

use crate::harness::{ArkretServer, expect_json};
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, submit_and_expect_commit,
};
use crate::scenarios::mls_lifecycle_live::{self as mls, Member};

mod evidence;
pub(crate) mod service;

/// This independent composition does not award native operation obligations.
pub async fn verify_native_composition() -> Result<()> {
    crate::harness::heap_future(evidence::run).await
}

async fn submit(member: &Member, event: &Event) -> Result<CommittedEventFullView> {
    submit_and_expect_commit(
        &member.client,
        &member.account,
        member.device.as_str(),
        event,
    )
    .await?;
    mls::accepted_full_view(&member.client, &event.event_id).await
}

async fn owner_event(
    member: &Member,
    realm: &RealmId,
    kind: EventKind,
    payload: Value,
) -> Result<CommittedEventFullView> {
    let event = member
        .client
        .author_event(realm.as_str(), kind.as_str(), payload)
        .await?;
    submit(member, &event).await
}

pub(crate) async fn verify_owned_originals(
    member: &Member,
    originals: &[&CommittedEventFullView],
) -> Result<Vec<(VerifiedProducerEvent, VerifiedRealmCommit)>> {
    let mut entropy = [0; 32];
    getrandom::fill(&mut entropy)?;
    let request = arkret_wire::RealmAuthorityBundleRequestBody {
        realm_id: originals
            .first()
            .context("originals absent")?
            .event
            .realm_id
            .clone(),
        nonce: Base64UrlString::new(arkret_canonical::base64url_encode(entropy))
            .map_err(anyhow::Error::msg)?,
    };
    let http = member.client.sdk();
    let bundle = http.realm_authority_bundle(&request).await?;
    let keys = garth::fetch_historical_station_key_directory(&http, &bundle, None, None).await?;
    let authority = arkret_identity::verify_realm_authority_bundle(
        &bundle,
        &arkret_identity::RealmAuthorityFreshness::new(chrono::Utc::now(), request.nonce),
        &keys,
    )?;
    originals
        .iter()
        .map(|full| {
            Ok((
                VerifiedProducerEvent::verify(
                    full.event.clone(),
                    &ProducerVerificationContext {
                        actor: member.actor.clone(),
                        verification_method: member.method.clone(),
                        public_key: arkret_signatures::PublicKeyMaterial::Ed25519Raw {
                            bytes: member.key.verifying_key().as_bytes().to_vec(),
                        },
                        digest_suite: arkret_canonical::DigestSuite::Sha256,
                    },
                )?,
                VerifiedRealmCommit::verify(full.commit.clone(), &authority, &keys)?,
            ))
        })
        .collect()
}

fn mls_current(
    snapshot: &arkret_wire::RealmStateSnapshot,
    scope: &ScopeRef,
) -> Result<MlsGroupValue> {
    let mut rows = snapshot.current_state_entries.iter().filter_map(|row| {
        let CurrentState::Value {
            selector,
            value,
            source_stream_ref,
            ..
        } = row;
        matches!(selector, CurrentSelector::MlsGroup { scope_ref } if scope_ref==scope)
            .then_some((source_stream_ref, value))
    });
    let (stream, value) = rows.next().context("native MLS current absent")?;
    ensure!(
        rows.next().is_none() && stream.scope_ref() == *scope,
        "native MLS current is duplicate or foreign"
    );
    Ok(garth::current_ingest::closed_current_value(
        value,
        "mls_group",
    )?)
}

async fn genesis(
    member: &Member,
    realm: &RealmId,
) -> Result<(ArkretMlsGroup, CommittedEventFullView)> {
    let scope = ScopeRef::realm(realm.clone());
    let binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mut group = member
        .mls_identity()?
        .create_group_with_governance_binding(&scope, &binding)?;
    group.install_local_creator_binding(
        member.actor.clone(),
        Some(member.authorize_event_id.clone()),
    )?;
    let leaf = group
        .verified_leaf_bindings()?
        .into_iter()
        .next()
        .context("real founding MLS leaf absent")?;
    let (info, tree) = group.public_group_state_bytes()?;
    let payload = arkret_models_collaboration::events_payloads::MlsGenesisPayload {
        cipher_suite: arkret_wire::NonEmptyString::new(mls::ACTIVE_SUITE)
            .map_err(anyhow::Error::msg)?,
        group_info_ref: mls::upload_public_blob(&member.client, realm, &info)
            .await?
            .parse()?,
        ratchet_tree_ref: mls::upload_public_blob(&member.client, realm, &tree)
            .await?
            .parse()?,
        creator_leaf_authority:
            arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority {
                leaf_signature_key_base64url: leaf.signature_key,
                endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
                    device_id: member.device.clone(),
                },
                authorization_event_ref: member.authorize_event_id.clone(),
            },
        governance_binding: binding,
        created_at: chrono::Utc::now(),
    };
    let mut event = member
        .client
        .author_event(
            realm.as_str(),
            EventKind::MlsGenesis.as_str(),
            serde_json::to_value(payload)?,
        )
        .await?;
    event.payload.insert(
        "created_at".into(),
        json!(arkret_canonical::format_timestamp_canonical(
            event.created_at
        )),
    );
    crate::harness::refresh_typed_event_proof_with_signing_seed(&mut event, member.key.to_bytes())?;
    let accepted = submit(member, &event).await?;
    Ok((group, accepted))
}

pub(crate) fn material_request(
    member: &Member,
    current: &MlsGroupValue,
    state: &CommittedEventFullView,
) -> Result<MlsMemberGroupStateMaterialReadRequestBody> {
    let payload = &state.event.payload;
    Ok(MlsMemberGroupStateMaterialReadRequestBody {
        realm_id: state.event.realm_id.clone(),
        effective_scope: current.effective_scope.clone(),
        mls_group_id: current.effective_scope.canonical_mls_group_id()?,
        epoch: current.epoch,
        group_state_event_id: current.current_mls_commit_event_ref.clone(),
        caller_actor_id: member.actor.clone(),
        target_commit_event_ref: state.event.event_id.clone(),
        target_epoch: current.epoch,
        group_info_ref: serde_json::from_value(
            payload
                .get("group_info_ref")
                .context("original GroupInfo ref absent")?
                .clone(),
        )?,
        ratchet_tree_ref: serde_json::from_value(
            payload
                .get("ratchet_tree_ref")
                .context("original tree ref absent")?
                .clone(),
        )?,
        max_response_bytes: None,
    })
}

async fn grant_start(member: &Member, realm: &RealmId) -> Result<CommittedEventFullView> {
    owner_event(member,realm,EventKind::CapabilityGrant,json!({"grant":{
        "schema":"ak.schema.capability.v1","realm_id":realm,"issuer_id":member.actor,"subject":member.actor,
        "actions":["ak.call.record"],"resources":[{"kind":"realm","realm_id":realm}],
        "constraints":[{"constraint_kind":"quota","constraint_subkind":"rate","effect":"allow","max_operation_count":1,"period":"PT1H","constraint_scope":"per_actor"}],
        "issuer_authority_refs":[{"kind":"realm_root","realm_id":realm,"authority_event_ref":realm.event_id(),"authority_generation":"0"}],
        "issued_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}})).await
}

async fn original_rows(
    station: &ArkretServer,
    realm: &RealmId,
    blob: &arkret_wire::BlobRef,
    grant: &GrantId,
) -> Result<Value> {
    let database = station
        .owned_database_url()
        .context("native recording database absent")?
        .to_owned();
    let realm = realm.to_string();
    let blob = blob.to_string();
    let grant = grant.to_string();
    tokio::task::spawn_blocking(move || ->Result<Value> {
        let mut db=postgres::Client::connect(&database,postgres::NoTls)?;
        let events=db.query("SELECT e.envelope,c.commit_json,p.producer_source_fact,p.outcome FROM canonical_events e JOIN realm_commits c ON c.event_pk=e.pk LEFT JOIN agent_producer_signer_keys p ON p.commit_id=c.commit_id WHERE c.realm_id=$1 ORDER BY c.stream_position", &[&realm])?;
        let blob=db.query_one("SELECT to_jsonb(b) FROM blobs b WHERE id=$1", &[&blob])?.get::<_,Value>(0);
        let capture=db.query("SELECT to_jsonb(c) FROM call_component_current_states c WHERE realm_id=$1 ORDER BY selector::text", &[&realm])?.into_iter().map(|row|row.get::<_,Value>(0)).collect::<Vec<_>>();
        let quota=db.query("SELECT to_jsonb(q) FROM capability_quota_consumptions q WHERE grant_id=$1", &[&grant])?.into_iter().map(|row|row.get::<_,Value>(0)).collect::<Vec<_>>();
        let originals=events.into_iter().map(|row|json!({"event":row.get::<_,Value>(0),"commit":row.get::<_,Value>(1),"producer_source_fact":row.get::<_,Option<Value>>(2),"signer_outcome":row.get::<_,Option<Value>>(3)})).collect::<Vec<_>>();
        Ok(json!({"canonical_originals":originals,"blob":blob,"capture":capture,"start_quota":quota}))
    }).await?
}

fn artifact(
    output: &RecordingStreamOutput,
    start: &CommittedEventFullView,
    initiator: &GrantId,
) -> Result<CallRecordingArtifact> {
    let payload: CallRecordingStartPayload = serde_json::from_value(json!(start.event.payload))?;
    Ok(CallRecordingArtifact {
        schema: CallRecordingArtifact::SCHEMA.into(),
        realm_id: start.event.realm_id.clone(),
        call_id: payload.call_id,
        recording_id: payload.recording_id,
        recording_start_event_id: start.event.event_id.clone(),
        blob_ref: output.blob_ref().clone(),
        size_bytes: output.size_bytes(),
        duration_ms: 25,
        media_type: output.media_type().into(),
        encryption: output.encryption().clone(),
        retention_policy_id: None,
        retention: payload.capture_metadata.retention,
        produced_by: payload.recording_agent_id,
        recording_initiator_capability_ref: initiator.clone(),
        created_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        deletion_audit: None,
    })
}

pub async fn run() -> Result<Value> {
    let deployment =
        crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment(
            "native-call-recording-codec",
        )
        .await?;
    let member = Member::from_client(deployment.controller.clone(), deployment.account.clone())?;
    let recorder = service::RecorderService::start(&deployment.station).await?;
    let realm: RealmId = create_realm_with_join_rule(
        &member.client,
        "Native RTC recording codec",
        "closed",
        &[&deployment.station],
    )
    .await?
    .parse()?;
    let (install, registration, service_grant) = recorder
        .install(&deployment.station, &member, &realm)
        .await?;
    let (mut group, genesis) = genesis(&member, &realm).await?;
    let scope = ScopeRef::realm(realm.clone());
    let permission = grant_start(&member, &realm).await?;
    let initiator = GrantId::from_event_id(&permission.event.event_id);
    let descriptor=owner_event(&member,&realm,EventKind::RealmMediaService,json!({"value":{"service_id":recorder.service_id(),"recording_supported":true,
        "foci":[{"focus_id":"recording-focus","focus_kind":"livekit","token_endpoint":format!("{}/token",recorder.package.base_url),"connect_url":recorder.package.base_url.replace("https:","wss:")} ]}})).await?;
    let create = owner_event(
        &member,
        &realm,
        EventKind::CallCreate,
        json!({"initial_state":"ringing"}),
    )
    .await?;
    let call = CallId::from_event_id(&create.event.event_id);
    let active=owner_event(&member,&realm,EventKind::CallState,json!({"call_id":call,"state_transition":{"from":"ringing","to":"active"},"focus":{"mode":"sfu","session_focus":"recording-focus"}})).await?;
    let own = member
        .client
        .sdk()
        .own_station_result_client()?
        .context("actual issuer host source absent")?;
    let current = own.snapshot_head(&realm).await?;
    let value = mls_current(current.value()?, &scope)?;
    let key_ref: EncryptedAttachmentKeyRef = serde_json::from_value(
        json!({"algorithm":"MLS","group_state_ref":value.current_mls_commit_event_ref}),
    )?;
    let material = own
        .self_mls_group_state_material(&material_request(&member, &value, &genesis)?)
        .await?;
    let start_payload = CallRecordingStartPayload {
        call_id: call.clone(),
        recording_id: CallRecordingId::new("native-segment-1")?,
        recording_agent_id: recorder.service_id().clone(),
        capture_kind: RecordingCaptureKind::Recording,
        mode: RecordingMode::AudioOnly,
        visible_notice: VisibleCaptureNotice,
        capture_metadata: RecordingStartMetadata {
            key_ref: Some(key_ref.clone()),
            retention: CallRecordingRetention {
                retention_expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
                deletion_trigger: None,
                audit_lock: None,
                consent_confirmed: Some(true),
            },
        },
    };
    let mut start_event = member
        .client
        .author_event(
            realm.as_str(),
            EventKind::CallRecordingStart.as_str(),
            serde_json::to_value(&start_payload)?,
        )
        .await?;
    start_event.authorization_ref =
        Some(arkret_wire::AuthorizationRef::new(initiator.as_str()).map_err(anyhow::Error::msg)?);
    crate::harness::refresh_typed_event_proof_with_signing_seed(
        &mut start_event,
        member.key.to_bytes(),
    )?;
    let start = submit(&member, &start_event).await?;
    let verified = verify_owned_originals(&member, &[&genesis, &start]).await?;
    let source = arkret::call_recording::BoundRecordingSource::bind(
        &group,
        current,
        material,
        &verified[0].0,
        &verified[0].1,
        &verified[0].0,
        &verified[0].1,
    )?;
    let fence = source.new_writer_fence()?;
    let mut writer = source.begin_recording(
        &group,
        &fence,
        &verified[1].0,
        &verified[1].1,
        "recording-focus".into(),
        arkret_mls::call_recording::RecordingStreamParameters {
            segment_bytes: 1024,
            media_type: "audio/ogg".into(),
            digest_suite: arkret_canonical::DigestSuite::Sha256,
        },
    )?;
    let original_group = ArkretMlsGroup::restore_from_state_record(&group.export_state_record()?)?;
    let plaintext = (0..2057)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let mut ciphertext = Vec::new();
    writer.push_to(&plaintext, |chunk| {
        ciphertext.extend_from_slice(chunk);
        Ok(())
    })?;
    let stop=owner_event(&member,&realm,EventKind::CallState,json!({"call_id":call,"recording_transition":{"recording_id":start_payload.recording_id,"from":"recording","to":"stopped"}})).await?;
    let binding = MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(genesis.event.event_id.clone()),
        value.epoch,
        value.epoch + 1,
        value.current_key_access_revision,
    )?;
    let transition = group.self_update_commit_with_governance_binding(&binding)?;
    let payload = mls::commit_payload_with_public_material(
        &member.client,
        &group,
        genesis.event.event_id.clone(),
        value.current_key_access_revision,
        &transition,
        binding,
    )
    .await?;
    let next_event = member
        .client
        .author_event(
            realm.as_str(),
            EventKind::MlsCommit.as_str(),
            serde_json::to_value(payload)?,
        )
        .await?;
    let next_submission =
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::MlsCommit(
            arkret_wire::MlsCommitSubmission {
                recovery_source: None,
                commit_event: next_event.clone(),
                welcomes: Vec::new(),
                idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7())?,
            },
        );
    expect_json(
        member
            .client
            .post("/_arkret/self/events")
            .json(&next_submission),
        reqwest::StatusCode::OK,
    )
    .await?;
    let next = mls::accepted_full_view(&member.client, &next_event.event_id).await?;
    fence.with_epoch_install(|| group.install_accepted_commit(&next, &value))?;
    let next_current = own.snapshot_head(&realm).await?;
    let next_value = mls_current(next_current.value()?, &scope)?;
    ensure!(
        next_value.current_mls_commit_event_ref == next.event.event_id,
        "native current did not adopt actual Q1"
    );
    let next_material = own
        .self_mls_group_state_material(&material_request(&member, &next_value, &next)?)
        .await?;
    let next_verified = verify_owned_originals(&member, &[&genesis, &next]).await?;
    let next_source = arkret::call_recording::BoundRecordingSource::bind(
        &group,
        next_current,
        next_material,
        &next_verified[0].0,
        &next_verified[0].1,
        &next_verified[1].0,
        &next_verified[1].1,
    )?;
    fence.adopt_installed_epoch(&group, next_source.installed_epoch()?)?;
    let mut delivered = Vec::new();
    fence.with_media_delivery(&group, next_source.installed_epoch()?, || {
        delivered.extend_from_slice(b"new epoch plaintext");
        Ok(())
    })?;
    ensure!(
        delivered == b"new epoch plaintext",
        "new epoch delivery did not use the requalified same fence"
    );
    let mut leaked = false;
    ensure!(
        writer
            .push_to(b"new epoch plaintext", |_| {
                leaked = true;
                Ok(())
            })
            .is_err()
            && !leaked,
        "old writer admitted plaintext after actual new epoch installation"
    );
    let output = writer.finish(|chunk| {
        ciphertext.extend_from_slice(chunk);
        Ok(())
    })?;
    let artifact = artifact(&output, &start, &initiator)?;
    ensure!(
        artifact.encryption.key_ref == key_ref,
        "old segment silently replaced its original Q"
    );
    let upload: BlobUploadResponseBody = serde_json::from_value(
        expect_json(
            member.client.post("/_arkret/self/blob/upload").multipart(
                crate::scenarios::delivery_media::blob_upload_classified_form(
                    &ciphertext,
                    "application/octet-stream",
                    Some(BlobStorageEncryption {
                        scheme: BlobStorageEncryptionScheme::StreamV1,
                    }),
                )?
                .text("realm_id", realm.to_string()),
            ),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        upload.blob_ref == artifact.blob_ref && upload.size_bytes == artifact.size_bytes,
        "actual Blob receipt changed codec ciphertext"
    );
    let g2 = GrantId::from_event_id(&service_grant.event_id);
    let ready_payload: CallStatePayload = serde_json::from_value(
        json!({"call_id":call,"recording_transition":{"recording_id":start_payload.recording_id,"from":"stopped","to":"ready","expected_commit_id":start.commit.commit_id,"capture_metadata":{"artifact":artifact}}}),
    )?;
    let ready_event = recorder.ready_event(&member.actor, &realm, &g2, ready_payload)?;
    let ready_reply = recorder.submit(&deployment.station, &ready_event).await?;
    let ready = mls::accepted_full_view(&member.client, &ready_event.event_id).await?;
    let ready_replay = recorder.submit(&deployment.station, &ready_event).await?;
    ensure!(
        mls::accepted_full_view(&member.client, &ready_event.event_id).await? == ready,
        "exact Service retry rewrote its original ready Event/Commit"
    );
    let final_snapshot = own.snapshot_head(&realm).await?;
    ensure!(
        mls_current(final_snapshot.value()?, &scope)?.current_mls_commit_event_ref
            == next.event.event_id,
        "native current winner did not advance to the actual Q1"
    );
    let fetched = crate::harness::expect_response(
        member.client.get(&format!(
            "/_arkret/self/blob/get?blob_ref={}",
            artifact.blob_ref
        )),
        reqwest::StatusCode::OK,
    )
    .await?;
    ensure!(
        fetched.body == ciphertext,
        "native Blob read changed stored ciphertext"
    );
    let opened = source.installed_epoch()?.decrypt_recording(
        &original_group,
        &start.event.event_id,
        &start_payload,
        &artifact,
        &fetched.body,
    )?;
    ensure!(
        *opened == plaintext,
        "real recording receiver did not recover original sample"
    );
    let mut corrupt = ciphertext.clone();
    corrupt[1024 + 15] ^= 1;
    let mut corrupt_artifact = artifact.clone();
    corrupt_artifact.blob_ref = arkret_wire::BlobRef::new(format!(
        "ak:blob:{}",
        arkret_canonical::sha256_digest(&corrupt)
    ))?;
    let tag_error = source
        .installed_epoch()?
        .decrypt_recording(
            &original_group,
            &start.event.event_id,
            &start_payload,
            &corrupt_artifact,
            &corrupt,
        )
        .err()
        .context("receiver accepted bad AEAD tag after valid whole address recomputation")?;
    ensure!(
        matches!(tag_error, arkret_mls::MlsError::Crypto(_)),
        "tag corruption did not reach the real AEAD gate: {tag_error}"
    );
    let mut wrong_aad = artifact.clone();
    wrong_aad.media_type = "audio/webm".into();
    let aad_error = source
        .installed_epoch()?
        .decrypt_recording(
            &original_group,
            &start.event.event_id,
            &start_payload,
            &wrong_aad,
            &ciphertext,
        )
        .err()
        .context("receiver accepted another RTC AAD")?;
    ensure!(
        matches!(aad_error, arkret_mls::MlsError::Crypto(_)),
        "wrong RTC AAD did not reach the real AEAD gate: {aad_error}"
    );
    ensure!(
        source
            .installed_epoch()?
            .decrypt_recording(
                &group,
                &start.event.event_id,
                &start_payload,
                &artifact,
                &ciphertext
            )
            .is_err(),
        "current epoch substituted for original recording epoch"
    );
    let originals =
        original_rows(&deployment.station, &realm, &artifact.blob_ref, &initiator).await?;
    ensure!(
        originals["start_quota"]
            .as_array()
            .context("native quota rows absent")?
            .len()
            == 1,
        "ready recharged original Start quota"
    );
    let service_resolution = recorder.current_resolution(&deployment.station).await?;
    Ok(
        json!({"realm_id":realm,"install":install,"registration_event":registration,"service_grant_event":service_grant,"service_resolution":service_resolution,
        "grant":permission,"descriptor":descriptor,"call":create,"active":active,"genesis":genesis,"start":start,"stop":stop,"next_epoch":next,"ready":ready,"ready_reply":ready_reply,
        "artifact":artifact,"upload":upload,"ready_replay":ready_replay,"final_snapshot":final_snapshot.value()?,"tag_error":tag_error.to_string(),"aad_error":aad_error.to_string(),"plaintext_base64url":arkret_canonical::base64url_encode(&plaintext),"ciphertext_base64url":arkret_canonical::base64url_encode(&ciphertext),
        "fetched_base64url":arkret_canonical::base64url_encode(&fetched.body),"corrupt_ciphertext_base64url":arkret_canonical::base64url_encode(&corrupt),"corrupt_artifact":corrupt_artifact,
        "wrong_aad":wrong_aad,"originals":originals,"boundary":"Real native process/HTTP/PG and real RFC MLS/RTC byte codec composition; test sample production, not an Inkson recorder/MediaRecorder claim.",
        "processes":[deployment.coauth.server.native_process_identity()?,deployment.station.native_process_identity()?]}),
    )
}
