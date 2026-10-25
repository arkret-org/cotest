//! Ordinary encrypted messages between two Stations. The local controller
//! performs the MLS transitions; the remote member receives and sends ordinary
//! Messages without requiring a remote high-risk MLS grant.

use anyhow::{Context, Result, ensure};
use arkret::{ArkretMlsGroup, MlsCommitPayload, MlsGovernanceBindingPayload};
use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody;
use arkret_models_collaboration::events_payloads::message::MessageCreatePayload;
use arkret_wire::{
    AuthoritySubmitResponseBody, EventId, EventKind, MlsCommitSubmission, RealmId, ScopeRef,
};
use base64::Engine as _;
use reqwest::StatusCode;

use crate::harness::TestServerGroup;
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::cross_station_mls_welcome::{
    claim_for, genesis_creator_leaf_authority, join_through_invite, publish_one, wait_for_welcome,
};
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, ensure_commit_signed_by, station_env,
    submit_and_expect_commit, wait_for_committed,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use crate::scenarios::mls_lifecycle_live::{
    ACTIVE_SUITE, Member, accepted_full_view, canonical, claimed_keypackage_record, fresh_uuid_v7,
    post_json, signed_welcome, upload_public_blob,
};

mod call_holders;

const GROUP: &str = "message-mls-cross-station";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002801";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002802";

/// This shared fixture also runs inside existing Send production journeys.
/// Native UI observation must finish on its own executor before returning.
#[async_trait::async_trait]
pub trait CrossStationCallObserver: Send + Sync {
    fn configure_emission_probe(&self, path: &std::path::Path) -> Result<()>;
    #[expect(
        clippy::too_many_arguments,
        reason = "Observation binds the complete accepted MLS fixture"
    )]
    async fn observe_ordinary_call_invite(
        &self,
        sender: &Member,
        holder: &Member,
        station: &crate::harness::ArkretServer,
        holder_station: &crate::harness::ArkretServer,
        realm: &RealmId,
        accepted_group: &EventId,
        sender_group: &mut ArkretMlsGroup,
        holder_group: &ArkretMlsGroup,
        other_holder: &Member,
        other_group: &ArkretMlsGroup,
        observe_receipt: bool,
    ) -> Result<()>;
    async fn after_station_restart(&self, holder: &Member) -> Result<()>;
    #[expect(
        clippy::too_many_arguments,
        reason = "Recovery observation binds both holders, their accepted MLS state, and scan control"
    )]
    async fn observe_material_recovery(
        &self,
        sender: &Member,
        holder: &Member,
        realm: &RealmId,
        accepted_group: &EventId,
        sender_group: &ArkretMlsGroup,
        holder_group: &ArkretMlsGroup,
        control: crate::harness::ScanGapControl,
    ) -> Result<()>;
    fn media_token_ttl_seconds(&self) -> Option<u64> {
        None
    }

    fn verify_service_signer_rotation(&self) -> bool {
        false
    }
}

/// Bind every actual occupied leaf to the accepted founding device facts,
/// not the isolated cryptography test helper's synthetic authorization ID.
pub async fn install_bindings(group: &mut ArkretMlsGroup, members: &[&Member]) -> Result<()> {
    let mut bindings = Vec::new();
    for leaf in group.active_author_leaves() {
        let arkret::AuthorLeafCredential::Basic { identity } = leaf.credential else {
            anyhow::bail!("the ordinary Message group requires BasicCredential")
        };
        let actor = arkret_models_crypto::decode_mls_basic_credential_identity(&identity)?;
        let member = members
            .iter()
            .find(|member| member.actor == actor)
            .context("an occupied leaf has no provisioned member")?;
        let authorization = accepted_full_view(&member.client, &member.authorize_event_id).await?;
        ensure!(authorization.event.kind == EventKind::DeviceAuthorize);
        ensure!(authorization.commit.event_ref == member.authorize_event_id);
        ensure!(authorization.event.actor_id == member.actor);
        let accepted_device = arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload::try_from(&authorization.event)?;
        ensure!(accepted_device.device_id == member.device);
        ensure!(accepted_device.authorized_generation_ref == 1);
        ensure!(
            accepted_device.authorization_binding_kind
                == arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizationBindingKind::RegistrationAnchor
        );
        ensure!(
            accepted_device.device_public_key_did.as_str()
                == format!(
                    "did:key:{}",
                    arkret_crypto::identity_root::ed25519_public_multikey(
                        &member.key.verifying_key().to_bytes()
                    )
                )
        );
        ensure!(leaf.signature_key == member.key.verifying_key().to_bytes());
        bindings.push(arkret::MlsVerifiedLeafBinding {
            leaf_index: leaf.leaf_index,
            actor_id: actor,
            endpoint: arkret_models_crypto::MlsEndpointIdentity::human_device(
                member.account.principal_id.clone(),
                member.device.clone(),
            ),
            signature_key: arkret_wire::Base64UrlString::new(
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&leaf.signature_key),
            )
            .map_err(anyhow::Error::msg)?,
            device_authorize_event_id: Some(member.authorize_event_id.clone()),
        });
    }
    ensure!(bindings.len() == members.len());
    group.install_verified_leaf_bindings(bindings)?;
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "Cross-station fixture binds sender, recipient and signed routing context"
)]
pub(crate) async fn submit_and_open(
    sender: &Member,
    receiver: &Member,
    sender_group: &mut ArkretMlsGroup,
    receiver_group: &mut ArkretMlsGroup,
    realm: &RealmId,
    strand: &str,
    state_ref: &EventId,
    body: &str,
) -> Result<arkret_wire::RealmCommit> {
    let content = arkret::ContentBlock::text(body);
    submit_and_open_content(
        sender,
        receiver,
        sender_group,
        receiver_group,
        realm,
        strand,
        state_ref,
        content,
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn submit_and_open_content(
    sender: &Member,
    receiver: &Member,
    sender_group: &mut ArkretMlsGroup,
    receiver_group: &mut ArkretMlsGroup,
    realm: &RealmId,
    strand: &str,
    state_ref: &EventId,
    content: arkret::ContentBlock,
    scope: ScopeRef,
) -> Result<arkret_wire::RealmCommit> {
    let plaintext = arkret_canonical::canonical_json_bytes(&content)?;
    let before = sender_group.export_state_record()?.serialized_state;
    let header = arkret::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/vnd.arkret.message+json",
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        scope.clone(),
        EventKind::MessageCreate.as_str(),
        sender_group.epoch(),
        state_ref.clone(),
        sender_group.local_content_sender_domain()?,
        arkret::EventContentRoutingContext::None,
    )?;
    let sealed = arkret::MessageCrypto::encrypt(sender_group, fresh_uuid_v7(), header, &plaintext)?;
    let state_after = sender_group.export_state_record()?;
    ensure!(
        before != state_after.serialized_state,
        "encryption did not advance the sender state"
    );
    // Deserialize at the envelope boundary into the SDK's closed payload type.
    let payload: MessageCreatePayload = serde_json::from_value(serde_json::json!({
        "strand_id": strand, "track_name": "discussion", "encrypted_content": sealed.payload.to_envelope()?,
    }))?;
    let mut event = sender
        .client
        .author_event(
            realm.as_str(),
            EventKind::MessageCreate.as_str(),
            canonical(serde_json::to_value(payload)?)?,
        )
        .await?;
    event.scope_ref = scope.clone();
    crate::harness::refresh_typed_event_proof_with_signing_seed(&mut event, sender.key.to_bytes())?;
    let frozen =
        garth::FrozenMessageSubmission::from_signed_request(garth::MessageSubmitRequestBody {
            submission: arkret_wire::EventAdmissionSubmission::new(event.clone()),
        })?;
    let file = tempfile::NamedTempFile::new()?;
    std::fs::write(file.path(), serde_json::to_vec(&frozen)?)?;
    // Persist the real ratchet state as well as the frozen request. This
    // run-scoped fixture file is not a product checkpoint storage format.
    let sender_checkpoint = tempfile::NamedTempFile::new()?;
    std::fs::write(sender_checkpoint.path(), serde_json::to_vec(&state_after)?)?;
    let outcome = sender
        .client
        .post("/_arkret/self/events")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(frozen.canonical_submission_bytes().to_vec())
        .send()
        .await?;
    ensure!(
        outcome.status() == StatusCode::OK,
        "encrypted Message submission: {}",
        outcome.status()
    );
    let outcome: AuthoritySubmitResponseBody = outcome.json().await?;
    let AuthoritySubmitResponseBody::Accepted { commit, .. } = outcome else {
        anyhow::bail!("encrypted Message was not accepted: {outcome:?}")
    };
    drop(frozen);
    let mut reopened: garth::FrozenMessageSubmission =
        serde_json::from_slice(&std::fs::read(file.path())?)?;
    let persisted_state = serde_json::from_slice(&std::fs::read(sender_checkpoint.path())?)?;
    let mut restored_sender = ArkretMlsGroup::restore_from_state_record(&persisted_state)?;
    let replay = sender
        .client
        .post("/_arkret/self/events")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(reopened.canonical_submission_bytes().to_vec())
        .send()
        .await?;
    ensure!(replay.status() == StatusCode::OK);
    let replay: AuthoritySubmitResponseBody = replay.json().await?;
    ensure!(
        matches!(&replay, AuthoritySubmitResponseBody::Accepted { commit: original, .. } if original == &commit),
        "encrypted exact replay allocated another Commit"
    );
    reopened.apply_outcome(replay)?;
    ensure!(reopened.state() == garth::MessageSubmissionState::Committed);
    ensure!(
        restored_sender.export_state_record()?.serialized_state == state_after.serialized_state
    );
    ensure!(sender_group.export_state_record()?.serialized_state == state_after.serialized_state);
    wait_for_committed(&receiver.client, &event.event_id).await?;
    let view = accepted_full_view(&receiver.client, &event.event_id).await?;
    ensure!(
        view.event == event && view.commit == commit,
        "replication changed the Message or its covering Commit"
    );
    let received: MessageCreatePayload =
        serde_json::from_value(serde_json::to_value(&view.event.payload)?)?;
    let envelope = received
        .encrypted_content
        .context("received Message lost its envelope")?;
    let sender_domain = String::from_utf8(arkret_models_crypto::mls_basic_credential_identity(
        &view.event.actor_id,
    )?)?;
    let header = envelope.reconstruct_pre_encryption_header(
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        scope,
        EventKind::MessageCreate.as_str(),
        sender_domain,
        None,
    )?;
    let payload = arkret::encrypted_envelope_to_payload_with_verified_header(&envelope, header)?;
    let opened = arkret::MessageCrypto::decrypt(
        receiver_group,
        &arkret::EncryptedMessage {
            message_id: event.event_id.to_string(),
            payload,
        },
    )?;
    ensure!(
        opened == plaintext,
        "remote recipient could not decrypt the canonical ContentBlock"
    );
    // Continue from exactly the state recovered from disk.
    std::mem::swap(sender_group, &mut restored_sender);
    Ok(commit)
}

pub async fn run() -> Result<()> {
    run_with_signal(false).await
}

pub(crate) async fn run_with_signal(include_signal: bool) -> Result<()> {
    run_with_signal_boundary(
        include_signal,
        super::signal_live::emission::Boundary::Leave,
    )
    .await
}

pub(crate) async fn run_with_signal_boundary(
    include_signal: bool,
    boundary: super::signal_live::emission::Boundary,
) -> Result<()> {
    run_at_two_stations(include_signal, boundary, None).await
}

pub async fn run_with_call_observer(observer: &dyn CrossStationCallObserver) -> Result<()> {
    run_at_two_stations(
        false,
        super::signal_live::emission::Boundary::Leave,
        Some(observer),
    )
    .await
}

async fn run_at_two_stations(
    include_signal: bool,
    boundary: super::signal_live::emission::Boundary,
    observer: Option<&dyn CrossStationCallObserver>,
) -> Result<()> {
    let Some(x_database) = database(GROUP)? else {
        ensure!(
            observer.is_none(),
            "cross-Station Call evidence requires PostgreSQL"
        );
        return Ok(());
    };
    let Some(y_database) = database(GROUP)? else {
        ensure!(
            observer.is_none(),
            "cross-Station Call evidence requires the second PostgreSQL database"
        );
        return Ok(());
    };
    ensure!(x_database.connect_url != y_database.connect_url);
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let emission_probe = tempfile::tempdir()?;
    let pause_file = emission_probe.path().join("signal-emission.pause");
    let mut recipient_env = station_env(&y_database.connect_url, &coauth);
    if let Some(ttl) = observer.and_then(|observer| observer.media_token_ttl_seconds()) {
        recipient_env.push(("COLAND_MEDIA_TOKEN_TTL_SECONDS".into(), ttl.to_string()));
    }
    if include_signal || observer.is_some() {
        if observer.is_some() {
            recipient_env.push((
                "COLAND_CONFORMANCE_MEDIA_TOKEN_RELEASE_PAUSE_FILE".into(),
                pause_file
                    .with_file_name("media-token-release.pause")
                    .to_string_lossy()
                    .into_owned(),
            ));
        }
        recipient_env.push((
            "COLAND_CONFORMANCE_SIGNAL_EMISSION_PAUSE_FILE".to_owned(),
            pause_file.to_string_lossy().into_owned(),
        ));
    }
    let Some(mut group) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[station_env(&x_database.connect_url, &coauth), recipient_env],
    )
    .await?
    else {
        ensure!(
            observer.is_none(),
            "cross-Station Call evidence requires a prebuilt Coland"
        );
        return skip_or_fail(GROUP, "prebuilt Coland unavailable");
    };
    let x = group.server(0);
    let y = group.server(1);
    let alice = Member::provision(x, &coauth, "message-mls-alice", ALICE_DEVICE).await?;
    let bob = Member::provision(y, &coauth, "message-mls-bob", BOB_DEVICE).await?;
    let realm =
        create_realm_with_join_rule(&alice.client, "Message MLS two Stations", "invite", &[x, y])
            .await?;
    let realm_id = RealmId::new(realm.clone())?;
    let strand = alice.client.default_strand_id(&realm)?;
    let mut authority_nonce = [0u8; 32];
    getrandom::fill(&mut authority_nonce).map_err(anyhow::Error::msg)?;
    let before_bob_join = alice
        .client
        .sdk()
        .realm_authority_bundle(&arkret_wire::RealmAuthorityBundleRequestBody {
            realm_id: realm_id.clone(),
            nonce: arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
                authority_nonce,
            ))
            .map_err(anyhow::Error::msg)?,
        })
        .await?
        .realm_stream_head;
    join_through_invite(
        &alice,
        x,
        &bob,
        &realm,
        "ak:request:019b0000-0000-7000-8000-000000002803",
        'c',
    )
    .await?;
    let initial_message_grant = super::human_device_producer_live::grant_realm_actions(
        &alice.client,
        x,
        &realm,
        &bob.account,
        &[arkret_wire::CapabilityActionId::MESSAGE_CREATE],
    )
    .await?;
    let other = if observer.is_some() {
        Some(call_holders::provision_other(&alice, x, y, &coauth, &realm_id).await?)
    } else {
        None
    };
    let bob_identity = publish_one(&bob).await?;
    let scope = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let group_id = scope.canonical_mls_group_id()?;
    let (claim, ..) = claim_for(&alice, x, y, &bob, &realm_id, &group_id, 0x81).await?;
    ensure!(claim.claims.len() == 1);
    ensure!(claim.claims[0].actor_id == bob.actor);
    ensure!(claim.claims[0].device_authorize_event_id.as_ref() == Some(&bob.authorize_event_id));
    ensure!(claim.claims[0].agent_key_authorize_event_id.is_none());
    let mut alice_group = alice.mls_identity()?.create_group_with_governance_binding(
        &scope,
        &MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?,
    )?;
    let creator_leaf_authority = genesis_creator_leaf_authority(&mut alice_group, &alice)?;
    let (info, tree) = alice_group.public_group_state_bytes()?;
    let info_ref = upload_public_blob(&alice.client, &realm_id, &info).await?;
    let tree_ref = upload_public_blob(&alice.client, &realm_id, &tree).await?;
    let genesis_payload = arkret::MlsGenesisPayload {
        cipher_suite: arkret::NonEmptyString::new(ACTIVE_SUITE.to_owned())
            .map_err(anyhow::Error::msg)?,
        group_info_ref: arkret_wire::BlobRef::new(info_ref)?,
        ratchet_tree_ref: arkret_wire::BlobRef::new(tree_ref.clone())?,
        creator_leaf_authority,
        governance_binding: MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?,
        created_at: chrono::Utc::now(),
    };
    genesis_payload.validate()?;
    let genesis = alice
        .client
        .author_event(
            &realm,
            EventKind::MlsGenesis.as_str(),
            canonical(serde_json::to_value(genesis_payload)?)?,
        )
        .await?;
    let genesis_commit =
        submit_and_expect_commit(&alice.client, &alice.account, ALICE_DEVICE, &genesis).await?;
    ensure_commit_signed_by(&genesis_commit, x)?;
    install_bindings(&mut alice_group, &[&alice]).await?;
    let stale_header = arkret::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        "application/vnd.arkret.message+json",
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        scope.clone(),
        EventKind::MessageCreate.as_str(),
        0,
        genesis.event_id.clone(),
        alice_group.local_content_sender_domain()?,
        arkret::EventContentRoutingContext::None,
    )?;
    let stale_sealed = arkret::MessageCrypto::encrypt(
        &mut alice_group,
        fresh_uuid_v7(),
        stale_header,
        &arkret_canonical::canonical_json_bytes(&arkret::ContentBlock::text("epoch zero intent"))?,
    )?;
    let stale_payload: MessageCreatePayload = serde_json::from_value(serde_json::json!({
        "strand_id": strand,
        "track_name": "discussion",
        "encrypted_content": stale_sealed.payload.to_envelope()?,
    }))?;
    let stale_event = alice
        .client
        .author_event(
            &realm,
            EventKind::MessageCreate.as_str(),
            canonical(serde_json::to_value(stale_payload)?)?,
        )
        .await?;
    let stale =
        garth::FrozenMessageSubmission::from_signed_request(garth::MessageSubmitRequestBody {
            submission: arkret_wire::EventAdmissionSubmission::new(stale_event.clone()),
        })?;
    let binding =
        MlsGovernanceBindingPayload::new(scope.clone(), Some(genesis.event_id.clone()), 0, 1, 0)?;
    let add = alice_group.add_member_with_governance_binding(
        &claimed_keypackage_record(&claim.claims[0], &bob)?,
        &binding,
    )?;
    let payload = MlsCommitPayload::new(genesis.event_id.clone(), 0, &add.commit, binding)?;
    let commit_event = alice
        .client
        .author_event(
            &realm,
            EventKind::MlsCommit.as_str(),
            canonical(serde_json::to_value(payload)?)?,
        )
        .await?;
    let welcome = signed_welcome(&alice, &commit_event, &bob, &add.welcome)?;
    let submission = SelfAuthoritySubmitRequestBody::MlsCommit(MlsCommitSubmission {
        commit_event: commit_event.clone(),
        welcomes: vec![welcome.clone()],
        idempotency_key: arkret_wire::UuidV7::new(fresh_uuid_v7().parse()?)?,
    });
    submission.validate()?;
    let (status, outcome) = post_json(&alice.client, &submission).await?;
    ensure!(
        status == StatusCode::OK,
        "local controller Add failed: {status} {outcome}"
    );
    let outcome: AuthoritySubmitResponseBody = serde_json::from_value(outcome)?;
    let AuthoritySubmitResponseBody::Accepted { commit, .. } = outcome else {
        anyhow::bail!("Add was refused: {outcome:?}")
    };
    ensure_commit_signed_by(&commit, x)?;
    let accepted = accepted_full_view(&alice.client, &commit_event.event_id).await?;
    let base = arkret_wire::MlsGroupValue {
        effective_scope: scope,
        genesis_event_ref: genesis.event_id.clone(),
        cipher_suite: arkret_wire::NonEmptyString::new(
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        )
        .unwrap(),
        current_mls_commit_event_ref: genesis.event_id,
        epoch: 0,
        current_key_access_revision: 0,
        covered_key_access_revision: 0,
        public_tree_ref: arkret_wire::BlobRef::new(tree_ref)?,
    };
    alice_group.install_accepted_commit(&accepted, &base)?;
    wait_for_welcome(&bob, &welcome).await?;
    let remote_commit = accepted_full_view(&bob.client, &commit_event.event_id).await?;
    ensure!(
        remote_commit == accepted,
        "member Station did not replicate the accepted Add"
    );
    let mut bob_group = ArkretMlsGroup::join_from_verified_welcome_delivery(
        bob_identity,
        &welcome,
        &remote_commit,
    )?;
    install_bindings(&mut alice_group, &[&alice, &bob]).await?;
    install_bindings(&mut bob_group, &[&alice, &bob]).await?;
    if let Some(observer) = observer {
        let other = other
            .as_ref()
            .context("Call fixture's actual second holder")?;
        let (other_group, call_group_event) = call_holders::add_other(
            &alice,
            &bob,
            other,
            x,
            y,
            &realm_id,
            &x_database.connect_url,
            &mut alice_group,
            &mut bob_group,
        )
        .await?;
        observer.configure_emission_probe(&pause_file)?;
        observer
            .observe_ordinary_call_invite(
                &alice,
                &bob,
                x,
                y,
                &realm_id,
                &call_group_event,
                &mut alice_group,
                &bob_group,
                other,
                &other_group,
                false,
            )
            .await?;
        let material_relay = group.server_mut(1).install_scan_gap_relay().await?;
        observer
            .observe_material_recovery(
                &alice,
                &bob,
                &realm_id,
                &call_group_event,
                &alice_group,
                &bob_group,
                material_relay.control(),
            )
            .await?;
        group.server_mut(0).restart_external_process().await?;
        group.server_mut(1).restart_external_process().await?;
        observer.after_station_restart(&bob).await?;
        if observer.verify_service_signer_rotation() {
            let (seed, _) =
                crate::harness::test_service_signing_key("consent-cross-station-roster-rotation");
            group
                .server_mut(1)
                .restart_external_process_with_notary_signing_key(&seed)
                .await?;
            group.server_mut(0).restart_external_process().await?;
            observer.after_station_restart(&bob).await?;
        }
        return Ok(());
    }
    if include_signal {
        if matches!(
            boundary,
            super::signal_live::emission::Boundary::LeaveWithRemainingMember
                | super::signal_live::emission::Boundary::BanWithRemainingMember
        ) {
            return super::signal_live::emission::exercise_remaining_member(
                &alice,
                &bob,
                &mut alice_group,
                &mut bob_group,
                &realm_id,
                &strand,
                x,
                y,
                &coauth,
                &[&x_database.connect_url, &y_database.connect_url],
                &pause_file,
                boundary,
            )
            .await;
        }
        // Signal uses the accepted device/member/MLS bootstrap directly.
        // Ordinary Message franking publication belongs to the other scenario
        // and must not race the negative Signal zero-write observations.
        return crate::scenarios::signal_live::exercise_two_station_signal(
            &alice,
            &bob,
            &mut alice_group,
            &mut bob_group,
            &realm_id,
            &strand,
            &commit_event.event_id,
            &commit.commit_id,
            &before_bob_join.commit_id,
            &initial_message_grant,
            x,
            y,
            &x_database.connect_url,
            &y_database.connect_url,
            &pause_file,
            boundary,
        )
        .await;
    }
    // The old ciphertext is explicitly refused after the accepted transition;
    // a fresh encryption at the new epoch is allowed only after this answer.
    let before_refusal = alice_group.export_state_record()?.serialized_state;
    let (status, refusal) = post_json(
        &alice.client,
        &SelfAuthoritySubmitRequestBody::Event(stale.request().submission.clone()),
    )
    .await?;
    ensure!(
        status == StatusCode::CONFLICT
            && refusal["type"]
                .as_str()
                .is_some_and(|kind| kind.ends_with("epoch_mismatch")),
        "stale MLS ciphertext was not refused as epoch_mismatch: {status} {refusal}"
    );
    ensure!(alice_group.export_state_record()?.serialized_state == before_refusal);
    crate::scenarios::human_device_producer_live::ensure_never_committed(
        &alice.client,
        &stale_event.event_id,
        std::time::Duration::from_secs(2),
    )
    .await?;
    let fresh_commit = submit_and_open(
        &alice,
        &bob,
        &mut alice_group,
        &mut bob_group,
        &realm_id,
        &strand,
        &commit_event.event_id,
        "epoch zero intent",
    )
    .await?;
    ensure!(
        fresh_commit.stream_position == commit.stream_position + 1,
        "the refused old ciphertext changed the accepted stream"
    );
    submit_and_open(
        &bob,
        &alice,
        &mut bob_group,
        &mut alice_group,
        &realm_id,
        &strand,
        &commit_event.event_id,
        "Bob through authority forwarding",
    )
    .await?;
    Ok(())
}
