//! Ordinary encrypted messages between two Stations. The local controller
//! performs the MLS transitions; the remote member receives and sends ordinary
//! Messages without requiring a remote high-risk MLS grant.

use anyhow::{Context, Result, ensure};
use arkret::{ArkretMlsGroup, MlsCommitPayload, MlsGovernanceBindingPayload};
use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
use arkret_models_collaboration::events_payloads::message::MessageCreatePayload;
use arkret_wire::{
    AuthoritySubmitOutcome, EventId, EventKind, MlsCommitSubmission, RealmId, ScopeRef,
};
use base64::Engine as _;
use reqwest::StatusCode;

use crate::harness::TestServerGroup;
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::cross_station_mls_welcome::{
    claim_for, join_through_invite, publish_one, wait_for_welcome,
};
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, ensure_commit_signed_by, grant_message_create,
    station_env, submit_and_expect_commit, wait_for_committed,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use crate::scenarios::mls_lifecycle_live::{
    ACTIVE_SUITE, Member, accepted_full_view, canonical, claimed_keypackage_record, fresh_uuid_v7,
    post_json, signed_welcome, upload_public_blob,
};

const GROUP: &str = "message-mls-cross-station";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002801";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002802";

/// Bind every actual occupied leaf to the accepted founding device facts,
/// not the isolated cryptography test helper's synthetic authorization ID.
pub(crate) async fn install_bindings(
    group: &mut ArkretMlsGroup,
    members: &[&Member],
) -> Result<()> {
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

async fn submit_and_open(
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
    let plaintext = arkret_canonical::canonical_json_bytes(&content)?;
    let before = sender_group.export_state_record()?.serialized_state;
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
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
    let event = sender
        .client
        .author_event(
            realm.as_str(),
            EventKind::MessageCreate.as_str(),
            canonical(serde_json::to_value(payload)?)?,
        )
        .await?;
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
    let outcome: AuthoritySubmitOutcome = outcome.json().await?;
    let AuthoritySubmitOutcome::Accepted { commit, .. } = outcome else {
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
    let replay: AuthoritySubmitOutcome = replay.json().await?;
    ensure!(
        matches!(&replay, AuthoritySubmitOutcome::Accepted { commit: original, .. } if original == &commit),
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
    let Some(x_database) = database(GROUP)? else {
        return Ok(());
    };
    let Some(y_database) = database(GROUP)? else {
        return Ok(());
    };
    ensure!(x_database.connect_url != y_database.connect_url);
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[
            station_env(&x_database.connect_url, &coauth),
            station_env(&y_database.connect_url, &coauth),
        ],
    )
    .await?
    else {
        return skip_or_fail(GROUP, "prebuilt Soland unavailable");
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
    join_through_invite(
        &alice,
        x,
        &bob,
        &realm,
        "ak:request:019b0000-0000-7000-8000-000000002803",
        'c',
    )
    .await?;
    grant_message_create(&alice.client, x, &realm, &bob.account).await?;
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
    let (info, tree) = alice_group.public_group_state_bytes()?;
    let info_ref = upload_public_blob(&alice.client, &realm_id, &info).await?;
    let tree_ref = upload_public_blob(&alice.client, &realm_id, &tree).await?;
    let genesis = alice.client.author_event(&realm, EventKind::MlsGenesis.as_str(), canonical(serde_json::json!({
        "cipher_suite": ACTIVE_SUITE, "group_info_ref": info_ref, "ratchet_tree_ref": tree_ref,
        "governance_binding": MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?,
        "created_at": arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
    }))?).await?;
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
    let submission = SelfAuthoritySubmitRequest::MlsCommit(MlsCommitSubmission {
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
    let outcome: AuthoritySubmitOutcome = serde_json::from_value(outcome)?;
    let AuthoritySubmitOutcome::Accepted { commit, .. } = outcome else {
        anyhow::bail!("Add was refused: {outcome:?}")
    };
    ensure_commit_signed_by(&commit, x)?;
    let accepted = accepted_full_view(&alice.client, &commit_event.event_id).await?;
    let base = arkret_wire::MlsGroupCurrent {
        effective_scope: scope,
        genesis_event_ref: genesis.event_id.clone(),
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
    // The old ciphertext is explicitly refused after the accepted transition;
    // a fresh encryption at the new epoch is allowed only after this answer.
    let before_refusal = alice_group.export_state_record()?.serialized_state;
    let (status, refusal) = post_json(
        &alice.client,
        &SelfAuthoritySubmitRequest::Event(stale.request().submission.clone()),
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
