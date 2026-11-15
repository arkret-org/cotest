//! Actual invitation delivery is proved by the recipient, never by Deferred.
use arkret::ArkretMlsGroup;
use arkret_models_collaboration::call_invitation::*;
use arkret_models_collaboration::call_signal::*;
use arkret_models_collaboration::events_payloads::consent::{ConsentPeer, ConsentPermission};
use arkret_models_collaboration::{SignalDeliveryAuthority, SignalStreamFrame};
use arkret_wire::{ActorId, CommittedEventFullView, EventKind, ScopeRef, SignalClass};

use super::*;
use crate::harness::{ArkretServer, expect_json};
use crate::scenarios::mls_lifecycle_live::{self as mls, Member};

const SCOPE: [&str; 3] = [
    "ak.self.call.invitation.command.send.v1",
    "ak.peer.call.invitation.command.relay.v1",
    "ak.peer.call.invitation.read.admission.v1",
];

fn nonce() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).context("invitation outstanding request entropy")?;
    Ok(arkret_canonical::base64url_encode(bytes))
}

// These are observations of the actual databases, not an authorization oracle.
async fn footprint(station: &ArkretServer, include_signal: bool) -> Result<Value> {
    let database = station
        .owned_database_url()
        .context("owned invitation database")?
        .to_owned();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let mut value = serde_json::Map::new();
        let mut tables = vec!["canonical_events", "realm_commits", "consent_current_states", "consent_result_versions", "current_state_heads", "current_state_versions", "capability_grant_current_states", "capability_quota_counters", "capability_quota_buckets", "capability_quota_consumptions", "call_state_current_states", "call_component_current_states", "call_participant_issuer_sources", "call_voluntary_join_nonces", "actor_private_events", "account_datas"];
        if include_signal { tables.extend(["signal_relay", "signal_relay_position", "signal_relay_watermark"]); }
        for table in tables {
            let row = db.query_one(&format!("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM {table} r"), &[])?;
            value.insert(table.into(), row.get(0));
        }
        Ok(Value::Object(value))
    }).await?
}

async fn peer(
    destination: &ArkretServer,
    source: &ArkretServer,
    path: &str,
    body: &impl serde::Serialize,
) -> Result<(u16, Value)> {
    let bytes = arkret_canonical::canonical_json_bytes(body)?;
    let request = destination.signed_peer_post_request_with_idempotency_key(
        source,
        path,
        &bytes,
        destination.service_id(),
        None,
    )?;
    let original = request
        .try_clone()
        .context("buffered actual invitation peer request")?;
    let response = destination.http().execute(request).await?;
    let status = response.status().as_u16();
    let bytes = response.bytes().await?;
    cotest_test_support::operation_observation::record_response(Some(&original), status, &bytes)?;
    Ok((status, serde_json::from_slice(&bytes)?))
}

async fn consent(holder: &Member, sender: &Member, grant: bool) -> Result<Value> {
    let peer = ConsentPeer::Actor {
        actor_id: sender.actor.clone(),
    };
    let before =
        crate::scenarios::consent_call_context::read_peer_current(&holder.client, &peer).await?;
    let permissions = if grant {
        vec![ConsentPermission {
            consent_scope: arkret_wire::ConsentScope::VoiceCall,
            not_before: None,
            expires_at: Some(arkret_canonical::normalize_timestamp_canonical(
                chrono::Utc::now() + chrono::Duration::minutes(10),
            )),
            constraints: None,
            evidence_ref: None,
            reason: None,
        }]
    } else {
        Vec::new()
    };
    let (summary, event) = crate::scenarios::consent_call_context::replace_peer_permissions(
        &holder.client,
        peer.clone(),
        &before,
        permissions,
    )
    .await?;
    let accepted = mls::accepted_full_view(&holder.client, &event.event_id).await?;
    let current =
        crate::scenarios::consent_call_context::read_peer_current(&holder.client, &peer).await?;
    let ConsentCurrentReadState::Present { current_state } = &current.current else {
        anyhow::bail!("accepted Consent has no signed current")
    };
    ensure!(
        accepted.event == event
            && current_state.revision.commit_id == accepted.commit.commit_id
            && current_state.revision.stream_position == accepted.commit.stream_position
            && current_state.value.permissions.is_empty() != grant,
        "Consent original/current differs from actual acceptance"
    );
    Ok(json!({"before":before,"summary":summary,"accepted":accepted,"current":current}))
}

async fn mls_pair(
    source: &ArkretServer,
    destination: &ArkretServer,
    alice: &Member,
    bob: &Member,
    realm: &arkret_wire::RealmId,
) -> Result<(ArkretMlsGroup, ArkretMlsGroup, Value)> {
    use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody;
    use arkret_models_crypto::KeyPackagesClaimRequestBody;
    let scope = ScopeRef::Realm {
        realm_id: realm.clone(),
    };
    let identity = crate::scenarios::cross_station_mls_welcome::publish_one(bob).await?;
    let mut entropy = [0u8; 16];
    getrandom::fill(&mut entropy).context("native invitation KeyPackage request entropy")?;
    let request: KeyPackagesClaimRequestBody = mls::claim_request_between(
        alice,
        source,
        destination,
        bob,
        realm,
        scope.canonical_mls_group_id()?.as_str(),
        entropy,
        chrono::Duration::minutes(4),
    )?;
    let (claim, pending) =
        super::peer_keypackage_claims::await_source_claim(&alice.client, &request).await?;
    ensure!(
        claim.claims.len() == 1 && claim.claims[0].actor_id == bob.actor,
        "native invitation claim changed actual recipient"
    );
    let binding = arkret::MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mut sender = alice
        .mls_identity()?
        .create_group_with_governance_binding(&scope, &binding)?;
    let creator = crate::scenarios::cross_station_mls_welcome::genesis_creator_leaf_authority(
        &mut sender,
        alice,
    )?;
    let (info, tree) = sender.public_group_state_bytes()?;
    let tree_ref: arkret_wire::BlobRef = mls::upload_public_blob(&alice.client, realm, &tree)
        .await?
        .parse()?;
    let genesis = alice.client.author_event(realm.as_str(), EventKind::MlsGenesis.as_str(), mls::canonical(json!({
        "cipher_suite":mls::ACTIVE_SUITE,"group_info_ref":mls::upload_public_blob(&alice.client, realm, &info).await?,
        "ratchet_tree_ref":tree_ref,"governance_binding":binding,"creator_leaf_authority":creator,"created_at":arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now())
    }))?).await?;
    crate::scenarios::human_device_producer_live::submit_and_expect_commit(
        &alice.client,
        &alice.account,
        alice.device.as_str(),
        &genesis,
    )
    .await?;
    let accepted_genesis = mls::accepted_full_view(&alice.client, &genesis.event_id).await?;
    let base = arkret_wire::MlsGroupValue {
        effective_scope: scope.clone(),
        genesis_event_ref: genesis.event_id.clone(),
        cipher_suite: arkret_wire::NonEmptyString::new(mls::ACTIVE_SUITE)
            .map_err(anyhow::Error::msg)?,
        current_mls_commit_event_ref: genesis.event_id.clone(),
        epoch: 0,
        current_key_access_revision: 0,
        covered_key_access_revision: 0,
        public_tree_ref: tree_ref,
    };
    crate::scenarios::message_mls_cross_station_live::install_bindings(&mut sender, &[alice])
        .await?;
    let binding =
        arkret::MlsGovernanceBindingPayload::new(scope, Some(genesis.event_id.clone()), 0, 1, 0)?;
    let add = sender.add_member_with_governance_binding(
        &mls::claimed_keypackage_record(&claim.claims[0], bob)?,
        &binding,
    )?;
    let payload = mls::commit_payload_with_public_material(
        &alice.client,
        &sender,
        genesis.event_id.clone(),
        0,
        &add.commit,
        binding,
    )
    .await?;
    let event = alice
        .client
        .author_event(
            realm.as_str(),
            EventKind::MlsCommit.as_str(),
            mls::canonical(json!(payload))?,
        )
        .await?;
    let welcome = mls::signed_welcome(alice, &event, bob, &add.welcome)?;
    let submission = SelfAuthoritySubmitRequestBody::MlsCommit(arkret_wire::MlsCommitSubmission {
        recovery_source: None,
        commit_event: event.clone(),
        welcomes: vec![welcome.clone()],
        idempotency_key: arkret_wire::UuidV7::new(mls::fresh_uuid_v7().parse()?)?,
    });
    let accepted = expect_json(
        alice.client.post("/_arkret/self/events").json(&submission),
        reqwest::StatusCode::OK,
    )
    .await?;
    let committed = mls::accepted_full_view(&alice.client, &event.event_id).await?;
    sender.install_accepted_commit(&committed, &base)?;
    let (welcomes, _) =
        crate::scenarios::cross_station_mls_welcome::wait_for_welcome(bob, &welcome).await?;
    ensure!(
        welcomes.contains(&welcome),
        "native invitation recipient has no accepted Welcome"
    );
    let remote = mls::accepted_full_view(&bob.client, &event.event_id).await?;
    ensure!(
        remote == committed,
        "native invitation recipient changed its actual Add Commit"
    );
    let mut receiver =
        ArkretMlsGroup::join_from_verified_welcome_delivery(identity, &welcome, &remote)?;
    crate::scenarios::message_mls_cross_station_live::install_bindings(&mut sender, &[alice, bob])
        .await?;
    crate::scenarios::message_mls_cross_station_live::install_bindings(
        &mut receiver,
        &[alice, bob],
    )
    .await?;
    ensure!(
        sender.epoch() == 1 && receiver.epoch() == 1,
        "invitation groups have not installed actual accepted Add"
    );
    Ok((
        sender,
        receiver,
        json!({"claim_request":request,"claim":claim,"pending":pending,"genesis":accepted_genesis,"submission":submission,"accepted":accepted,"committed":committed,"welcome":welcome,"remote":remote,"epoch":1}),
    ))
}

async fn invitation(
    source: &ArkretServer,
    alice: &Member,
    bob: &Member,
    group: &mut ArkretMlsGroup,
    call: &CommittedEventFullView,
    state: &arkret_wire::EventId,
    sequence: u64,
) -> Result<(
    CallInvitationSendRequestBody,
    Vec<u8>,
    arkret_wire::CommitStreamHead,
    Value,
)> {
    let snapshot =
        crate::scenarios::strand_watch_live::signed_snapshot(&alice.client, &call.event.realm_id)
            .await?;
    let head = snapshot
        .visible_stream_heads
        .iter()
        .find(|h| h.stream_ref == call.commit.stream_ref)
        .context("actual invitation current Realm head")?;
    let call_id = arkret_wire::CallId::from_event_id(&call.event.event_id);
    let plaintext = CallSignalPlaintext::new(
        sequence,
        call_id.clone(),
        sequence,
        CallSignalData::Invite(CallInviteSignalData {
            lifetime_ms: 30_000,
            offer: SessionDescription {
                sdp_type: SessionDescriptionType::Offer,
                sdp: "v=0\r\n".into(),
            },
            media: CallMediaSelection {
                audio: true,
                video: false,
                screen: None,
            },
        }),
    )?
    .canonical_plaintext()?;
    let strand = alice
        .client
        .default_strand_id(call.event.realm_id.as_str())?;
    let envelope = crate::scenarios::signal_live::scoped_envelope_with_payload(
        alice,
        group,
        &call.event.realm_id,
        &strand,
        state,
        &head.commit_id,
        SignalClass::Setup,
        sequence,
        call.event.scope_ref.clone(),
        None,
        Some(plaintext.clone()),
    )?;
    let mut invitation = CallInvitationEnvelope {
        inviter_actor_id: alice.actor.clone(),
        holder_account_id: bob.account.clone(),
        scope_ref: call.event.scope_ref.clone(),
        call_id,
        media: CallInvitationMedia {
            audio: true,
            video: false,
            screen: false,
        },
        envelope_digest: call_invitation_envelope_digest(&envelope)?,
        expires_at: envelope.expires_at,
        proof: CallInvitationProof {
            verification_method: alice.method.to_string(),
            jws: String::new(),
        },
    };
    arkret_signatures::call_invitation::sign_call_invitation(&mut invitation, &alice.key)?;
    invitation.validate_for_envelope(&envelope)?;
    ensure!(
        source.service_id() == &alice.account.station_id,
        "invitation is not signed by actual source Station member"
    );
    Ok((
        CallInvitationSendRequestBody {
            invitation,
            envelope,
        },
        plaintext,
        head.clone(),
        json!(snapshot),
    ))
}

fn verify_decision(
    observations: &NativeOperationObservations,
    request: &CallInvitationAdmissionRequestBody,
    decision: &CallInvitationAdmissionDecision,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<bool> {
    let holder_station = &request.invitation.holder_account_id.station_id;
    let method = arkret_wire::DidUrl::new(decision.proof.verification_method.as_str())
        .map_err(anyhow::Error::msg)?;
    ensure!(
        arkret_wire::project_did_to_core_id(&arkret_identity::verification_method_did(
            method.as_str()
        )?)? == *holder_station,
        "Human admission signer is not its immutable owning Station"
    );
    let key = native_station_key(observations, &method, decision.evaluated_at)?;
    arkret_signatures::call_invitation::verify_call_invitation_admission(
        decision,
        request,
        &method,
        &key,
        0,
        received_at,
    )
    .map_err(Into::into)
}

fn verify_original(
    observations: &NativeOperationObservations,
    full: &CommittedEventFullView,
    producer: &ActorId,
    producer_key: &arkret_signatures::PublicKeyMaterial,
) -> Result<()> {
    full.validate_shape()?;
    full.commit.validate_content_address()?;
    let suite = arkret_canonical::DigestSuite::Sha256;
    full.event
        .verify_event_id_matches_content_with_digest_suite(suite)?;
    full.event.verify_producer_proof_self_consistency(suite)?;
    ensure!(
        &full.event.actor_id == producer && full.event.executed_by.is_none(),
        "original producer differs from the native accepted Device"
    );
    let proof = full
        .event
        .producer_proof
        .as_ref()
        .context("actual accepted original lacks producer signature")?;
    let bytes = arkret_signatures::EventProofBuilder::new().envelope_bytes(&full.event)?;
    arkret_signatures::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        producer,
        producer_key,
        suite,
    )?;
    let key = native_station_key(
        observations,
        &full.commit.signature.verification_method,
        full.commit.signature.created_at,
    )?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &full.commit.signature,
        &arkret_canonical::canonical::unsigned_value(&full.commit, &["signature"])?,
        arkret_wire::DetachedSignatureContext::RealmCommit,
        &key,
    )?;
    Ok(())
}

// The live Signal subscriber retains the exact encrypted frame and its separate
// product admission. Negative admission may still deliver ciphertext, never ring.
async fn receive(
    stream: &mut arkret_http_client::SignalSubscribeFrameStream,
    request: &CallInvitationSendRequestBody,
    alice: &Member,
    recipient: (&Member, &mut ArkretMlsGroup),
    basis: (&arkret_wire::EventId, &arkret_wire::RealmCommitId),
    expected: &[u8],
    admitted: bool,
) -> Result<Value> {
    let (bob, receiver) = recipient;
    let (state, head) = basis;
    let (envelope, authority) = tokio::time::timeout(std::time::Duration::from_secs(25), async {
        loop {
            match stream
                .next_frame()
                .await?
                .context("actual invitation Signal rail closed")?
            {
                SignalStreamFrame::Heartbeat => {}
                SignalStreamFrame::Signal {
                    envelope,
                    delivery_authority,
                } if envelope.proof.envelope_digest == request.envelope.proof.envelope_digest => {
                    break Ok::<_, anyhow::Error>((envelope, delivery_authority));
                }
                other => anyhow::bail!("unexpected actual invitation Signal frame: {other:?}"),
            }
        }
    })
    .await
    .context("actual invitation did not reach the authorized recipient")??;
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    ensure!(
        envelope == request.envelope
            && authority.recipient_account_id == bob.account
            && authority.key.actor == alice.actor
            && authority.key.authorization_ref == alice.authorize_event_id
            && authority.key.verification_method == alice.method,
        "invitation recipient/source original changed"
    );
    authority.validate_for_envelope(&envelope)?;
    let bytes = arkret_canonical::base64url_decode(authority.key.public_key_base64url.as_str())?;
    ensure!(
        bytes == alice.key.verifying_key().to_bytes(),
        "invitation delivery substituted accepted sender key"
    );
    let key = arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes };
    arkret_signatures::call_invitation::verify_call_invitation(
        &request.invitation,
        &envelope,
        &key,
        at,
    )?;
    let plaintext = receiver.open_signal_envelope(
        &envelope,
        arkret::mls::SignalSenderAuthority::AccountDevice {
            public_key: &key,
            device_authorize_event_id: &alice.authorize_event_id,
        },
        state.as_str(),
        head,
        &mut arkret::AeadNonceReplayTracker::default(),
    )?;
    ensure!(
        plaintext == expected,
        "invitation ciphertext did not decrypt to the actual producer's plaintext"
    );
    request
        .invitation
        .validate_plaintext(&CallSignalPlaintext::from_plaintext(&plaintext)?)?;
    ensure!(
        authority.call_invitation.is_some() == admitted,
        "revoked Consent was rendered as ringing permission, or valid admission was absent"
    );
    Ok(
        json!({"envelope":envelope,"delivery_authority":authority,"plaintext_base64url":arkret_canonical::base64url_encode(plaintext),"received_at":at}),
    )
}

pub(super) async fn run() -> Result<()> {
    let (result, observations) = observe(crate::harness::heap_future(|| async {
        let mut source = crate::harness::heap_future(||crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-invitation-source")).await?;
        let mut holder = crate::harness::heap_future(||crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-invitation-holder")).await?;
        ensure!(source.station.service_id()!=holder.station.service_id() && source.station.owned_database_url()!=holder.station.owned_database_url(), "invitation requires independently owned Station authorities/storage");
        source.station.restart_with_federation_mesh(&[holder.station.url("")]).await?;
        holder.station.restart_with_federation_mesh(&[source.station.url("")]).await?;
        let alice = super::mls_interop::member(source.controller.clone(), source.station.service_id())?;
        let bob = super::mls_interop::member(holder.controller.clone(), holder.station.service_id())?;
        let realm:arkret_wire::RealmId = crate::scenarios::human_device_producer_live::create_realm_with_join_rule(&alice.client,"Native invitation recipient proof","public",&[&source.station,&holder.station]).await?.parse()?;
        crate::scenarios::human_device_producer_live::prepare_join(&bob.client,realm.as_str(),&source.station,&arkret_identifiers::new_prefixed_uuid7("ak:request:"),arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent::MemberJoin).await?;
        let join=bob.client.author_event(realm.as_str(),EventKind::MemberState.as_str(),crate::scenarios::human_device_producer_live::membership_payload(realm.as_str(),bob.account.clone(),arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join,"native invitation recipient")?).await?;
        crate::scenarios::human_device_producer_live::submit_and_expect_commit(&bob.client,&bob.account,bob.device.as_str(),&join).await?;
        let realm_genesis=mls::accepted_full_view(&alice.client,&realm.event_id()).await?;
        let membership=mls::accepted_full_view(&alice.client,&join.event_id).await?;
        let mut grants=Vec::new();
        for member in [&alice,&bob] { let grant=crate::scenarios::human_device_producer_live::grant_realm_actions(&alice.client,&source.station,realm.as_str(),&member.account,&[arkret_wire::CapabilityActionId::CALL_JOIN,arkret_wire::CapabilityActionId::CALL_SIGNAL_SEND]).await?; grants.push(mls::accepted_full_view(&alice.client,&grant.event_ref).await?); }
        let (mut sender,mut receiver,mls_originals)=crate::harness::heap_future(||mls_pair(&source.station,&holder.station,&alice,&bob,&realm)).await?;
        let state:arkret_wire::EventId=serde_json::from_value(mls_originals["committed"]["event"]["event_id"].clone())?;
        let event=alice.client.author_event(realm.as_str(),EventKind::CallCreate.as_str(),json!({"initial_state":"connecting"})).await?;
        crate::scenarios::human_device_producer_live::submit_and_expect_commit(&alice.client,&alice.account,alice.device.as_str(),&event).await?;
        let call=mls::accepted_full_view(&alice.client,&event.event_id).await?;
        let deadline=tokio::time::Instant::now()+std::time::Duration::from_secs(90);
        let remote=loop { if let Ok(view)=mls::accepted_full_view(&bob.client,&event.event_id).await { break view; } ensure!(tokio::time::Instant::now()<deadline,"holder never received accepted Call original");tokio::time::sleep(std::time::Duration::from_millis(100)).await; };
        ensure!(remote==call,"holder Call original differs from source");
        let grant=consent(&bob,&alice,true).await?;
        let mut stream=bob.client.sdk().signal_subscribe_frames().await?;
        ensure!(matches!(tokio::time::timeout(std::time::Duration::from_secs(25),stream.next_frame()).await.context("recipient initial Signal heartbeat did not arrive")??,Some(SignalStreamFrame::Heartbeat)),"recipient Signal rail was not connected");
        let before=json!([footprint(&source.station,false).await?,footprint(&holder.station,false).await?]);
        let (first,plain,first_basis,snapshot_first)=invitation(&source.station,&alice,&bob,&mut sender,&call,&state,1).await?;
        let sent=expect_json(alice.client.post("/_arkret/self/rtc/invitation").json(&first),reqwest::StatusCode::OK).await?;
        ensure!(serde_json::from_value::<CallInvitationSendResponseBody>(sent.clone())?.status==CallInvitationSendStatus::Deferred,"self invitation exposed private delivery result");
        let delivered=receive(&mut stream,&first,&alice,(&bob,&mut receiver),(&state,&first_basis.commit_id),&plain,true).await?;
        let (second,plain,second_basis,snapshot_second)=invitation(&source.station,&alice,&bob,&mut sender,&call,&state,2).await?;
        let (status,relayed)=peer(&holder.station,&source.station,"/_arkret/peer/rtc/invitation",&second).await?;
        ensure!(status==200 && relayed==json!({"status":"deferred"}),"peer invitation did not retain opaque Deferred");
        let peer_delivered=receive(&mut stream,&second,&alice,(&bob,&mut receiver),(&state,&second_basis.commit_id),&plain,true).await?;
        let mut request:CallInvitationAdmissionRequestBody=serde_json::from_value(peer_delivered["delivery_authority"]["call_invitation"]["request"].clone())?;
        request.nonce=nonce()?;
        let (status,decision)=peer(&holder.station,&holder.station,"/_arkret/peer/rtc/invitation-admission",&request).await?;
        ensure!(status==200,"actual hosting consumer admission failed: {decision}");
        let admission_request=request.clone();
        let received_at=arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let after=json!([footprint(&source.station,false).await?,footprint(&holder.station,false).await?]);
        ensure!(before==after,"invitation send/relay/admission wrote canonical history or Consent");
        let wrong_before=footprint(&holder.station,true).await?;
        let mut wrong=request.clone();wrong.nonce=nonce()?;
        let (wrong_status,problem)=peer(&holder.station,&source.station,"/_arkret/peer/rtc/invitation-admission",&wrong).await?;
        let typed:arkret_wire::problem_details::Problem=serde_json::from_value(problem.clone())?;
        ensure!(wrong_status==403 && typed.status==403 && typed.error_code()==Some(arkret_wire::ErrorCode::CapabilityDenied) && typed.detail=="caller is not exact authorized token issuer","inviter read private admission: {wrong_status} {problem}");
        let wrong_after=footprint(&holder.station,true).await?;
        ensure!(wrong_before==wrong_after,"unauthorized admission source wrote holder state or Signal relay");
        let revoked=consent(&bob,&alice,false).await?;
        let negative_before=json!([footprint(&source.station,false).await?,footprint(&holder.station,false).await?]);
        request.nonce=nonce()?;
        let (status,denied)=peer(&holder.station,&holder.station,"/_arkret/peer/rtc/invitation-admission",&request).await?;
        ensure!(status==200,"fresh denial did not return an actual authority verdict");
        let denied_at=arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let (third,plain,third_basis,snapshot_third)=invitation(&source.station,&alice,&bob,&mut sender,&call,&state,3).await?;
        let denied_sent=expect_json(alice.client.post("/_arkret/self/rtc/invitation").json(&third),reqwest::StatusCode::OK).await?;
        ensure!(denied_sent==sent,"inviter observed holder Consent revocation");
        let denied_delivery=receive(&mut stream,&third,&alice,(&bob,&mut receiver),(&state,&third_basis.commit_id),&plain,false).await?;
        let negative_after=json!([footprint(&source.station,false).await?,footprint(&holder.station,false).await?]);
        ensure!(negative_before==negative_after,"revoked invitation re-created Consent or a durable participant");
        let restored=consent(&bob,&alice,true).await?;
        let (fourth,plain,fourth_basis,snapshot_fourth)=invitation(&source.station,&alice,&bob,&mut sender,&call,&state,4).await?;
        let restored_sent=expect_json(alice.client.post("/_arkret/self/rtc/invitation").json(&fourth),reqwest::StatusCode::OK).await?;
        ensure!(restored_sent==sent,"restoration disclosed a private admission outcome");
        let restored_delivery=receive(&mut stream,&fourth,&alice,(&bob,&mut receiver),(&state,&fourth_basis.commit_id),&plain,true).await?;
        let sender_authorize=mls::accepted_full_view(&alice.client,&alice.authorize_event_id).await?;
        let holder_authorize=mls::accepted_full_view(&bob.client,&bob.authorize_event_id).await?;
        // Native issuer/account source material is retained by observe. Verify
        // the exact Event/Commit originals while their real Device custody is
        // still available; no key is reconstructed from an opaque grant.
        let mut originals=vec![realm_genesis.clone(),membership.clone(),call.clone(),sender_authorize.clone(),holder_authorize.clone()];
        originals.extend(grants.iter().cloned());
        originals.push(serde_json::from_value(mls_originals["genesis"].clone())?);
        originals.push(serde_json::from_value(mls_originals["committed"].clone())?);
        for consent in [&grant,&revoked,&restored] { originals.push(serde_json::from_value(consent["accepted"].clone())?); }
        Ok::<_,anyhow::Error>(json!({"source_station":source.station.service_id(),"holder_station":holder.station.service_id(),"sender":alice.actor,"sender_public_key_base64url":arkret_canonical::base64url_encode(alice.key.verifying_key().to_bytes()),"holder_public_key_base64url":arkret_canonical::base64url_encode(bob.key.verifying_key().to_bytes()),"originals":originals,"holder":bob.account,"holder_device":bob.device,"sender_authorize":sender_authorize,"holder_authorize":holder_authorize,"realm_genesis":realm_genesis,"membership":membership,"grants":grants,"mls":mls_originals,"call":call,"remote_call":remote,"consent_grant":grant,"consent_revoke":revoked,"consent_restore":restored,"self_request":first,"self_basis":snapshot_first,"self_response":sent,"self_delivery":delivered,"relay_request":second,"relay_basis":snapshot_second,"relay_response":relayed,"relay_delivery":peer_delivered,"admission_request":admission_request,"denial_request":request,"admission":decision,"admission_received_at":received_at,"denial":denied,"denial_received_at":denied_at,"wrong_request":wrong,"wrong_status":wrong_status,"wrong_problem":problem,"wrong_before":wrong_before,"wrong_after":wrong_after,"revoked_request":third,"revoked_basis":snapshot_third,"revoked_response":denied_sent,"revoked_delivery":denied_delivery,"restored_request":fourth,"restored_basis":snapshot_fourth,"restored_response":restored_sent,"restored_delivery":restored_delivery,"before":before,"after":after,"negative_before":negative_before,"negative_after":negative_after,"processes":[source.coauth.server.native_process_identity()?,source.station.native_process_identity()?,holder.coauth.server.native_process_identity()?,holder.station.native_process_identity()?]}))
    })).await;
    retain_attempt("call-invitation", &observations)?;
    let mut artifact = result?;
    validate_exchange_schemas(&observations, &SCOPE)?;
    verify_native_issuer_bindings(&observations)?;
    let sender: ActorId = serde_json::from_value(artifact["sender"].clone())?;
    let holder = ActorId::account(serde_json::from_value(artifact["holder"].clone())?);
    let mut keys = Vec::new();
    for (actor, field, original) in [
        (&sender, "sender_public_key_base64url", "sender_authorize"),
        (&holder, "holder_public_key_base64url", "holder_authorize"),
    ] {
        let account = actor
            .as_account_id()
            .context("native invitation actor must retain full Account")?;
        let public = arkret_canonical::base64url_decode(
            artifact[field]
                .as_str()
                .context("actual public custody absent")?,
        )?;
        let raw: [u8; 32] = public
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("native public key width"))?;
        let expected_did = format!(
            "did:key:{}",
            arkret_canonical::ed25519_pubkey_to_did_key_multibase(&raw)
        );
        let authorize = &artifact[original]["event"];
        ensure!(
            authorize["actor_id"] == json!(actor)
                && authorize["payload"]["device_public_key_did"] == expected_did,
            "accepted native authorize differs from actual signing key"
        );
        ensure!(observations.accepted_identity_material.iter().any(|material| material["register_request"]["principal_id"]==json!(account.principal_id) && material["station_resolution"]["service_id"]==json!(account.station_id) && material["register_request"]["identity_creation"]["pcr_genesis_unit"]["events"][1]==*authorize),"Device original is not in this full Account's actual accepted native founding unit");
        keys.push(arkret_signatures::PublicKeyMaterial::Ed25519Raw { bytes: public });
    }
    for original in artifact["originals"]
        .as_array()
        .context("accepted original set absent")?
    {
        let full: CommittedEventFullView = serde_json::from_value(original.clone())?;
        if full.event.actor_id == sender {
            verify_original(&observations, &full, &sender, &keys[0])?;
        } else {
            ensure!(
                full.event.actor_id == holder,
                "unknown accepted original producer"
            );
            verify_original(&observations, &full, &holder, &keys[1])?;
        }
    }
    for name in [
        "self_basis",
        "relay_basis",
        "revoked_basis",
        "restored_basis",
    ] {
        let snapshot: arkret_wire::RealmStateSnapshot =
            serde_json::from_value(artifact[name].clone())?;
        let key = native_station_key(
            &observations,
            &snapshot.signature.verification_method,
            snapshot.signature.created_at,
        )?;
        arkret_signatures::detached_object::verify_detached_object_signature(
            &snapshot.signature,
            &arkret_canonical::canonical::unsigned_value(&snapshot, &["signature"])?,
            arkret_wire::DetachedSignatureContext::RealmSnapshot,
            &key,
        )?;
    }
    for name in ["self_delivery", "relay_delivery", "restored_delivery"] {
        let authority: SignalDeliveryAuthority =
            serde_json::from_value(artifact[name]["delivery_authority"].clone())?;
        let delivery = authority
            .call_invitation
            .context("actual invitation product verdict absent")?;
        let received = serde_json::from_value(artifact[name]["received_at"].clone())?;
        ensure!(
            verify_decision(
                &observations,
                &delivery.request,
                &delivery.decision,
                received
            )?,
            "actual product admitted a false authority verdict"
        );
    }
    let request: CallInvitationAdmissionRequestBody =
        serde_json::from_value(artifact["admission_request"].clone())?;
    let decision = serde_json::from_value(artifact["admission"].clone())?;
    ensure!(
        verify_decision(
            &observations,
            &request,
            &decision,
            serde_json::from_value(artifact["admission_received_at"].clone())?
        )?,
        "actual explicit admission was denied"
    );
    let denied_request = serde_json::from_value(artifact["denial_request"].clone())?;
    let denied = serde_json::from_value(artifact["denial"].clone())?;
    ensure!(
        !verify_decision(
            &observations,
            &denied_request,
            &denied,
            serde_json::from_value(artifact["denial_received_at"].clone())?
        )?,
        "fresh explicit admission survived accepted Consent revoke"
    );
    for exchange in observations
        .exchanges
        .iter()
        .filter(|r| SCOPE[1..].contains(&r.operation_id.as_str()))
    {
        verify_native_station_http_request(
            &observations,
            exchange,
            &[
                arkret_signatures::http_signature::Component::Header("source-trust-domain".into()),
                arkret_signatures::http_signature::Component::Header(
                    "destination-trust-domain".into(),
                ),
            ],
        )?;
    }
    artifact["case"] = json!("call_invitation");
    artifact["scope"] = json!(SCOPE);
    artifact["observations"] = json!(observations);
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("call-invitation.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
