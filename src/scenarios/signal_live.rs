//! Real accepted-device, MLS, self ingress, peer relay and recipient delivery.

use anyhow::{Context, Result, ensure};
use arkret::ArkretMlsGroup;
use arkret::mls::SignalSenderAuthority;
use arkret_models_collaboration::signal_plaintext::TypingPlaintext;
use arkret_wire::{
    EventId, RealmCommitId, RealmId, ScopeRef, SignalAeadBinding, SignalClass, SignalEnvelope,
    SignalKeyRef, SignalProof, SignalStreamFrame,
};
use chrono::{Duration, Utc};

use crate::scenarios::mls_lifecycle_live::{ACTIVE_SUITE, Member};

pub async fn run() -> Result<()> {
    crate::scenarios::message_mls_cross_station_live::run_with_signal(true).await
}

#[expect(
    clippy::too_many_arguments,
    reason = "Signal fixture binds the complete authenticated sender and recipient scope"
)]
fn envelope(
    sender: &Member,
    group: &mut ArkretMlsGroup,
    realm: &RealmId,
    strand: &str,
    state: &EventId,
    head: &RealmCommitId,
    class: SignalClass,
    sequence: u64,
) -> Result<SignalEnvelope> {
    scoped_envelope(
        sender,
        group,
        realm,
        strand,
        state,
        head,
        class,
        sequence,
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        None,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Signal fixture binds the complete authenticated sender and recipient scope"
)]
fn scoped_envelope(
    sender: &Member,
    group: &mut ArkretMlsGroup,
    realm: &RealmId,
    strand: &str,
    state: &EventId,
    head: &RealmCommitId,
    class: SignalClass,
    sequence: u64,
    scope: ScopeRef,
    parent_cut: Option<&RealmCommitId>,
) -> Result<SignalEnvelope> {
    let key_ref = SignalKeyRef {
        group_state_ref: state.to_string(),
    };
    let sent_at = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let expires_at = sent_at + Duration::seconds(30);
    let binding = SignalAeadBinding {
        realm_id: realm,
        scope_ref: &scope,
        sender_actor_id: &sender.actor,
        sender_device_id: Some(&sender.device),
        authority_commit_id: head,
        parent_realm_authority_commit_id: parent_cut,
        signal_class: class,
        sent_at,
        expires_at,
        scheme: arkret_wire::SIGNAL_AEAD_SCHEME,
        key_ref: &key_ref,
        purpose: arkret_wire::SIGNAL_AEAD_PURPOSE,
        aead_profile: ACTIVE_SUITE,
        epoch: group.epoch(),
    };
    let plaintext = if class == SignalClass::Moderation {
        use arkret_models_collaboration::call_signal::*;
        CallSignalPlaintext::new(
            sequence,
            arkret_wire::CallId::from_event_id(state),
            sequence,
            CallSignalData::Moderation(CallModerationSignalData {
                action: CallModerationAction::EndForAll,
                target_actor_id: None,
                target_device_id: None,
                reason: None,
            }),
        )?
        .canonical_plaintext()?
    } else {
        arkret_canonical::canonical_json_bytes(&TypingPlaintext::new(
            sequence,
            arkret_wire::StrandId::new(strand)?,
            true,
        )?)?
    };
    let encrypted = group.encrypt_signal_payload(&binding, &plaintext)?;
    // Persist the real full-width allocator before any request can be sent.
    let checkpoint = tempfile::NamedTempFile::new()?;
    std::fs::write(
        checkpoint.path(),
        serde_json::to_vec(&group.export_state_record()?)?,
    )?;
    let restored = ArkretMlsGroup::restore_from_state_record(&serde_json::from_slice(
        &std::fs::read(checkpoint.path())?,
    )?)?;
    ensure!(restored.signal_nonce_counter() == group.signal_nonce_counter());
    let mut envelope = SignalEnvelope {
        realm_id: realm.clone(),
        scope_ref: scope,
        sender_actor_id: sender.actor.clone(),
        sender_device_id: Some(sender.device.clone()),
        authority_commit_id: head.clone(),
        parent_realm_authority_commit_id: parent_cut.cloned(),
        signal_class: class,
        sent_at,
        expires_at,
        encrypted_payload: encrypted.encrypted_payload,
        proof: SignalProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method: sender.method.clone(),
            envelope_digest: arkret_wire::Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            domain: None,
            audience: None,
            jws: String::new(),
        },
    };
    crate::harness::attach_signal_proof(&mut envelope, &sender.key);
    envelope.validate_structural()?;
    Ok(envelope)
}

// The atomic allocator measures inserts even when TTL collection removes
// retained rows during a live observation. Rollback cannot advance it.
async fn counts(url: &str, realm: &RealmId) -> Result<[i64; 3]> {
    let url = url.to_owned();
    let realm = realm.to_string();
    tokio::task::spawn_blocking(move || -> Result<_> {
        let mut connection=postgres::Client::connect(&url,postgres::NoTls)?;
        let row=connection.query_one("SELECT (SELECT COUNT(*) FROM canonical_events WHERE realm_id=$1),(SELECT COUNT(*) FROM realm_commits WHERE realm_id=$1),COALESCE((SELECT next_position FROM signal_relay_position WHERE realm_id=$1),0)",&[&realm])?;
        Ok([row.get(0),row.get(1),row.get(2)])
    }).await?
}

async fn deny(
    sender: &Member,
    signal: &SignalEnvelope,
    realm: &RealmId,
    urls: &[&str],
) -> Result<()> {
    let mut before = Vec::new();
    for url in urls {
        before.push(counts(url, realm).await?);
    }
    let response = sender
        .client
        .post("/_arkret/self/signal")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(arkret_canonical::canonical_json_bytes(signal)?)
        .send()
        .await?;
    let status = response.status();
    let problem: arkret_wire::Problem = response.json().await?;
    ensure!(
        status.is_client_error() && problem.problem_type.ends_with("signal_class_denied"),
        "Signal governance denial uses the registered opaque class problem: {status} {}",
        problem.problem_type
    );
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    for (index, url) in urls.iter().enumerate() {
        let after = counts(url, realm).await?;
        let latest_kind = if after != before[index] {
            let url = url.to_string();
            let realm = realm.to_string();
            tokio::task::spawn_blocking(move || -> Result<String> {
                let mut connection = postgres::Client::connect(&url, postgres::NoTls)?;
                let row = connection.query_one(
                    "SELECT kind FROM canonical_events WHERE realm_id=$1 ORDER BY pk DESC LIMIT 1",
                    &[&realm],
                )?;
                Ok(row.get(0))
            })
            .await??
        } else {
            String::new()
        };
        ensure!(
            after == before[index],
            "denied Signal observation station={index} counters(events,commits,relay_allocations) before={:?} after={after:?} latest_kind={latest_kind}",
            before[index]
        );
    }
    Ok(())
}

async fn deny_peer(
    signal: &SignalEnvelope,
    source: &crate::harness::ArkretServer,
    destination: &crate::harness::ArkretServer,
    urls: &[&str],
) -> Result<()> {
    let mut before = Vec::new();
    for url in urls {
        before.push(counts(url, &signal.realm_id).await?);
    }
    let request = arkret_wire::SignalRelayRequest {
        realm_id: signal.realm_id.clone(),
        signals: vec![signal.clone()],
    };
    request.validate()?;
    let (status, bytes) = destination
        .signed_peer_post(
            source,
            "/_arkret/peer/signal",
            &arkret_canonical::canonical_json_bytes(&request)?,
            destination.service_id(),
        )
        .await?;
    ensure!(status == reqwest::StatusCode::OK);
    ensure!(serde_json::from_slice::<arkret_wire::SignalRelayOutcome>(&bytes)?.accepted);
    for (index, url) in urls.iter().enumerate() {
        let after = counts(url, &signal.realm_id).await?;
        ensure!(
            after == before[index],
            "opaque peer drop observation station={index} before={:?} after={after:?}",
            before[index]
        );
    }
    Ok(())
}

async fn wait_for_replica_cut(url: &str, commit: &arkret_wire::RealmCommit) -> Result<()> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let url = url.to_owned();
        let commit = commit.clone();
        let ready = tokio::task::spawn_blocking(move || -> Result<bool> {
            let mut connection = postgres::Client::connect(&url, postgres::NoTls)?;
            let stream = serde_json::to_value(&commit.stream_ref)?;
            let row = connection.query_opt("SELECT head_commit_id,head_stream_position FROM replica_authorization_cuts WHERE realm_id=$1 AND source_stream_ref=$2",
                &[&commit.realm_id.as_str(), &stream])?;
            Ok(row.is_some_and(|row| {
                let position = row.get::<_,i64>(1) as u64;
                position > commit.stream_position || (position == commit.stream_position && row.get::<_,String>(0) == commit.commit_id.as_str())
            }))
        }).await??;
        if ready {
            return Ok(());
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "member Station installs the verified complete authorization cut"
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

async fn scoped_event(
    member: &Member,
    scope: &ScopeRef,
    kind: arkret_wire::EventKind,
    payload: serde_json::Value,
) -> Result<arkret_wire::Event> {
    let mut event = member
        .client
        .author_event(scope.realm_id().as_str(), kind.as_str(), payload)
        .await?;
    event.scope_ref = scope.clone();
    crate::harness::refresh_typed_event_proof(&mut event)?;
    Ok(event)
}

async fn circle_membership(
    member: &Member,
    authority_reader: &crate::harness::TestActorClient,
    scope: &ScopeRef,
    joined: bool,
) -> Result<arkret_wire::RealmCommit> {
    let ScopeRef::Circle {
        realm_id,
        circle_id,
    } = scope
    else {
        anyhow::bail!("Circle scope required")
    };
    let mut payload = serde_json::json!({"circle_id":circle_id,"member_id":member.actor,
        "membership":if joined {"join"} else {"leave"},
        "expected_membership":if joined { serde_json::Value::Null } else {serde_json::json!("join")}});
    if joined {
        payload["parent_membership_revision"] = serde_json::to_value(
            authority_reader
                .parent_membership_revision(realm_id.as_str(), &member.actor)
                .await?,
        )?;
    }
    let event = scoped_event(
        member,
        scope,
        arkret_wire::EventKind::CircleMemberState,
        payload,
    )
    .await?;
    super::human_device_producer_live::submit_and_expect_commit(
        &member.client,
        &member.account,
        member.device.as_str(),
        &event,
    )
    .await
}

async fn exercise_circle(
    alice: &Member,
    bob: &Member,
    x: &crate::harness::ArkretServer,
    y: &crate::harness::ArkretServer,
    realm: &RealmId,
    urls: &[&str],
) -> Result<()> {
    use arkret::{MlsCommitPayload, MlsGovernanceBindingPayload};
    use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
    use arkret_wire::{AuthoritySubmitOutcome, EventKind, MlsCommitSubmission};

    use super::cross_station_mls_welcome::{
        claim_for, genesis_creator_leaf_authority, publish_one, wait_for_welcome,
    };
    use super::human_device_producer_live::submit_and_expect_commit;
    use super::message_mls_cross_station_live::install_bindings;
    use super::mls_lifecycle_live::{
        accepted_full_view, canonical, claimed_keypackage_record, fresh_uuid_v7, post_json,
        signed_welcome, upload_public_blob,
    };
    let mut create = alice
        .client
        .author_event(
            realm.as_str(),
            EventKind::CircleCreate.as_str(),
            serde_json::json!({"object":{
        "schema":"ak.schema.circle.v1","realm_id":realm,"title":"Signal Circle",
        "display":{"short_name":"Signal Circle","color_token":"blue","symbol":{"glyph":"lock"}},
        "directory_visibility":"members","join_rule":"public","history_access":"since_join",
        "state":"active","created_by":alice.actor}}),
        )
        .await?;
    create.payload.get_mut("object").context("Circle object")?["created_at"] = serde_json::json!(
        arkret_canonical::format_timestamp_canonical(create.created_at)
    );
    crate::harness::refresh_typed_event_proof(&mut create)?;
    let circle = arkret_wire::CircleId::from_event_id(&create.event_id);
    crate::harness::expect_json(
        alice.client.post("/_arkret/self/circles").json(
            &arkret_models_collaboration::governance::circle::CircleCreateRequestBody {
                create_event: arkret_wire::EventAdmissionSubmission::new(create),
            },
        ),
        reqwest::StatusCode::OK,
    )
    .await?;
    let scope = ScopeRef::Circle {
        realm_id: realm.clone(),
        circle_id: circle.clone(),
    };
    super::circle_parent_membership_live::grant_circle_actions(alice, realm.as_str(), &circle, bob)
        .await?;
    circle_membership(alice, &alice.client, &scope, true).await?;
    let bob_join = circle_membership(bob, &alice.client, &scope, true).await?;
    accepted_full_view(&bob.client, &bob_join.event_ref).await?;
    let mut strand = scoped_event(alice, &scope, EventKind::StrandCreate, serde_json::json!({"object":{
        "schema":"ak.schema.strand.v1","realm_id":realm,"scope_circle_id":circle,"tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
        "metadata":{"title":"Circle Signal target"},"state":"active","created_by":alice.actor,
        "created_at":arkret_canonical::format_timestamp_canonical(Utc::now())}})).await?;
    strand.payload.get_mut("object").context("Strand object")?["created_at"] = serde_json::json!(
        arkret_canonical::format_timestamp_canonical(strand.created_at)
    );
    crate::harness::refresh_typed_event_proof(&mut strand)?;
    submit_and_expect_commit(
        &alice.client,
        &alice.account,
        alice.device.as_str(),
        &strand,
    )
    .await?;
    let strand_id = arkret_wire::StrandId::from_event_id(&strand.event_id);
    let bob_identity = publish_one(bob).await?;
    let (claim, ..) = claim_for(
        alice,
        x,
        y,
        bob,
        realm,
        &scope.canonical_mls_group_id()?,
        0x82,
    )
    .await?;
    let genesis_binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mut alice_group = alice
        .mls_identity()?
        .create_group_with_governance_binding(&scope, &genesis_binding)?;
    let creator_leaf = genesis_creator_leaf_authority(&mut alice_group, alice)?;
    let (info, tree) = alice_group.public_group_state_bytes()?;
    let info_ref = upload_public_blob(&alice.client, realm, &info).await?;
    let tree_ref = upload_public_blob(&alice.client, realm, &tree).await?;
    let genesis = scoped_event(
        alice,
        &scope,
        EventKind::MlsGenesis,
        canonical(serde_json::json!({
        "cipher_suite":ACTIVE_SUITE,"group_info_ref":info_ref,"ratchet_tree_ref":tree_ref,
        "creator_leaf_authority":creator_leaf,"governance_binding":genesis_binding,
        "created_at":arkret_canonical::format_timestamp_canonical(Utc::now())}))?,
    )
    .await?;
    submit_and_expect_commit(
        &alice.client,
        &alice.account,
        alice.device.as_str(),
        &genesis,
    )
    .await?;
    let add_binding =
        MlsGovernanceBindingPayload::new(scope.clone(), Some(genesis.event_id.clone()), 0, 1, 0)?;
    let add = alice_group.add_member_with_governance_binding(
        &claimed_keypackage_record(&claim.claims[0], bob)?,
        &add_binding,
    )?;
    let commit_event = scoped_event(
        alice,
        &scope,
        EventKind::MlsCommit,
        canonical(serde_json::to_value(MlsCommitPayload::new(
            genesis.event_id.clone(),
            0,
            &add.commit,
            add_binding,
        )?)?)?,
    )
    .await?;
    let welcome = signed_welcome(alice, &commit_event, bob, &add.welcome)?;
    let submission = SelfAuthoritySubmitRequest::MlsCommit(MlsCommitSubmission {
        commit_event: commit_event.clone(),
        welcomes: vec![welcome.clone()],
        idempotency_key: arkret_wire::UuidV7::new(fresh_uuid_v7().parse()?)?,
    });
    submission.validate()?;
    let (status, outcome) = post_json(&alice.client, &submission).await?;
    ensure!(
        status == reqwest::StatusCode::OK,
        "Circle MLS Add accepted: {status} {outcome}"
    );
    let AuthoritySubmitOutcome::Accepted { commit, .. } = serde_json::from_value(outcome)? else {
        anyhow::bail!("Circle MLS Add refused")
    };
    let accepted = accepted_full_view(&alice.client, &commit_event.event_id).await?;
    let base = arkret_wire::MlsGroupCurrent {
        effective_scope: scope.clone(),
        genesis_event_ref: genesis.event_id.clone(),
        cipher_suite: arkret_wire::NonEmptyString::new(ACTIVE_SUITE.to_owned())
            .map_err(anyhow::Error::msg)?,
        current_mls_commit_event_ref: genesis.event_id,
        epoch: 0,
        current_key_access_revision: 0,
        covered_key_access_revision: 0,
        public_tree_ref: arkret_wire::BlobRef::new(tree_ref)?,
    };
    alice_group.install_accepted_commit(&accepted, &base)?;
    wait_for_welcome(bob, &welcome).await?;
    let remote = accepted_full_view(&bob.client, &commit_event.event_id).await?;
    ensure!(remote == accepted);
    wait_for_replica_cut(urls[1], &commit).await?;
    let mut bob_group =
        ArkretMlsGroup::join_from_verified_welcome_delivery(bob_identity, &welcome, &remote)?;
    install_bindings(&mut alice_group, &[alice, bob]).await?;
    install_bindings(&mut bob_group, &[alice, bob]).await?;
    let parent = super::websocket_live::realm_head(&alice.client, realm.as_str()).await?;
    let before = [counts(urls[0], realm).await?, counts(urls[1], realm).await?];
    deliver(
        alice,
        bob,
        &mut alice_group,
        &bob_group,
        realm,
        strand_id.as_str(),
        &commit_event.event_id,
        &commit.commit_id,
        scope.clone(),
        Some(&parent.commit_id),
        SignalClass::Session,
        1,
        None,
    )
    .await?;
    deliver(
        bob,
        alice,
        &mut bob_group,
        &alice_group,
        realm,
        strand_id.as_str(),
        &commit_event.event_id,
        &commit.commit_id,
        scope.clone(),
        Some(&parent.commit_id),
        SignalClass::Session,
        1,
        Some(x),
    )
    .await?;
    for (index, url) in urls.iter().enumerate() {
        let after = counts(url, realm).await?;
        ensure!(after[0..2] == before[index][0..2] && after[2] == before[index][2] + 2);
    }
    let left = circle_membership(bob, &alice.client, &scope, false).await?;
    super::circle_parent_membership_live::wait_for_membership_current(
        urls[1], &left, &bob.actor, "leave",
    )
    .await?;
    let signal = scoped_envelope(
        bob,
        &mut bob_group,
        realm,
        strand_id.as_str(),
        &commit_event.event_id,
        &commit.commit_id,
        SignalClass::Session,
        2,
        scope,
        Some(&parent.commit_id),
    )?;
    deny(bob, &signal, realm, urls).await?;
    deny_peer(&signal, y, x, urls).await?;
    eprintln!(
        "[signal-live] circle_scope=1 independent_mls_group=1 bidirectional_delivery=2 current_circle_leave_denials=2 zero_denial_writes=1"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn deliver(
    sender: &Member,
    receiver: &Member,
    sender_group: &mut ArkretMlsGroup,
    receiver_group: &ArkretMlsGroup,
    realm: &RealmId,
    strand: &str,
    state: &EventId,
    head: &RealmCommitId,
    scope: ScopeRef,
    parent_cut: Option<&RealmCommitId>,
    class: SignalClass,
    sequence: u64,
    websocket_server: Option<&crate::harness::ArkretServer>,
) -> Result<()> {
    let mut stream = if websocket_server.is_some() {
        None
    } else {
        Some(
            receiver
                .client
                .sdk()
                .signal_subscribe_frames()
                .await
                .context("recipient authenticated live rail before sending")?,
        )
    };
    let mut websocket = if let Some(websocket_server) = websocket_server {
        Some(
            super::websocket_live::LiveSignalReader::connect(
                websocket_server,
                &receiver.client,
                realm.as_str(),
            )
            .await?,
        )
    } else {
        None
    };
    ensure!(matches!(
        if let Some(stream) = &mut stream {
            stream.next_frame().await?
        } else {
            websocket.as_mut().unwrap().next_frame().await?
        },
        Some(SignalStreamFrame::Heartbeat)
    ));
    let signal = scoped_envelope(
        sender,
        sender_group,
        realm,
        strand,
        state,
        head,
        class,
        sequence,
        scope,
        parent_cut,
    )?;
    let outcome = sender
        .client
        .sdk()
        .signal_send(&signal)
        .await
        .context("real source Signal self ingress")?;
    ensure!(outcome.accepted && outcome.envelope_digest == signal.envelope_digest()?);
    let received = tokio::time::timeout(std::time::Duration::from_secs(25), async {
        loop {
            match (if let Some(stream) = &mut stream {
                stream.next_frame().await?
            } else {
                websocket.as_mut().unwrap().next_frame().await?
            })
            .context("Signal live rail remains open")?
            {
                SignalStreamFrame::Signal {
                    envelope,
                    delivery_authority,
                } if envelope.proof.envelope_digest == signal.proof.envelope_digest => {
                    break Ok::<_, anyhow::Error>((envelope, delivery_authority));
                }
                SignalStreamFrame::Heartbeat => {}
                _ => anyhow::bail!("unexpected live Signal control or envelope"),
            }
        }
    })
    .await
    .context("real two-station Signal delivery deadline")??;
    ensure!(
        received.1.recipient_account_id == receiver.account,
        "delivery authority binds the actual receiver"
    );
    ensure!(
        arkret_canonical::canonical_json_bytes(&received.0)?
            == arkret_canonical::canonical_json_bytes(&signal)?,
        "relay preserves the entire canonical envelope"
    );
    ensure!(
        received.0 == signal,
        "canonical envelope round-trip preserves typed values"
    );
    ensure!(
        received.1.key.actor == sender.actor
            && received.1.key.authorization_ref == sender.authorize_event_id
    );
    let public = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: arkret_canonical::base64url_decode(received.1.key.public_key_b64u.as_str())?,
    };
    let mut replay = arkret::AeadNonceReplayTracker::default();
    let plaintext = receiver_group.open_signal_envelope(
        &received.0,
        SignalSenderAuthority::AccountDevice {
            public_key: &public,
            device_authorize_event_id: &received.1.key.authorization_ref,
        },
        state.as_str(),
        head,
        &mut replay,
    )?;
    let payload = arkret_models_collaboration::signal_plaintext::open_signal_plaintext(&plaintext)?;
    ensure!(payload.signal_class() == class && payload.payload_sequence() == sequence);
    if let Some(websocket) = &mut websocket {
        websocket.finish().await?;
    }
    eprintln!(
        "[signal-live] transport={} accepted_self=1 accepted_peer=1 decrypted_recipient=1 durable_rails_shared={}",
        if websocket_server.is_some() {
            "websocket"
        } else {
            "http"
        },
        websocket_server.is_some()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn exercise_two_station_signal(
    alice: &Member,
    bob: &Member,
    alice_group: &mut ArkretMlsGroup,
    bob_group: &mut ArkretMlsGroup,
    realm: &RealmId,
    strand: &str,
    state: &EventId,
    head: &RealmCommitId,
    old_head: &RealmCommitId,
    x: &crate::harness::ArkretServer,
    y: &crate::harness::ArkretServer,
    x_url: &str,
    y_url: &str,
) -> Result<()> {
    let bootstrap = super::mls_lifecycle_live::accepted_full_view(&bob.client, state).await?;
    ensure!(bootstrap.commit.commit_id == *head);
    wait_for_replica_cut(y_url, &bootstrap.commit).await?;
    let before = [counts(x_url, realm).await?, counts(y_url, realm).await?];
    for reverse in [false, true] {
        let (sender, receiver, sender_group, receiver_group) = if reverse {
            (bob, alice, &mut *bob_group, &*alice_group)
        } else {
            (alice, bob, &mut *alice_group, &*bob_group)
        };
        deliver(
            sender,
            receiver,
            sender_group,
            receiver_group,
            realm,
            strand,
            state,
            head,
            ScopeRef::Realm {
                realm_id: realm.clone(),
            },
            None,
            SignalClass::Session,
            1,
            reverse.then_some(x),
        )
        .await?;
    }
    for (index, url) in [x_url, y_url].iter().enumerate() {
        let after = counts(url, realm).await?;
        ensure!(
            after[0..2] == before[index][0..2] && after[2] == before[index][2] + 2,
            "Signal is transient and relays exactly once at each Station"
        );
    }
    let old = envelope(
        bob,
        bob_group,
        realm,
        strand,
        state,
        old_head,
        SignalClass::Session,
        2,
    )?;
    deny(bob, &old, realm, &[x_url, y_url])
        .await
        .context("old cut did not contain sender membership")?;
    deny_peer(&old, y, x, &[x_url, y_url]).await?;
    let moderation = envelope(
        bob,
        bob_group,
        realm,
        strand,
        state,
        head,
        SignalClass::Moderation,
        3,
    )?;
    deny(bob, &moderation, realm, &[x_url, y_url])
        .await
        .context("moderation has no accepted capability")?;
    let moderation_grant = super::human_device_producer_live::grant_realm_actions(
        &alice.client,
        x,
        realm.as_str(),
        &bob.account,
        &["ak.call.moderate"],
    )
    .await?;
    super::mls_lifecycle_live::accepted_full_view(&bob.client, &moderation_grant.event_ref).await?;
    wait_for_replica_cut(y_url, &moderation_grant).await?;
    let old_moderation = envelope(
        bob,
        bob_group,
        realm,
        strand,
        state,
        head,
        SignalClass::Moderation,
        4,
    )?;
    deny(bob, &old_moderation, realm, &[x_url, y_url]).await?;
    deliver(
        bob,
        alice,
        bob_group,
        alice_group,
        realm,
        strand,
        state,
        &moderation_grant.commit_id,
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        None,
        SignalClass::Moderation,
        5,
        Some(x),
    )
    .await?;
    let revoke: arkret_wire::AuthoritySubmitOutcome = serde_json::from_value(
        alice
            .client
            .revoke_realm_grant(
                realm.as_str(),
                arkret_wire::GrantId::from_event_id(&moderation_grant.event_ref).as_str(),
            )
            .await?,
    )?;
    let arkret_wire::AuthoritySubmitOutcome::Accepted {
        commit: revoked, ..
    } = revoke
    else {
        anyhow::bail!("moderation revoke must be accepted")
    };
    super::mls_lifecycle_live::accepted_full_view(&bob.client, &revoked.event_ref).await?;
    wait_for_replica_cut(y_url, &revoked).await?;
    let revoked_signal = envelope(
        bob,
        bob_group,
        realm,
        strand,
        state,
        &moderation_grant.commit_id,
        SignalClass::Moderation,
        6,
    )?;
    deny(bob, &revoked_signal, realm, &[x_url, y_url]).await?;
    deny_peer(&revoked_signal, y, x, &[x_url, y_url]).await?;
    exercise_circle(alice, bob, x, y, realm, &[x_url, y_url]).await?;
    let fresh = envelope(
        bob,
        bob_group,
        realm,
        strand,
        state,
        head,
        SignalClass::Session,
        7,
    )?;
    let removal = alice
        .client
        .remove_member(realm.as_str(), &bob.client)
        .await?;
    let removal: arkret_wire::AuthoritySubmitOutcome = serde_json::from_value(removal)?;
    let arkret_wire::AuthoritySubmitOutcome::Accepted { commit, .. } = removal else {
        anyhow::bail!("membership removal must have an accepted Commit");
    };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let url = y_url.to_owned();
        let expected = serde_json::to_value(&commit)?;
        let id = commit.commit_id.to_string();
        let held = tokio::task::spawn_blocking(move || -> Result<bool> {
            let mut conn = postgres::Client::connect(&url, postgres::NoTls)?;
            Ok(conn
                .query_opt(
                    "SELECT commit_json FROM realm_commits WHERE commit_id=$1",
                    &[&id],
                )?
                .is_some_and(|row| row.get::<_, serde_json::Value>(0) == expected))
        })
        .await??;
        if held {
            break;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "recipient Station holds exact accepted leave Commit"
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    deny(bob, &fresh, realm, &[x_url, y_url])
        .await
        .context("current revoke denies an older otherwise valid cut")?;
    eprintln!(
        "[signal-live] actual TLS Stations=2 directions=2 realm_session_deliveries=2 circle_session_deliveries=2 granted_moderation_deliveries=1 recipient_proof_mls_aead_plaintext=5 old_cut_denied=1 moderation_denied=1 current_membership_revoke_denied=1 denied_relay_event_commit_writes=0"
    );
    Ok(())
}
