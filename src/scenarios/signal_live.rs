//! Real accepted-device, MLS, self ingress, peer relay and recipient delivery.

use anyhow::{Context, Result, ensure};
use arkret::ArkretMlsGroup;
use arkret::mls::SignalSenderAuthority;
use arkret_models_collaboration::SignalStreamFrame;
use arkret_models_collaboration::signal_plaintext::TypingPlaintext;
use arkret_wire::{
    EventId, RealmCommitId, RealmId, ScopeRef, SignalAeadBinding, SignalClass, SignalEnvelope,
    SignalKeyRef, SignalProof,
};
use chrono::{Duration, Utc};
use serde_json::json;

use crate::scenarios::mls_lifecycle_live::{ACTIVE_SUITE, Member};

pub(crate) mod emission;

pub async fn run() -> Result<()> {
    crate::scenarios::message_mls_cross_station_live::run_with_signal(true).await
}

pub async fn run_ban() -> Result<()> {
    super::message_mls_cross_station_live::run_with_signal_boundary(true, emission::Boundary::Ban)
        .await
}

pub async fn run_terminal() -> Result<()> {
    super::message_mls_cross_station_live::run_with_signal_boundary(
        true,
        emission::Boundary::Tombstone,
    )
    .await
}

pub async fn run_remaining_member_leave() -> Result<()> {
    super::message_mls_cross_station_live::run_with_signal_boundary(
        true,
        emission::Boundary::LeaveWithRemainingMember,
    )
    .await
}

pub async fn run_remaining_member_ban() -> Result<()> {
    super::message_mls_cross_station_live::run_with_signal_boundary(
        true,
        emission::Boundary::BanWithRemainingMember,
    )
    .await
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
    scoped_envelope_with_payload(
        sender, group, realm, strand, state, head, class, sequence, scope, parent_cut, None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn scoped_envelope_with_payload(
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
    product_payload: Option<Vec<u8>>,
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
    let plaintext = if let Some(payload) = product_payload {
        payload
    } else if class == SignalClass::Moderation {
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
    let request = arkret_wire::SignalRelayRequestBody {
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
    ensure!(serde_json::from_slice::<arkret_wire::SignalRelayResponseBody>(&bytes)?.accepted);
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

pub(crate) async fn scoped_event(
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

pub(crate) async fn circle_membership(
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

pub(crate) struct CircleDiscussionBasis {
    pub scope: ScopeRef,
    pub circle: arkret_wire::CircleId,
    pub strand_id: arkret_wire::StrandId,
}

pub(crate) async fn circle_discussion_basis(
    alice: &Member,
    bob: &Member,
    realm: &RealmId,
) -> Result<CircleDiscussionBasis> {
    use arkret_wire::EventKind;

    use super::human_device_producer_live::submit_and_expect_commit;
    let unique = arkret_identifiers::new_prefixed_uuid7("ak:request:");
    let short_name = format!("Signal {}", &unique[unique.len() - 8..]);
    let mut create = alice
        .client
        .author_event(
            realm.as_str(),
            EventKind::CircleCreate.as_str(),
            serde_json::json!({"object":{
        "schema":"ak.schema.circle.v1","realm_id":realm,"title":"Signal Circle",
        "display":{"short_name":short_name,"color_token":"blue","symbol":{"glyph":"lock"}},
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
    super::mls_lifecycle_live::accepted_full_view(&bob.client, &bob_join.event_ref).await?;
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
    Ok(CircleDiscussionBasis {
        scope,
        circle,
        strand_id,
    })
}

pub(crate) struct CircleMlsFixture {
    pub basis: CircleDiscussionBasis,
    pub source_group: ArkretMlsGroup,
    pub holder_group: ArkretMlsGroup,
    pub state_ref: EventId,
    pub head: arkret_wire::RealmCommit,
    pub parent_head: arkret_wire::CommitStreamHead,
}

pub(crate) async fn circle_mls_fixture(
    alice: &Member,
    bob: &Member,
    x: &crate::harness::ArkretServer,
    y: &crate::harness::ArkretServer,
    realm: &RealmId,
) -> Result<CircleMlsFixture> {
    use arkret::{MlsCommitPayload, MlsGovernanceBindingPayload};
    use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody;
    use arkret_wire::{AuthoritySubmitResponseBody, EventKind, MlsCommitSubmission};

    use super::cross_station_mls_welcome::{
        claim_for, genesis_creator_leaf_authority, publish_one, wait_for_welcome,
    };
    use super::human_device_producer_live::submit_and_expect_commit;
    use super::message_mls_cross_station_live::install_bindings;
    use super::mls_lifecycle_live::{
        accepted_full_view, canonical, claimed_keypackage_record, fresh_uuid_v7, post_json,
        signed_welcome, upload_public_blob,
    };
    let CircleDiscussionBasis {
        scope,
        circle,
        strand_id,
    } = circle_discussion_basis(alice, bob, realm).await?;
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
    let submission = SelfAuthoritySubmitRequestBody::MlsCommit(MlsCommitSubmission {
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
    let AuthoritySubmitResponseBody::Accepted { commit, .. } = serde_json::from_value(outcome)?
    else {
        anyhow::bail!("Circle MLS Add refused")
    };
    let accepted = accepted_full_view(&alice.client, &commit_event.event_id).await?;
    let base = arkret_wire::MlsGroupValue {
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
    let mut bob_group =
        ArkretMlsGroup::join_from_verified_welcome_delivery(bob_identity, &welcome, &remote)?;
    install_bindings(&mut alice_group, &[alice, bob]).await?;
    install_bindings(&mut bob_group, &[alice, bob]).await?;
    let (queued, acknowledgement_token) =
        super::mls_lifecycle_live::recipient_welcomes(&bob.client).await?;
    ensure!(
        queued.contains(&welcome),
        "Circle recipient queue omitted the exact installed Welcome"
    );
    let _ = bob
        .client
        .sdk()
        .ack_device_messages(
            &arkret_models_collaboration::device_messages::DeviceMessagesAcknowledgementRequestBody {
                acknowledgement_token,
            },
        )
        .await?;
    let parent = super::websocket_live::realm_head(&alice.client, realm.as_str()).await?;
    Ok(CircleMlsFixture {
        basis: CircleDiscussionBasis {
            scope,
            circle,
            strand_id,
        },
        source_group: alice_group,
        holder_group: bob_group,
        state_ref: commit_event.event_id,
        head: commit,
        parent_head: parent,
    })
}

async fn exercise_circle(
    alice: &Member,
    bob: &Member,
    x: &crate::harness::ArkretServer,
    y: &crate::harness::ArkretServer,
    realm: &RealmId,
    urls: &[&str],
) -> Result<()> {
    let CircleMlsFixture {
        basis: CircleDiscussionBasis {
            scope, strand_id, ..
        },
        source_group: mut alice_group,
        holder_group: mut bob_group,
        state_ref,
        head: commit,
        parent_head: parent,
    } = circle_mls_fixture(alice, bob, x, y, realm).await?;
    wait_for_replica_cut(urls[1], &commit).await?;
    let before = [counts(urls[0], realm).await?, counts(urls[1], realm).await?];
    deliver(
        alice,
        bob,
        &mut alice_group,
        &bob_group,
        realm,
        strand_id.as_str(),
        &state_ref,
        &commit.commit_id,
        scope.clone(),
        Some(&parent.commit_id),
        SignalClass::Session,
        1,
        None,
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
        &state_ref,
        &commit.commit_id,
        scope.clone(),
        Some(&parent.commit_id),
        SignalClass::Session,
        1,
        Some(x),
        None,
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
        &state_ref,
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
    product_case: Option<(Vec<u8>, bool)>,
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
    let signal = scoped_envelope_with_payload(
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
        product_case.as_ref().map(|(payload, _)| payload.clone()),
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
        bytes: arkret_canonical::base64url_decode(received.1.key.public_key_base64url.as_str())?,
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
    if let Some((_, expected)) = product_case {
        let material = received
            .1
            .product_authority
            .as_deref()
            .context("complete per-frame product material")?;
        material.validate_for_envelope(&received.0)?;
        let domain = garth::SignalSequenceDomain {
            sender_actor_id: sender.actor.clone(),
            endpoint: garth::SignalSequenceEndpoint::AccountDevice {
                device_id: sender.device.clone(),
            },
            scope_ref: received.0.scope_ref.clone(),
        };
        match &payload {
            arkret::SignalPlaintext::Typing(typing) => {
                let allowed = arkret_policy::signal_authorization::typing_allowed(
                    material,
                    &domain.sender_actor_id,
                    &domain.scope_ref,
                    &typing.strand_id,
                    Utc::now(),
                );
                ensure!(
                    allowed == expected,
                    "Typing original/current product gate differs"
                );
                eprintln!(
                    "[signal-typing] actual_two_station=1 proof_mls_aead=1 original_and_current_material=1 broadcast_allowed={allowed} indicator_count={}",
                    usize::from(allowed)
                );
            }
            arkret::SignalPlaintext::MessageStream(frame) => {
                let mut projection = garth::MessageStreamProjection::new();
                let result = projection.apply(
            &domain,
            frame,
            &|domain: &garth::SignalSequenceDomain, frame: &arkret_models_collaboration::signal_message_stream::MessageStreamFrame| {
                arkret_policy::signal_authorization::message_stream_allowed(
                    material,
                    &domain.sender_actor_id,
                    &domain.scope_ref,
                    frame.strand_id(),
                    Utc::now(),
                )
            },
            Utc::now(),
        );
                ensure!(
                    result.is_ok() == expected,
                    "MessageStream dual-action product gate must match accepted original/current sources: {result:?}"
                );
                ensure!(
                    projection.previews().count() == usize::from(expected),
                    "denied product has no body side effect"
                );
                eprintln!(
                    "[signal-message-stream] actual_two_station=1 proof_mls_aead=1 original_and_current_material=1 dual_action_allowed={expected} preview_count={}",
                    projection.previews().count()
                );
            }
            _ => anyhow::bail!("unexpected Signal product profile"),
        }
    }
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
    initial_message_grant: &arkret_wire::RealmCommit,
    x: &crate::harness::ArkretServer,
    y: &crate::harness::ArkretServer,
    x_url: &str,
    y_url: &str,
    pause_file: &std::path::Path,
    boundary: emission::Boundary,
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
            None,
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
    let product_frame = |sequence| -> Result<Vec<u8>> {
        let frame = arkret::MessageStreamKeyframe::new(
            sequence,
            strand.parse()?,
            arkret::MessageId::from_event_id(state),
            0,
            arkret::MessageStreamId::new_v7_at(Utc::now().timestamp_millis() as u64),
            0,
            arkret::MessageStreamFormat::Plain,
            "authorized transient body",
            false,
        )?;
        Ok(arkret_canonical::canonical_json_bytes(&frame)?)
    };
    deliver(
        bob,
        alice,
        bob_group,
        alice_group,
        realm,
        strand,
        state,
        head,
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        None,
        SignalClass::Session,
        8,
        None,
        Some((product_frame(8)?, false)),
    )
    .await?;
    let initial_revoke: arkret_wire::AuthoritySubmitResponseBody = serde_json::from_value(
        alice
            .client
            .revoke_realm_grant(
                realm.as_str(),
                arkret_wire::GrantId::from_event_id(&initial_message_grant.event_ref).as_str(),
            )
            .await?,
    )?;
    let arkret_wire::AuthoritySubmitResponseBody::Accepted {
        commit: initial_revoked,
        ..
    } = initial_revoke
    else {
        anyhow::bail!("initial MessageCreate grant revoke must be accepted");
    };
    super::mls_lifecycle_live::accepted_full_view(&bob.client, &initial_revoked.event_ref).await?;
    wait_for_replica_cut(y_url, &initial_revoked).await?;
    let send_grant = super::human_device_producer_live::grant_realm_actions(
        &alice.client,
        x,
        realm.as_str(),
        &bob.account,
        &[arkret_wire::CapabilityActionId::MESSAGE_STREAM_SEND],
    )
    .await?;
    super::mls_lifecycle_live::accepted_full_view(&bob.client, &send_grant.event_ref).await?;
    wait_for_replica_cut(y_url, &send_grant).await?;
    deliver(
        bob,
        alice,
        bob_group,
        alice_group,
        realm,
        strand,
        state,
        &send_grant.commit_id,
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        None,
        SignalClass::Session,
        9,
        None,
        Some((product_frame(9)?, false)),
    )
    .await?;
    let dual_grant = super::human_device_producer_live::grant_realm_actions(
        &alice.client,
        x,
        realm.as_str(),
        &bob.account,
        &[
            arkret_wire::CapabilityActionId::MESSAGE_STREAM_SEND,
            arkret_wire::CapabilityActionId::MESSAGE_CREATE,
        ],
    )
    .await?;
    super::mls_lifecycle_live::accepted_full_view(&bob.client, &dual_grant.event_ref).await?;
    wait_for_replica_cut(y_url, &dual_grant).await?;
    deliver(
        bob,
        alice,
        bob_group,
        alice_group,
        realm,
        strand,
        state,
        &dual_grant.commit_id,
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        None,
        SignalClass::Session,
        10,
        Some(x),
        Some((product_frame(10)?, true)),
    )
    .await?;
    let revoke_product: arkret_wire::AuthoritySubmitResponseBody = serde_json::from_value(
        alice
            .client
            .revoke_realm_grant(
                realm.as_str(),
                arkret_wire::GrantId::from_event_id(&dual_grant.event_ref).as_str(),
            )
            .await?,
    )?;
    let arkret_wire::AuthoritySubmitResponseBody::Accepted {
        commit: product_revoked,
        ..
    } = revoke_product
    else {
        anyhow::bail!("MessageStream revoke must be accepted");
    };
    super::mls_lifecycle_live::accepted_full_view(&bob.client, &product_revoked.event_ref).await?;
    wait_for_replica_cut(y_url, &product_revoked).await?;
    deliver(
        bob,
        alice,
        bob_group,
        alice_group,
        realm,
        strand,
        state,
        &dual_grant.commit_id,
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        None,
        SignalClass::Session,
        11,
        None,
        Some((product_frame(11)?, false)),
    )
    .await?;
    let typing_frame = |sequence: u64| -> Result<Vec<u8>> {
        Ok(arkret_canonical::canonical_json_bytes(&json!({
            "kind":"ak.typing", "payload_sequence":(sequence).to_string(), "strand_id":strand, "typing":true
        }))?)
    };
    deliver(
        bob,
        alice,
        bob_group,
        alice_group,
        realm,
        strand,
        state,
        &product_revoked.commit_id,
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        None,
        SignalClass::Session,
        12,
        None,
        Some((typing_frame(12)?, false)),
    )
    .await?;
    let typing_grant = super::human_device_producer_live::grant_realm_actions(
        &alice.client,
        x,
        realm.as_str(),
        &bob.account,
        &[arkret_wire::CapabilityActionId::TYPING_BROADCAST],
    )
    .await?;
    super::mls_lifecycle_live::accepted_full_view(&bob.client, &typing_grant.event_ref).await?;
    wait_for_replica_cut(y_url, &typing_grant).await?;
    deliver(
        bob,
        alice,
        bob_group,
        alice_group,
        realm,
        strand,
        state,
        &typing_grant.commit_id,
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        None,
        SignalClass::Session,
        13,
        Some(x),
        Some((typing_frame(13)?, true)),
    )
    .await?;
    let policy_id = arkret_wire::PolicyId::new_v7_at(Utc::now().timestamp_millis() as u64);
    let mut policy: arkret_models_collaboration::governance::operation_wire::Policy =
        serde_json::from_value(json!({
            "id":policy_id, "schema":"ak.schema.policy.v1", "realm_id":realm,
            "policy_kind":"access", "rules":[{"rule_id":"typing","kind":"action","effect":"deny","actions":[arkret_wire::CapabilityActionId::TYPING_BROADCAST]}],
            "default_effect":"allow", "created_by":alice.actor,
            "created_at":arkret_canonical::format_timestamp_canonical(Utc::now())
        }))?;
    policy.validate()?;
    let set_policy = |policy: &arkret_models_collaboration::governance::operation_wire::Policy| -> Result<
        arkret_models_collaboration::governance::operation_wire::PolicySetStatePayload,
    > {
        Ok(serde_json::from_value(
            json!({"policy_id":policy_id,"value":policy}),
        )?)
    };
    let outcome: arkret_wire::AuthoritySubmitResponseBody = serde_json::from_value(
        alice
            .client
            .submit_event(
                realm.as_str(),
                arkret_wire::EventKind::PolicySet.as_str(),
                serde_json::to_value(set_policy(&policy)?)?,
            )
            .await?,
    )?;
    let arkret_wire::AuthoritySubmitResponseBody::Accepted {
        commit: policy_denied,
        ..
    } = outcome
    else {
        anyhow::bail!("Typing Policy deny must be accepted");
    };
    super::mls_lifecycle_live::accepted_full_view(&bob.client, &policy_denied.event_ref).await?;
    wait_for_replica_cut(y_url, &policy_denied).await?;
    // The original cut had the grant and no deny; the current Policy must win.
    deliver(
        bob,
        alice,
        bob_group,
        alice_group,
        realm,
        strand,
        state,
        &typing_grant.commit_id,
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        None,
        SignalClass::Session,
        14,
        None,
        Some((typing_frame(14)?, false)),
    )
    .await?;
    policy.rules[0].effect = arkret_wire::PolicyEffect::Allow;
    let outcome: arkret_wire::AuthoritySubmitResponseBody = serde_json::from_value(
        alice
            .client
            .submit_event(
                realm.as_str(),
                arkret_wire::EventKind::PolicySet.as_str(),
                serde_json::to_value(set_policy(&policy)?)?,
            )
            .await?,
    )?;
    let arkret_wire::AuthoritySubmitResponseBody::Accepted {
        commit: policy_allowed,
        ..
    } = outcome
    else {
        anyhow::bail!("Typing Policy allow must be accepted");
    };
    super::mls_lifecycle_live::accepted_full_view(&bob.client, &policy_allowed.event_ref).await?;
    wait_for_replica_cut(y_url, &policy_allowed).await?;
    deliver(
        bob,
        alice,
        bob_group,
        alice_group,
        realm,
        strand,
        state,
        &policy_allowed.commit_id,
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        None,
        SignalClass::Session,
        15,
        Some(x),
        Some((typing_frame(15)?, true)),
    )
    .await?;
    let typing_revoke: arkret_wire::AuthoritySubmitResponseBody = serde_json::from_value(
        alice
            .client
            .revoke_realm_grant(
                realm.as_str(),
                arkret_wire::GrantId::from_event_id(&typing_grant.event_ref).as_str(),
            )
            .await?,
    )?;
    let arkret_wire::AuthoritySubmitResponseBody::Accepted {
        commit: typing_revoked,
        ..
    } = typing_revoke
    else {
        anyhow::bail!("Typing revoke must be accepted");
    };
    super::mls_lifecycle_live::accepted_full_view(&bob.client, &typing_revoked.event_ref).await?;
    wait_for_replica_cut(y_url, &typing_revoked).await?;
    // Keep the original grant-bearing basis; current revocation must win.
    deliver(
        bob,
        alice,
        bob_group,
        alice_group,
        realm,
        strand,
        state,
        &policy_allowed.commit_id,
        ScopeRef::Realm {
            realm_id: realm.clone(),
        },
        None,
        SignalClass::Session,
        16,
        None,
        Some((typing_frame(16)?, false)),
    )
    .await?;
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
        17,
        Some(x),
        None,
    )
    .await?;
    let revoke: arkret_wire::AuthoritySubmitResponseBody = serde_json::from_value(
        alice
            .client
            .revoke_realm_grant(
                realm.as_str(),
                arkret_wire::GrantId::from_event_id(&moderation_grant.event_ref).as_str(),
            )
            .await?,
    )?;
    let arkret_wire::AuthoritySubmitResponseBody::Accepted {
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
    // Circle bootstrap can advance the replica's signed baseline beyond the
    // original Realm cut. New producers select a currently held exact basis.
    let fresh_head = super::websocket_live::realm_head(&alice.client, realm.as_str()).await?;
    let fresh_tail = alice
        .client
        .sdk()
        .scan_commit_stream_tail(
            realm.clone(),
            fresh_head.stream_ref.clone(),
            fresh_head.stream_position.checked_sub(1),
            1,
        )
        .await?;
    let fresh_basis = fresh_tail
        .committed_events
        .last()
        .context("fresh accepted Realm basis")?
        .commit()
        .clone();
    ensure!(fresh_basis.commit_id == fresh_head.commit_id);
    super::mls_lifecycle_live::accepted_full_view(&bob.client, &fresh_basis.event_ref).await?;
    wait_for_replica_cut(y_url, &fresh_basis).await?;

    let fresh = envelope(
        bob,
        bob_group,
        realm,
        strand,
        state,
        &fresh_basis.commit_id,
        SignalClass::Session,
        18,
    )?;
    emission::exercise(
        alice,
        bob,
        alice_group,
        bob_group,
        realm,
        strand,
        state,
        &fresh_basis.commit_id,
        x,
        y,
        &[x_url, y_url],
        pause_file,
        boundary,
    )
    .await?;

    deny(bob, &fresh, realm, &[x_url, y_url])
        .await
        .context("current membership or terminal fence denies an older otherwise valid cut")?;
    eprintln!(
        "[signal-live] actual TLS Stations=2 directions=2 realm_session_deliveries=2 circle_session_deliveries=2 granted_moderation_deliveries=1 recipient_proof_mls_aead_plaintext=5 old_cut_denied=1 moderation_denied=1 current_membership_or_terminal_denied=1 denied_relay_event_commit_writes=0"
    );
    Ok(())
}
