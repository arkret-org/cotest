//! Actual accepted MLS domains and whole HTTP Snapshot capacity, independently
//! of the native-operation inventory. No reference projection is installed.

use anyhow::{Context as _, Result, ensure};
use arkret_mls::ArkretMlsGroup;
use arkret_models_collaboration::events_payloads::{MessageReactionsCurrentValue, ReactionPayload};
use arkret_models_crypto::{EncryptedEnvelope, MlsGovernanceBindingPayload};
use arkret_wire::{
    CommittedEventFullView, CurrentSelector, CurrentState, Event, EventId, EventKind,
    MlsGroupValue, RealmId, RealmStateSnapshot, ScopeRef,
};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use crate::harness::{ArkretServer, expect_json, heap_future};
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, submit_and_expect_commit,
};
use crate::scenarios::mls_lifecycle_live::{self as lifecycle, Member};

mod capacity;

const CONTENT_TYPE: &str = "application/vnd.arkret.reaction+json";

pub async fn verify_domains() -> Result<()> {
    heap_future(domain_case).await
}

pub async fn verify_capacity() -> Result<()> {
    heap_future(capacity::run).await
}

async fn fixture(label: &str) -> Result<(ArkretServer, Member, RealmId, EventId)> {
    let station = ArkretServer::spawn(label).await?;
    let actor = crate::scenarios::identity_test_support::actor_did_for_service_did(
        station.service_did(),
        label,
    )?;
    let device = format!("ak:device:{}", uuid::Uuid::now_v7());
    let client = station.standard_client(&actor, &device).await?;
    let principal = client
        .principal
        .as_ref()
        .context("native founding Device absent")?;
    let account =
        arkret_wire::AccountId::new(principal.core_id.clone(), station.service_id().clone());
    let member = Member::from_client(client, account)?;
    let realm: RealmId = create_realm_with_join_rule(
        &member.client,
        "Actual reaction domains and HTTP capacity",
        "closed",
        &[&station],
    )
    .await?
    .parse()?;
    let strand = member
        .client
        .create_strand(realm.as_str(), "Native reaction target")
        .await?;
    let target = member.client.author_event(realm.as_str(), EventKind::MessageCreate.as_str(),
        json!({"strand_id":strand,"track_name":"discussion","content":{"kind":"ak.content.text","body":"reaction target","format":"plain"}})).await?;
    submit(&member, &target).await?;
    Ok((station, member, realm, target.event_id))
}

/// Event display time and the time this Device signs it are independent.
/// Native admission still checks both against the real current Device window.
fn sign_now(member: &Member, event: &mut Event) -> Result<()> {
    event.producer_proof = None;
    let mut authored = arkret_wire::AuthoredEvent::finalize_with_digest_suite(
        event.clone(),
        arkret_canonical::DigestSuite::Sha256,
    )?;
    let signer = arkret_signatures::Ed25519PayloadSigner::from_did_key_seed(
        member.key.to_bytes(),
        member
            .client
            .principal
            .as_ref()
            .context("Device custody absent")?
            .did
            .clone(),
        member.method.clone(),
    );
    arkret_signatures::sign_event(
        &mut authored,
        &signer,
        arkret_signatures::SignEventOptions::new().with_created_at(Utc::now()),
    )?;
    *event = authored.into_event();
    Ok(())
}

async fn submit(member: &Member, event: &Event) -> Result<CommittedEventFullView> {
    let commit = submit_and_expect_commit(
        &member.client,
        &member.account,
        member.device.as_str(),
        event,
    )
    .await?;
    let full = lifecycle::accepted_full_view(&member.client, &event.event_id).await?;
    ensure!(
        full.event == *event && full.commit == commit,
        "HTTP changed the accepted original"
    );
    Ok(full)
}

async fn snapshot(member: &Member, realm: &RealmId) -> Result<RealmStateSnapshot> {
    let source = member
        .client
        .sdk()
        .own_station_result_client()?
        .context("native own-Station source absent")?;
    let response = source.snapshot_head(realm).await?;
    source.check_session()?;
    let value = response.value()?.clone();
    let mut replica = garth::own_station_results::OwnStationReplica::new(realm.clone());
    replica.install_bound_snapshot(&response)?;
    ensure!(
        replica.snapshot() == Some(&value),
        "whole bound Snapshot changed during installation"
    );
    source.check_session()?;
    Ok(value)
}

fn current_group(snapshot: &RealmStateSnapshot, scope: &ScopeRef) -> Result<MlsGroupValue> {
    let mut rows = snapshot.current_state_entries.iter().filter_map(|row| {
        let CurrentState::Value {
            selector,
            value,
            source_stream_ref,
            ..
        } = row;
        matches!(selector, CurrentSelector::MlsGroup { scope_ref } if scope_ref==scope)
            .then_some((value, source_stream_ref))
    });
    let (value, stream) = rows.next().context("actual current MLS group absent")?;
    ensure!(
        rows.next().is_none() && stream.scope_ref() == *scope,
        "duplicate/foreign MLS current"
    );
    Ok(garth::current_ingest::closed_current_value(
        value,
        "mls_group",
    )?)
}

fn reactions(
    snapshot: &RealmStateSnapshot,
    target: &EventId,
) -> Result<MessageReactionsCurrentValue> {
    let mut rows = snapshot.current_state_entries.iter().filter_map(|row| {
        let CurrentState::Value { selector, value, source_stream_ref, revision } = row;
        matches!(selector, CurrentSelector::MessageReactions { target_ref } if target_ref == arkret_wire::MessageId::from_event_id(target).as_str())
            .then_some((value, source_stream_ref, revision))
    });
    let (value, stream, revision) = rows.next().context("actual Reaction current absent")?;
    ensure!(rows.next().is_none(), "duplicate Reaction current");
    let set: MessageReactionsCurrentValue = serde_json::from_value(value.clone())?;
    let head = snapshot
        .visible_stream_heads
        .iter()
        .find(|head| &head.stream_ref == stream)
        .context("Reaction current stream head absent")?;
    set.validate_installation(
        arkret_wire::MessageId::from_event_id(target).as_ref(),
        stream,
        revision,
        head,
        None,
    )?;
    Ok(set)
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
        .context("actual founding MLS leaf absent")?;
    let (info, tree) = group.public_group_state_bytes()?;
    let payload = arkret_models_collaboration::events_payloads::MlsGenesisPayload {
        cipher_suite: arkret_wire::NonEmptyString::new(lifecycle::ACTIVE_SUITE)
            .map_err(anyhow::Error::msg)?,
        group_info_ref: lifecycle::upload_public_blob(&member.client, realm, &info)
            .await?
            .parse()?,
        ratchet_tree_ref: lifecycle::upload_public_blob(&member.client, realm, &tree)
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
        created_at: Utc::now(),
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
    sign_now(member, &mut event)?;
    let accepted = submit(member, &event).await?;
    Ok((group, accepted))
}

fn window(at: DateTime<Utc>) -> Result<u64> {
    Ok(u64::try_from(at.timestamp_millis().div_euclid(3_600_000))?)
}

fn tag(
    group: &ArkretMlsGroup,
    scope: &ScopeRef,
    target: &EventId,
    at: DateTime<Utc>,
    emoji: &str,
) -> Result<String> {
    use hmac::{Hmac, KeyInit as _, Mac as _};
    let root = arkret_mls::exporter_kdf::derive_reaction_routing_root(group, scope)?;
    let key = arkret_mls::exporter_kdf::derive_reaction_routing_key(
        &root,
        &arkret_mls::exporter_kdf::ReactionRoutingKeyContext {
            effective_scope: scope.clone(),
            target_ref: target.clone(),
            routing_window: window(at)?,
        },
    )?;
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(&key)?;
    mac.update(arkret_canonical::to_nfc(emoji).as_bytes());
    Ok(arkret_canonical::base64url_encode(
        mac.finalize().into_bytes(),
    ))
}

struct Domain<'a> {
    reference: &'a EventId,
    target: &'a EventId,
    at: DateTime<Utc>,
}

async fn seal(
    member: &Member,
    group: &mut ArkretMlsGroup,
    domain: &Domain<'_>,
    kind: EventKind,
) -> Result<Event> {
    let scope = group.scope().clone();
    let key = tag(group, &scope, domain.target, domain.at, "👍")?;
    let plaintext = arkret_canonical::canonical_json_bytes(&json!({"key":"👍"}))?;
    let mut event = member
        .client
        .author_event(
            scope.realm_id().as_str(),
            kind.as_str(),
            json!({"target_ref":arkret_wire::MessageId::from_event_id(domain.target),"key":key}),
        )
        .await?;
    event.created_at = domain.at;
    sign_now(member, &mut event)?;
    let material = heap_future(|| {
        crate::harness::content::prepare_device(
            &member.client,
            group,
            &event,
            domain.reference,
            "/payload/encrypted_payload",
            CONTENT_TYPE,
            &plaintext,
        )
    })
    .await?;
    let header = arkret::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        CONTENT_TYPE,
        arkret::EncryptedPayloadScheme::EpochContentAead,
        scope,
        kind.as_str(),
        group.epoch(),
        domain.reference.clone(),
        group.local_content_sender_domain()?,
        arkret::EventContentRoutingContext::Reaction {
            target_ref: domain.target.clone(),
            routing_window: window(domain.at)?,
            routing_tag: key,
        },
        material,
    )?;
    let payload = group.encrypt_payload(header, &plaintext)?;
    event.payload.insert(
        "encrypted_payload".into(),
        serde_json::to_value(payload.to_envelope()?)?,
    );
    sign_now(member, &mut event)?;
    Ok(event)
}

async fn open(member: &Member, receiver: &mut ArkretMlsGroup, event: &Event) -> Result<()> {
    let payload: ReactionPayload = serde_json::from_value(json!(event.payload))?;
    let envelope: EncryptedEnvelope = payload
        .encrypted_payload
        .context("accepted encrypted original absent")?;
    let material =
        crate::harness::content::original_material(&member.client, receiver, event, &envelope)
            .await?;
    let header = envelope.reconstruct_pre_encryption_header(
        arkret::EncryptedPayloadScheme::EpochContentAead,
        event.scope_ref.clone(),
        event.kind.as_str(),
        receiver.local_content_sender_domain()?,
        Some(window(event.created_at)?),
        material,
    )?;
    let encrypted = arkret::encrypted_envelope_to_payload_with_verified_header(&envelope, header)?;
    let opened: Value = serde_json::from_slice(&receiver.decrypt_payload(&encrypted)?)?;
    ensure!(
        opened == json!({"key":"👍"}),
        "actual receiver did not open the real emoji"
    );
    Ok(())
}

async fn domain_case() -> Result<()> {
    let (station, member, realm, target) = fixture("reaction-mls-domain-native").await?;
    let scope = ScopeRef::realm(realm.clone());
    // Both actual targets must be accepted before MLS activation: a new
    // plaintext Message is correctly forbidden once a current group exists.
    let target_view = lifecycle::accepted_full_view(&member.client, &target).await?;
    let mut other_payload = json!(target_view.event.payload);
    other_payload["content"]["body"] = json!("second accepted same-scope Reaction target");
    let other = member
        .client
        .author_event(
            realm.as_str(),
            EventKind::MessageCreate.as_str(),
            other_payload,
        )
        .await?;
    let other = submit(&member, &other).await?;
    ensure!(other.event.event_id != target && other.event.scope_ref == scope);
    // Both display instants are in the past. HTTP/DPoP and producer signatures
    // are issued now; native acceptance independently proves their source.
    let boundary_ms = Utc::now().timestamp_millis().div_euclid(3_600_000) * 3_600_000 - 3_600_000;
    let before = DateTime::from_timestamp_millis(boundary_ms - 1).context("previous hour time")?;
    let after = DateTime::from_timestamp_millis(boundary_ms + 1).context("next hour time")?;
    ensure!(window(after)? == window(before)? + 1 && after < Utc::now());
    let authorization =
        lifecycle::accepted_full_view(&member.client, &member.authorize_event_id).await?;
    let authorization: arkret_models_collaboration::events_payloads::DeviceAuthorizePayload =
        serde_json::from_value(json!(authorization.event.payload))?;
    ensure!(
        authorization.device_id == member.device
            && authorization.not_before <= before
            && authorization
                .expires_at
                .flatten()
                .is_none_or(|end| Utc::now() < end),
        "the actual accepted Device window does not cover both historical display times and fresh admission"
    );
    let (mut group, genesis) = heap_future(|| genesis(&member, &realm)).await?;
    let original = snapshot(&member, &realm).await?;
    let current = current_group(&original, &scope)?;
    ensure!(
        current.epoch == group.epoch()
            && current.current_mls_commit_event_ref == genesis.event.event_id
    );
    let root0 = arkret_mls::exporter_kdf::derive_reaction_routing_root(&group, &scope)?;
    let mut receiver0 = ArkretMlsGroup::restore_from_state_record(&group.export_state_record()?)?;
    let first_domain = Domain {
        reference: &genesis.event.event_id,
        target: &target,
        at: before,
    };
    let first =
        heap_future(|| seal(&member, &mut group, &first_domain, EventKind::ReactionAdd)).await?;
    let first = submit(&member, &first).await?;
    open(&member, &mut receiver0, &first.event).await?;
    let second_domain = Domain {
        reference: &genesis.event.event_id,
        target: &target,
        at: after,
    };
    let second =
        heap_future(|| seal(&member, &mut group, &second_domain, EventKind::ReactionAdd)).await?;
    let second = submit(&member, &second).await?;
    open(&member, &mut receiver0, &second.event).await?;
    ensure!(
        first.event.payload["key"] != second.event.payload["key"],
        "adjacent windows merged"
    );
    // Freeze a genuinely self-consistent Q0/epoch0/root0 body while Q0 is
    // current. Opening it now proves the old ciphertext is valid, without
    // submitting it or reserving its nonce domain on the Station.
    let old_pending =
        heap_future(|| seal(&member, &mut group, &second_domain, EventKind::ReactionAdd)).await?;
    let old_envelope: EncryptedEnvelope =
        serde_json::from_value(old_pending.payload["encrypted_payload"].clone())?;
    ensure!(
        old_envelope.encryption_context.epoch() == current.epoch
            && old_envelope.encryption_context.group_state_ref() == &genesis.event.event_id
    );
    let old_salt =
        old_pending.payload["encrypted_payload"]["encryption_context"]["content_key_salt"]
            .as_str()
            .context("actual old pending salt")?;
    for accepted in [&first, &second] {
        ensure!(accepted.event.event_id!=old_pending.event_id
            && accepted.event.payload["encrypted_payload"]["encryption_context"]["content_key_salt"].as_str()!=Some(old_salt),
            "pending old-source intent reused an already accepted nonce domain");
    }
    open(&member, &mut receiver0, &old_pending).await?;
    let binding = MlsGovernanceBindingPayload::new(
        scope.clone(),
        Some(genesis.event.event_id.clone()),
        current.epoch,
        current.epoch + 1,
        current.current_key_access_revision,
    )?;
    let transition = group.self_update_commit_with_governance_binding(&binding)?;
    let payload = lifecycle::commit_payload_with_public_material(
        &member.client,
        &group,
        genesis.event.event_id.clone(),
        current.current_key_access_revision,
        &transition,
        binding,
    )
    .await?;
    let next = member
        .client
        .author_event(
            realm.as_str(),
            EventKind::MlsCommit.as_str(),
            serde_json::to_value(payload)?,
        )
        .await?;
    let submission =
        arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequestBody::MlsCommit(
            arkret_wire::MlsCommitSubmission {
                recovery_source: None,
                commit_event: next.clone(),
                welcomes: Vec::new(),
                idempotency_key: arkret_wire::UuidV7::new(uuid::Uuid::now_v7())?,
            },
        );
    expect_json(
        member.client.post("/_arkret/self/events").json(&submission),
        reqwest::StatusCode::OK,
    )
    .await?;
    let next = lifecycle::accepted_full_view(&member.client, &next.event_id).await?;
    group.install_accepted_commit(&next, &current)?;
    let installed = current_group(&snapshot(&member, &realm).await?, &scope)?;
    ensure!(
        installed.epoch == group.epoch()
            && installed.epoch == current.epoch + 1
            && installed.current_mls_commit_event_ref == next.event.event_id
            && installed.covered_key_access_revision >= installed.current_key_access_revision,
        "real accepted epoch was not installed"
    );
    ensure!(
        root0.as_slice()
            != arkret_mls::exporter_kdf::derive_reaction_routing_root(&group, &scope)?.as_slice()
    );
    let mut receiver1 = ArkretMlsGroup::restore_from_state_record(&group.export_state_record()?)?;
    let domain = Domain {
        reference: &next.event.event_id,
        target: &target,
        at: after,
    };
    let third = heap_future(|| seal(&member, &mut group, &domain, EventKind::ReactionAdd)).await?;
    let third = submit(&member, &third).await?;
    open(&member, &mut receiver1, &third.event).await?;
    let complete = snapshot(&member, &realm).await?;
    let set = reactions(&complete, &target)?;
    ensure!(
        set.entries().len() == 3,
        "MLS/window current domains were merged"
    );
    for original in [&first, &second, &third] {
        let entry = set
            .entries()
            .iter()
            .find(|entry| json!(entry.key) == original.event.payload["key"])
            .context("real domain key absent")?;
        ensure!(
            entry.actor_id == member.actor
                && entry.source.event_id == original.event.event_id
                && entry.source.commit_id == original.commit.commit_id
                && entry.source.stream_position == original.commit.stream_position
        );
    }
    // Repeating one domain updates only its own source; the old domains survive.
    let repeated =
        heap_future(|| seal(&member, &mut group, &domain, EventKind::ReactionAdd)).await?;
    let repeated = submit(&member, &repeated).await?;
    let set = reactions(&snapshot(&member, &realm).await?, &target)?;
    ensure!(
        set.entries().len() == 3
            && set
                .entries()
                .iter()
                .any(|entry| entry.source.event_id == repeated.event.event_id)
    );
    let remove =
        heap_future(|| seal(&member, &mut group, &domain, EventKind::ReactionRemove)).await?;
    submit(&member, &remove).await?;
    let set = reactions(&snapshot(&member, &realm).await?, &target)?;
    ensure!(
        set.entries().len() == 2
            && set
                .entries()
                .iter()
                .all(|entry| entry.source.event_id == first.event.event_id
                    || entry.source.event_id == second.event.event_id)
    );
    // Seal genuinely new intents without accepting any of their ciphertexts.
    // Reusing an accepted salt would test the nonce-domain fence instead of
    // the public key/target equality being tested here.
    let mut baselines = Vec::new();
    for _ in 0..2 {
        baselines.push(
            heap_future(|| seal(&member, &mut group, &domain, EventKind::ReactionAdd)).await?,
        );
    }
    let mut salts = std::collections::BTreeSet::new();
    for baseline in &baselines {
        let salt = baseline.payload["encrypted_payload"]["encryption_context"]["content_key_salt"]
            .as_str()
            .context("actual fresh content salt")?;
        ensure!(
            salts.insert(salt.to_owned()),
            "distinct negative intents reused their content nonce domain"
        );
    }
    let mut wrong_key = baselines[0].clone();
    let actual_key = wrong_key.payload["key"]
        .as_str()
        .context("real routing key")?;
    ensure!(
        actual_key.len() == 43 && actual_key.is_ascii(),
        "actual HMAC tag is not the registered base64url width"
    );
    let replacement = format!(
        "{}{}",
        if actual_key.starts_with('A') {
            'B'
        } else {
            'A'
        },
        &actual_key[1..]
    );
    wrong_key.payload.insert("key".into(), json!(replacement));
    sign_now(&member, &mut wrong_key)?;
    let mut wrong_target = baselines[1].clone();
    wrong_target.payload.insert(
        "target_ref".into(),
        json!(arkret_wire::MessageId::from_event_id(&other.event.event_id)),
    );
    sign_now(&member, &mut wrong_target)?;
    capacity::reject_domain_mutations(
        &station,
        &member,
        &realm,
        &[
            (
                "fresh outer key differs from inner routing tag",
                wrong_key,
                reqwest::StatusCode::UNPROCESSABLE_ENTITY,
                arkret_wire::ErrorCode::SchemaViolation,
            ),
            (
                "fresh same-scope Message target differs from inner Event target",
                wrong_target,
                reqwest::StatusCode::UNPROCESSABLE_ENTITY,
                arkret_wire::ErrorCode::SchemaViolation,
            ),
            // This whole original is unchanged since Q0 was current. The
            // fresh HTTP proof authenticates this attempt, not a new inner
            // intent or a misleading Q-only mutation of an epoch1 body.
            (
                "unaccepted self-consistent old epoch/root/Q0 source",
                old_pending,
                reqwest::StatusCode::CONFLICT,
                arkret_wire::ErrorCode::EpochMismatch,
            ),
        ],
    )
    .await?;
    // The unchanged originals must now pass. This proves the refusal did not
    // come from missing roots, expired credentials or an occupied nonce domain.
    for baseline in baselines {
        submit(&member, &baseline).await?;
    }
    println!(
        "reaction MLS composition passed: real epochs {} -> {}, adjacent windows {} -> {}, 3 independent native current keys",
        current.epoch,
        installed.epoch,
        window(before)?,
        window(after)?
    );
    Ok(())
}
