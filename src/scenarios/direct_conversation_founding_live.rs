//! A complete Direct Conversation on one Station, from the Contact round
//! production Contact admission produced to encrypted messages both ways
//! (`contact-and-direct-conversation.md` sections 2, 5.2, 5.5, 6.1, 7.2,
//! 8.3 and 8.4).
//!
//! Bob requests Alice and Alice answers with a normal response through the
//! self Contact operations, so the pair's Contact row is the one the atomic
//! Contact admission wrote. The normal round's founder is the responder:
//!
//! * Alice authors the four-Event founding unit naming the round and submits it through the self
//!   events union; it commits as four consecutive RealmCommits and an exact retry replays them.
//! * Before the scope's group Genesis no bootstrap phase exists, so Alice's first Message is
//!   refused by the participant evaluator. The technical root's materialization mask admits Alice's
//!   `ak.mls.genesis`.
//! * Provisional phase: only the founder sends under the bootstrap source; Bob's attempt is
//!   refused. Alice claims Bob's KeyPackage and Adds him with a Welcome, still under the bootstrap
//!   source.
//! * Bob joins from the Welcome and acknowledges it; before he consumes his claim an endorsement is
//!   still refused. Once consumed, the completion phase admits only binding endorsements: one
//!   naming another group state is `direct_conversation_binding_invalid`, the founder's provisional
//!   Message is refused, and Bob's exact endorsement and Alice's compatible one are both accepted.
//! * Found: both participants send MLS ciphertext under the participant source citing an
//!   endorsement and each decrypts the other's committed Message. The bootstrap source no longer
//!   carries a Message, an invite of a third party is
//!   `direct_conversation_third_party_member_forbidden` although it is also an invite, an invite of
//!   the peer is `direct_conversation_invite_forbidden`, banning the peer relies on the technical
//!   root and is `direct_conversation_root_mask_violation`, and a destroy by the root is
//!   `direct_conversation_terminal_forbidden` although it also relies on the root.
//!
//! Every refusal is the closed `{status="rejected",reason_code}` outcome and
//! leaves no committed Event.

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail, ensure};
use arkret::{ArkretMlsGroup, MlsCommitPayload, MlsGovernanceBindingPayload};
use arkret_models_collaboration::authority_commit::{
    AggregateAcceptanceStatus, CommittedEventSubmission,
    DirectConversationFoundingAcceptanceOutcome,
    DirectConversationFoundingDependencyMissingProblem,
    DirectConversationFoundingFederationSubmission, DirectConversationFoundingMissingDependency,
    DirectConversationFoundingUnitKind, DirectConversationFoundingUnitSubmission,
    PeerAuthoritySubmitRequest, PeerRegisteredAtomicUnit, PeerRegisteredAtomicUnitRequest,
    RegisteredAtomicUnitBranch, SelfAuthoritySubmitRequest,
};
use arkret_models_collaboration::device_messages::DeviceMessagesAckRequestBody;
use arkret_models_collaboration::direct_conversation::{
    DirectConversationFoundingPlan, DirectConversationResolveOutcome,
    DirectConversationResolveRequestBody,
};
use arkret_models_collaboration::events_payloads::MlsGenesisCreatorLeafAuthority;
use arkret_models_collaboration::events_payloads::direct_conversation::DirectConversationBoundPayload;
use arkret_models_collaboration::governance::invite_addressing::{
    InviteLocatorIssueRequestBody, InviteLocatorResolveRequestBody, PrincipalLocator,
};
use arkret_models_collaboration::governance::membership_invite::MembershipPayloadState;
use arkret_models_collaboration::governance::peer_contact::ContactIntroductionEvidence;
use arkret_models_collaboration::objects::direct_conversation::{
    DirectConversationAuthorizationBasis, DirectConversationFoundingAuthorityEvidence,
    direct_conversation_main_strand_create_payload, direct_conversation_member_join_payload,
    direct_conversation_peer_membership_bootstrap, direct_conversation_realm_create_payload,
};
use arkret_models_crypto::{KeyPackagesClaimOutcome, KeyPackagesUploadOutcome};
use arkret_wire::{
    AccountId, ActorId, AuthorityCommitStatus, AuthoritySubmitOutcome, Did, Event,
    EventAdmissionSubmission, EventId, GenesisSalt, MlsCommitSubmission, RealmId, ScopeRef,
    SemanticRef, StrandId,
};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{TestServerGroup, expect_json};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::human_device_producer_live::{
    database, membership_payload, standard_client, station_env, wait_for_committed,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use crate::scenarios::mls_lifecycle_live::{
    ACTIVE_SUITE, Member, accepted_full_view, canonical, claim_request_between,
    claimed_keypackage_record, fresh_uuid_v7, post_bytes_at, post_claim, post_json, problem_type,
    recipient_welcomes, signed_welcome,
};

const GROUP: &str = "direct-conversation-founding";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002401";
const ALICE_SECOND_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002404";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002402";
const THIRD_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002403";
const CONTACT_ROUND_ROLE: &str = "direct_conversation_contact_round";
const FOUNDING_UNIT_ROLE: &str = "direct_conversation_founding_unit";
const BINDING_ROLE: &str = "direct_conversation_binding";
const BOOTSTRAP_SOURCE: &str = "ak.authority.direct_conversation_bootstrap_participant.v1";
const PARTICIPANT_SOURCE: &str = "ak.authority.direct_conversation_participant.v1";
const MESSAGE_CONTENT_TYPE: &str = "application/vnd.arkret.message+json";
const PARTICIPANT_DENIED: &str = "direct_conversation_participant_authority_denied";

/// The authority source and critical ref a Direct Conversation Event names.
#[derive(Clone, Copy)]
enum Cites<'a> {
    Nothing,
    Bootstrap(&'a EventId),
    Participant(&'a EventId),
}

/// One Event authored now and signed by `member`'s founding device.
fn authored(
    member: &Member,
    kind: &str,
    scope_ref: ScopeRef,
    payload: Value,
    semantic_refs: Vec<SemanticRef>,
    cites: Cites<'_>,
) -> Result<Event> {
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    authored_at(member, kind, scope_ref, payload, semantic_refs, cites, at)
}

/// [`authored`] at `at`, for Events whose payload repeats their creation time.
fn authored_at(
    member: &Member,
    kind: &str,
    scope_ref: ScopeRef,
    payload: Value,
    semantic_refs: Vec<SemanticRef>,
    cites: Cites<'_>,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<Event> {
    let mut event = arkret_wire::test_support::raw_event_at(
        kind,
        scope_ref,
        member.account.principal_id.clone(),
        member.account.station_id.clone(),
        canonical(payload)?,
        at,
    )?;
    event.semantic_refs = semantic_refs;
    let cited = match cites {
        Cites::Nothing => None,
        Cites::Bootstrap(reference) => Some((BOOTSTRAP_SOURCE, FOUNDING_UNIT_ROLE, reference)),
        Cites::Participant(reference) => Some((PARTICIPANT_SOURCE, BINDING_ROLE, reference)),
    };
    if let Some((source, role, reference)) = cited {
        event.authorization_ref = Some(
            arkret_wire::AuthorizationRef::new(source.to_owned()).map_err(anyhow::Error::msg)?,
        );
        event
            .semantic_refs
            .push(SemanticRef::new(reference.to_string(), role));
    }
    let signer = arkret_test_kit::seeded_signer_for_seed(
        member.key.to_bytes(),
        Did::new(member.client.actor.clone())?,
        member.method.clone(),
    );
    Ok(arkret_test_kit::sign_verifiable_event(
        event,
        &signer,
        arkret::canonical::DigestSuite::Sha256,
    )?
    .expect_verifiable())
}

/// Upload one public MLS state Blob to the member's own Station without a
/// Realm binding and return its content-addressed ref.
async fn upload_unbound_blob(member: &Member, bytes: &[u8]) -> Result<String> {
    let uploaded = expect_json(
        member.client.post("/_arkret/self/blob/upload").multipart(
            crate::scenarios::delivery_media::blob_upload_form(bytes, "application/octet-stream")?,
        ),
        StatusCode::OK,
    )
    .await?;
    uploaded["blob_ref"]
        .as_str()
        .map(ToOwned::to_owned)
        .context("the Blob upload returned its ref")
}

/// Submit one Event through the self events union and return its outcome.
async fn submit(member: &Member, event: &Event) -> Result<AuthoritySubmitOutcome> {
    let (status, body) = post_json(
        &member.client,
        &EventAdmissionSubmission::new(event.clone()),
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "{} was not decided with a closed outcome: {status} {body}",
        event.kind.as_str()
    );
    Ok(serde_json::from_value(body)?)
}

fn expect_committed(outcome: &AuthoritySubmitOutcome, event: &Event) -> Result<()> {
    match outcome {
        AuthoritySubmitOutcome::Accepted {
            status: AuthorityCommitStatus::Committed,
            commit,
        } if commit.event_ref == event.event_id => Ok(()),
        other => bail!("{} was not committed: {other:?}", event.kind.as_str()),
    }
}

async fn expect_rejected(member: &Member, event: &Event, reason: &str) -> Result<()> {
    match submit(member, event).await? {
        AuthoritySubmitOutcome::Rejected { reason_code, .. } if reason_code == reason => {}
        other => bail!(
            "{} must be rejected as {reason}, got {other:?}",
            event.kind.as_str()
        ),
    }
    ensure!(
        member
            .client
            .sdk()
            .committed_event_get(&event.event_id)
            .await
            .is_err(),
        "a rejected {} left a committed Event",
        event.kind.as_str()
    );
    Ok(())
}

/// The accepted normal round `holder` sees with `peer`, with its accepted
/// request and accept Event refs.
async fn assert_peer_endpoint(
    holder: &Member,
    peer: &Member,
    expected_source: Option<&EventId>,
) -> Result<()> {
    let mut previous = None;
    // Each call is a fresh authenticated read, without client receipt caches.
    for _ in 0..2 {
        let row = holder
            .client
            .sdk()
            .contacts_list()
            .await?
            .contacts
            .into_iter()
            .find(|row| row.peer.contact_actor_id() == peer.actor)
            .context("accepted peer row")?;
        ensure!(row.state == arkret::ContactState::Accepted);
        let endpoint = row.peer_endpoint.context("accepted peer endpoint")?;
        ensure!(endpoint.device_id == peer.device);
        if let Some(source) = expected_source {
            ensure!(&endpoint.contact_event_ref == source);
        }
        if let Some(previous) = &previous {
            ensure!(previous == &endpoint);
        }
        if holder.account.station_id != peer.account.station_id {
            let response = holder
                .client
                .get(&format!(
                    "/_arkret/self/committed-events/{}",
                    endpoint.contact_event_ref
                ))
                .send()
                .await?;
            ensure!(
                response.status() == StatusCode::NOT_FOUND,
                "peer PCR Event was disclosed through the self read"
            );
        }
        previous = Some(endpoint);
    }
    Ok(())
}

async fn accepted_round(
    holder: &Member,
    peer: &AccountId,
) -> Result<(arkret_wire::Hash, [EventId; 2])> {
    let peer = ActorId::account(peer.clone());
    let row = holder
        .client
        .sdk()
        .contacts_list()
        .await?
        .contacts
        .into_iter()
        .find(|row| row.peer.contact_actor_id() == peer)
        .context("the accepted Contact row is listed")?;
    ensure!(
        row.state == arkret::ContactState::Accepted,
        "the pair's Contact round is not accepted: {:?}",
        row.state
    );
    let heads = [
        row.request_event_ref
            .clone()
            .context("an accepted row names its request")?,
        row.response_event_ref
            .clone()
            .context("an accepted row names its accept")?,
    ];
    Ok((
        row.next_prepare_input
            .context("an accepted row carries its next prepare input")?
            .contact_round_id,
        heads,
    ))
}

async fn wait_contact_state(
    holder: &Member,
    peer: &AccountId,
    expected: arkret::ContactState,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let state = holder
            .client
            .sdk()
            .contacts_list()
            .await?
            .contacts
            .into_iter()
            .find(|row| row.peer.contact_actor_id() == ActorId::account(peer.clone()))
            .map(|row| row.state);
        if state == Some(expected) {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "the cross-Station Contact did not converge to {expected:?}; last state: {state:?}"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn issued_locator(member: &Member) -> Result<PrincipalLocator> {
    let issued = expect_json(
        member
            .client
            .post("/_arkret/self/invite-locators")
            .json(&InviteLocatorIssueRequestBody {
                ttl_seconds: Some(900),
                ..Default::default()
            }),
        StatusCode::OK,
    )
    .await?;
    let token = issued["locator_token"]
        .as_str()
        .context("locator issue omitted locator_token")?;
    let resolved = expect_json(
        member
            .client
            .post("/_arkret/open/invite-locators/resolve")
            .json(&InviteLocatorResolveRequestBody::new(token)),
        StatusCode::OK,
    )
    .await?;
    Ok(serde_json::from_value(resolved)?)
}

/// One MLS ciphertext Message sealed by `group` at its current epoch over
/// `group_state_ref`, the committed winning state that epoch was reached by.
fn sealed_message(
    group: &mut ArkretMlsGroup,
    scope: &ScopeRef,
    strand_id: &StrandId,
    group_state_ref: &EventId,
    plaintext: &[u8],
) -> Result<Value> {
    let header = arkret::EventContentPreEncryptionHeader::reconstruct(
        "1.0",
        MESSAGE_CONTENT_TYPE,
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        scope.clone(),
        arkret_wire::event_kind_str::MESSAGE_CREATE,
        group.epoch(),
        group_state_ref.clone(),
        group.local_content_sender_domain()?,
        arkret::EventContentRoutingContext::None,
    )?;
    let sealed = arkret::MessageCrypto::encrypt(group, fresh_uuid_v7(), header, plaintext)?;
    Ok(json!({
        "strand_id": strand_id,
        "track_name": "discussion",
        "encrypted_content": sealed.payload.to_envelope()?,
    }))
}

/// Read `event_id` as `reader` sees it committed and decrypt it with the
/// reader's own group, the sender domain derived from the committed actor.
async fn open_committed_message(
    reader: &Member,
    group: &mut ArkretMlsGroup,
    scope: &ScopeRef,
    event_id: &EventId,
) -> Result<Vec<u8>> {
    wait_for_committed(&reader.client, event_id).await?;
    let view = accepted_full_view(&reader.client, event_id).await?;
    let event = &view.event;
    // The sender domain is the sender leaf's BasicCredential identity, the
    // canonical ActorId of the verified Event producer.
    let sender_domain = String::from_utf8(arkret_models_crypto::mls_basic_credential_identity(
        &event.actor_id,
    )?)?;
    let envelope: arkret::EncryptedEnvelope = serde_json::from_value(
        serde_json::to_value(&event.payload)?
            .get("encrypted_content")
            .cloned()
            .context("the committed Message is MLS ciphertext")?,
    )?;
    let header = envelope.reconstruct_pre_encryption_header(
        arkret::EncryptedPayloadScheme::MlsRfc9420,
        scope.clone(),
        arkret_wire::event_kind_str::MESSAGE_CREATE,
        sender_domain,
        None,
    )?;
    let payload = arkret::encrypted_envelope_to_payload_with_verified_header(&envelope, header)?;
    Ok(arkret::MessageCrypto::decrypt(
        group,
        &arkret::EncryptedMessage {
            message_id: event_id.to_string(),
            payload,
        },
    )?)
}

/// The peer holds the entire founding stream even though `since_join` keeps
/// the founder's join (position 1) outside the peer member's self read window.
async fn wait_for_peer_founding_commits(
    connect_url: &str,
    realm_id: &RealmId,
    expected: &[arkret_wire::RealmCommit; 4],
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let connect_url = connect_url.to_owned();
        let realm_id = realm_id.to_string();
        let commits = tokio::task::spawn_blocking(move || -> Result<Vec<arkret_wire::RealmCommit>> {
            let mut db = postgres::Client::connect(&connect_url, postgres::NoTls)?;
            db.query(
                "SELECT commit_json::text FROM realm_commits WHERE realm_id=$1 ORDER BY stream_position",
                &[&realm_id],
            )?
            .into_iter()
            .map(|row| serde_json::from_str(row.get::<_, String>(0).as_str()).map_err(Into::into))
            .collect()
        })
        .await??;
        if commits.len() == expected.len() {
            ensure!(
                commits.as_slice() == expected,
                "the peer did not hold the four exact source Commits"
            );
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("the peer held {} of four founding Commits", commits.len());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn assert_no_peer_founding_writes(connect_url: &str, realm_id: &RealmId) -> Result<()> {
    let connect_url = connect_url.to_owned();
    let realm_id = realm_id.to_string();
    let counts = tokio::task::spawn_blocking(move || -> Result<Vec<i64>> {
        let mut db = postgres::Client::connect(&connect_url, postgres::NoTls)?;
        let row = db.query_one(
            "SELECT \
             (SELECT count(*) FROM canonical_events WHERE realm_id=$1), \
             (SELECT count(*) FROM realm_commits WHERE realm_id=$1), \
             (SELECT count(*) FROM realm_authorities WHERE realm_id=$1), \
             (SELECT count(*) FROM direct_conversation_founding_slots WHERE realm_id=$1), \
             (SELECT count(*) FROM federation_outbox WHERE payload_json LIKE '%' || $1 || '%')",
            &[&realm_id],
        )?;
        Ok((0..5).map(|index| row.get(index)).collect())
    })
    .await??;
    ensure!(
        counts == [0; 5],
        "missing dependency left peer Event/Commit/authority/slot/outbox writes: {counts:?}"
    );
    Ok(())
}

/// Client retention oracles are supplied explicitly; founding/admission remains in the server
/// harness.
#[async_trait::async_trait(?Send)]
pub trait DirectClientObserver {
    async fn block_direct_peer(&self, holder: &Member, peer: &Member) -> Result<()>;
    async fn unblock_direct_peer(&self, holder: &Member) -> Result<()>;
    async fn observe_dm_retained_receipt(
        &self,
        sender: &Member,
        holder: &Member,
        realm: &arkret_wire::RealmId,
        strand: &str,
        accepted_group: &arkret_wire::EventId,
        sender_group: &arkret::ArkretMlsGroup,
        holder_group: &arkret::ArkretMlsGroup,
        message_id: &arkret_wire::EventId,
        latest_cursor: &arkret_wire::EventId,
    ) -> Result<()>;
}

pub async fn run_with_client_observer(
    observer: &dyn DirectClientObserver,
    observe_case5_contact_terminal: bool,
) -> Result<()> {
    run(
        false,
        false,
        false,
        true,
        observe_case5_contact_terminal,
        Some(observer),
    )
    .await
}

pub async fn contact_round_founds_direct_conversation() -> Result<()> {
    run(false, false, false, false, false, None).await
}

pub async fn cross_station_contact_round_founds_direct_conversation() -> Result<()> {
    run(true, false, false, false, false, None).await
}

pub async fn cross_station_missing_contact_dependency_is_atomic() -> Result<()> {
    run(true, true, false, false, false, None).await
}

pub async fn blocklist_dm_binding_snapshot_live() -> Result<()> {
    run(false, false, true, false, false, None).await
}

fn founding_unit_for(
    founder: &Member,
    server: &crate::harness::ArkretServer,
    peer: &AccountId,
    contact_round_id: &arkret_wire::Hash,
    idempotency_key: arkret_wire::UuidV7,
) -> Result<(RealmId, DirectConversationFoundingUnitSubmission)> {
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let create = authored_at(
        founder,
        arkret_wire::event_kind_str::REALM_CREATE,
        ScopeRef::RealmGenesis,
        serde_json::to_value(direct_conversation_realm_create_payload(
            GenesisSalt::generate()?,
            server.trust_domain().clone(),
            server.service_id().clone(),
            at,
        )?)?,
        vec![SemanticRef::new(
            contact_round_id.to_string(),
            CONTACT_ROUND_ROLE,
        )],
        Cites::Nothing,
        at,
    )?;
    let realm_id = RealmId::from_event_id(&create.event_id);
    let scope = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let founder_join = authored_at(
        founder,
        arkret_wire::event_kind_str::MEMBER_STATE,
        scope.clone(),
        serde_json::to_value(direct_conversation_member_join_payload(
            realm_id.clone(),
            founder.account.clone(),
        ))?,
        Vec::new(),
        Cites::Nothing,
        at,
    )?;
    let peer_join = authored_at(
        founder,
        arkret_wire::event_kind_str::MEMBER_STATE,
        scope.clone(),
        serde_json::to_value(direct_conversation_peer_membership_bootstrap(
            realm_id.clone(),
            &founder.account,
            [founder.account.clone(), peer.clone()],
        )?)?,
        Vec::new(),
        Cites::Nothing,
        at,
    )?;
    let strand = authored_at(
        founder,
        arkret_wire::event_kind_str::STRAND_CREATE,
        scope,
        serde_json::to_value(direct_conversation_main_strand_create_payload(
            realm_id.clone(),
            founder.actor.clone(),
            at,
        ))?,
        Vec::new(),
        Cites::Nothing,
        at,
    )?;
    let unit = DirectConversationFoundingUnitSubmission {
        unit_kind: DirectConversationFoundingUnitKind::DirectConversationFounding,
        idempotency_key,
        events: [create, founder_join, peer_join, strand].map(EventAdmissionSubmission::new),
    };
    unit.validate()?;
    Ok((realm_id, unit))
}

pub async fn cross_station_two_authorized_devices_race_founding() -> Result<()> {
    let Some(founder_database) = database("direct-conversation-two-device-race")? else {
        return Ok(());
    };
    let Some(peer_database) = database("direct-conversation-two-device-race")? else {
        return Ok(());
    };
    ensure!(founder_database.connect_url != peer_database.connect_url);
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let node_envs = [
        station_env(&founder_database.connect_url, &coauth),
        station_env(&peer_database.connect_url, &coauth),
    ];
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        "direct-conversation-two-device-race",
        &node_envs,
    )
    .await?
    else {
        return skip_or_fail(
            "direct-conversation-two-device-race",
            "prebuilt Soland unavailable",
        );
    };
    let founder_server = group.server(0);
    let peer_server = group.server(1);
    let alice_first =
        Member::provision(founder_server, &coauth, "dc-race-alice", ALICE_DEVICE).await?;
    let alice_second = Member::provision(
        founder_server,
        &coauth,
        "dc-race-alice",
        ALICE_SECOND_DEVICE,
    )
    .await?;
    ensure!(alice_first.account == alice_second.account);
    ensure!(alice_first.authorize_event_id != alice_second.authorize_event_id);
    let bob = Member::provision(peer_server, &coauth, "dc-race-bob", BOB_DEVICE).await?;
    let locator = issued_locator(&alice_first).await?;
    bob.client
        .request_contact_with_peer(
            arkret::contact_operations::ContactPeer::Human {
                account_id: alice_first.account.clone(),
            },
            ContactIntroductionEvidence::LocatorRef {
                principal_locator: locator,
            },
        )
        .await?;
    wait_contact_state(
        &alice_first,
        &bob.account,
        arkret::ContactState::PendingIncoming,
    )
    .await?;
    alice_first.client.accept_contact(&bob.client).await?;
    wait_contact_state(&bob, &alice_first.account, arkret::ContactState::Accepted).await?;
    assert_peer_endpoint(&alice_first, &bob, None).await?;
    assert_peer_endpoint(&alice_second, &bob, None).await?;
    let (round, _) = accepted_round(&alice_first, &bob.account).await?;
    let key_a = arkret_wire::UuidV7::new(fresh_uuid_v7().parse()?)?;
    let key_b = arkret_wire::UuidV7::new(fresh_uuid_v7().parse()?)?;
    let (realm_a, unit_a) =
        founding_unit_for(&alice_first, founder_server, &bob.account, &round, key_a)?;
    let (realm_b, unit_b) =
        founding_unit_for(&alice_second, founder_server, &bob.account, &round, key_b)?;
    ensure!(realm_a != realm_b);
    let (reply_a, reply_b) = tokio::join!(
        post_bytes_at(&alice_first.client, "/_arkret/self/events", &unit_a),
        post_bytes_at(&alice_second.client, "/_arkret/self/events", &unit_b),
    );
    let reply_a = reply_a?;
    let reply_b = reply_b?;
    let (winner, winner_unit, winner_realm, loser, loser_realm, winner_member) =
        if reply_a.0 == StatusCode::OK {
            (reply_a, &unit_a, &realm_a, reply_b, &realm_b, &alice_first)
        } else {
            (reply_b, &unit_b, &realm_b, reply_a, &realm_a, &alice_second)
        };
    ensure!(
        winner.0 == StatusCode::OK,
        "neither device won founding: first {} {}, second {} {}",
        winner.0,
        String::from_utf8_lossy(&winner.1),
        loser.0,
        String::from_utf8_lossy(&loser.1),
    );
    let founded: DirectConversationFoundingAcceptanceOutcome = serde_json::from_slice(&winner.1)?;
    founded.validate()?;
    ensure!(founded.status == AggregateAcceptanceStatus::Committed);
    let (loser_status, loser_body) = loser;
    ensure!(
        loser_status == StatusCode::CONFLICT
            && problem_type(&loser_body)? == "conflict"
            && serde_json::from_slice::<Value>(&loser_body)?["reason_code"]
                == "direct_conversation_slot_already_committed",
        "losing device returned {loser_status}: {}",
        String::from_utf8_lossy(&loser_body),
    );
    for (index, commit) in founded.commits.iter().enumerate() {
        ensure!(
            commit.stream_position == index as u64
                && commit.event_ref == winner_unit.events[index].event.event_id
                && commit.realm_id == *winner_realm
        );
    }
    let replayed: DirectConversationFoundingAcceptanceOutcome = serde_json::from_value(
        expect_json(
            winner_member
                .client
                .post("/_arkret/self/events")
                .json(winner_unit),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        replayed.status == AggregateAcceptanceStatus::Duplicate
            && serde_json::to_vec(&replayed.commits)? == serde_json::to_vec(&founded.commits)?,
        "exact retry changed the winner's Commit bytes"
    );
    let (_, same_key_other_unit) = founding_unit_for(
        winner_member,
        founder_server,
        &bob.account,
        &round,
        winner_unit.idempotency_key.clone(),
    )?;
    let (conflict_status, conflict_body) = post_bytes_at(
        &winner_member.client,
        "/_arkret/self/events",
        &same_key_other_unit,
    )
    .await?;
    ensure!(
        conflict_status == StatusCode::CONFLICT
            && problem_type(&conflict_body)? == "duplicate_conflict",
        "same key with different unit returned {conflict_status}: {}",
        String::from_utf8_lossy(&conflict_body)
    );
    assert_no_peer_founding_writes(&founder_database.connect_url, loser_realm).await?;
    assert_no_peer_founding_writes(&peer_database.connect_url, loser_realm).await?;
    wait_for_peer_founding_commits(&peer_database.connect_url, winner_realm, &founded.commits)
        .await?;
    Ok(())
}

/// A glare round has two request heads and no normal response Event. Its
/// selected founder must still admit the same four-Event founding unit.
pub async fn cross_station_glare_founds_direct_conversation() -> Result<()> {
    let Some(founder_database) = database("direct-conversation-glare-founding")? else {
        return Ok(());
    };
    let Some(peer_database) = database("direct-conversation-glare-founding")? else {
        return Ok(());
    };
    ensure!(founder_database.connect_url != peer_database.connect_url);
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let node_envs = [
        station_env(&founder_database.connect_url, &coauth),
        station_env(&peer_database.connect_url, &coauth),
    ];
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        "direct-conversation-glare-founding",
        &node_envs,
    )
    .await?
    else {
        return skip_or_fail(
            "direct-conversation-glare-founding",
            "prebuilt Soland unavailable",
        );
    };
    let first = Member::provision(group.server(0), &coauth, "dc-glare-a", ALICE_DEVICE).await?;
    let second = Member::provision(group.server(1), &coauth, "dc-glare-b", BOB_DEVICE).await?;
    let first_locator = issued_locator(&first).await?;
    let second_locator = issued_locator(&second).await?;
    let (first_request, second_request) = tokio::join!(
        first.client.request_contact_with_peer(
            arkret::contact_operations::ContactPeer::Human {
                account_id: second.account.clone(),
            },
            ContactIntroductionEvidence::LocatorRef {
                principal_locator: second_locator,
            },
        ),
        second.client.request_contact_with_peer(
            arkret::contact_operations::ContactPeer::Human {
                account_id: first.account.clone(),
            },
            ContactIntroductionEvidence::LocatorRef {
                principal_locator: first_locator,
            },
        )
    );
    let first_request = first_request?;
    let second_request = second_request?;
    ensure!(
        first_request.core.request_event_ref != second_request.core.request_event_ref,
        "glare requests share an Event ref"
    );
    wait_contact_state(&first, &second.account, arkret::ContactState::Accepted).await?;
    wait_contact_state(&second, &first.account, arkret::ContactState::Accepted).await?;
    assert_peer_endpoint(
        &first,
        &second,
        Some(&second_request.core.request_event_ref),
    )
    .await?;
    assert_peer_endpoint(&second, &first, Some(&first_request.core.request_event_ref)).await?;
    let first_resolution = first
        .client
        .sdk()
        .direct_conversation_resolve(&DirectConversationResolveRequestBody {
            peer: arkret::contact_operations::ContactPeer::Human {
                account_id: second.account.clone(),
            },
        })
        .await?;
    let second_resolution = second
        .client
        .sdk()
        .direct_conversation_resolve(&DirectConversationResolveRequestBody {
            peer: arkret::contact_operations::ContactPeer::Human {
                account_id: first.account.clone(),
            },
        })
        .await?;
    let (founder, peer, founder_server, peer_database, input) =
        match (&first_resolution, &second_resolution) {
            (
                DirectConversationResolveOutcome::CreationRequired {
                    next_founding_input,
                },
                DirectConversationResolveOutcome::AwaitingFounder { .. },
            ) => (
                &first,
                &second,
                group.server(0),
                &peer_database,
                next_founding_input,
            ),
            (
                DirectConversationResolveOutcome::AwaitingFounder { .. },
                DirectConversationResolveOutcome::CreationRequired {
                    next_founding_input,
                },
            ) => (
                &second,
                &first,
                group.server(1),
                &founder_database,
                next_founding_input,
            ),
            _ => bail!(
                "glare did not select one founder: {first_resolution:?}, {second_resolution:?}"
            ),
        };
    let DirectConversationFoundingAuthorityEvidence::Human {
        contact_round_evidence,
        ..
    } = &input.founding_authority_evidence
    else {
        bail!("glare founder did not receive Contact authority evidence");
    };
    let round = contact_round_evidence.contact_round_id.clone();
    ensure!(
        accepted_round_id(founder, &peer.account).await? == round
            && accepted_round_id(peer, &founder.account).await? == round,
        "glare founding input differs from accepted Contact round"
    );
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let genesis = direct_conversation_realm_create_payload(
        GenesisSalt::generate()?,
        founder_server.trust_domain().clone(),
        founder_server.service_id().clone(),
        at,
    )?;
    let create = authored_at(
        founder,
        arkret_wire::event_kind_str::REALM_CREATE,
        ScopeRef::RealmGenesis,
        serde_json::to_value(genesis)?,
        vec![SemanticRef::new(round.to_string(), CONTACT_ROUND_ROLE)],
        Cites::Nothing,
        at,
    )?;
    let realm_id = RealmId::from_event_id(&create.event_id);
    let scope = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let founder_join = authored_at(
        founder,
        arkret_wire::event_kind_str::MEMBER_STATE,
        scope.clone(),
        serde_json::to_value(direct_conversation_member_join_payload(
            realm_id.clone(),
            founder.account.clone(),
        ))?,
        Vec::new(),
        Cites::Nothing,
        at,
    )?;
    let peer_join = authored_at(
        founder,
        arkret_wire::event_kind_str::MEMBER_STATE,
        scope.clone(),
        serde_json::to_value(direct_conversation_peer_membership_bootstrap(
            realm_id.clone(),
            &founder.account,
            [founder.account.clone(), peer.account.clone()],
        )?)?,
        Vec::new(),
        Cites::Nothing,
        at,
    )?;
    let strand = authored_at(
        founder,
        arkret_wire::event_kind_str::STRAND_CREATE,
        scope,
        serde_json::to_value(direct_conversation_main_strand_create_payload(
            realm_id.clone(),
            founder.actor.clone(),
            at,
        ))?,
        Vec::new(),
        Cites::Nothing,
        at,
    )?;
    let unit = DirectConversationFoundingUnitSubmission {
        unit_kind: DirectConversationFoundingUnitKind::DirectConversationFounding,
        idempotency_key: arkret_wire::UuidV7::new(fresh_uuid_v7().parse()?)?,
        events: [create, founder_join, peer_join, strand].map(EventAdmissionSubmission::new),
    };
    unit.validate()?;
    let founded: DirectConversationFoundingAcceptanceOutcome = serde_json::from_value(
        expect_json(
            founder.client.post("/_arkret/self/events").json(&unit),
            StatusCode::OK,
        )
        .await?,
    )?;
    founded.validate()?;
    ensure!(founded.status == AggregateAcceptanceStatus::Committed);
    for (position, commit) in founded.commits.iter().enumerate() {
        ensure!(
            commit.stream_position == position as u64
                && commit.event_ref == unit.events[position].event.event_id
                && commit.realm_id == realm_id,
            "glare founding Commit {position} differs from its Event"
        );
    }
    wait_for_peer_founding_commits(&peer_database.connect_url, &realm_id, &founded.commits).await?;
    Ok(())
}

async fn accepted_round_id(holder: &Member, peer: &AccountId) -> Result<arkret_wire::Hash> {
    let row = holder
        .client
        .sdk()
        .contacts_list()
        .await?
        .contacts
        .into_iter()
        .find(|row| row.peer.contact_actor_id() == ActorId::account(peer.clone()))
        .context("glare Contact row is listed")?;
    ensure!(row.state == arkret::ContactState::Accepted);
    Ok(row
        .next_prepare_input
        .context("accepted glare round has no prepare input")?
        .contact_round_id)
}

async fn run(
    cross_station: bool,
    missing_contact_dependency: bool,
    observe_binding_snapshot: bool,
    observe_dm_receipt: bool,
    observe_case5_contact_terminal: bool,
    observer: Option<&dyn DirectClientObserver>,
) -> Result<()> {
    let Some(governance_database) = database(GROUP)? else {
        return Ok(());
    };
    let peer_database = if cross_station {
        database(GROUP)?
    } else {
        None
    };
    if let Some(peer_database) = &peer_database {
        ensure!(
            peer_database.connect_url != governance_database.connect_url,
            "the two Stations must have separate databases"
        );
    }
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let mut node_envs = vec![station_env(&governance_database.connect_url, &coauth)];
    if let Some(peer_database) = &peer_database {
        node_envs.push(station_env(&peer_database.connect_url, &coauth));
    }
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(GROUP, &node_envs).await?
    else {
        return skip_or_fail(GROUP, "prebuilt Soland unavailable");
    };
    let server = group.server(0);
    let peer_server = group.server(usize::from(cross_station));
    let alice = Member::provision(server, &coauth, "dc-alice", ALICE_DEVICE).await?;
    let bob = Member::provision(peer_server, &coauth, "dc-bob", BOB_DEVICE).await?;

    // Bob requests; Alice, the responder, accepts. Both directions grant
    // `direct_message`.
    if cross_station {
        let locator = issued_locator(&alice).await?;
        bob.client
            .request_contact_with_peer(
                arkret::contact_operations::ContactPeer::Human {
                    account_id: alice.account.clone(),
                },
                ContactIntroductionEvidence::LocatorRef {
                    principal_locator: locator,
                },
            )
            .await?;
        wait_contact_state(&alice, &bob.account, arkret::ContactState::PendingIncoming).await?;
    } else {
        bob.client.request_contact(&alice.client.actor).await?;
    }
    alice.client.accept_contact(&bob.client).await?;
    if cross_station {
        wait_contact_state(&bob, &alice.account, arkret::ContactState::Accepted).await?;
    }
    assert_peer_endpoint(&alice, &bob, None).await?;
    assert_peer_endpoint(&bob, &alice, None).await?;
    let (contact_round_id, heads) = accepted_round(&alice, &bob.account).await?;
    ensure!(
        accepted_round(&bob, &alice.account).await?.0 == contact_round_id,
        "both holders must list the same accepted round"
    );
    let founding_evidence = if missing_contact_dependency {
        let resolved = alice
            .client
            .sdk()
            .direct_conversation_resolve(&DirectConversationResolveRequestBody {
                peer: arkret::contact_operations::ContactPeer::Human {
                    account_id: bob.account.clone(),
                },
            })
            .await?;
        let DirectConversationResolveOutcome::CreationRequired {
            next_founding_input,
        } = resolved
        else {
            bail!("the normal-round responder did not receive founding material: {resolved:?}");
        };
        let peer_url = peer_database
            .as_ref()
            .expect("missing dependency needs two Stations")
            .connect_url
            .clone();
        let deleted = tokio::task::spawn_blocking(move || -> Result<u64> {
            let mut db = postgres::Client::connect(&peer_url, postgres::NoTls)?;
            Ok(db.execute("DELETE FROM contacts", &[])?)
        })
        .await??;
        ensure!(deleted > 0, "the peer had no Contact to remove");
        Some(next_founding_input.founding_authority_evidence)
    } else {
        None
    };

    // Section 5.5: Alice authors the four-Event unit and signs every Event.
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let genesis = direct_conversation_realm_create_payload(
        GenesisSalt::generate()?,
        server.trust_domain().clone(),
        server.service_id().clone(),
        at,
    )?;
    let create = authored_at(
        &alice,
        arkret_wire::event_kind_str::REALM_CREATE,
        ScopeRef::RealmGenesis,
        serde_json::to_value(genesis)?,
        vec![SemanticRef::new(
            contact_round_id.to_string(),
            CONTACT_ROUND_ROLE,
        )],
        Cites::Nothing,
        at,
    )?;
    let realm_id = RealmId::from_event_id(&create.event_id);
    let scope = ScopeRef::Realm {
        realm_id: realm_id.clone(),
    };
    let founder_join = authored_at(
        &alice,
        arkret_wire::event_kind_str::MEMBER_STATE,
        scope.clone(),
        serde_json::to_value(direct_conversation_member_join_payload(
            realm_id.clone(),
            alice.account.clone(),
        ))?,
        Vec::new(),
        Cites::Nothing,
        at,
    )?;
    let peer_join = authored_at(
        &alice,
        arkret_wire::event_kind_str::MEMBER_STATE,
        scope.clone(),
        serde_json::to_value(direct_conversation_peer_membership_bootstrap(
            realm_id.clone(),
            &alice.account,
            [alice.account.clone(), bob.account.clone()],
        )?)?,
        Vec::new(),
        Cites::Nothing,
        at,
    )?;
    let strand = authored_at(
        &alice,
        arkret_wire::event_kind_str::STRAND_CREATE,
        scope.clone(),
        serde_json::to_value(direct_conversation_main_strand_create_payload(
            realm_id.clone(),
            alice.actor.clone(),
            at,
        ))?,
        Vec::new(),
        Cites::Nothing,
        at,
    )?;
    let unit = DirectConversationFoundingUnitSubmission {
        unit_kind: DirectConversationFoundingUnitKind::DirectConversationFounding,
        idempotency_key: arkret_wire::UuidV7::new(fresh_uuid_v7().parse()?)?,
        events: [create, founder_join, peer_join, strand].map(EventAdmissionSubmission::new),
    };
    unit.validate()?;
    let plan = DirectConversationFoundingPlan::from_events(
        unit.events.each_ref().map(|submission| &submission.event),
    )?;
    ensure!(plan.realm_id == realm_id, "the unit derives its own Realm");
    let create_ref = unit.events[0].event.event_id.clone();
    let strand_id = plan.main_strand_id.clone();
    let founded: DirectConversationFoundingAcceptanceOutcome = serde_json::from_value(
        expect_json(
            alice.client.post("/_arkret/self/events").json(&unit),
            StatusCode::OK,
        )
        .await?,
    )
    .context("the founding response is the closed founding outcome")?;
    founded.validate()?;
    ensure!(
        founded.status == AggregateAcceptanceStatus::Committed,
        "the first founding unit must commit"
    );
    for (position, commit) in founded.commits.iter().enumerate() {
        ensure!(
            commit.stream_position == position as u64
                && commit.event_ref == unit.events[position].event.event_id
                && commit.realm_id == realm_id,
            "founding Commit {position} does not cover its unit Event"
        );
    }
    if let Some(founding_authority_evidence) = founding_evidence {
        let mut original_facts = Vec::with_capacity(4);
        for (submission, commit) in unit.events.iter().zip(&founded.commits) {
            original_facts.push(
                crate::scenarios::human_device_producer_live::original_human_signer_fact(
                    &alice.client,
                    &submission.event,
                    commit,
                )
                .await?,
            );
        }
        let request =
            PeerAuthoritySubmitRequest::RegisteredAtomicUnit(PeerRegisteredAtomicUnitRequest {
                branch: RegisteredAtomicUnitBranch::RegisteredAtomicUnit,
                unit: PeerRegisteredAtomicUnit::DirectConversationFounding(
                    DirectConversationFoundingFederationSubmission {
                        unit_kind: unit.unit_kind,
                        committed_events: std::array::from_fn(|index| CommittedEventSubmission {
                            event_submission: unit.events[index].clone(),
                            source_commit: founded.commits[index].clone(),
                            producer_signer_fact: Some(original_facts[index].clone()),
                            genesis_event_ref: None,
                            welcomes: None,
                        }),
                        founding_authority_evidence,
                    },
                ),
            });
        request.validate()?;
        let body = arkret_canonical::canonical_json_bytes(&request)?;
        let idempotency_key = format!("direct-conversation-founding:{}", plan.founding_unit_digest);
        for _ in 0..2 {
            let (status, answer) = peer_server
                .signed_peer_post_with_idempotency_key(
                    server,
                    "/_arkret/peer/events",
                    &body,
                    peer_server.service_id(),
                    Some(&idempotency_key),
                )
                .await?;
            ensure!(
                status == StatusCode::CONFLICT,
                "missing Contact dependency answered {status}: {}",
                String::from_utf8_lossy(&answer)
            );
            let problem: DirectConversationFoundingDependencyMissingProblem =
                serde_json::from_slice(&answer)?;
            problem.validate()?;
            ensure!(
                problem.details.missing_dependencies
                    == vec![
                        DirectConversationFoundingMissingDependency::ContactRoundEvidence {
                            source_event_ref: heads[0].clone(),
                        }
                    ],
                "missing dependency list does not name the source Contact request"
            );
        }
        assert_no_peer_founding_writes(
            &peer_database.expect("two Stations").connect_url,
            &realm_id,
        )
        .await?;
        return Ok(());
    }
    // Section 5.5: an exact retry replays the same four source Commits.
    let replayed: DirectConversationFoundingAcceptanceOutcome = serde_json::from_value(
        expect_json(
            alice.client.post("/_arkret/self/events").json(&unit),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        replayed.status == AggregateAcceptanceStatus::Duplicate
            && replayed.commits == founded.commits,
        "an exact founding retry must replay the committed unit"
    );
    if cross_station {
        wait_for_peer_founding_commits(
            &peer_database
                .as_ref()
                .expect("cross-station database")
                .connect_url,
            &realm_id,
            &founded.commits,
        )
        .await?;
        for index in [0, 2, 3] {
            let item = &unit.events[index];
            let replica = wait_for_committed(&bob.client, &item.event.event_id).await?;
            ensure!(
                replica.commit() == &founded.commits[index],
                "the peer Station did not materialize exact source Commit {index}"
            );
        }
    }

    // The accepted founding slot is the coordinate authority.  From this
    // point on the scenario deliberately consumes the public resolver result
    // instead of carrying the locally-derived founding plan as a second
    // coordinate source.
    let resolved = alice
        .client
        .sdk()
        .direct_conversation_resolve(&DirectConversationResolveRequestBody {
            peer: arkret::contact_operations::ContactPeer::Human {
                account_id: bob.account.clone(),
            },
        })
        .await
        .context("founding provisional resolver")?;
    let DirectConversationResolveOutcome::Provisional {
        coordinates,
        authorization_basis,
        group_state_ref,
        initial_exact_pair_group_state_ref,
        peer_mls_admission,
    } = resolved
    else {
        bail!("founding slot did not resolve as provisional: {resolved:?}");
    };
    ensure!(
        coordinates.realm_id == realm_id
            && coordinates.main_strand_id == strand_id
            && coordinates.binding_event_ref.is_none()
            && group_state_ref.is_none()
            && initial_exact_pair_group_state_ref.is_none()
            && peer_mls_admission
                == arkret::direct_conversation::DirectConversationPeerMlsAdmission::Missing,
        "resolver did not return the accepted founding coordinates"
    );
    authorization_basis.validate_shape()?;
    let mut founding_refs = heads.to_vec();
    founding_refs.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
    ensure!(
        authorization_basis
            == DirectConversationAuthorizationBasis::accepted_contact(founding_refs),
        "resolver changed the accepted founding basis"
    );
    let pair_key = coordinates.pair_key.clone();
    let realm_id = coordinates.realm_id;
    let strand_id = coordinates.main_strand_id;

    // Section 7.2: before the group Genesis there is no provisional phase.
    let early = authored(
        &alice,
        arkret_wire::event_kind_str::MESSAGE_CREATE,
        scope.clone(),
        crate::harness::message_create_text_payload_for_strand(strand_id.clone(), "too early")?,
        Vec::new(),
        Cites::Bootstrap(&create_ref),
    )?;
    expect_rejected(&alice, &early, PARTICIPANT_DENIED).await?;

    // Bob publishes a KeyPackage under his device key.
    let bob_identity = bob.mls_identity()?;
    let bob_package = bob_identity.key_package_record()?;
    let upload = bob_identity.signed_key_packages_upload_request(
        std::slice::from_ref(&bob_package),
        bob.method.as_str(),
        None,
    )?;
    let uploaded: KeyPackagesUploadOutcome = serde_json::from_value(
        expect_json(
            bob.client
                .post("/_arkret/self/keys/keypackages/upload")
                .json(&upload),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(uploaded.accepted == 1, "Bob's KeyPackage was not published");

    // The root's materialization mask admits the scope's one Genesis.
    let alice_identity = alice.mls_identity()?;
    let genesis_binding = MlsGovernanceBindingPayload::new(scope.clone(), None, 0, 0, 0)?;
    let mut alice_group =
        alice_identity.create_group_with_governance_binding(&scope, &genesis_binding)?;
    alice_group.install_local_creator_binding(
        alice.actor.clone(),
        Some(alice.authorize_event_id.clone()),
    )?;
    let bindings = alice_group.verified_leaf_bindings()?;
    let [creator] = bindings.as_slice() else {
        bail!("Direct Conversation Genesis requires one verified creator leaf");
    };
    ensure!(creator.leaf_index == 0 && creator.actor_id == alice.actor);
    let creator_leaf_authority = MlsGenesisCreatorLeafAuthority {
        leaf_signature_key_b64u: creator.signature_key.clone(),
        endpoint: arkret_wire::MlsWelcomeRecipientEndpoint::Device {
            device_id: alice.device.clone(),
        },
        authorization_event_ref: creator
            .device_authorize_event_id
            .clone()
            .context("creator leaf lacks DeviceAuthorize Event")?,
    };
    creator_leaf_authority.validate()?;
    let (group_info, tree) = alice_group.public_group_state_bytes()?;
    // The Direct Conversation declares no plaintext-visible service, so the
    // public MLS state goes to the creator's Station as content-addressed
    // Blobs outside any Realm (encryption-and-audit.md §5.1.2).
    let group_info_ref = upload_unbound_blob(&alice, &group_info).await?;
    let tree_ref = upload_unbound_blob(&alice, &tree).await?;
    let mls_genesis = authored(
        &alice,
        arkret_wire::event_kind_str::MLS_GENESIS,
        scope.clone(),
        json!({
            "cipher_suite": ACTIVE_SUITE,
            "group_info_ref": group_info_ref,
            "ratchet_tree_ref": tree_ref,
            "creator_leaf_authority": creator_leaf_authority,
            "governance_binding": genesis_binding,
            "created_at": arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
        }),
        Vec::new(),
        Cites::Nothing,
    )?;
    expect_committed(&submit(&alice, &mls_genesis).await?, &mls_genesis)?;
    let genesis_ref = mls_genesis.event_id.clone();

    // Provisional: only the founder sends, under the bootstrap source.
    let provisional = authored(
        &alice,
        arkret_wire::event_kind_str::MESSAGE_CREATE,
        scope.clone(),
        sealed_message(
            &mut alice_group,
            &scope,
            &strand_id,
            &genesis_ref,
            b"before Bob joins",
        )?,
        Vec::new(),
        Cites::Bootstrap(&create_ref),
    )?;
    expect_committed(&submit(&alice, &provisional).await?, &provisional)?;
    let bob_early = authored(
        &bob,
        arkret_wire::event_kind_str::MESSAGE_CREATE,
        scope.clone(),
        crate::harness::message_create_text_payload_for_strand(
            strand_id.clone(),
            "not Bob's to send",
        )?,
        Vec::new(),
        Cites::Bootstrap(&create_ref),
    )?;
    expect_rejected(&bob, &bob_early, PARTICIPANT_DENIED).await?;

    // Alice claims Bob's KeyPackage and Adds him with a Welcome.
    let group_id = scope.canonical_mls_group_id()?;
    let claim_request = claim_request_between(
        &alice,
        server,
        peer_server,
        &bob,
        &realm_id,
        group_id.as_str(),
        [0x41; 16],
        chrono::Duration::minutes(4),
    )?;
    let claim_deadline = Instant::now() + Duration::from_secs(120);
    let claim_bytes = loop {
        let (status, bytes) = post_claim(&alice.client, &claim_request).await?;
        if status == StatusCode::OK {
            break bytes;
        }
        ensure!(
            status == StatusCode::CONFLICT
                && problem_type(&bytes)? == "failed_precondition"
                && Instant::now() < claim_deadline,
            "Alice's claim of Bob's KeyPackage was not admitted: {status} {}",
            String::from_utf8_lossy(&bytes)
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    let claimed: KeyPackagesClaimOutcome = serde_json::from_slice(&claim_bytes)?;
    let claim = claimed
        .claims
        .first()
        .cloned()
        .context("the claim selected Bob's KeyPackage")?;
    let add_binding =
        MlsGovernanceBindingPayload::new(scope.clone(), Some(genesis_ref.clone()), 0, 1, 0)?;
    let add = alice_group.add_member_with_governance_binding(
        &claimed_keypackage_record(&claim, &bob)?,
        &add_binding,
    )?;
    let add_event = authored(
        &alice,
        arkret_wire::event_kind_str::MLS_COMMIT,
        scope.clone(),
        serde_json::to_value(MlsCommitPayload::new(
            genesis_ref.clone(),
            0,
            &add.commit,
            add_binding,
        )?)?,
        Vec::new(),
        Cites::Bootstrap(&create_ref),
    )?;
    let welcome = signed_welcome(&alice, &add_event, &bob, &add.welcome)?;
    let submission = SelfAuthoritySubmitRequest::MlsCommit(MlsCommitSubmission {
        commit_event: add_event.clone(),
        welcomes: vec![welcome.clone()],
        idempotency_key: arkret_wire::UuidV7::new(fresh_uuid_v7().parse()?)?,
    });
    submission.validate()?;
    let (status, outcome) = post_json(&alice.client, &submission).await?;
    ensure!(
        status == StatusCode::OK,
        "the Add Commit was not decided: {status} {outcome}"
    );
    expect_committed(&serde_json::from_value(outcome)?, &add_event)?;
    let add_ref = add_event.event_id.clone();
    let accepted_add = accepted_full_view(&alice.client, &add_ref).await?;
    let base = arkret_wire::MlsGroupCurrent {
        effective_scope: scope.clone(),
        genesis_event_ref: genesis_ref.clone(),
        cipher_suite: arkret_wire::NonEmptyString::new(
            "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
        )
        .unwrap(),
        current_mls_commit_event_ref: genesis_ref.clone(),
        epoch: 0,
        current_key_access_revision: 0,
        covered_key_access_revision: 0,
        public_tree_ref: arkret_wire::BlobRef::new(tree_ref.clone())?,
    };
    ensure!(
        alice_group.install_accepted_commit(&accepted_add, &base)? == 1,
        "Alice did not install her accepted Add Commit"
    );

    // Bob joins from his Welcome and acknowledges it.
    let (queued, ack_token) = if cross_station {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let page = recipient_welcomes(&bob.client).await?;
            if !page.0.is_empty() {
                break page;
            }
            ensure!(
                Instant::now() < deadline,
                "Bob's cross-Station Welcome was not delivered"
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    } else {
        recipient_welcomes(&bob.client).await?
    };
    ensure!(
        queued == vec![welcome.clone()],
        "Bob's recipient queue does not hold exactly the Add's Welcome: {queued:?}"
    );
    let mut bob_group =
        ArkretMlsGroup::join_from_verified_welcome_delivery(bob_identity, &welcome, &accepted_add)?;
    ensure!(bob_group.epoch() == 1, "Bob did not join at epoch 1");
    if observe_dm_receipt {
        crate::scenarios::message_mls_cross_station_live::install_bindings(
            &mut alice_group,
            &[&alice, &bob],
        )
        .await?;
        crate::scenarios::message_mls_cross_station_live::install_bindings(
            &mut bob_group,
            &[&alice, &bob],
        )
        .await?;
    }
    bob.client
        .post("/_arkret/self/device_messages/ack")
        .json(&DeviceMessagesAckRequestBody { ack_token })
        .send()
        .await?
        .error_for_status()?;

    let admission = alice
        .client
        .sdk()
        .direct_conversation_resolve(&DirectConversationResolveRequestBody {
            peer: arkret::contact_operations::ContactPeer::Human {
                account_id: bob.account.clone(),
            },
        })
        .await
        .context("occupied leaf pending resolver")?;
    ensure!(
        matches!(admission, DirectConversationResolveOutcome::Provisional {
        initial_exact_pair_group_state_ref: Some(ref initial),
        peer_mls_admission: arkret::direct_conversation::DirectConversationPeerMlsAdmission::Pending,
        ..
    } if initial == &add_ref),
        "resolver did not return the exact occupied leaf Pending cut"
    );

    // Before Bob consumes his claim the Realm is still provisional.
    let endorsement = |group_state_ref: &EventId| -> Result<Value> {
        let payload = DirectConversationBoundPayload {
            pair_key: pair_key.clone(),
            unordered_participant_ids: vec![alice.actor.clone(), bob.actor.clone()],
            realm_id: realm_id.clone(),
            main_strand_id: strand_id.clone(),
            founding_unit_digest: plan.founding_unit_digest.clone(),
            authorization_basis: authorization_basis.clone(),
            initial_exact_pair_group_state_ref: group_state_ref.clone(),
            created_at: arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()),
        };
        payload.validate_shape()?;
        Ok(serde_json::to_value(payload)?)
    };
    let unconsumed = authored(
        &bob,
        arkret_wire::event_kind_str::DIRECT_CONVERSATION_BOUND,
        scope.clone(),
        endorsement(&add_ref)?,
        Vec::new(),
        Cites::Bootstrap(&create_ref),
    )?;
    expect_rejected(&bob, &unconsumed, PARTICIPANT_DENIED).await?;

    let bob_signer = bob.mls_identity()?;
    let receipt = bob_signer.sign_recipient_mls_durable_receipt(
        arkret_models_crypto::RecipientMlsDurableReceipt {
            domain: arkret_wire::NonEmptyString::new(
                arkret_wire::DomainSeparationId::MLS_RECIPIENT_DURABLE_RECEIPT_V1.to_owned(),
            )
            .map_err(anyhow::Error::msg)?,
            claim_request_id: claim_request.claim_request_id.clone(),
            key_package_ref: arkret_wire::NonEmptyString::new(claim.keypackage_ref.clone())
                .map_err(anyhow::Error::msg)?,
            recipient: arkret_models_crypto::RecipientMlsDurableSigner::Device {
                recipient_account_id: bob.account.clone(),
                recipient_device_id: bob.device.clone(),
                device_verification_method: bob.method.clone(),
            },
            recipient_id: peer_server.service_id().clone(),
            realm_id: realm_id.clone(),
            mls_group_id: group_id.clone(),
            mls_epoch: 1,
            welcome_ref: welcome.welcome_id.clone(),
            welcome_digest: welcome.durable_receipt_digest()?,
            durable_at: chrono::Utc::now(),
            signature: arkret_models_crypto::KeyOperationSignature {
                kid: arkret_wire::NonEmptyString::new(bob.method.to_string())
                    .map_err(anyhow::Error::msg)?,
                signature_algorithm: None,
                sig: arkret_wire::Base64UrlString::new("AA".to_owned())
                    .map_err(anyhow::Error::msg)?,
            },
        },
    )?;
    let consume = bob_signer.signed_key_packages_consume_request(
        arkret_wire::KeypackageClaimId::new(claim.claim_id.clone())?,
        receipt,
    )?;
    let (status, consumed) = post_bytes_at(
        &bob.client,
        "/_arkret/self/keys/keypackages/consume",
        &consume,
    )
    .await?;
    ensure!(
        status == StatusCode::OK,
        "Bob's consume was not admitted: {status} {}",
        String::from_utf8_lossy(&consumed)
    );

    // Cross-Station consumption and the source Welcome outbox acknowledgement
    // converge independently. Require the same exact leaf's Durable cut rather
    // than assuming both relay transactions finish with Bob's HTTP response.
    let deadline = Instant::now() + Duration::from_secs(120);
    let admission = loop {
        let result = alice
            .client
            .sdk()
            .direct_conversation_resolve(&DirectConversationResolveRequestBody {
                peer: arkret::contact_operations::ContactPeer::Human {
                    account_id: bob.account.clone(),
                },
            })
            .await;
        match result {
            Ok(ref outcome) if !cross_station || matches!(outcome,
                DirectConversationResolveOutcome::Provisional {
                    peer_mls_admission: arkret::direct_conversation::DirectConversationPeerMlsAdmission::Durable,
                    ..
                }) => break result?,
            _ if cross_station && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            _ => break result?,
        }
    };
    ensure!(
        matches!(admission, DirectConversationResolveOutcome::Provisional {
        initial_exact_pair_group_state_ref: Some(ref initial),
        peer_mls_admission: arkret::direct_conversation::DirectConversationPeerMlsAdmission::Durable,
        ..
    } if initial == &add_ref),
        "resolver did not return the exact occupied leaf Durable cut"
    );

    // Completion: only an exact endorsement. One naming another group state
    // fails binding integrity, and the provisional Message no longer passes.
    let wrong_state = authored(
        &bob,
        arkret_wire::event_kind_str::DIRECT_CONVERSATION_BOUND,
        scope.clone(),
        endorsement(&genesis_ref)?,
        Vec::new(),
        Cites::Bootstrap(&create_ref),
    )?;
    expect_rejected(&bob, &wrong_state, "direct_conversation_binding_invalid").await?;
    let late_provisional = authored(
        &alice,
        arkret_wire::event_kind_str::MESSAGE_CREATE,
        scope.clone(),
        sealed_message(
            &mut alice_group,
            &scope,
            &strand_id,
            &add_ref,
            b"provisional is over",
        )?,
        Vec::new(),
        Cites::Bootstrap(&create_ref),
    )?;
    expect_rejected(&alice, &late_provisional, PARTICIPANT_DENIED).await?;
    let bob_endorsement = authored(
        &bob,
        arkret_wire::event_kind_str::DIRECT_CONVERSATION_BOUND,
        scope.clone(),
        endorsement(&add_ref)?,
        Vec::new(),
        Cites::Bootstrap(&create_ref),
    )?;
    expect_committed(&submit(&bob, &bob_endorsement).await?, &bob_endorsement)?;
    let alice_endorsement = authored(
        &alice,
        arkret_wire::event_kind_str::DIRECT_CONVERSATION_BOUND,
        scope.clone(),
        endorsement(&add_ref)?,
        Vec::new(),
        Cites::Bootstrap(&create_ref),
    )?;
    expect_committed(
        &submit(&alice, &alice_endorsement).await?,
        &alice_endorsement,
    )?;

    let resolved = alice
        .client
        .sdk()
        .direct_conversation_resolve(&DirectConversationResolveRequestBody {
            peer: arkret::contact_operations::ContactPeer::Human {
                account_id: bob.account.clone(),
            },
        })
        .await?;
    let DirectConversationResolveOutcome::Found {
        coordinates,
        group_state_ref,
        send_blockers,
    } = resolved
    else {
        bail!("completed binding did not resolve as found: {resolved:?}");
    };
    ensure!(
        coordinates.pair_key == pair_key
            && coordinates.realm_id == realm_id
            && coordinates.main_strand_id == strand_id
            && coordinates
                .binding_event_ref
                .as_ref()
                .is_some_and(|event_ref| {
                    event_ref == &alice_endorsement.event_id
                        || event_ref == &bob_endorsement.event_id
                })
            && group_state_ref == add_ref
            && send_blockers.is_empty(),
        "resolver did not return the accepted bound coordinates"
    );

    // Found: both participants send under the binding and read each other.
    if observe_dm_receipt {
        observer
            .context("client observation requires an explicit observer")?
            .block_direct_peer(&alice, &bob)
            .await?;
    }
    let bob_plaintext = b"hello, Alice".to_vec();
    let bob_message = authored(
        &bob,
        arkret_wire::event_kind_str::MESSAGE_CREATE,
        scope.clone(),
        sealed_message(&mut bob_group, &scope, &strand_id, &add_ref, &bob_plaintext)?,
        Vec::new(),
        Cites::Participant(&bob_endorsement.event_id),
    )?;
    let blocked_dm_sender = if observe_dm_receipt {
        let observation = crate::conformance::shared_submission::observed_authored_shared_message(
            &bob.client,
            bob_message.clone(),
        )
        .await
        .context("blocked DM paired Message HTTP submission")?;
        expect_committed(&observation.outcome, &bob_message)?;
        Some(observation)
    } else {
        expect_committed(&submit(&bob, &bob_message).await?, &bob_message)?;
        None
    };
    if observe_dm_receipt {
        observer
            .context("client observation requires an explicit observer")?
            .observe_dm_retained_receipt(
                &bob,
                &alice,
                &realm_id,
                strand_id.as_str(),
                &add_ref,
                &bob_group,
                &alice_group,
                &bob_message.event_id,
                &provisional.event_id,
            )
            .await?;
        let unblocked_dm_message = authored(
            &bob,
            arkret_wire::event_kind_str::MESSAGE_CREATE,
            scope.clone(),
            sealed_message(
                &mut bob_group,
                &scope,
                &strand_id,
                &add_ref,
                b"after Alice unblocks",
            )?,
            Vec::new(),
            Cites::Participant(&bob_endorsement.event_id),
        )?;
        let unblocked_dm_sender =
            crate::conformance::shared_submission::observed_authored_shared_message(
                &bob.client,
                unblocked_dm_message.clone(),
            )
            .await
            .context("unblocked DM paired Message HTTP submission")?;
        expect_committed(&unblocked_dm_sender.outcome, &unblocked_dm_message)?;
        crate::conformance::shared_submission::compare_shared_sender_observations(
            blocked_dm_sender
                .as_ref()
                .context("DM paired transport omitted the blocked submission")?,
            &unblocked_dm_sender,
        )?;
        if observe_case5_contact_terminal {
            // A second private block is paired with a real Contact terminal
            // command. Removing the private entry cannot recreate a Message
            // that the durable Contact authority never accepted.
            observer
                .context("client observation requires an explicit observer")?
                .block_direct_peer(&alice, &bob)
                .await?;
            let contact = alice
                .client
                .sdk()
                .contacts_list()
                .await?
                .contacts
                .into_iter()
                .find(|row| row.peer.contact_actor_id() == bob.actor)
                .context("case5 accepted Contact row is absent")?;
            ensure!(contact.state == arkret::ContactState::Accepted);
            let next = contact
                .next_prepare_input
                .context("case5 accepted Contact lacks its next signed head")?;
            let tombstoned = crate::scenarios::api_contracts_auth::contact_command(
                &alice.client,
                "/_arkret/self/contacts/tombstone",
                json!({
                    "peer": contact.peer,
                    "contact_round_id": next.contact_round_id,
                    "version": next.version,
                    "predecessor_event_ref": next.predecessor_event_ref,
                    "block_peer": true,
                }),
                arkret_wire::event_kind_str::CONTACT_TOMBSTONE,
            )
            .await?;
            ensure!(
                matches!(
                    &tombstoned,
                    arkret::contact_operations::ContactOperationOutcome::Accepted {
                        outcome: arkret::contact_operations::ContactAcceptedOutcome::Tombstone { .. }
                    }
                ),
                "case5 Contact tombstone did not commit: {tombstoned:?}"
            );
            wait_contact_state(&alice, &bob.account, arkret::ContactState::Tombstoned).await?;
            wait_contact_state(&bob, &alice.account, arkret::ContactState::Tombstoned).await?;
            let refused = authored(
                &bob,
                arkret_wire::event_kind_str::MESSAGE_CREATE,
                scope.clone(),
                sealed_message(
                    &mut bob_group,
                    &scope,
                    &strand_id,
                    &add_ref,
                    b"Contact terminal refused this request",
                )?,
                Vec::new(),
                Cites::Participant(&bob_endorsement.event_id),
            )?;
            expect_rejected(&bob, &refused, PARTICIPANT_DENIED).await?;
            observer
                .context("client observation requires an explicit observer")?
                .unblock_direct_peer(&alice)
                .await?;
            ensure!(
                alice
                    .client
                    .sdk()
                    .committed_event_get(&refused.event_id)
                    .await
                    .is_err(),
                "unblock back-filled a Message refused by the Contact terminal"
            );
            wait_contact_state(&alice, &bob.account, arkret::ContactState::Tombstoned).await?;
            eprintln!(
                "blocklist case5 DM retained Event restored after unblock; Contact tombstone kept refused Event {} absent after the next private unblock",
                refused.event_id
            );
        }
        return Ok(());
    }
    ensure!(
        open_committed_message(&alice, &mut alice_group, &scope, &bob_message.event_id).await?
            == bob_plaintext,
        "Alice did not decrypt Bob's committed Message"
    );
    let alice_message = authored(
        &alice,
        arkret_wire::event_kind_str::MESSAGE_CREATE,
        scope.clone(),
        sealed_message(
            &mut alice_group,
            &scope,
            &strand_id,
            &add_ref,
            b"hello, Bob",
        )?,
        Vec::new(),
        Cites::Participant(&alice_endorsement.event_id),
    )?;
    expect_committed(&submit(&alice, &alice_message).await?, &alice_message)?;
    ensure!(
        open_committed_message(&bob, &mut bob_group, &scope, &alice_message.event_id).await?
            == b"hello, Bob",
        "Bob did not decrypt Alice's committed Message"
    );

    // Once found the bootstrap source carries nothing but endorsements.
    let bootstrap_after = authored(
        &alice,
        arkret_wire::event_kind_str::MESSAGE_CREATE,
        scope.clone(),
        sealed_message(
            &mut alice_group,
            &scope,
            &strand_id,
            &add_ref,
            b"stale source",
        )?,
        Vec::new(),
        Cites::Bootstrap(&create_ref),
    )?;
    expect_rejected(&alice, &bootstrap_after, PARTICIPANT_DENIED).await?;

    // Registered precedence on double matches: a third-party invite is also
    // an invite, and a destroy by the technical root also relies on it.
    let (_, third) = standard_client(server, &coauth, "dc-third", THIRD_DEVICE).await?;
    let invite = authored(
        &alice,
        arkret_wire::event_kind_str::INVITE_CREATE,
        scope.clone(),
        json!({
            "invitee_account_id": third,
            "introduction_evidence_digest": format!("sha256:{}", "4".repeat(64)),
            "expires_at": "2099-01-01T00:00:00.000Z",
        }),
        Vec::new(),
        Cites::Nothing,
    )?;
    expect_rejected(
        &alice,
        &invite,
        "direct_conversation_third_party_member_forbidden",
    )
    .await?;
    let pair_invite = authored(
        &alice,
        arkret_wire::event_kind_str::INVITE_CREATE,
        scope.clone(),
        json!({
            "invitee_account_id": bob.account,
            "introduction_evidence_digest": format!("sha256:{}", "4".repeat(64)),
            "expires_at": "2099-01-01T00:00:00.000Z",
        }),
        Vec::new(),
        Cites::Nothing,
    )?;
    expect_rejected(&alice, &pair_invite, "direct_conversation_invite_forbidden").await?;
    // Banning the peer would lean on the technical root's owner aggregate,
    // whose mask is empty once found.
    let ban = authored(
        &alice,
        arkret_wire::event_kind_str::MEMBER_STATE,
        scope.clone(),
        membership_payload(
            realm_id.as_str(),
            bob.account.clone(),
            MembershipPayloadState::Ban,
            "direct conversation root mask",
        )?,
        Vec::new(),
        Cites::Nothing,
    )?;
    expect_rejected(&alice, &ban, "direct_conversation_root_mask_violation").await?;
    let destroy = authored(
        &alice,
        arkret_wire::event_kind_str::REALM_DESTROY,
        scope.clone(),
        json!({ "realm_id": realm_id }),
        Vec::new(),
        Cites::Nothing,
    )?;
    expect_rejected(&alice, &destroy, "direct_conversation_terminal_forbidden").await?;
    if observe_binding_snapshot {
        for participant in [&alice, &bob] {
            let snapshot = crate::scenarios::strand_watch_live::signed_snapshot(
                &participant.client,
                &realm_id,
            )
            .await?;
            let binding = snapshot
                .current_state_entries
                .iter()
                .find_map(|entry| match entry {
                    arkret_wire::TypedCurrentResult::Value {
                        selector:
                            arkret_wire::CurrentSelector::DirectConversationBinding {
                                pair_key: subject,
                            },
                        value,
                        source_stream_ref,
                        ..
                    } if subject == &pair_key => Some((value, source_stream_ref)),
                    _ => None,
                })
                .context("signed participant Snapshot omitted its exact DM binding current")?;
            ensure!(
                binding.1
                    == &arkret_wire::CommitStreamRef::Realm {
                        realm_id: realm_id.clone(),
                    },
                "DM binding current has another source stream"
            );
            let value: arkret_models_collaboration::events_payloads::direct_conversation::DirectConversationBindingCurrentValue =
                serde_json::from_value(binding.0.clone())?;
            ensure!(
                value.endorsements.len() == 2
                    && value.endorsed_by(&alice_endorsement.event_id)
                    && value.endorsed_by(&bob_endorsement.event_id),
                "signed participant Snapshot did not contain both accepted binding endorsements"
            );
        }
        let outsider = Member::provision(
            server,
            &coauth,
            "dc-binding-outsider",
            "ak:device:01904100-0000-7000-8000-000000002405",
        )
        .await?;
        ensure!(
            outsider
                .client
                .sdk()
                .realm_state_snapshot_head(&realm_id)
                .await
                .is_err(),
            "a nonparticipant obtained the Direct Conversation Snapshot"
        );
    }
    drop(coauth);
    Ok(())
}
