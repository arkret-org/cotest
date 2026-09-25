//! Two-Station live checks against committed Event replication and current
//! signer resolution. The wire authority is Event + RealmCommit throughout.
//! Every self Event is authored over a standard DPoP SessionGrant.

use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use arkret_models_collaboration::authority_commit::{
    CommittedEventSubmission, CommittedReplicationBranch, PeerAuthoritySubmitOutcome,
    PeerAuthoritySubmitRequest, PeerCommittedReplicationOutcomeRecord,
    PeerCommittedReplicationRequest,
};
use arkret_models_collaboration::governance::membership_invite::{
    MembershipPayload, MembershipPayloadState,
};
use arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent;
use arkret_models_identity::{
    CurrentSignerKeyQuerySender, SignerKeyQueryResult, SignerKeyQuerySelector,
    SignerKeysQueryRequestBody,
};
use arkret_wire::{
    AccountId, ActorId, CommittedEventView, Did, DidCoreId, DidUrl, Event,
    EventAdmissionSubmission, EventId, EventKind, RealmCommit, RealmId, RequestId,
};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{ArkretServer, TestActorClient, TestServerGroup, message_create_text_payload};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, ensure_commit_signed_by, ensure_same_commit,
    membership_payload, prepare_join, standard_client, station_env, submit_and_expect_commit,
};
use crate::scenarios::identity_test_support::{
    HARNESS_ACCOUNT_AUTHORITY_ORIGIN, HARNESS_INTERNAL_AUTHORITY_SECRET, actor_did_for_service_did,
};

const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002002";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002003";

/// The committed-replication failure matrix between a governance Station X
/// and a member Station Y (`federation.md` §3, §4.1.1).
///
/// 1. Bob on Y joins Alice's public Realm on X by his own forwarded join; X replicates the
///    committed join, which opens Y's held Realm stream.
/// 2. Route miss: a Message committed while Y is down survives an X restart and reaches Y exactly
///    once Y is back, with the source Commit.
/// 3. An exact replay of that replication body is `duplicate`, twice.
/// 4. The same body naming another destination, a Commit paired with another Event, and a body a
///    Station that does not govern the Realm signs as its source are refused with nothing stored.
/// 5. With Y down, a Message owed to Y through Bob's basis is followed by Bob's removal: the intent
///    is cancelled and Y never receives it; a later Commit whose predecessor Y does not hold is
///    `dependency_missing`.
/// 6. A plaintext Message of a Realm that does not list Y as a plaintext Station is never
///    replicated to Y, although Bob is joined there.
pub async fn run_fanout_route_miss_live() -> Result<()> {
    const GROUP: &str = "fanout-route-miss";
    let Some(governance_database) = database(GROUP)? else {
        return Ok(());
    };
    let Some(member_database) = database(GROUP)? else {
        return Ok(());
    };
    ensure!(
        governance_database.connect_url != member_database.connect_url,
        "the governance and member Stations must use separate databases"
    );
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(mut group) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[
            station_env(&governance_database.connect_url, &coauth),
            station_env(&member_database.connect_url, &coauth),
        ],
    )
    .await?
    else {
        return skip_or_fail(GROUP, "prebuilt Soland unavailable");
    };
    let (alice, alice_account) =
        standard_client(group.server(0), &coauth, "fanout-alice", ALICE_DEVICE).await?;
    let (bob, bob_account) =
        standard_client(group.server(1), &coauth, "fanout-bob", BOB_DEVICE).await?;
    let governance_id = group.server(0).service_id().clone();

    // (1) Bob's join opens Y's held Realm stream.
    let realm = create_realm_with_join_rule(
        &alice,
        "Fanout route miss",
        "public",
        &[group.server(0), group.server(1)],
    )
    .await?;
    let strand = alice.default_strand_id(&realm)?;
    let (join, join_commit) = join_from_member_station(
        &bob,
        &bob_account,
        &realm,
        group.server(0),
        "ak:request:019b0000-0000-7000-8000-000000002501",
    )
    .await?;

    // (2) Route miss across an X restart.
    group.server_mut(1).stop_external_process().await?;
    let missed = alice_message(&alice, &alice_account, &realm, &strand, "while Y is down").await?;
    group.server_mut(0).restart_external_process().await?;
    group.server_mut(1).start_external_process().await?;
    ensure_same_commit(
        &missed.1,
        &wait_held(&bob, &missed.0.event_id, ROUTE_MISS_WINDOW).await?,
    )?;

    // (3) Byte-exact replay of the source body.
    let replay = replication_body(&missed.0, &missed.1)?;
    for _ in 0..2 {
        let outcomes = replicate(group.server(1), group.server(0), &replay).await?;
        ensure!(
            matches!(
                outcomes.as_slice(),
                [PeerCommittedReplicationOutcomeRecord::Duplicate {}]
            ),
            "an exact replay of a stored replication is not duplicate: {outcomes:?}"
        );
    }
    ensure_same_commit(
        &missed.1,
        &wait_held(&bob, &missed.0.event_id, HELD_WINDOW).await?,
    )?;

    // (4) Wrong destination, Event/Commit mismatch, wrong source.
    let (status, body) = group
        .server(1)
        .signed_peer_post(group.server(0), PEER_EVENTS, &replay, &governance_id)
        .await?;
    ensure!(
        !status.is_success(),
        "a body naming another destination was accepted: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let mismatched = serde_json::to_vec(&json!({
        "branch": "committed_replication",
        "replications": [{
            "event_submission": {"event": join},
            "source_commit": missed.1,
        }],
    }))?;
    ensure_not_stored(group.server(1), group.server(0), &mismatched).await?;
    ensure_same_commit(
        &join_commit,
        &wait_held(&bob, &join.event_id, HELD_WINDOW).await?,
    )?;
    ensure_same_commit(
        &missed.1,
        &wait_held(&bob, &missed.0.event_id, HELD_WINDOW).await?,
    )?;

    // (5) Membership loss while Y is down.
    group.server_mut(1).stop_external_process().await?;
    let owed = alice_message(&alice, &alice_account, &realm, &strand, "owed to Y").await?;
    let removal = alice
        .author_event(
            &realm,
            EventKind::MemberState.as_str(),
            membership_payload(
                &realm,
                bob_account.clone(),
                MembershipPayloadState::Leave,
                "removed while Y is down",
            )?,
        )
        .await?;
    submit_and_expect_commit(&alice, &alice_account, ALICE_DEVICE, &removal).await?;
    let after = alice_message(&alice, &alice_account, &realm, &strand, "after Bob left").await?;
    group.server_mut(1).start_external_process().await?;
    ensure_not_held(&bob, &owed.0.event_id, NOT_HELD_WINDOW).await?;
    ensure_not_held(&bob, &after.0.event_id, Duration::ZERO).await?;
    let after_body = replication_body(&after.0, &after.1)?;
    // A Station that does not govern the Realm cannot be its source.
    ensure_not_stored(group.server(1), group.server(1), &after_body).await?;
    let outcomes = replicate(group.server(1), group.server(0), &after_body).await?;
    ensure!(
        matches!(
            outcomes.as_slice(),
            [PeerCommittedReplicationOutcomeRecord::Rejected { reason_code }]
                if reason_code == "dependency_missing"
        ),
        "a Commit after an unheld predecessor is not dependency_missing: {outcomes:?}"
    );
    ensure_not_held(&bob, &after.0.event_id, Duration::ZERO).await?;

    // (6) A restricted plaintext Message is not replicated.
    let restricted = create_realm_with_join_rule(
        &alice,
        "Fanout plaintext restricted",
        "public",
        &[group.server(0)],
    )
    .await?;
    let restricted_strand = alice.default_strand_id(&restricted)?;
    join_from_member_station(
        &bob,
        &bob_account,
        &restricted,
        group.server(0),
        "ak:request:019b0000-0000-7000-8000-000000002502",
    )
    .await?;
    let plaintext = alice_message(
        &alice,
        &alice_account,
        &restricted,
        &restricted_strand,
        "held by X only",
    )
    .await?;
    ensure_same_commit(
        &plaintext.1,
        &wait_held(&alice, &plaintext.0.event_id, HELD_WINDOW).await?,
    )?;
    ensure_not_held(&bob, &plaintext.0.event_id, NOT_HELD_WINDOW).await?;
    drop(coauth);
    Ok(())
}

const PEER_EVENTS: &str = "/_arkret/peer/events";
const ROUTE_MISS_WINDOW: Duration = Duration::from_secs(360);
const HELD_WINDOW: Duration = Duration::from_secs(120);
const NOT_HELD_WINDOW: Duration = Duration::from_secs(15);

/// Bob prepares on Y, signs his own `join` and submits it to Y, which forwards
/// it to X; X's committed join then reaches Y by committed replication.
async fn join_from_member_station(
    member: &TestActorClient,
    member_account: &AccountId,
    realm: &str,
    governance: &ArkretServer,
    request_id: &str,
) -> Result<(Event, RealmCommit)> {
    prepare_join(
        member,
        realm,
        governance,
        request_id,
        RealmJoinIntent::MemberJoin,
    )
    .await?;
    let join = member
        .author_event(
            realm,
            EventKind::MemberState.as_str(),
            membership_payload(
                realm,
                member_account.clone(),
                MembershipPayloadState::Join,
                "fanout member",
            )?,
        )
        .await?;
    let commit = submit_and_expect_commit(member, member_account, BOB_DEVICE, &join).await?;
    ensure_commit_signed_by(&commit, governance)?;
    ensure_same_commit(
        &commit,
        &wait_held(member, &join.event_id, HELD_WINDOW).await?,
    )?;
    Ok((join, commit))
}

async fn alice_message(
    alice: &TestActorClient,
    alice_account: &AccountId,
    realm: &str,
    strand: &str,
    body: &str,
) -> Result<(Event, RealmCommit)> {
    let event = alice
        .author_event(
            realm,
            EventKind::MessageCreate.as_str(),
            message_create_text_payload(strand, body)?,
        )
        .await?;
    let commit = submit_and_expect_commit(alice, alice_account, ALICE_DEVICE, &event).await?;
    Ok((event, commit))
}

/// The exact `committed_replication` body X's outbox sends for one Event.
fn replication_body(event: &Event, commit: &RealmCommit) -> Result<Vec<u8>> {
    let request =
        PeerAuthoritySubmitRequest::CommittedReplication(PeerCommittedReplicationRequest {
            branch: CommittedReplicationBranch::CommittedReplication,
            replications: vec![CommittedEventSubmission {
                event_submission: EventAdmissionSubmission::new(event.clone()),
                source_commit: commit.clone(),
            }],
        });
    request.validate()?;
    Ok(arkret_canonical::canonical_json_bytes(&request)?)
}

/// Send `body` to `receiver` signed by `source` and return its same-order
/// replication outcomes.
async fn replicate(
    receiver: &ArkretServer,
    source: &ArkretServer,
    body: &[u8],
) -> Result<Vec<PeerCommittedReplicationOutcomeRecord>> {
    let (status, answer) = receiver
        .signed_peer_post(source, PEER_EVENTS, body, receiver.service_id())
        .await?;
    ensure!(
        status == StatusCode::OK,
        "committed_replication answered {status}: {}",
        String::from_utf8_lossy(&answer)
    );
    match serde_json::from_slice::<PeerAuthoritySubmitOutcome>(&answer)? {
        PeerAuthoritySubmitOutcome::CommittedReplication(value) => Ok(value.replication_outcomes),
        other => bail!("committed_replication answered another branch: {other:?}"),
    }
}

/// The receiver refuses `body` as a whole or rejects its item: nothing is
/// stored.
async fn ensure_not_stored(
    receiver: &ArkretServer,
    source: &ArkretServer,
    body: &[u8],
) -> Result<()> {
    let (status, answer) = receiver
        .signed_peer_post(source, PEER_EVENTS, body, receiver.service_id())
        .await?;
    if !status.is_success() {
        return Ok(());
    }
    let PeerAuthoritySubmitOutcome::CommittedReplication(value) =
        serde_json::from_slice::<PeerAuthoritySubmitOutcome>(&answer)?
    else {
        bail!("committed_replication answered another branch");
    };
    ensure!(
        value.replication_outcomes.iter().all(|record| matches!(
            record,
            PeerCommittedReplicationOutcomeRecord::Rejected { .. }
        )),
        "the receiver stored a refused replication: {:?}",
        value.replication_outcomes
    );
    Ok(())
}

async fn wait_held(
    client: &TestActorClient,
    event_id: &EventId,
    window: Duration,
) -> Result<CommittedEventView> {
    let deadline = Instant::now() + window;
    loop {
        if let Ok(view) = client.sdk().committed_event_get(event_id).await {
            view.validate_shape()?;
            ensure!(view.commit().event_ref == *event_id);
            return Ok(view);
        }
        if Instant::now() >= deadline {
            bail!("committed Event {event_id} did not reach the Station");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn ensure_not_held(
    client: &TestActorClient,
    event_id: &EventId,
    window: Duration,
) -> Result<()> {
    let deadline = Instant::now() + window;
    loop {
        ensure!(
            client.sdk().committed_event_get(event_id).await.is_err(),
            "the member Station holds {event_id}, which it is not owed"
        );
        if Instant::now() >= deadline {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// `ak.self.signer_keys.read.resolve.v1`: a recipient without Alice's signer
/// cache asks its own Station for the `current_admission` signing key bound to
/// the accepted cross-Station membership history.
pub async fn run_signer_keys_query_live() -> Result<()> {
    let source_ephemeral = match std::env::var("COTEST_SIGNER_KEYS_SOURCE_DATABASE_URL") {
        Ok(_) => None,
        Err(_) => crate::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres()?,
    };
    let target_ephemeral = match std::env::var("COTEST_SIGNER_KEYS_TARGET_DATABASE_URL") {
        Ok(_) => None,
        Err(_) => crate::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres()?,
    };
    let source_database_url = std::env::var("COTEST_SIGNER_KEYS_SOURCE_DATABASE_URL")
        .ok()
        .or_else(|| {
            source_ephemeral
                .as_ref()
                .map(|database| database.connect_url.clone())
        });
    let target_database_url = std::env::var("COTEST_SIGNER_KEYS_TARGET_DATABASE_URL")
        .ok()
        .or_else(|| {
            target_ephemeral
                .as_ref()
                .map(|database| database.connect_url.clone())
        });
    let (Some(source_database_url), Some(target_database_url)) =
        (source_database_url, target_database_url)
    else {
        ensure!(
            std::env::var("COTEST_REQUIRE_LIVE").as_deref() != Ok("1"),
            "required live signer-keys query needs two PostgreSQL databases"
        );
        eprintln!("skipping signer-keys query live E2E: databases unavailable");
        return Ok(());
    };
    ensure!(source_database_url != target_database_url);
    let node_envs = vec![
        federation_node_env(source_database_url),
        federation_node_env(target_database_url),
    ];
    let Some(mut group) =
        TestServerGroup::try_multi_external_with_node_envs("signer-keys-query", &node_envs).await?
    else {
        ensure!(
            std::env::var("COTEST_REQUIRE_LIVE").as_deref() != Ok("1"),
            "required live signer-keys query needs a prebuilt Soland"
        );
        eprintln!("skipping signer-keys query live E2E: prebuilt Soland unavailable");
        return Ok(());
    };
    let alice_did = actor_did_for_service_did(group.server(0).service_did(), "signer-keys-alice")?;
    let bob_did = actor_did_for_service_did(group.server(1).service_did(), "signer-keys-bob")?;
    let alice = group
        .server(0)
        .register_client(&alice_did, "signer-keys-alice", ALICE_DEVICE)
        .await?;
    let bob = group
        .server(1)
        .register_client(&bob_did, "signer-keys-bob", BOB_DEVICE)
        .await?;
    let alice_principal = alice.principal.as_ref().context("source PCR bootstrap")?;
    let bob_principal = bob.principal.as_ref().context("recipient PCR bootstrap")?;
    let alice_account = AccountId::new(
        alice_principal.core_id.clone(),
        group.server(0).service_id().clone(),
    );
    let bob_account = AccountId::new(
        bob_principal.core_id.clone(),
        group.server(1).service_id().clone(),
    );
    let realm_id = create_realm(&alice, "Signer keys query").await?;
    let bob_join = member_payload(
        &realm_id,
        &bob_did,
        group.server(1).service_id().clone(),
        MembershipPayloadState::Join,
    )?;
    let bob_join_id = submit_and_settle_member_transition(&alice, &realm_id, bob_join).await?;
    group.server_mut(0).restart_external_process().await?;
    let bob = group.server(1).demo_client(&bob_did, BOB_DEVICE).await?;
    wait_for_committed(&bob, &bob_join_id).await?;

    let verification_method = DidUrl::new(format!(
        "{}#{}",
        alice_principal.did, alice_principal.device_id
    ))
    .map_err(anyhow::Error::msg)?;
    let request = SignerKeysQueryRequestBody {
        request_id: RequestId::new("ak:request:019b0000-0000-7000-8000-000000000101")?,
        realm_id: RealmId::new(realm_id)?,
        recipient_account_id: bob_account.clone(),
        queries: vec![SignerKeyQuerySelector::CurrentAdmission {
            sender: CurrentSignerKeyQuerySender::AccountDevice {
                actor: ActorId::account(alice_account),
                device_id: alice_principal.device_id.clone(),
                verification_method,
            },
        }],
    };
    request.validate()?;
    let outcome = bob.sdk().signer_keys_query(&request).await?;
    outcome.validate_for_request(&request)?;
    let [SignerKeyQueryResult::CurrentResolved { selector, key }] = outcome.results.as_slice()
    else {
        bail!("recipient Station did not resolve the current admitted sender");
    };
    ensure!(selector == &request.queries[0]);
    key.validate()?;

    let mut wrong_station = request.clone();
    wrong_station.request_id = RequestId::new("ak:request:019b0000-0000-7000-8000-000000000102")?;
    let SignerKeyQuerySelector::CurrentAdmission {
        sender: CurrentSignerKeyQuerySender::AccountDevice { actor, .. },
    } = &mut wrong_station.queries[0]
    else {
        bail!("current signer request changed selector kind");
    };
    let ActorId::Account { account_id } = actor else {
        bail!("current signer selector lost account Actor");
    };
    account_id.station_id = group.server(1).service_id().clone();
    let wrong = bob.sdk().signer_keys_query(&wrong_station).await?;
    wrong.validate_for_request(&wrong_station)?;
    ensure!(matches!(
        wrong.results.as_slice(),
        [SignerKeyQueryResult::Unavailable { .. }]
    ));
    let mut misbound = outcome;
    let SignerKeyQueryResult::CurrentResolved {
        selector:
            SignerKeyQuerySelector::CurrentAdmission {
                sender: CurrentSignerKeyQuerySender::AccountDevice { actor, .. },
            },
        ..
    } = &mut misbound.results[0]
    else {
        bail!("current signer outcome changed shape");
    };
    *actor = ActorId::account(bob_account);
    ensure!(misbound.validate_for_request(&request).is_err());
    Ok(())
}

fn federation_node_env(database_url: String) -> Vec<(String, String)> {
    vec![
        ("DATABASE_URL".to_owned(), database_url),
        ("SOLAND_FEDERATION_OUTBOUND".to_owned(), "1".to_owned()),
        (
            "SOLAND_ACCOUNT_AUTHORITY_URL".to_owned(),
            HARNESS_ACCOUNT_AUTHORITY_ORIGIN.to_owned(),
        ),
    ]
}

async fn create_realm(client: &TestActorClient, title: &str) -> Result<String> {
    let bootstrap = client
        .create_realm_bootstrap_with(json!({
            "title": title,
            "summary": title,
            "public": false,
            "plaintext_visible_services": [client.service_id()]
        }))
        .await?;
    let realm_id = bootstrap["realm_id"]
        .as_str()
        .context("ordinary Realm bootstrap omitted realm_id")?;
    RealmId::new(realm_id.to_owned())?;
    Ok(realm_id.to_owned())
}

fn member_payload(
    realm_id: &str,
    member: &str,
    member_service: DidCoreId,
    membership: MembershipPayloadState,
) -> Result<Value> {
    let realm_id = RealmId::new(realm_id.to_owned())?;
    let member = arkret_wire::project_did_to_core_id(&Did::new(member.to_owned())?)?;
    let member = ActorId::account(AccountId::new(member, member_service));
    let payload = if membership == MembershipPayloadState::Join {
        MembershipPayload::join(realm_id, member, "fanout route-miss fixture").to_value()?
    } else {
        MembershipPayload::transition(membership, member, "fanout authority ended")
            .with_realm_id(realm_id)
            .to_value()?
    };
    arkret_schema_conformance::event_payload_validator_catalog()?
        .validate_payload(EventKind::MemberState.as_str(), &payload)?;
    Ok(payload)
}

async fn submit_and_settle_member_transition(
    client: &TestActorClient,
    realm_id: &str,
    payload: Value,
) -> Result<EventId> {
    let response = client
        .submit_event(realm_id, EventKind::MemberState.as_str(), payload)
        .await?;
    let event_id = crate::harness::submitted_event_id(&response)?;
    client
        .await_event_seal_coverage(realm_id, &event_id)
        .await?;
    Ok(event_id)
}

async fn wait_for_committed(
    client: &TestActorClient,
    event_id: &EventId,
) -> Result<CommittedEventView> {
    let deadline = Instant::now() + Duration::from_secs(360);
    loop {
        if let Ok(view) = client.sdk().committed_event_get(event_id).await {
            view.validate_shape()?;
            ensure!(view.commit().event_ref == *event_id);
            return Ok(view);
        }
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "committed Event {event_id} did not reach the Station"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
