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
use arkret_models_collaboration::governance::membership_invite::MembershipPayloadState;
use arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent;
use arkret_models_identity::{
    CurrentSignerKeyQuerySender, SignerKeyQueryResult, SignerKeyQuerySelector,
    SignerKeysQueryRequestBody,
};
use arkret_wire::{
    AccountId, ActorId, CommittedEventView, DidUrl, Event, EventAdmissionSubmission, EventId,
    EventKind, ReadableFloorReason, RealmCommit, RealmId, RequestId,
};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    ArkretServer, TestActorClient, TestServerGroup, message_create_text_payload,
    test_service_signing_key,
};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::coauth_bootstrap::EphemeralPg;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::cross_station_invite_join::{wait_for_member_scan, wait_for_titled_row};
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, ensure_commit_signed_by, ensure_same_commit,
    membership_payload, prepare_join, standard_client, station_env, submit_and_expect_commit,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use crate::scenarios::protocol_payloads::account_summary::{account_frames, listed_row};

const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002002";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002003";
const CAROL_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002004";

struct CurrentOriginFixture {
    alice: TestActorClient,
    bob: TestActorClient,
    alice_account: AccountId,
    realm: String,
    group: TestServerGroup,
    _coauth: MockCoauthIntrospectionServer,
    _governance_database: EphemeralPg,
    _member_database: EphemeralPg,
}

async fn current_origin_fixture(name: &str) -> Result<Option<CurrentOriginFixture>> {
    let Some(governance_database) = database(name)? else {
        return Ok(None);
    };
    let Some(member_database) = database(name)? else {
        return Ok(None);
    };
    ensure!(
        governance_database.connect_url != member_database.connect_url,
        "the governance and member Stations must use separate databases"
    );
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        name,
        &[
            station_env(&governance_database.connect_url, &coauth),
            station_env(&member_database.connect_url, &coauth),
        ],
    )
    .await?
    else {
        skip_or_fail(name, "prebuilt Soland unavailable")?;
        return Ok(None);
    };
    let (alice, alice_account) =
        standard_client(group.server(0), &coauth, "origin-alice", ALICE_DEVICE).await?;
    let (bob, bob_account) =
        standard_client(group.server(1), &coauth, "origin-bob", BOB_DEVICE).await?;
    let realm = create_realm_with_join_rule(
        &alice,
        "Federation current origin replay",
        "public",
        &[group.server(0), group.server(1)],
    )
    .await?;
    let (_, join_commit) = join_from_member_station(
        &bob,
        &bob_account,
        &realm,
        group.server(0),
        "ak:request:019b0000-0000-7000-8000-000000002504",
    )
    .await?;
    let page = wait_for_member_scan(&bob, &RealmId::new(realm.clone())?).await?;
    let floor = page
        .readable_floor
        .as_ref()
        .context("the member's held Realm stream has no readable floor")?;
    ensure!(
        floor.oldest_position == join_commit.stream_position
            && floor.floor_commit_id == join_commit.commit_id
            && floor.floor_reason == ReadableFloorReason::MembershipJoin,
        "the member's held Realm stream is not anchored at its joined Commit: {floor:?}"
    );
    ensure!(
        page.committed_events
            .first()
            .is_some_and(|item| item.commit() == &join_commit),
        "the member's held Realm stream does not begin with its join Commit"
    );
    wait_for_titled_row(&bob, &realm, "Federation current origin replay").await?;
    Ok(Some(CurrentOriginFixture {
        alice,
        bob,
        alice_account,
        realm,
        group,
        _coauth: coauth,
        _governance_database: governance_database,
        _member_database: member_database,
    }))
}

/// A focused production replay check with two independently signed Stations,
/// separate PostgreSQL stores, and a held Event/RealmCommit. It ends before
/// the route-miss and membership-loss lifecycle exercised below.
pub async fn run_federation_current_origin_replay_live() -> Result<()> {
    const GROUP: &str = "federation-current-origin-replay";
    let Some(fixture) = current_origin_fixture(GROUP).await? else {
        return Ok(());
    };
    let strand = fixture.alice.default_strand_id(&fixture.realm)?;
    let (event, commit) = alice_message(
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &strand,
        "held Commit for current-origin replay",
    )
    .await?;
    ensure_same_commit(
        &commit,
        &wait_held(&fixture.bob, &event.event_id, HELD_WINDOW).await?,
    )?;
    let replay = replication_body(&fixture.alice, &event, &commit).await?;
    assert_held_commit_current_origin(
        &fixture.group,
        &fixture.bob,
        &replay,
        &event.event_id,
        &commit,
    )
    .await?;
    Ok(())
}

/// Replay one byte-identical RFC 9421 peer request after the source Station
/// publishes a verified WebVH successor that replaces its assertion key.
/// The old accepted Commit stays held, but its old transport signature is no
/// longer current authority for either a cached outcome or another write.
pub async fn run_federation_revoked_service_key_replay_live() -> Result<()> {
    const GROUP: &str = "federation-revoked-service-key-replay";
    let Some(mut fixture) = current_origin_fixture(GROUP).await? else {
        return Ok(());
    };
    let strand = fixture.alice.default_strand_id(&fixture.realm)?;
    let (event, commit) = alice_message(
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &strand,
        "held Commit before service key rotation",
    )
    .await?;
    ensure_same_commit(
        &commit,
        &wait_held(&fixture.bob, &event.event_id, HELD_WINDOW).await?,
    )?;
    let body = replication_body(&fixture.alice, &event, &commit).await?;
    let request = fixture
        .group
        .server(1)
        .signed_peer_post_request_with_idempotency_key(
            fixture.group.server(0),
            PEER_EVENTS,
            &body,
            fixture.group.server(1).service_id(),
            Some("federation-key-revoke-replay"),
        )?;
    ensure!(
        request.body().and_then(reqwest::Body::as_bytes) == Some(body.as_slice()),
        "the signed replay request does not contain the exact replication body"
    );
    let signed_at = Instant::now();
    let baseline = fixture
        .group
        .server(1)
        .http()
        .execute(
            request
                .try_clone()
                .context("clone the original signed request")?,
        )
        .await?;
    ensure!(baseline.status() == StatusCode::OK);
    let baseline: PeerAuthoritySubmitOutcome = baseline.json().await?;
    ensure!(
        matches!(
            &baseline,
            PeerAuthoritySubmitOutcome::CommittedReplication(value)
                if matches!(
                    value.replication_outcomes.as_slice(),
                    [PeerCommittedReplicationOutcomeRecord::Duplicate {}]
                )
        ),
        "the original request did not return its accepted duplicate outcome"
    );
    let held_before_same_basis_replay = held_commit_ids(&fixture.bob, &fixture.realm).await?;
    let same_basis_response = fixture
        .group
        .server(1)
        .http()
        .execute(
            request
                .try_clone()
                .context("clone the accepted signed request for same-basis replay")?,
        )
        .await?;
    ensure!(same_basis_response.status() == StatusCode::OK);
    let same_basis: PeerAuthoritySubmitOutcome = same_basis_response.json().await?;
    ensure!(
        same_basis == baseline,
        "an unchanged key and authorization basis did not replay the original per-item outcome: first {baseline:?}, replay {same_basis:?}"
    );
    ensure!(
        held_commit_ids(&fixture.bob, &fixture.realm).await? == held_before_same_basis_replay,
        "same-basis idempotency replay changed the recipient's committed Realm stream"
    );
    let old_key = current_federation_key(fixture.group.server(0)).await?;
    let (new_seed, _) = test_service_signing_key("federation-revoked-key-successor");
    fixture
        .group
        .server_mut(0)
        .restart_external_process_with_notary_signing_key(&new_seed)
        .await?;
    let new_key = current_federation_key(fixture.group.server(0)).await?;
    ensure!(
        old_key != new_key,
        "WebVH successor retained the old assertion key"
    );
    // The recipient resolves current peer assertion state on every request.
    // Prove it accepts a newly signed source Commit before replaying the old
    // request; restarting the recipient would add an unrelated hydration cut.
    let (fresh_event, fresh_commit) = alice_message(
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &strand,
        "fresh Commit under successor service key",
    )
    .await?;
    let successor_outcomes = replicate(
        fixture.group.server(1),
        fixture.group.server(0),
        &replication_body(&fixture.alice, &fresh_event, &fresh_commit).await?,
    )
    .await?;
    ensure!(
        matches!(
            successor_outcomes.as_slice(),
            [PeerCommittedReplicationOutcomeRecord::Stored {}
                | PeerCommittedReplicationOutcomeRecord::Duplicate {}]
        ),
        "the successor service key did not authenticate and store a current peer submit: {successor_outcomes:?}"
    );
    ensure_same_commit(
        &fresh_commit,
        &wait_held(&fixture.bob, &fresh_event.event_id, HELD_WINDOW).await?,
    )?;
    let successor_replay = replicate(
        fixture.group.server(1),
        fixture.group.server(0),
        &replication_body(&fixture.alice, &fresh_event, &fresh_commit).await?,
    )
    .await?;
    ensure!(
        matches!(
            successor_replay.as_slice(),
            [PeerCommittedReplicationOutcomeRecord::Duplicate {}]
        ),
        "the successor service key did not authenticate a held Commit replay: {successor_replay:?}"
    );
    let before = held_commit_ids(&fixture.bob, &fixture.realm).await?;
    ensure!(
        before.contains(&commit.commit_id) && before.contains(&fresh_commit.commit_id),
        "the recipient lacks the old and successor Commits"
    );
    for _ in 0..2 {
        ensure!(
            signed_at.elapsed() < Duration::from_secs(240),
            "the original signed request is near expiry; revocation evidence is inconclusive"
        );
        let response = fixture
            .group
            .server(1)
            .http()
            .execute(
                request
                    .try_clone()
                    .context("clone the byte-identical revoked request")?,
            )
            .await?;
        let status = response.status();
        let bytes = response.bytes().await?;
        let problem: arkret_wire::Problem = serde_json::from_slice(&bytes)
            .with_context(|| format!("revoked peer request returned {status}"))?;
        ensure!(
            !status.is_success()
                && problem.error_code() == Some(arkret_wire::ErrorCode::SignatureInvalid),
            "revoked key replay was not rejected by current transport auth: {status} {problem:?}"
        );
        ensure!(
            held_commit_ids(&fixture.bob, &fixture.realm).await? == before,
            "a revoked-key replay changed the recipient's committed Realm stream"
        );
    }
    Ok(())
}

async fn current_federation_key(server: &ArkretServer) -> Result<String> {
    let history = server
        .http()
        .get(server.url("/webvh/service/did.jsonl"))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let head: Value = serde_json::from_str(
        history
            .lines()
            .filter(|line| !line.trim().is_empty())
            .last()
            .context("service WebVH history is empty")?,
    )?;
    let method_id = format!("{}#federation-fanout-key", server.service_did());
    head["state"]["verificationMethod"]
        .as_array()
        .context("service WebVH head has no verification methods")?
        .iter()
        .find(|method| method["id"].as_str() == Some(method_id.as_str()))
        .and_then(|method| method["publicKeyMultibase"].as_str())
        .map(ToOwned::to_owned)
        .context("service WebVH head lacks the federation assertion method")
}

async fn held_commit_ids(
    member: &TestActorClient,
    realm: &str,
) -> Result<Vec<arkret_wire::RealmCommitId>> {
    let realm_id = RealmId::new(realm.to_owned())?;
    let page = member
        .sdk()
        .scan_commit_stream_to_head(
            realm_id.clone(),
            arkret_wire::CommitStreamRef::Realm { realm_id },
            None,
            200,
        )
        .await?;
    Ok(page
        .committed_events
        .iter()
        .map(|view| view.commit().commit_id.clone())
        .collect())
}

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
/// 5. With Y down, a Message owed to Y through Bob's basis is followed by Bob's removal: the
///    Message's intent is cancelled, but the removal itself is owed to Y (decision 0116 §0355). Y
///    pulls the cancelled predecessor through the peer scan, stores the removal and withdraws Bob's
///    realm list row; exact replays of both are `duplicate`, and a later Commit is refused because
///    Y no longer hosts a joined member.
/// 5b. Bob joins again: his own join re-opens Y's held stream, which Y re-anchors (decision 0122);
///    Bob's scan on Y restarts at the rejoin, his realm list carries the title again, and the
///    Message between his removal and his rejoin is never held.
/// 6. A plaintext Message of a Realm that does not list Y as a plaintext Station is never
///    replicated to Y, although Bob is joined there; the same Message validly signed by X and sent
///    to Y is refused by Y's own re-verification against its anchored typed current (§0356). A
///    later Commit owed to Y still arrives and Bob reads it directly on Y without a restart: Y
///    keeps the withheld Message as a continuity-only chain node and reads it only as the withheld
///    branch (§0357).
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
    let replay = replication_body(&alice, &missed.0, &missed.1).await?;
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

    assert_held_commit_current_origin(&group, &bob, &replay, &missed.0.event_id, &missed.1).await?;

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
    let removal_commit =
        submit_and_expect_commit(&alice, &alice_account, ALICE_DEVICE, &removal).await?;
    let after = alice_message(&alice, &alice_account, &realm, &strand, "after Bob left").await?;
    group.server_mut(1).start_external_process().await?;
    // Y learns Bob's removal only after it filled the cancelled Message in
    // front of it; the replays prove it holds both exactly.
    wait_not_listed(&bob, &realm, ROUTE_MISS_WINDOW).await?;
    for (event, commit) in [(&owed.0, &owed.1), (&removal, &removal_commit)] {
        let outcomes = replicate(
            group.server(1),
            group.server(0),
            &replication_body(&alice, event, commit).await?,
        )
        .await?;
        ensure!(
            matches!(
                outcomes.as_slice(),
                [PeerCommittedReplicationOutcomeRecord::Duplicate {}]
            ),
            "Y does not hold {} after Bob's removal: {outcomes:?}",
            event.event_id
        );
    }
    let after_body = replication_body(&alice, &after.0, &after.1).await?;
    // A Station that does not govern the Realm cannot be its source.
    ensure_not_stored(group.server(1), group.server(1), &after_body).await?;
    let outcomes = replicate(group.server(1), group.server(0), &after_body).await?;
    ensure!(
        matches!(
            outcomes.as_slice(),
            [PeerCommittedReplicationOutcomeRecord::Rejected { reason_code }]
                if reason_code == "capability_denied"
        ),
        "a Commit after Bob's removal was not refused for want of a hosted member: {outcomes:?}"
    );

    // (5b) Bob joins again (decision 0122): his own join re-opens Y's held
    //      stream, which Y re-anchors on a new snapshot; his scan on Y starts
    //      at the rejoin, his realm list carries the title again, and the
    //      position between his removal and his rejoin is never held.
    let (_, rejoin_commit) = join_from_member_station(
        &bob,
        &bob_account,
        &realm,
        group.server(0),
        "ak:request:019b0000-0000-7000-8000-000000002503",
    )
    .await?;
    let page = wait_for_member_scan(&bob, &RealmId::new(realm.clone())?).await?;
    let floor = page
        .readable_floor
        .as_ref()
        .context("Bob's scan on Y names no readable floor after the rejoin")?;
    ensure!(
        floor.oldest_position == rejoin_commit.stream_position
            && floor.floor_commit_id == rejoin_commit.commit_id
            && floor.floor_reason == ReadableFloorReason::MembershipJoin,
        "Bob's scan on Y does not restart at his rejoin: {floor:?}"
    );
    ensure!(
        page.committed_events
            .first()
            .is_some_and(|item| item.commit() == &rejoin_commit),
        "Bob's scan on Y does not begin with his rejoin"
    );
    wait_for_titled_row(&bob, &realm, "Fanout route miss").await?;
    ensure_not_stored(group.server(1), group.server(0), &after_body).await?;

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
    wait_for_member_scan(&bob, &RealmId::new(restricted.clone())?).await?;
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
    let forged = replicate(
        group.server(1),
        group.server(0),
        &replication_body(&alice, &plaintext.0, &plaintext.1).await?,
    )
    .await?;
    ensure!(
        matches!(
            forged.as_slice(),
            [PeerCommittedReplicationOutcomeRecord::Rejected { reason_code }]
                if reason_code == "capability_denied"
        ),
        "Y stored a plaintext Message its Realm does not let it hold: {forged:?}"
    );
    ensure_not_held(&bob, &plaintext.0.event_id, Duration::ZERO).await?;
    // Carol joins on X; her join is owed to Y after the withheld Message.
    let (carol, carol_account) =
        standard_client(group.server(0), &coauth, "fanout-carol", CAROL_DEVICE).await?;
    let carol_join = carol
        .author_event(
            &restricted,
            EventKind::MemberState.as_str(),
            membership_payload(
                &restricted,
                carol_account.clone(),
                MembershipPayloadState::Join,
                "local member after the plaintext",
            )?,
        )
        .await?;
    let carol_commit =
        submit_and_expect_commit(&carol, &carol_account, CAROL_DEVICE, &carol_join).await?;
    // Bob reads Carol's join on Y directly from Y's typed current; the
    // withheld Message stays its exact Commit alone.
    ensure_same_commit(
        &carol_commit,
        &wait_held(&bob, &carol_join.event_id, ROUTE_MISS_WINDOW).await?,
    )?;
    match bob.sdk().committed_event_get(&plaintext.0.event_id).await? {
        CommittedEventView::Withheld(view) => ensure!(
            view.commit == plaintext.1,
            "Y's chain node is not the Message's exact Commit"
        ),
        CommittedEventView::Full(_) => bail!("Y holds the restricted plaintext Message in full"),
    }
    drop(coauth);
    Ok(())
}

/// Poll `client`'s realm list on its Station until it no longer names
/// `realm_id`.
async fn wait_not_listed(client: &TestActorClient, realm_id: &str, window: Duration) -> Result<()> {
    let deadline = Instant::now() + window;
    loop {
        if listed_row(&account_frames(client, None).await?, realm_id).is_err() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("the member Station still lists {realm_id} after the removal");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

const PEER_EVENTS: &str = "/_arkret/peer/events";
const ROUTE_MISS_WINDOW: Duration = Duration::from_secs(360);
const HELD_WINDOW: Duration = Duration::from_secs(120);

async fn assert_held_commit_current_origin(
    group: &TestServerGroup,
    member: &TestActorClient,
    replay: &[u8],
    event_id: &EventId,
    source_commit: &RealmCommit,
) -> Result<()> {
    // A matching idempotency key and an already held Commit cannot turn an
    // authenticated but non-origin Station into the current Realm authority.
    let replay_key = "federation-current-origin-replay";
    let (status, answer) = group
        .server(1)
        .signed_peer_post_with_idempotency_key(
            group.server(0),
            PEER_EVENTS,
            replay,
            group.server(1).service_id(),
            Some(replay_key),
        )
        .await?;
    ensure!(status == StatusCode::OK, "origin replay failed: {status}");
    let authorized = serde_json::from_slice::<PeerAuthoritySubmitOutcome>(&answer)?;
    ensure!(
        matches!(
            authorized,
            PeerAuthoritySubmitOutcome::CommittedReplication(value)
                if matches!(
                    value.replication_outcomes.as_slice(),
                    [PeerCommittedReplicationOutcomeRecord::Duplicate {}]
                )
        ),
        "the active origin did not replay the held Commit"
    );
    let (status, answer) = group
        .server(1)
        .signed_peer_post_with_idempotency_key(
            group.server(1),
            PEER_EVENTS,
            replay,
            group.server(1).service_id(),
            Some(replay_key),
        )
        .await?;
    ensure!(
        status == StatusCode::OK,
        "wrong-origin replay failed: {status}"
    );
    let denied = serde_json::from_slice::<PeerAuthoritySubmitOutcome>(&answer)?;
    ensure!(
        matches!(
            &denied,
            PeerAuthoritySubmitOutcome::CommittedReplication(value)
                if matches!(
                    value.replication_outcomes.as_slice(),
                    [PeerCommittedReplicationOutcomeRecord::Rejected { reason_code }]
                        if reason_code == "capability_denied"
                )
        ),
        "a cached Commit was replayed by a non-origin Station: {denied:?}"
    );
    ensure_same_commit(
        source_commit,
        &wait_held(member, event_id, HELD_WINDOW).await?,
    )?;
    Ok(())
}

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
async fn replication_body(
    client: &TestActorClient,
    event: &Event,
    commit: &RealmCommit,
) -> Result<Vec<u8>> {
    let fact = crate::scenarios::human_device_producer_live::original_human_signer_fact(
        client, event, commit,
    )
    .await?;
    let request =
        PeerAuthoritySubmitRequest::CommittedReplication(PeerCommittedReplicationRequest {
            branch: CommittedReplicationBranch::CommittedReplication,
            replications: vec![CommittedEventSubmission {
                event_submission: EventAdmissionSubmission::new(event.clone()),
                source_commit: commit.clone(),
                producer_signer_fact: Some(fact.into()),
                genesis_event_ref: None,
                welcomes: None,
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
    let Some(mut fixture) = current_origin_fixture("signer-keys-query").await? else {
        return Ok(());
    };
    fixture
        .group
        .server_mut(0)
        .restart_external_process()
        .await?;
    let alice_principal = fixture
        .alice
        .principal
        .as_ref()
        .context("source PCR bootstrap")?;
    let bob = &fixture.bob;
    let bob_principal = bob.principal.as_ref().context("recipient PCR bootstrap")?;
    let bob_account = AccountId::new(
        bob_principal.core_id.clone(),
        fixture.group.server(1).service_id().clone(),
    );
    let alice_account = fixture.alice_account;
    let realm_id = fixture.realm;

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
    let [SignerKeyQueryResult::CurrentDeviceResolved { selector, key }] =
        outcome.results.as_slice()
    else {
        bail!("recipient Station did not resolve the current admitted sender");
    };
    ensure!(selector == &request.queries[0]);
    key.validate()?;
    ensure!(
        key.public_key_b64u.as_str()
            == arkret_canonical::base64url_encode(
                &alice_principal
                    .device_signing_key
                    .verifying_key()
                    .to_bytes()
            ),
        "the resolved current key is not the sender device key"
    );

    let serialized = serde_json::to_value(&outcome)?;
    ensure!(
        serialized["results"][0]["key"]
            .as_object()
            .context("key object")?
            .len()
            == 1
    );
    for wrong in ["method", "device"] {
        let mut changed = request.clone();
        let SignerKeyQuerySelector::CurrentAdmission {
            sender:
                CurrentSignerKeyQuerySender::AccountDevice {
                    device_id,
                    verification_method,
                    ..
                },
        } = &mut changed.queries[0]
        else {
            bail!("current device selector");
        };
        if wrong == "method" {
            *verification_method =
                DidUrl::new("did:web:wrong.example#ak:device:01904100-0000-7000-8000-000000000001")
                    .map_err(anyhow::Error::msg)?;
        } else {
            *device_id =
                arkret_wire::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")?;
        }
        let unavailable = bob.sdk().signer_keys_query(&changed).await?;
        unavailable.validate_for_request(&changed)?;
        ensure!(matches!(
            unavailable.results.as_slice(),
            [SignerKeyQueryResult::Unavailable { .. }]
        ));
    }
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
    account_id.station_id = fixture.group.server(1).service_id().clone();
    let wrong = bob.sdk().signer_keys_query(&wrong_station).await?;
    wrong.validate_for_request(&wrong_station)?;
    ensure!(matches!(
        wrong.results.as_slice(),
        [SignerKeyQueryResult::Unavailable { .. }]
    ));
    let mut misbound = outcome;
    let SignerKeyQueryResult::CurrentDeviceResolved {
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
