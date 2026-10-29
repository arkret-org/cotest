//! S3 — a same-Station account joins a Realm by accepting its directed
//! Invite (`zh/models/governance-objects.md` §5.3, `zh/models/common-fields.md`
//! §4.5) on the single Event/RealmCommit carrier.
//!
//! Against a live Coland with real PostgreSQL:
//!
//! 1. Alice creates a Realm and invites Bob, who lives on the same Station; Bob's Account realm
//!    list does not name the Realm yet;
//! 2. Bob's `ak.invite.accept` is committed on the Realm stream and his Account realm list now
//!    lists the Realm as a joined member; a second accept of the terminal Invite is
//!    `invite_already_terminal` and appends no Commit;
//! 3. joining grants no writing: Bob's Message is `capability_denied` until Alice grants him
//!    `ak.message.create`, after which it is committed and Alice's stream scan returns it in full;
//! 4. Bob's own scan starts at his accepting Commit (`membership_join`, decision 0108 §1045); his
//!    `/head` Snapshot names the same floor and carries the Invite, grant and roster rows; his
//!    Account window above that floor names an independently issued exact `stream_history` Snapshot
//!    as its committed prefix (`zh/sync/client-sync.md` §5.2); a current `/head` Snapshot cannot
//!    replace that historical basis;
//! 5. Bob leaves by his own `ak.member.state`; his Account realm list removes the Realm and his
//!    scan is refused.

use anyhow::{Context, Result, anyhow, ensure};
use arkret_models_collaboration::governance::membership_invite::{
    InviteAcceptPayload, InvitePreviousState, MembershipPayload, MembershipPayloadState,
};
use arkret_wire::{
    AccountId, ActorId, AuthoritySubmitResponseBody, CommitStreamRef, DidCoreId, InviteId, RealmId,
};
use chrono::{Duration as ChronoDuration, Utc};
use reqwest::StatusCode;
use serde_json::Value;

use crate::harness::{
    CanonicalJsonBody, TestActorClient, actor_core_id, expect_json, invite_create_payload,
    submitted_event_id,
};
use crate::scenarios::invite_create_and_dispatch::InviteStation;
use crate::scenarios::protocol_payloads::account_summary::{
    account_frames, last_cursor, listed_row,
};

const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-0000000000a5";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-0000000000b5";

fn account_of(client: &TestActorClient) -> Result<AccountId> {
    Ok(AccountId::new(
        DidCoreId::new(actor_core_id(&client.actor)?)?,
        DidCoreId::new(client.service_id().to_owned())?,
    ))
}

/// Submit `kind` as `actor` and return the raw status and body.
async fn submit(
    actor: &TestActorClient,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Result<(StatusCode, Value)> {
    let event = actor.author_event(realm_id, kind, payload).await?;
    let response = actor
        .post("/_arkret/self/events")
        .canonical_json(&crate::publication::initial_submission(event, "")?)?
        .send()
        .await?;
    let status = response.status();
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    Ok((status, body))
}

fn committed(body: &Value) -> Result<arkret_wire::RealmCommit> {
    match serde_json::from_value::<AuthoritySubmitResponseBody>(body.clone())
        .with_context(|| format!("submit outcome is not closed SDK wire data: {body}"))?
    {
        AuthoritySubmitResponseBody::Accepted { commit, .. } => Ok(commit),
        AuthoritySubmitResponseBody::Rejected { reason_code, .. } => {
            Err(anyhow!("submit was rejected: {reason_code}"))
        }
    }
}

/// The Realm stream head position Alice can scan.
async fn realm_head(client: &TestActorClient, realm_id: &RealmId) -> Result<u64> {
    let scanned = client
        .sdk()
        .scan_commit_stream_to_head(
            realm_id.clone(),
            CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            None,
            200,
        )
        .await?;
    scanned
        .committed_events
        .last()
        .map(|item| item.commit().stream_position)
        .context("the Realm stream has no Commit")
}

/// The first Account subscribe frame's Realm detail for `realm` at
/// `window_limit`, after the SDK's closed frame contract.
async fn realm_window(
    client: &TestActorClient,
    realm: &str,
    window_limit: u32,
) -> Result<arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry> {
    let filter = serde_json::json!({"realm_ids": [realm], "window_limit": window_limit});
    let filter = String::from_utf8(arkret_canonical::canonical_json_bytes(&filter)?)?;
    let response = client
        .get("/_arkret/self/account/subscribe")
        .query(&[("filter", filter.as_str())])
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    ensure!(
        status == StatusCode::OK,
        "account subscribe {status}: {body}"
    );
    let line = body
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .context("account subscribe returned no frame")?;
    let frame: arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame =
        serde_json::from_str(line).with_context(|| format!("closed Account frame: {line}"))?;
    frame
        .validate()
        .map_err(|error| anyhow!("Account frame contract: {error}: {line}"))?;
    frame
        .realms
        .as_ref()
        .and_then(|realms| realms.entries.get(realm))
        .cloned()
        .with_context(|| format!("the requested Realm detail is absent: {line}"))
}

fn window_positions(
    entry: &arkret_models_collaboration::sync_frames::account_subscribe::RealmSyncEntry,
) -> Vec<u64> {
    entry
        .committed_events
        .iter()
        .flatten()
        .map(|row| row.commit().stream_position)
        .collect()
}

async fn exact_window_basis(
    client: &TestActorClient,
    realm: &RealmId,
    stream: &CommitStreamRef,
    account: &AccountId,
    basis: &arkret_models_collaboration::sync_frames::account_sync::StreamWindowStartBasis,
) -> Result<arkret_wire::RealmStateSnapshot> {
    let snapshot = client
        .sdk()
        .realm_state_snapshot_by_ref(realm, &basis.snapshot_ref)
        .await
        .context("retrieve the window's exact original historical basis")?;
    snapshot.validate_purpose()?;
    ensure!(
        &snapshot.realm_id == realm && snapshot.snapshot_id == basis.snapshot_ref,
        "historical response does not bind the exact requested Realm and Snapshot"
    );
    let history = snapshot
        .history_basis
        .as_ref()
        .context("historical window basis omitted its signed scope")?;
    ensure!(
        snapshot.purpose == arkret_wire::RealmSnapshotPurpose::StreamHistory
            && snapshot.governance_generation == basis.governance_generation
            && &history.account_id == account
            && &history.stream_ref == stream
            && history.anchor_position == basis.anchor_position
            && history.anchor_commit_ref == basis.anchor_commit_ref
            && history.accepted_dependency_refs.as_slice()
                == basis
                    .accepted_dependency_refs
                    .as_deref()
                    .unwrap_or_default(),
        "the exact original does not cover the window's authenticated account and prefix"
    );
    let (_, seed) = crate::harness::test_service_signing_key("local-invite-accept-join");
    let key = arkret_signatures::PublicKeyMaterial::Ed25519Raw {
        bytes: ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
            .to_vec(),
    };
    let unsigned = arkret_canonical::unsigned_value(&snapshot, &["signature"])?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &key,
    )?;
    let identity = arkret_canonical::unsigned_value(&snapshot, &["signature", "snapshot_id"])?;
    let expected_id = arkret_wire::RealmSnapshotId::from_digest(arkret_canonical::sha256_bytes(
        &arkret_canonical::canonical_json_bytes(&identity)?,
    ));
    ensure!(
        snapshot.snapshot_id == expected_id,
        "history original is not content-addressed"
    );
    ensure!(
        snapshot.require_full_recovery().is_err(),
        "history must not replace current"
    );
    Ok(snapshot)
}

pub async fn local_invite_accept_join_run() -> Result<()> {
    let station = InviteStation::spawn("local-invite-accept-join").await?;
    let alice = station
        .grant_bearing_client("alice-local-accept", ALICE_DEVICE)
        .await
        .context("bootstrap Alice")?;
    let bob = station
        .grant_bearing_client("bob-local-accept", BOB_DEVICE)
        .await
        .context("bootstrap Bob")?;
    let bob_account = account_of(&bob)?;
    let bob_actor = ActorId::account(bob_account.clone());

    // (1) Alice's Realm and her directed Invite to Bob.
    let realm = alice.create_realm("Local Invite Accept").await?;
    let realm_id = RealmId::new(realm.clone())?;
    let strand_id = alice.default_strand_id(&realm)?;
    let created = alice
        .submit_event(
            &realm,
            "ak.invite.create",
            invite_create_payload(
                &bob.actor,
                bob.service_id(),
                format!("sha256:{}", "c".repeat(64)),
                Utc::now() + ChronoDuration::days(7),
            )?,
        )
        .await
        .context("commit the directed invite")?;
    let invite_id = InviteId::from_event_id(&submitted_event_id(&created)?);
    let before = account_frames(&bob, None).await?;
    ensure!(
        listed_row(&before, &realm).is_err(),
        "an invited account is not yet listed as a member"
    );

    // (2) Bob accepts; the accept is his join.
    let accept = serde_json::to_value(InviteAcceptPayload::directed(
        invite_id.clone(),
        bob_account.clone(),
        InvitePreviousState::Pending,
    ))?;
    let (status, body) = submit(&bob, &realm, "ak.invite.accept", accept.clone()).await?;
    ensure!(
        status == StatusCode::OK,
        "Bob's accept must be committed: {status} {body}"
    );
    let accept_commit = committed(&body)?;
    ensure!(
        accept_commit.stream_ref
            == (CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            }),
        "the accept is committed on the Realm stream: {body}"
    );
    let joined = account_frames(&bob, None).await?;
    let row = listed_row(&joined, &realm)?;
    ensure!(
        row.membership
            == arkret_models_collaboration::sync_frames::demand_sync::RealmListMembership::Join
            && row.title.as_deref() == Some("Local Invite Accept"),
        "Bob's realm list names the Realm as joined: {row:?}"
    );
    let head = realm_head(&alice, &realm_id).await?;
    let (status, body) = submit(&bob, &realm, "ak.invite.accept", accept).await?;
    ensure!(
        !status.is_success() && body["reason_code"] == "invite_already_terminal",
        "a second accept of the terminal Invite is refused: {status} {body}"
    );
    ensure!(
        realm_head(&alice, &realm_id).await? == head,
        "a refused accept appends no Commit"
    );

    // (3) Joining grants no writing; Alice's grant does.
    let (status, body) = submit(
        &bob,
        &realm,
        "ak.message.create",
        crate::harness::message_create_text_payload(&strand_id, "before the grant")?,
    )
    .await?;
    ensure!(
        status == StatusCode::FORBIDDEN
            && body["type"]
                .as_str()
                .is_some_and(|kind| kind.ends_with("/capability_denied")),
        "a member without ak.message.create is refused: {status} {body}"
    );
    alice
        .grant_realm_actions_to(&realm, &bob.actor, &["ak.message.create"])
        .await
        .context("grant Bob ak.message.create")?;
    let sent = bob
        .send_message(&realm, &strand_id, "hello from Bob")
        .await
        .context("Bob's Message is committed")?;
    let message_event_id = submitted_event_id(&sent)?;
    let scanned = alice
        .sdk()
        .scan_commit_stream_to_head(
            realm_id.clone(),
            CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            None,
            200,
        )
        .await?;
    ensure!(
        scanned.committed_events.iter().any(|item| {
            item.reducer_input().is_some_and(|event| {
                event.event_id == message_event_id && event.actor_id == bob_actor
            })
        }),
        "Alice's scan returns Bob's Message in full"
    );

    // (4) Bob reads from his own join.
    let bob_scan = bob
        .sdk()
        .scan_commit_stream_to_head(
            realm_id.clone(),
            CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            None,
            200,
        )
        .await?;
    let floor = bob_scan
        .readable_floor
        .clone()
        .context("Bob's scan names its readable floor")?;
    ensure!(
        floor.oldest_position == accept_commit.stream_position
            && floor.floor_commit_id == accept_commit.commit_id
            && floor.floor_reason == arkret_wire::ReadableFloorReason::MembershipJoin,
        "Bob's floor is his accepting Commit: {floor:?}"
    );
    ensure!(
        bob_scan
            .committed_events
            .first()
            .is_some_and(|item| item.commit().commit_id == accept_commit.commit_id),
        "Bob's scan starts at his join"
    );

    // (4b) Bob's `/head` names the same floor and every Realm state row.
    let head_body = expect_json(
        bob.get("/_arkret/self/realm-state-snapshot/head")
            .query(&[("realm_id", realm.as_str())]),
        StatusCode::OK,
    )
    .await
    .context("Bob's /head")?;
    let head_snapshot: arkret_wire::RealmStateSnapshot = serde_json::from_value(head_body.clone())
        .context("Bob's /head is a closed signed Snapshot")?;
    head_snapshot.require_full_recovery()?;
    let head_position = realm_head(&alice, &realm_id).await?;
    let realm_stream = CommitStreamRef::Realm {
        realm_id: realm_id.clone(),
    };
    ensure!(
        head_snapshot.retention_and_history_floor.stream_floors
            == [arkret_wire::StreamHistoryFloor {
                stream_ref: realm_stream.clone(),
                oldest_position: accept_commit.stream_position,
            }]
            && head_snapshot.visible_stream_heads.len() == 1
            && head_snapshot.visible_stream_heads[0].stream_position == head_position,
        "Bob's Snapshot floor is his accepting Commit at the current head: {head_body}"
    );
    let selectors = head_snapshot
        .current_state_entries
        .iter()
        .map(|entry| match entry {
            arkret_wire::CurrentState::Value { selector, .. } => selector.clone(),
        })
        .collect::<Vec<_>>();
    ensure!(
        selectors.contains(&arkret_wire::CurrentSelector::InviteLifecycle {
            invite_id: invite_id.clone(),
        }) && selectors.contains(&arkret_wire::CurrentSelector::MemberState {
            actor_id: bob_actor.clone(),
        }) && selectors.iter().any(|selector| matches!(
            selector,
            arkret_wire::CurrentSelector::CapabilityGrant { .. }
        )),
        "Bob's Snapshot carries his Invite, membership and grant rows: {head_body}"
    );

    // With no newer Commit, the tail is empty above Bob's join floor. Its
    // independent historical basis must be read by the exact issued reference.
    let whole = realm_window(&bob, &realm, 20).await?;
    let whole_window = whole
        .streams
        .as_deref()
        .and_then(|streams| streams.first())
        .context("Bob's Realm stream window")?;
    ensure!(
        window_positions(&whole).is_empty()
            && whole_window.limited
            && whole_window.preview_only.is_none()
            && whole_window.head_commit_ref == head_snapshot.visible_stream_heads[0].commit_id
            && whole_window
                .window_start_basis
                .as_ref()
                .is_some_and(|basis| basis.anchor_position == head_position
                    && basis.anchor_commit_ref == whole_window.head_commit_ref),
        "Bob's empty tail must bind the exact committed head: {whole_window:?}"
    );
    let whole_basis = whole_window
        .window_start_basis
        .as_ref()
        .context("Bob's empty tail omitted its historical basis")?;
    let original_basis =
        exact_window_basis(&bob, &realm_id, &realm_stream, &bob_account, whole_basis).await?;

    // One more Commit: the one-row tail retains the same committed prefix.
    bob.send_message(&realm, &strand_id, "after the head")
        .await
        .context("Bob's second Message is committed")?;
    let latest = realm_window(&bob, &realm, 1).await?;
    let latest_window = latest
        .streams
        .as_deref()
        .and_then(|streams| streams.first())
        .context("Bob's one-row window")?;
    let basis = latest_window
        .window_start_basis
        .as_ref()
        .with_context(|| format!("a window above the floor names a basis: {latest_window:?}"))?;
    ensure!(
        window_positions(&latest) == vec![head_position + 1]
            && latest_window.limited
            && latest_window.preview_only.is_none()
            && basis.anchor_position == head_position
            && basis.anchor_commit_ref == whole_basis.anchor_commit_ref,
        "the one-row window is backed by the original committed prefix: {latest_window:?}"
    );
    exact_window_basis(&bob, &realm_id, &realm_stream, &bob_account, basis).await?;
    ensure!(
        bob.sdk()
            .realm_state_snapshot_by_ref(&realm_id, &whole_basis.snapshot_ref)
            .await?
            == original_basis,
        "the later message or window replaced the earlier original historical basis"
    );

    // (5) Bob leaves by his own Event.
    let cursor = last_cursor(&joined)?;
    let mut leave = MembershipPayload::transition(
        MembershipPayloadState::Leave,
        bob_actor.clone(),
        "leaving the Realm",
    );
    leave.realm_id = Some(realm_id.clone());
    bob.submit_event(&realm, "ak.member.state", serde_json::to_value(leave)?)
        .await
        .context("Bob's leave is committed")?;
    let changes = account_frames(&bob, Some(&cursor)).await?;
    ensure!(
        changes
            .iter()
            .filter_map(|frame| frame.realm_list_changes.as_ref())
            .flat_map(|changes| changes.removals.iter())
            .any(|removal| removal.realm_id == realm_id),
        "leaving removes the Realm from Bob's realm list: {changes:?}"
    );
    ensure!(
        listed_row(&account_frames(&bob, None).await?, &realm).is_err(),
        "a fresh realm list no longer names the Realm"
    );
    let refused = bob
        .sdk()
        .scan_commit_stream_to_head(
            realm_id.clone(),
            CommitStreamRef::Realm {
                realm_id: realm_id.clone(),
            },
            None,
            200,
        )
        .await;
    ensure!(
        refused.is_err(),
        "a member who left has no readable interval"
    );
    Ok(())
}
