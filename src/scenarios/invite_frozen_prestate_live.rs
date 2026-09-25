//! COT-STATE-02 — Invite frozen pre-state acceptance across SDK, Soland and
//! the Inkson producer, on the single Event/RealmCommit carrier.
//!
//! `zh/models/governance-objects.md` §5.3 makes the three Invite typed current
//! results (`invite_lifecycle`, `invite_directed_invitee`, `invite_live_target`)
//! the only admission basis of every Invite Event. Each refusal below is a
//! pre-acceptance predicate evaluated by the governing Station inside the
//! accepting transaction, so it must append no RealmCommit and leave the
//! Realm stream head where it was:
//!
//! 1. a second live directed create for the same account is `failed_precondition` /
//!    `invite_live_target_occupied`, whose closed details name the occupying create Event;
//! 2. a directed cancel with no `payload.invitee_account_id` violates the payload schema;
//! 3. a directed cancel naming a different account is `invite_directed_invitee_mismatch`;
//! 4. a new cancel against an Invite that is already terminal is `invite_already_terminal`.
//!
//! The positive path confirms the Inkson producer emits the frozen invitee,
//! an exact replay of the accepted cancel returns its stored Commit, the
//! released slot accepts a re-invite, and an `ak.invite.revoke` of that
//! re-invite releases the slot again for a third invite.

use anyhow::{Result, anyhow};
use chrono::Duration as ChronoDuration;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{CanonicalJsonBody, TestActorClient, actor_core_id};
use crate::transcripts::record_vector_event;

/// The server-side observable a refused Invite Event must leave untouched:
/// the committed Realm stream, Event by Event.
#[derive(Debug, PartialEq, Eq)]
struct RealmObservation {
    event_ids: Vec<String>,
    commit_head_id: String,
}

async fn observe(client: &TestActorClient, realm_id: &str) -> Result<RealmObservation> {
    let committed = client.realm_seal_frontier(realm_id).await?;
    let events = committed["committed_events"]
        .as_array()
        .ok_or_else(|| anyhow!("committed stream scan missing events: {committed}"))?;
    let event_ids = events
        .iter()
        .filter_map(|item| item["commit"]["event_ref"].as_str().map(ToOwned::to_owned))
        .collect();
    let commit_head_id = events
        .last()
        .and_then(|item| item["commit"]["commit_id"].as_str())
        .ok_or_else(|| anyhow!("committed Realm stream has no head: {committed}"))?
        .to_owned();
    Ok(RealmObservation {
        event_ids,
        commit_head_id,
    })
}

async fn submit(actor: &TestActorClient, event: arkret_wire::Event) -> Result<(StatusCode, Value)> {
    let response = actor
        .post("/_arkret/self/events")
        .canonical_json(&crate::publication::initial_submission(event, "")?)?
        .send()
        .await?;
    let status = response.status();
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    Ok((status, body))
}

async fn submit_invite_event(
    actor: &TestActorClient,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Result<(arkret_wire::Event, StatusCode, Value)> {
    let event = actor.author_event(realm_id, kind, payload).await?;
    let (status, body) = submit(actor, event.clone()).await?;
    Ok((event, status, body))
}

fn problem(body: &Value) -> Result<arkret_wire::Problem> {
    serde_json::from_value::<arkret_wire::Problem>(body.clone())
        .map_err(|error| anyhow!("refusal is not a problem document ({error}): {body}"))
}

/// The registered sub-reason when the refusal carries one, else its code.
fn reason(body: &Value) -> String {
    body.get("reason_code")
        .or_else(|| body.get("code"))
        .and_then(Value::as_str)
        .unwrap_or("<no code>")
        .to_owned()
}

/// Submit an Invite Event that must be refused, and prove the Realm stream is
/// byte-identical before and after.
async fn assert_refused(
    actor: &TestActorClient,
    realm_id: &str,
    kind: &str,
    payload: Value,
    expected_reason: &str,
) -> Result<Value> {
    let before = observe(actor, realm_id).await?;
    let (_, status, body) = submit_invite_event(actor, realm_id, kind, payload).await?;
    assert!(
        !status.is_success(),
        "{kind} must be refused with {expected_reason}: {body}"
    );
    assert_eq!(reason(&body), expected_reason, "{kind} refusal: {body}");
    assert_eq!(
        observe(actor, realm_id).await?,
        before,
        "a refused {kind} must append no RealmCommit"
    );
    Ok(body)
}

pub async fn invite_frozen_prestate_is_enforced_before_acceptance() -> Result<()> {
    let station = crate::scenarios::invite_create_and_dispatch::InviteStation::spawn(
        "invite-frozen-prestate",
    )
    .await?;
    let server = &station.server;
    let alice = station
        .grant_bearing_client(
            "alice-invite-frozen",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let bob = server
        .register_client(
            &crate::scenarios::identity_test_support::actor_did_for_service_did(
                server.service_did(),
                "bob-invite-frozen",
            )?,
            "bob-invite-frozen",
            "ak:device:01904100-0000-7000-8000-0000000000b1",
        )
        .await?;
    let bob_account = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(actor_core_id(&bob.actor)?)?,
        arkret_wire::DidCoreId::new(bob.service_id().to_owned())?,
    );
    let mallory_account = arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(actor_core_id("did:web:mallory-invite-frozen.example")?)?,
        arkret_wire::DidCoreId::new(bob.service_id().to_owned())?,
    );
    let realm_id = alice.create_realm("Invite Frozen Pre-State").await?;
    let expires_at = chrono::Utc::now() + ChronoDuration::days(7);
    let create_payload = |digest: char| {
        crate::harness::invite_create_payload(
            bob.actor.as_str(),
            alice.service_id(),
            format!("sha256:{}", digest.to_string().repeat(64)),
            expires_at,
        )
    };

    let (_, status, body) =
        submit_invite_event(&alice, &realm_id, "ak.invite.create", create_payload('1')?).await?;
    assert_eq!(status, StatusCode::OK, "invite create: {body}");
    let create_event_id = crate::harness::submitted_event_id(&body)?;
    let invite_id = arkret_identifiers::InviteId::from_event_id(&create_event_id);

    // (1) A second live directed create for Bob hits the occupied slot.
    let occupied = assert_refused(
        &alice,
        &realm_id,
        "ak.invite.create",
        create_payload('2')?,
        arkret_wire::ReasonCode::INVITE_LIVE_TARGET_OCCUPIED,
    )
    .await?;
    let details = problem(&occupied)?
        .invite_live_target_occupied_details()
        .map_err(|error| anyhow!("occupied details are not closed: {error}"))?
        .ok_or_else(|| anyhow!("occupied refusal carries no closed details: {occupied}"))?;
    assert_eq!(details.create_event_id(), &create_event_id);
    assert_eq!(details.invite_id(), &invite_id);

    // (2) A directed cancel without the frozen invitee is not a cancel payload.
    assert_refused(
        &alice,
        &realm_id,
        "ak.invite.cancel",
        json!({
            "invite_id": invite_id,
            "previous_state": "pending",
            "target_state": "revoked",
            "reason": "missing invitee negative",
        }),
        arkret_wire::ErrorCode::SCHEMA_VIOLATION,
    )
    .await?;

    // (3) A directed cancel naming another account is a binding mismatch.
    assert_refused(
        &alice,
        &realm_id,
        "ak.invite.cancel",
        json!({
            "invite_id": invite_id,
            "previous_state": "pending",
            "invitee_account_id": mallory_account,
            "target_state": "revoked",
            "reason": "invitee mismatch negative",
        }),
        arkret_wire::ReasonCode::INVITE_DIRECTED_INVITEE_MISMATCH,
    )
    .await?;

    // The Inkson producer authors the accepted cancel: the builder is the
    // component that has to carry the frozen invitee onto the wire.
    let inkson_cancel = inkson::operation::ak_ops::invite_cancel_for_station(
        &realm_id,
        &alice.actor,
        arkret_wire::DidCoreId::new(alice.service_id().to_owned())?,
        invite_id.as_str(),
        &bob_account,
        "revoked",
        Some("inkson_producer_cancel"),
    )
    .map_err(|error| anyhow!("inkson invite_cancel builder: {error}"))?
    .build_sdk_event(alice.service_id())
    .map_err(|error| anyhow!("inkson invite_cancel event: {error}"))?;
    let inkson_payload = serde_json::to_value(inkson_cancel.payload())?;
    assert_eq!(
        inkson_payload["invitee_account_id"],
        serde_json::to_value(&bob_account)?,
        "the Inkson direct-cancel producer must carry the frozen invitee: {inkson_payload}"
    );
    assert_eq!(inkson_payload["target_state"].as_str(), Some("revoked"));
    assert_eq!(inkson_payload["previous_state"].as_str(), Some("pending"));

    let before_accept = observe(&alice, &realm_id).await?;
    let (cancel_event, status, accepted) = submit_invite_event(
        &alice,
        &realm_id,
        "ak.invite.cancel",
        inkson_payload.clone(),
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "Inkson-produced cancel must be accepted: {accepted}"
    );
    let after_accept = observe(&alice, &realm_id).await?;
    assert_eq!(
        after_accept.event_ids.len(),
        before_accept.event_ids.len() + 1,
        "an accepted cancel must append exactly one Event"
    );

    // An exact replay of the accepted cancel is its stored duplicate outcome.
    let (replay_status, replay) = submit(&alice, cancel_event).await?;
    assert_eq!(
        replay_status,
        StatusCode::OK,
        "exact cancel replay: {replay}"
    );
    assert_eq!(
        replay["status"], "duplicate",
        "exact cancel replay: {replay}"
    );
    assert_eq!(replay["commit"], accepted["commit"]);
    assert_eq!(observe(&alice, &realm_id).await?, after_accept);

    // (4) A newly authored cancel on the now-terminal Invite is refused.
    assert_refused(
        &alice,
        &realm_id,
        "ak.invite.cancel",
        inkson_payload.clone(),
        arkret_wire::ReasonCode::INVITE_ALREADY_TERMINAL,
    )
    .await?;

    // The cancel released the slot: a re-invite of Bob is accepted.
    let (_, status, body) =
        submit_invite_event(&alice, &realm_id, "ak.invite.create", create_payload('3')?).await?;
    assert_eq!(status, StatusCode::OK, "re-invite after cancel: {body}");
    let reinvite_id =
        arkret_identifiers::InviteId::from_event_id(&crate::harness::submitted_event_id(&body)?);

    // A revoke of the re-invite releases the slot again.
    let revoke = arkret_models_collaboration::governance::membership_invite::InviteRevokePayload::new(
        reinvite_id,
        arkret_models_collaboration::governance::membership_invite::InviteRevokePreviousState::Pending,
        Some(bob_account.clone()),
        arkret_models_collaboration::governance::membership_invite::InviteRevokeTargetState::Revoked,
    )
    .with_reason_code(arkret_wire::ReasonCode::from_wire("admin_revoke"))
    .to_value()?;
    let (_, status, body) =
        submit_invite_event(&alice, &realm_id, "ak.invite.revoke", revoke).await?;
    assert_eq!(status, StatusCode::OK, "revoke of the re-invite: {body}");
    let (_, status, body) =
        submit_invite_event(&alice, &realm_id, "ak.invite.create", create_payload('4')?).await?;
    assert_eq!(status, StatusCode::OK, "re-invite after revoke: {body}");

    record_vector_event(
        "invite.membership_transition_atomicity",
        &json!({"realm_id": realm_id, "invite_id": invite_id}),
        &json!({
            "occupied_live_target": "invite_live_target_occupied",
            "missing_invitee": "schema_violation",
            "mismatched_invitee": "invite_directed_invitee_mismatch",
            "terminal_invite": "invite_already_terminal",
            "zero_commit_on_refusal": true,
            "inkson_direct_cancel_carries_invitee": true,
            "reinvite_after_release": true,
        }),
        &json!({
            "occupied_create_event_id": details.create_event_id(),
            "inkson_direct_cancel_invitee": inkson_payload["invitee_account_id"].clone(),
            "accepted_cancel_commit": accepted["commit"].clone(),
        }),
    );
    Ok(())
}
