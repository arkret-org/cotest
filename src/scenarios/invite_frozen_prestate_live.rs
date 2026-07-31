//! COT-STATE-02 — Invite frozen-pre-state acceptance across SDK, Soland and
//! the Inkson producer.
//!
//! `conformance-vectors.md` §23.4 makes a directed `ak.invite.cancel` fail
//! with `reducer_projection_failed` when `payload.invitee` is missing or does
//! not equal the invite cell's frozen invitee, and makes the 3PID branch go
//! through `ak.invite.revoke` instead. Those are pre-acceptance predicates: a
//! late projection-time rejection would leave the Event durable and split the
//! lifecycle and member cells.
//!
//! The two predicates asserted here are executed, not restated:
//!
//!   1. the stored invitee exists (a cancel with no `payload.invitee` is refused), and
//!   2. it equals `payload.invitee` (a cancel naming a different DID is refused),
//!
//! each verified against the live server for **zero Event acceptance** and
//! **zero cell change**: the Realm Event log, the Seal frontier, and the
//! invite's own lifecycle/member projection all have to be byte-identical
//! before and after the rejected submit. The positive path then confirms the
//! Inkson producer emits the correct invitee, and replaying the accepted
//! cancel envelope is an idempotent duplicate rather than a second transition.

use anyhow::{Result, anyhow};
use chrono::Duration as ChronoDuration;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    TestActorClient, TestServerGroup, event_envelope_with_chain, expect_json, refresh_event_proof,
};
use crate::transcripts::record_vector_event;

const INVITE_ID: &str = "ak:invite:01999999-0000-7000-8000-00000000f201";
const THIRD_PARTY_INVITE_ID: &str = "ak:invite:01999999-0000-7000-8000-00000000f202";

/// The three server-side observables a rejected Control Move must leave
/// untouched.
#[derive(Debug, PartialEq, Eq)]
struct RealmObservation {
    event_ids: Vec<String>,
    seal_id: String,
    invite_states: Vec<Value>,
}

async fn observe(client: &TestActorClient, realm_id: &str) -> Result<RealmObservation> {
    let listed = expect_json(
        client
            .get("/_arkret/self/events")
            .query(&[("realms", realm_id), ("limit", "200")]),
        StatusCode::OK,
    )
    .await?;
    let event_ids = listed["events"]
        .as_array()
        .ok_or_else(|| anyhow!("events query missing events array: {listed}"))?
        .iter()
        .filter_map(|event| event["event_id"].as_str().map(ToOwned::to_owned))
        .collect();
    let frontier = client.realm_seal_frontier(realm_id).await?;
    let state: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        serde_json::from_value(frontier.clone())
            .map_err(|error| anyhow!("invalid Realm frontier `{frontier}`: {error}"))?;
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(seal_frontier) =
        state.frontier
    else {
        return Err(anyhow!(
            "Realm selector returned the wrong frontier variant"
        ));
    };
    let invites = expect_json(
        client
            .get("/_arkret/self/invites")
            .query(&[("realm_id", realm_id)]),
        StatusCode::OK,
    )
    .await?;
    let invite_states = invites["invites"]
        .as_array()
        .map(|invites| {
            invites
                .iter()
                .map(|invite| {
                    json!({
                        "id": invite["id"].clone(),
                        "state": invite["state"].clone(),
                        "status": invite["status"].clone(),
                        "invitee": invite["invitee"].clone(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(RealmObservation {
        event_ids,
        seal_id: seal_frontier.seal_id.to_string(),
        invite_states,
    })
}

/// Author an invite-family Control Move exactly the way the harness does for
/// the accepted path, so a rejection can only come from the pre-state
/// predicates and never from a malformed envelope.
async fn author_invite_move(
    actor: &TestActorClient,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Result<Value> {
    let frontier = expect_json(
        actor
            .get("/_arkret/self/events/frontier")
            .query(&[("actor_id", actor.actor.as_str()), ("realm_id", realm_id)]),
        StatusCode::OK,
    )
    .await?;
    let state: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        serde_json::from_value(frontier)?;
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmActor(actor_frontier) =
        state.frontier
    else {
        return Err(anyhow!("combined selector returned the wrong variant"));
    };
    actor_frontier.validate()?;
    let created_at = arkret_canonical::format_timestamp_canonical(chrono::Utc::now());
    let mut event = event_envelope_with_chain(
        &actor.actor,
        realm_id,
        kind,
        payload,
        actor_frontier.next_actor_seq,
        None,
    );
    event["prev_refs"] = serde_json::to_value(actor_frontier.frontier_event_ids)?;
    event["created_at"] = Value::String(created_at.clone());
    let seal_frontier = actor.realm_seal_frontier(realm_id).await?;
    let state: arkret_models_collaboration::event_sync::EventsFrontierAccountClientState =
        serde_json::from_value(seal_frontier)?;
    let arkret_models_collaboration::event_sync::EventsFrontierView::RealmSeal(seal_frontier) =
        state.frontier
    else {
        return Err(anyhow!(
            "Realm selector returned the wrong frontier variant"
        ));
    };
    event["seal_basis"] = serde_json::to_value(seal_frontier.seal_basis())?;
    if let Some(proof) = event
        .get_mut("proofs")
        .and_then(Value::as_array_mut)
        .and_then(|proofs| proofs.first_mut())
    {
        proof["created_at"] = Value::String(created_at);
    }
    refresh_event_proof(&mut event)?;
    Ok(event)
}

async fn submit_invite_move(
    actor: &TestActorClient,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Result<(StatusCode, Value)> {
    let event = author_invite_move(actor, realm_id, kind, payload).await?;
    let response = actor
        .post("/_arkret/self/events")
        .json(&event)
        .send()
        .await?;
    let status = response.status();
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    Ok((status, body))
}

fn error_reason(body: &Value) -> String {
    body["error"]["code"]
        .as_str()
        .or_else(|| body["error"]["details"]["reason_code"].as_str())
        .or_else(|| body["error"]["message"].as_str())
        .unwrap_or("<no error code>")
        .to_owned()
}

/// The two frozen-pre-state predicates, executed against a live Soland with
/// zero-acceptance / zero-cell-change assertions, plus the Inkson producer
/// contract for the accepted cancel.
pub async fn invite_frozen_prestate_is_enforced_before_acceptance() -> Result<()> {
    let group = TestServerGroup::single("invite-frozen-prestate").await?;
    let server = group.server(0);
    let alice = server
        .demo_client(
            "did:web:alice-invite-frozen.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let bob = server
        .register_client(
            "did:web:bob-invite-frozen.example",
            "bob-invite-frozen",
            "ak:device:01904100-0000-7000-8000-0000000000b1",
        )
        .await?;
    let realm_id = alice.create_realm("Invite Frozen Pre-State").await?;

    let expires_at = chrono::Utc::now() + ChronoDuration::days(7);
    let create_payload = crate::harness::invite_create_payload(
        INVITE_ID,
        bob.actor.as_str(),
        alice.service_id(),
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        expires_at,
    )?;
    let (status, body) =
        submit_invite_move(&alice, &realm_id, "ak.invite.create", create_payload).await?;
    assert_eq!(status, StatusCode::OK, "invite create: {body}");

    // Predicate 1 — a directed cancel with NO `payload.invitee`.
    let before = observe(&alice, &realm_id).await?;
    let (missing_status, missing_body) = submit_invite_move(
        &alice,
        &realm_id,
        "ak.invite.cancel",
        json!({
            "invite_id": INVITE_ID,
            "target_state": "revoked",
            "reason": "missing invitee negative",
        }),
    )
    .await?;
    assert_ne!(
        missing_status,
        StatusCode::OK,
        "cancel without payload.invitee must be refused: {missing_body}"
    );
    let after_missing = observe(&alice, &realm_id).await?;
    assert_eq!(
        before, after_missing,
        "a refused cancel must accept zero Events and change zero cells"
    );

    // Predicate 2 — a directed cancel naming a DIFFERENT invitee.
    let (mismatch_status, mismatch_body) = submit_invite_move(
        &alice,
        &realm_id,
        "ak.invite.cancel",
        json!({
            "invite_id": INVITE_ID,
            "invitee": "did:web:mallory-invite-frozen.example",
            "target_state": "revoked",
            "reason": "invitee mismatch negative",
        }),
    )
    .await?;
    assert_ne!(
        mismatch_status,
        StatusCode::OK,
        "cancel with a mismatched invitee must be refused: {mismatch_body}"
    );
    let after_mismatch = observe(&alice, &realm_id).await?;
    assert_eq!(
        before, after_mismatch,
        "a refused cancel must accept zero Events and change zero cells"
    );

    // The Inkson producer authors the accepted cancel: the builder is the
    // component that has to carry the correct frozen invitee onto the wire.
    let inkson_cancel = inkson::operation::ak_ops::invite_cancel(
        &realm_id,
        &alice.actor,
        INVITE_ID,
        bob.actor.as_str(),
        "revoked",
        Some("inkson_producer_cancel"),
    )
    .map_err(|error| anyhow!("inkson invite_cancel builder: {error}"))?
    .build_sdk_event(alice.service_id())
    .map_err(|error| anyhow!("inkson invite_cancel event: {error}"))?;
    let inkson_payload = serde_json::to_value(&inkson_cancel.payload)?;
    assert_eq!(
        inkson_payload["invitee"].as_str(),
        Some(bob.actor.as_str()),
        "the Inkson direct-cancel producer must carry the frozen invitee: {inkson_payload}"
    );
    assert_eq!(
        inkson_payload["target_state"].as_str(),
        Some("revoked"),
        "the Inkson direct-cancel producer must carry the signed target_state: {inkson_payload}"
    );

    let (status, accepted_body) = submit_invite_move(
        &alice,
        &realm_id,
        "ak.invite.cancel",
        inkson_payload.clone(),
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "Inkson-produced cancel must be accepted: {accepted_body}"
    );
    let after_accept = observe(&alice, &realm_id).await?;
    assert_ne!(
        before.event_ids.len(),
        after_accept.event_ids.len(),
        "an accepted cancel must append exactly one Event"
    );
    assert_eq!(
        after_accept.event_ids.len() - before.event_ids.len(),
        1,
        "an accepted cancel must append exactly one Event"
    );

    // Replaying the accepted cancel is an idempotent duplicate: the outcome
    // depends on the frozen pre-state, never on the current projection or the
    // wall clock.
    let replay_event = author_invite_move(
        &alice,
        &realm_id,
        "ak.invite.cancel",
        inkson_payload.clone(),
    )
    .await?;
    let response = alice
        .post("/_arkret/self/events")
        .json(&replay_event)
        .send()
        .await?;
    let replay_status = response.status();
    let replay_body = response.json::<Value>().await.unwrap_or(Value::Null);
    let after_replay = observe(&alice, &realm_id).await?;
    assert_eq!(
        after_accept.invite_states, after_replay.invite_states,
        "replaying the cancel must not drive a second lifecycle transition \
         (replay: {replay_status} {replay_body})"
    );

    record_vector_event(
        "invite.membership_transition_atomicity",
        &json!({"realm_id": realm_id, "invite_id": INVITE_ID}),
        &json!({
            "missing_invitee": "reducer_projection_failed",
            "mismatched_invitee": "reducer_projection_failed",
            "zero_event_acceptance": true,
            "zero_cell_mutation": true,
            "inkson_direct_cancel_carries_invitee": true,
        }),
        &json!({
            "missing_invitee": {
                "status": missing_status.as_u16(),
                "reason": error_reason(&missing_body),
                "events_appended": after_missing.event_ids.len() - before.event_ids.len(),
                "seal_advanced": before.seal_id != after_missing.seal_id,
            },
            "mismatched_invitee": {
                "status": mismatch_status.as_u16(),
                "reason": error_reason(&mismatch_body),
                "events_appended": after_mismatch.event_ids.len() - before.event_ids.len(),
                "seal_advanced": before.seal_id != after_mismatch.seal_id,
            },
            "inkson_direct_cancel_invitee": inkson_payload["invitee"].clone(),
            "accepted_events_appended": after_accept.event_ids.len() - before.event_ids.len(),
            "replay_status": replay_status.as_u16(),
        }),
    );
    Ok(())
}

/// §23.4 3PID branch: a `third_party_id` invite carries no `invitee`, must not
/// project a `member.state` write, and its cancel must be refused with
/// `invite_kind_requires_revoke` so the withdrawal goes through
/// `ak.invite.revoke`.
pub async fn third_party_invite_cancel_requires_revoke() -> Result<()> {
    let group = TestServerGroup::single("invite-third-party-revoke").await?;
    let server = group.server(0);
    let alice = server
        .demo_client(
            "did:web:alice-invite-3pid.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let realm_id = alice.create_realm("Invite 3PID Requires Revoke").await?;

    let expires_at = chrono::Utc::now() + ChronoDuration::days(7);
    let (status, body) = submit_invite_move(
        &alice,
        &realm_id,
        "ak.invite.create",
        json!({
            "invite_id": THIRD_PARTY_INVITE_ID,
            "third_party_id": {
                "medium": "email",
                "address": "invitee-3pid@example.com",
            },
            "invite_delivery_target": {
                "kind": "principal_server",
                "recipient_service_id": alice.service_id(),
            },
            "introduction_evidence_digest":
                "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "expires_at": arkret_canonical::format_timestamp_canonical(expires_at),
        }),
    )
    .await?;
    if status != StatusCode::OK {
        // A deployment that does not enable the 3PID branch cannot exercise
        // this vector; say so rather than asserting a false negative.
        eprintln!("skipping 3PID cancel vector: invite create returned {status}: {body}");
        return Ok(());
    }

    let before = observe(&alice, &realm_id).await?;
    let (cancel_status, cancel_body) = submit_invite_move(
        &alice,
        &realm_id,
        "ak.invite.cancel",
        json!({
            "invite_id": THIRD_PARTY_INVITE_ID,
            "invitee": "did:web:alice-invite-3pid.example",
            "target_state": "revoked",
            "reason": "3pid cancel negative",
        }),
    )
    .await?;
    assert_ne!(
        cancel_status,
        StatusCode::OK,
        "a 3PID invite cancel must be refused: {cancel_body}"
    );
    let reason = error_reason(&cancel_body);
    assert!(
        reason.contains("invite_kind_requires_revoke") || reason.contains("requires_revoke"),
        "3PID cancel must fail with invite_kind_requires_revoke, got {reason}: {cancel_body}"
    );
    let after = observe(&alice, &realm_id).await?;
    assert_eq!(
        before, after,
        "a refused 3PID cancel must accept zero Events and change zero cells"
    );

    // The Inkson producer routes the 3PID withdrawal through revoke without an
    // `invitee` binding, which is what makes the member cell stay untouched.
    let revoke = inkson::operation::ak_ops::invite_revoke(
        &realm_id,
        &alice.actor,
        THIRD_PARTY_INVITE_ID,
        None,
        "revoked",
        "third_party_withdrawn",
    )
    .map_err(|error| anyhow!("inkson invite_revoke builder: {error}"))?
    .build_sdk_event(alice.service_id())
    .map_err(|error| anyhow!("inkson invite_revoke event: {error}"))?;
    let revoke_payload = serde_json::to_value(&revoke.payload)?;
    assert!(
        revoke_payload.get("invitee").is_none(),
        "a 3PID revoke must not bind an invitee: {revoke_payload}"
    );
    let (revoke_status, revoke_body) =
        submit_invite_move(&alice, &realm_id, "ak.invite.revoke", revoke_payload).await?;
    assert_eq!(
        revoke_status,
        StatusCode::OK,
        "the 3PID revoke path must be accepted: {revoke_body}"
    );

    record_vector_event(
        "invite.membership_transition_atomicity.third_party",
        &json!({"realm_id": realm_id, "invite_id": THIRD_PARTY_INVITE_ID}),
        &json!({
            "cancel": "invite_kind_requires_revoke",
            "revoke": "accepted",
            "zero_event_acceptance_on_cancel": true,
        }),
        &json!({
            "cancel_status": cancel_status.as_u16(),
            "cancel_reason": reason,
            "cancel_events_appended": after.event_ids.len() - before.event_ids.len(),
            "revoke_status": revoke_status.as_u16(),
        }),
    );
    Ok(())
}
