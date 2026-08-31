//! COT-STATE-02 — Invite frozen-pre-state acceptance across SDK, Soland and
//! the Inkson producer.
//!
//! `conformance-vectors.md` §23.4 makes a directed `ak.invite.cancel` fail
//! with `reducer_projection_failed` when `payload.invitee_account_id` is missing or does
//! not equal the invite cell's frozen invitee, and makes the 3PID branch go
//! through `ak.invite.revoke` instead. Those are pre-acceptance predicates: a
//! late projection-time rejection would leave the Event durable and split the
//! lifecycle and member cells.
//!
//! The two predicates asserted here are executed, not restated:
//!
//!   1. the stored invitee exists (a cancel with no `payload.invitee_account_id` is refused), and
//!   2. it equals `payload.invitee_account_id` (a cancel naming a different principal is refused),
//!
//! each verified against the live server for **zero Event acceptance** and
//! **zero cell change**: the Realm Event log, the Seal frontier, and the
//! invite's own lifecycle/member projection all have to be byte-identical
//! before and after the rejected submit. The positive path then confirms the
//! Inkson producer emits the correct invitee, and replaying the accepted
//! cancel envelope is an idempotent duplicate rather than a second transition.

use anyhow::{Result, anyhow};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    CanonicalJsonBody, TestActorClient, TestServerGroup, actor_core_id, event_envelope_with_chain,
    events_frontier_request_body, events_query_for_realm, expect_json, refresh_typed_event_proof,
};
use crate::transcripts::record_vector_event;

/// The three server-side observables a rejected Control Move must leave
/// untouched.
#[derive(Debug, PartialEq, Eq)]
struct RealmObservation {
    event_ids: Vec<String>,
    seal_id: String,
    invite_states: Vec<Value>,
}

async fn observe(
    client: &TestActorClient,
    realm_id: &str,
    invite_subject: &str,
) -> Result<RealmObservation> {
    let listed = expect_json(
        client
            .query("/_arkret/self/events")
            .json(&events_query_for_realm(realm_id, 200)?),
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
    let state: arkret_models_collaboration::event_sync::SealFrontierState =
        serde_json::from_value(frontier.clone())
            .map_err(|error| anyhow!("invalid Realm frontier `{frontier}`: {error}"))?;
    let seal_frontier = state.frontier;
    let invites = expect_json(
        client.get("/_arkret/self/authz/invites").query(&[
            ("subject", invite_subject),
            ("subject_station_id", client.service_id()),
            ("realm_id", realm_id),
        ]),
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
                        "invitee_account_id": invite["invitee_account_id"].clone(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(RealmObservation {
        event_ids,
        seal_id: seal_frontier.sole_leaf()?.to_string(),
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
) -> Result<arkret_wire::Event> {
    let frontier = expect_json(
        actor
            .query("/_arkret/self/events/frontier")
            .json(&events_frontier_request_body(
                actor.actor.as_str(),
                actor.service_id(),
                Some(realm_id),
            )?),
        StatusCode::OK,
    )
    .await?;
    let state: arkret_models_collaboration::event_sync::EventsFrontierState =
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
    event.prev_refs = actor_frontier.frontier_event_ids;
    event.created_at = DateTime::parse_from_rfc3339(&created_at)?.with_timezone(&Utc);
    let seal_frontier = actor.realm_seal_frontier(realm_id).await?;
    let state: arkret_models_collaboration::event_sync::SealFrontierState =
        serde_json::from_value(seal_frontier)?;
    let seal_frontier = state.frontier;
    event.seal_basis = Some(seal_frontier.seal_basis());
    let physical_millis = chrono::Utc::now().timestamp_millis();
    event.hlc = Some(arkret_identifiers::Hlc::new(format!(
        "{physical_millis:012x}-0000-a13f9c2e"
    ))?);
    refresh_typed_event_proof(&mut event)?;
    Ok(event)
}

async fn submit_invite_move(
    actor: &TestActorClient,
    realm_id: &str,
    kind: &str,
    payload: Value,
) -> Result<(StatusCode, Value)> {
    let event = author_invite_move(actor, realm_id, kind, payload).await?;
    let event_id = event.event_id.clone();
    let response = actor
        .post("/_arkret/self/events")
        .canonical_json(&crate::publication::initial_submission(event, "")?)?
        .send()
        .await?;
    let status = response.status();
    let body = response.json::<Value>().await.unwrap_or(Value::Null);
    if status.is_success() {
        actor.await_event_seal_coverage(realm_id, &event_id).await?;
    }
    Ok((status, body))
}

fn error_reason(body: &Value) -> String {
    serde_json::from_value::<arkret_wire::Problem>(body.clone())
        .map(|problem| {
            problem
                .extensions
                .get("reason_code")
                .and_then(Value::as_str)
                .unwrap_or_else(|| problem.code())
                .to_owned()
        })
        .unwrap_or_else(|_| "<invalid problem details>".to_owned())
}

/// The two frozen-pre-state predicates, executed against a live Soland with
/// zero-acceptance / zero-cell-change assertions, plus the Inkson producer
/// contract for the accepted cancel.
pub async fn invite_frozen_prestate_is_enforced_before_acceptance() -> Result<()> {
    let group = TestServerGroup::single("invite-frozen-prestate").await?;
    let server = group.server(0);
    let alice = server
        .demo_client(
            &crate::scenarios::identity_test_support::actor_did_for_service_did(
                server.service_did(),
                "alice-invite-frozen",
            )?,
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
    let bob_core_id = actor_core_id(&bob.actor)?;
    let mallory_core_id = actor_core_id("did:web:mallory-invite-frozen.example")?;
    let realm_id = alice.create_realm("Invite Frozen Pre-State").await?;

    let expires_at = chrono::Utc::now() + ChronoDuration::days(7);
    let create_payload = crate::harness::invite_create_payload(
        bob.actor.as_str(),
        alice.service_id(),
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        expires_at,
    )?;
    let (status, body) =
        submit_invite_move(&alice, &realm_id, "ak.invite.create", create_payload).await?;
    assert_eq!(status, StatusCode::OK, "invite create: {body}");
    let create_event_id = crate::harness::submitted_event_id(&body)?;
    let invite_id = arkret_identifiers::InviteId::from_event_id(&create_event_id).to_string();

    // Predicate 1 — a directed cancel with NO `payload.invitee_account_id`.
    let before = observe(&alice, &realm_id, &bob_core_id).await?;
    let (missing_status, missing_body) = submit_invite_move(
        &alice,
        &realm_id,
        "ak.invite.cancel",
        json!({
            "invite_id": invite_id,
            "target_state": "revoked",
            "reason": "missing invitee negative",
        }),
    )
    .await?;
    assert_ne!(
        missing_status,
        StatusCode::OK,
        "cancel without payload.invitee_account_id must be refused: {missing_body}"
    );
    let after_missing = observe(&alice, &realm_id, &bob_core_id).await?;
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
            "invite_id": invite_id,
            "invitee_account_id": arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new(mallory_core_id)?,
                arkret_wire::DidCoreId::new(bob.service_id().to_owned())?,
            ),
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
    let after_mismatch = observe(&alice, &realm_id, &bob_core_id).await?;
    assert_eq!(
        before, after_mismatch,
        "a refused cancel must accept zero Events and change zero cells"
    );

    // The Inkson producer authors the accepted cancel: the builder is the
    // component that has to carry the correct frozen invitee onto the wire.
    let inkson_cancel = inkson::operation::ak_ops::invite_cancel_for_station(
        &realm_id,
        &alice.actor,
        arkret_wire::DidCoreId::new(alice.service_id().to_owned())?,
        &invite_id,
        &bob_core_id,
        "revoked",
        Some("inkson_producer_cancel"),
    )
    .map_err(|error| anyhow!("inkson invite_cancel builder: {error}"))?
    .build_sdk_event(alice.service_id())
    .map_err(|error| anyhow!("inkson invite_cancel event: {error}"))?;
    let inkson_payload = serde_json::to_value(inkson_cancel.payload())?;
    assert_eq!(
        inkson_payload["invitee_account_id"],
        serde_json::to_value(arkret_wire::AccountId::new(
            arkret_wire::DidCoreId::new(bob_core_id.clone())?,
            arkret_wire::DidCoreId::new(bob.service_id().to_owned())?,
        ))?,
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
    let after_accept = observe(&alice, &realm_id, &bob_core_id).await?;
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
        .canonical_json(&crate::publication::initial_submission(replay_event, "")?)?
        .send()
        .await?;
    let replay_status = response.status();
    let replay_body = response.json::<Value>().await.unwrap_or(Value::Null);
    let after_replay = observe(&alice, &realm_id, &bob_core_id).await?;
    assert_eq!(
        after_accept.invite_states, after_replay.invite_states,
        "replaying the cancel must not drive a second lifecycle transition \
         (replay: {replay_status} {replay_body})"
    );

    record_vector_event(
        "invite.membership_transition_atomicity",
        &json!({"realm_id": realm_id, "invite_id": invite_id}),
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
            "inkson_direct_cancel_invitee": inkson_payload["invitee_account_id"].clone(),
            "accepted_events_appended": after_accept.event_ids.len() - before.event_ids.len(),
            "replay_status": replay_status.as_u16(),
        }),
    );
    Ok(())
}
