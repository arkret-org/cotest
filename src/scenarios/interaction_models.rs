use anyhow::{Result, anyhow};
use arkret_identifiers::{EventId, MessageId, ReadCursorId};
use ed25519_dalek::SigningKey;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    events_query_for_realm, expect_json, expect_response, expect_status, message_redact_payload,
    message_revise_text_payload, next_typed_id,
};
use crate::scenarios::identity_test_support::{
    actor_did_for_service, authorize_device_public_key, spawn_with_harness_account_authority,
};

pub async fn message_revision_reaction_marker_and_subscribe_work() -> Result<()> {
    let server = spawn_with_harness_account_authority("interaction-messages", &[]).await?;
    let alice_did = actor_did_for_service(server.service_id(), "interaction-alice")?;
    let alice = server
        .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let alice_device_key = SigningKey::from_bytes(&[0xa1; 32]);
    authorize_device_public_key(
        &server,
        &alice.token,
        &alice.actor,
        &alice.device_id,
        &alice_device_key,
    )
    .await?;

    let bob_did = actor_did_for_service(server.service_id(), "interaction-bob")?;
    let bob = server
        .register_client(
            &bob_did,
            "@bob-interaction",
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;
    authorize_device_public_key(
        &server,
        &bob.token,
        &bob.actor,
        &bob.device_id,
        &SigningKey::from_bytes(&[0xb0; 32]),
    )
    .await?;

    let carol_did = actor_did_for_service(server.service_id(), "interaction-carol")?;
    let carol = server
        .register_client(
            &carol_did,
            "@carol-interaction",
            "ak:device:01904100-0000-7000-8000-000000000ca0",
        )
        .await?;
    authorize_device_public_key(
        &server,
        &carol.token,
        &carol.actor,
        &carol.device_id,
        &SigningKey::from_bytes(&[0xca; 32]),
    )
    .await?;

    let dave_did = actor_did_for_service(server.service_id(), "interaction-dave")?;
    let dave = server
        .register_client(
            &dave_did,
            "@dave-interaction",
            "ak:device:01904100-0000-7000-8000-000000000da0",
        )
        .await?;
    authorize_device_public_key(
        &server,
        &dave.token,
        &dave.actor,
        &dave.device_id,
        &SigningKey::from_bytes(&[0xda; 32]),
    )
    .await?;

    let realm_id = alice.create_realm("Interaction Model Realm").await?;
    let strand_id = alice.default_strand_id(&realm_id)?;
    for member in [&bob, &carol, &dave] {
        alice.add_member(&realm_id, member).await?;
    }
    alice
        .grant_realm_actions_to_client(&realm_id, &bob, &["ak.reaction.add"])
        .await?;
    alice
        .grant_realm_actions_to_client(&realm_id, &carol, &["ak.reaction.remove"])
        .await?;

    let sent = alice
        .send_message(&realm_id, &strand_id, "hello interaction")
        .await?;

    expect_status(
        server.http().get(server.url(&format!(
            "/_arkret/self/events/subscribe?realms={realm_id}&limit=1"
        ))),
        StatusCode::NOT_FOUND,
    )
    .await?;

    // A bare subscribe is live-only, and catch-up replay needs an `after`
    // resume cursor minted by the stream itself. Cover both legs: hold a
    // bounded live stream open while submitting a follow-up (live delivery),
    // then replay past that follow-up's own cursor with catchup=true.
    let live_subscribe = expect_response(
        alice.get(&format!(
            "/_arkret/self/events/subscribe?realms={realm_id}&max_duration_ms=2500&heartbeat_ms=200"
        )),
        StatusCode::OK,
    );
    let delayed_followup = async {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        alice
            .send_message(&realm_id, &strand_id, "hello live stream")
            .await
    };
    let (subscribe_response, followup) = tokio::join!(live_subscribe, delayed_followup);
    let (subscribe_response, followup) = (subscribe_response?, followup?);
    let subscribe_frames = ndjson_frames(&subscribe_response.text())?;
    let live_frame = subscribe_frames
        .iter()
        .find(|frame| frame["payload"]["event_id"] == followup["event_id"])
        .ok_or_else(|| {
            anyhow!("live subscribe must deliver the follow-up event: {subscribe_frames:?}")
        })?;
    let resume_cursor = live_frame["cursor"]
        .as_str()
        .ok_or_else(|| anyhow!("live event frame must mint a resume cursor: {live_frame}"))?
        .to_owned();

    let catchup_target = alice
        .send_message(&realm_id, &strand_id, "hello catchup")
        .await?;
    let catchup_response = expect_response(
        alice.get(&format!(
            "/_arkret/self/events/subscribe?realms={realm_id}&after={resume_cursor}&catchup=true&max_duration_ms=1500&heartbeat_ms=200"
        )),
        StatusCode::OK,
    )
    .await?;
    let catchup_frames = ndjson_frames(&catchup_response.text())?;
    assert!(
        catchup_frames
            .iter()
            .any(|frame| frame["payload"]["event_id"] == catchup_target["event_id"]),
        "catch-up replay must deliver the follow-up event: {catchup_frames:?}"
    );
    assert!(
        catchup_frames
            .iter()
            .any(|frame| frame["kind"] == "catchup_complete"),
        "catch-up replay must emit catchup_complete: {catchup_frames:?}"
    );

    let reaction = bob
        .submit_event(
            &realm_id,
            "ak.reaction.add",
            json!({
                "target_ref": sent["event_id"],
                "key": "like"
            }),
        )
        .await?;
    assert_eq!(reaction["status"], "accepted");

    let removed_reaction = carol
        .submit_event(
            &realm_id,
            "ak.reaction.remove",
            json!({
                "target_ref": sent["event_id"],
                "key": "like"
            }),
        )
        .await?;
    assert_eq!(removed_reaction["status"], "accepted");

    // Per read-cursor.schema.json, a `kind="thread"` read scope references the
    // thread's root *message* (`ak:message:<event-token>`), not an opaque
    // `ak:thread:` string. Derive it from the root message's event id.
    let thread_root_event_id = sent["event_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("sent message missing event_id: {sent}"))?;
    let thread_root_ref =
        MessageId::from_event_id(&EventId::new(thread_root_event_id)?).to_string();
    let read_cursor_id = ReadCursorId::new(next_typed_id("read_cursor"))?;
    let marker = dave
        .submit_event(
            &realm_id,
            "ak.read_cursor.advance",
            json!({
                "id": read_cursor_id,
                "schema": "ak.schema.read_cursor.v1",
                "actor_id": dave.actor,
                "device_id": dave.device_id,
                "realm_id": realm_id,
                "read_scope": {
                    "kind": "thread",
                    "container_ref": thread_root_ref
                },
                "position": {
                    "event_id": sent["event_id"],
                    "hlc": "019041000000-0001-1dae0001"
                },
                "updated_at": "2026-05-02T00:00:00.000Z"
            }),
        )
        .await?;
    assert_eq!(marker["status"], "accepted");
    let marker_event_id = marker["event_id"]
        .as_str()
        .ok_or_else(|| anyhow!("read cursor submit response missing event_id: {marker}"))?;

    let markers = expect_json(
        dave.query("/_arkret/self/events")
            .json(&events_query_for_realm(&realm_id, 50)?),
        StatusCode::OK,
    )
    .await?;
    let marker_events = markers["events"]
        .as_array()
        .expect("events query response includes events")
        .iter()
        .filter(|event| {
            event["kind"] == "ak.read_cursor.advance"
                || event["event_kind"] == "ak.read_cursor.advance"
        })
        .collect::<Vec<_>>();
    assert!(
        marker_events.iter().any(|event| {
            event["event_id"] == marker_event_id
                && event["payload"]["position"]["event_id"] == sent["event_id"]
                && event["payload"]["read_scope"]["container_ref"] == thread_root_ref
                && event["payload"]["read_scope"]["kind"] == "thread"
        }),
        "events query did not include accepted read cursor marker: {markers}"
    );

    let sent_event_id = sent["event_id"]
        .as_str()
        .ok_or_else(|| anyhow!("sent message missing event_id: {sent}"))?;
    let revised = alice
        .submit_event(
            &realm_id,
            "ak.message.revise",
            message_revise_text_payload(sent_event_id, "edited interaction")?,
        )
        .await?;
    assert_ne!(revised["event_id"], sent["event_id"]);

    let redacted = alice
        .submit_event(
            &realm_id,
            "ak.message.redact",
            message_redact_payload(sent_event_id, None)?,
        )
        .await?;
    assert_eq!(redacted["status"], "accepted");

    Ok(())
}

fn ndjson_frames(body: &str) -> Result<Vec<Value>> {
    let mut frames = Vec::new();
    for line in body.lines().map(str::trim).filter(|line| !line.is_empty()) {
        frames.push(serde_json::from_str(line)?);
    }
    if frames.is_empty() {
        return Err(anyhow!("events subscribe response did not include frames"));
    }
    Ok(frames)
}
