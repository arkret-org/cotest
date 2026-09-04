use anyhow::{Result, anyhow};
use arkret_identifiers::MessageId;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    actor_core_id, events_query_for_realm, expect_json, expect_response, expect_status,
    message_redact_payload, message_revise_text_payload, submitted_event_id,
};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, spawn_with_harness_account_authority,
};

pub async fn message_revision_reaction_marker_and_subscribe_work() -> Result<()> {
    let server = spawn_with_harness_account_authority("interaction-messages", &[]).await?;
    let alice_did = actor_did_for_service_did(server.service_did(), "interaction-alice")?;
    let alice = server
        .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;

    let bob_did = actor_did_for_service_did(server.service_did(), "interaction-bob")?;
    let bob = server
        .register_client(
            &bob_did,
            "@bob-interaction",
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;

    let carol_did = actor_did_for_service_did(server.service_did(), "interaction-carol")?;
    let carol = server
        .register_client(
            &carol_did,
            "@carol-interaction",
            "ak:device:01904100-0000-7000-8000-000000000ca0",
        )
        .await?;

    let dave_did = actor_did_for_service_did(server.service_did(), "interaction-dave")?;
    let dave = server
        .register_client(
            &dave_did,
            "@dave-interaction",
            "ak:device:01904100-0000-7000-8000-000000000da0",
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
    let sent_event_id = submitted_event_id(&sent)?;

    expect_status(
        server.http().get(server.url(&format!(
            "/_arkret/self/events/subscribe?realm_ids={realm_id}&limit=1"
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
            "/_arkret/self/events/subscribe?realm_ids={realm_id}&max_duration_ms=2500&heartbeat_ms=200"
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
    let followup_event_id = submitted_event_id(&followup)?;
    let subscribe_frames = ndjson_frames(&subscribe_response.text())?;
    let live_frame = subscribe_frames
        .iter()
        .find(|frame| frame["payload"]["event_id"].as_str() == Some(followup_event_id.as_str()))
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
    let catchup_target_event_id = submitted_event_id(&catchup_target)?;
    let catchup_response = expect_response(
        alice.get(&format!(
            "/_arkret/self/events/subscribe?realm_ids={realm_id}&after={resume_cursor}&catchup=true&max_duration_ms=1500&heartbeat_ms=200"
        )),
        StatusCode::OK,
    )
    .await?;
    let catchup_frames = ndjson_frames(&catchup_response.text())?;
    assert!(
        catchup_frames.iter().any(|frame| {
            frame["payload"]["event_id"].as_str() == Some(catchup_target_event_id.as_str())
        }),
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
                "target_ref": sent_event_id,
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
                "target_ref": sent_event_id,
                "key": "like"
            }),
        )
        .await?;
    assert_eq!(removed_reaction["status"], "accepted");

    // Per read-cursor.schema.json, a `kind="thread"` read scope references the
    // thread's root *message* (`ak:message:<event-token>`), not an opaque
    // `ak:thread:` string. Derive it from the root message's event id.
    let thread_root_ref = MessageId::from_event_id(&sent_event_id).to_string();
    let dave_actor_id = arkret_wire::ActorId::account(arkret_wire::AccountId::new(
        arkret_wire::DidCoreId::new(actor_core_id(&dave.actor)?)?,
        server.service_id().clone(),
    ));
    // `ak.read_cursor.advance` is actor-private (read-receipts.md §6.6): it is
    // submitted through `ak.self.read_cursor.command.advance.v1`, read back
    // from `/_arkret/self/read-cursors`, and MUST NOT enter the shared Realm
    // timeline -- not even for the cursor's own owner. The three assertions
    // below are that contract: accepted on the self surface, visible on the
    // self surface, absent from the Realm surface.
    let marker = dave
        .advance_read_cursor(
            &realm_id,
            json!({
                "schema": "ak.schema.read_cursor.v1",
                "actor_id": dave_actor_id,
                "device_id": dave.device_id,
                "realm_id": realm_id,
                "read_scope": {
                    "kind": "thread",
                    "container_ref": thread_root_ref
                },
                "position": {
                    "event_id": sent_event_id,
                    "hlc": "019041000000-0001-1dae0001"
                }
            }),
        )
        .await?;
    assert_eq!(
        marker["read_scope"]["container_ref"], thread_root_ref,
        "read marker outcome names the thread root: {marker}"
    );
    assert_eq!(
        marker["position"]["event_id"].as_str(),
        Some(sent_event_id.as_str()),
        "read marker outcome carries the acknowledged position: {marker}"
    );

    let markers = dave.read_cursors(&realm_id).await?;
    assert!(
        markers["markers"]
            .as_array()
            .expect("read cursor list response includes markers")
            .iter()
            .any(|entry| {
                entry["read_scope"]["kind"] == "thread"
                    && entry["read_scope"]["container_ref"] == thread_root_ref
                    && entry["position"]["event_id"].as_str() == Some(sent_event_id.as_str())
                    && entry["device_id"].as_str() == Some(dave.device_id.as_str())
            }),
        "actor-private read cursor surface did not return the accepted marker: {markers}"
    );

    let realm_events = expect_json(
        dave.query("/_arkret/self/events")
            .json(&events_query_for_realm(&realm_id, 50)?),
        StatusCode::OK,
    )
    .await?;
    let leaked = realm_events["events"]
        .as_array()
        .expect("events query response includes events")
        .iter()
        .filter(|event| {
            event["kind"] == "ak.read_cursor.advance"
                || event["event_kind"] == "ak.read_cursor.advance"
        })
        .collect::<Vec<_>>();
    assert!(
        leaked.is_empty(),
        "shared Realm query leaked actor-private read cursor Events: {leaked:?}"
    );

    let revised = alice
        .submit_event(
            &realm_id,
            "ak.message.revise",
            message_revise_text_payload(sent_event_id.as_str(), "edited interaction")?,
        )
        .await?;
    let revised_event_id = submitted_event_id(&revised)?;
    assert_ne!(revised_event_id, sent_event_id);

    let redacted = alice
        .submit_event(
            &realm_id,
            "ak.message.redact",
            message_redact_payload(sent_event_id.as_str(), None)?,
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
