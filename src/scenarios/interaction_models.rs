use anyhow::Result;
use arkret_identifiers::MessageId;
use arkret_wire::{CommitStreamRef, RealmId};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    actor_core_id, expect_json, message_redact_payload, message_revise_text_payload,
    submitted_event_id,
};
use crate::publication::initial_submission;
use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, spawn_with_harness_account_authority,
};

pub async fn message_revision_reaction_marker_and_scan_work() -> Result<()> {
    let server = spawn_with_harness_account_authority("interaction-messages", &[]).await?;
    let alice_did = actor_did_for_service_did(server.service_did(), "interaction-alice")?;
    let alice = server
        .standard_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;

    let bob_did = actor_did_for_service_did(server.service_did(), "interaction-bob")?;
    let bob = server
        .standard_register_client(
            &bob_did,
            "@bob-interaction",
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;

    let carol_did = actor_did_for_service_did(server.service_did(), "interaction-carol")?;
    let carol = server
        .standard_register_client(
            &carol_did,
            "@carol-interaction",
            "ak:device:01904100-0000-7000-8000-000000000ca0",
        )
        .await?;

    let dave_did = actor_did_for_service_did(server.service_did(), "interaction-dave")?;
    let dave = server
        .standard_register_client(
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

    // The registered single-stream scan is the catch-up surface. A later
    // write must appear as a committed Event in the same Realm stream.
    let followup = alice
        .send_message(&realm_id, &strand_id, "hello stream scan")
        .await?;
    let followup_event_id = submitted_event_id(&followup)?;
    let realm = RealmId::new(realm_id.clone())?;
    let stream_ref = CommitStreamRef::Realm {
        realm_id: realm.clone(),
    };
    let scanned = alice
        .sdk()
        .scan_commit_stream_to_head(realm.clone(), stream_ref.clone(), None, 100)
        .await?;
    assert!(
        scanned.committed_events.iter().any(|item| {
            item.reducer_input()
                .is_some_and(|event| event.event_id == followup_event_id)
        }),
        "stream scan must return the follow-up committed Event"
    );

    // strand-and-message.md section 9.8: a reaction targets the accepted
    // `ak:message:` in its own scope and is admitted at the same cut with the
    // actor's `ak.reaction.add` / `ak.reaction.remove` grant. A remove is
    // self-scoped and needs no prior add of its own.
    let message_ref = MessageId::from_event_id(&sent_event_id).to_string();
    let reacted = bob
        .submit_event(
            &realm_id,
            "ak.reaction.add",
            json!({
                "target_ref": message_ref,
                "key": "like"
            }),
        )
        .await?;
    assert_eq!(reacted["status"], "committed");
    let removed = carol
        .submit_event(
            &realm_id,
            "ak.reaction.remove",
            json!({
                "target_ref": message_ref,
                "key": "like"
            }),
        )
        .await?;
    assert_eq!(removed["status"], "committed");

    // v1 core rejects every non-Message target as a schema violation.
    let strand_reaction = bob
        .author_event(
            &realm_id,
            "ak.reaction.add",
            json!({
                "target_ref": strand_id,
                "key": "like"
            }),
        )
        .await?;
    expect_json(
        bob.post("/_arkret/self/events")
            .json(&initial_submission(strand_reaction, "")?),
        StatusCode::UNPROCESSABLE_ENTITY,
    )
    .await?;

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

    let realm_events = dave
        .sdk()
        .scan_commit_stream_to_head(realm, stream_ref, None, 100)
        .await?;
    let leaked = realm_events
        .committed_events
        .iter()
        .filter_map(|item| item.reducer_input())
        .filter(|event| event.kind.as_str() == "ak.read_cursor.advance")
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
    assert_eq!(redacted["status"], "committed");

    Ok(())
}
