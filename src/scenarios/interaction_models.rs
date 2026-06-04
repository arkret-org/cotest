use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::fixtures::TestActorBuilder;
use crate::harness::{CokretServer, expect_json, expect_response, expect_status};

pub async fn message_revision_reaction_marker_and_subscribe_work() -> Result<()> {
    let server = CokretServer::spawn("interaction-messages").await?;
    // Alice is the demo identity the server pre-seeds at boot; the builder is
    // for fresh accounts only.
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    // Bob / Carol / Dave are freshly registered via the builder. Default
    // derivations (`did:web:<bare-handle>.example` and `dev_<bare-handle>`)
    // would collide with other scenarios sharing the same server log dir, so
    // each gets an explicit `-interaction` suffix in the DID/device.
    let bob_actor = TestActorBuilder::new(&server, "@bob-interaction")
        .with_did("did:web:bob-interaction.example")
        .with_device("dev_bob")
        .create()
        .await?;
    let carol_actor = TestActorBuilder::new(&server, "@carol-interaction")
        .with_did("did:web:carol-interaction.example")
        .with_device("dev_carol")
        .create()
        .await?;
    let dave_actor = TestActorBuilder::new(&server, "@dave-interaction")
        .with_did("did:web:dave-interaction.example")
        .with_device("dev_dave")
        .create()
        .await?;
    let bob = bob_actor.client();
    let carol = carol_actor.client();
    let dave = dave_actor.client();

    let space_id = alice.create_realm("Interaction Model Space").await?;
    for member in [bob, carol, dave] {
        alice.add_member(&space_id, member).await?;
    }

    let sent = alice
        .send_message(&space_id, "ck:thread:interaction", "hello interaction")
        .await?;

    expect_status(
        server.http().get(server.url(&format!(
            "/_cokret/self/events/subscribe?spaces={space_id}&limit=1"
        ))),
        StatusCode::NOT_FOUND,
    )
    .await?;

    let subscribe_response = expect_response(
        alice.get(&format!(
            "/_cokret/self/events/subscribe?spaces={space_id}&limit=10"
        )),
        StatusCode::OK,
    )
    .await?;
    let subscribe_frames = ndjson_frames(&subscribe_response.text())?;
    assert!(
        subscribe_frames
            .iter()
            .any(|frame| frame["payload"]["event_id"] == sent["event_id"])
    );

    let reaction = bob
        .submit_event(
            &space_id,
            "ck.reaction.add",
            json!({
                "target_ref": sent["event_id"],
                "key": "like"
            }),
        )
        .await?;
    assert_eq!(reaction["status"], "accepted");

    let removed_reaction = carol
        .submit_event(
            &space_id,
            "ck.reaction.remove",
            json!({
                "target_ref": sent["event_id"],
                "key": "like"
            }),
        )
        .await?;
    assert_eq!(removed_reaction["status"], "accepted");

    // Per read-cursor.schema.json, a `kind="thread"` read scope references the
    // thread's root *message* (`ck:message:<uuidv7>`), not an opaque
    // `ck:thread:` string. Derive it from the root message's event id.
    let thread_root_ref = sent["event_id"]
        .as_str()
        .map(|event_id| event_id.replacen("ck:event:", "ck:message:", 1))
        .ok_or_else(|| anyhow::anyhow!("sent message missing event_id: {sent}"))?;
    let marker = dave
        .submit_event(
            &space_id,
            "ck.read_cursor.advance",
            json!({
                "id": sent["event_id"]
                    .as_str()
                    .expect("sent event id")
                    .replacen("ck:event:", "ck:read_cursor:", 1),
                "schema": "ck.schema.read_cursor.v1",
                "actor_id": dave.actor,
                "device_id": dave.device_id,
                "realm_id": space_id,
                "read_scope": {
                    "kind": "thread",
                    "ref": thread_root_ref
                },
                "position": {
                    "event_id": sent["event_id"],
                    "hlc": "019041000000-0001-1dae0001"
                },
                "updated_at": "2026-05-02T00:00:00Z"
            }),
        )
        .await?;
    assert_eq!(marker["status"], "accepted");
    assert_eq!(
        marker["event"]["payload"]["position"]["event_id"],
        sent["event_id"]
    );
    assert_eq!(marker["event"]["payload"]["read_scope"]["kind"], "thread");
    assert_eq!(
        marker["event"]["payload"]["read_scope"]["ref"],
        thread_root_ref
    );

    let markers = expect_json(
        dave.get(&format!("/_cokret/self/events?realms={space_id}&limit=50")),
        StatusCode::OK,
    )
    .await?;
    let marker_events = markers["events"]
        .as_array()
        .expect("events query response includes events")
        .iter()
        .filter(|event| {
            event["kind"] == "ck.read_cursor.advance"
                || event["event_kind"] == "ck.read_cursor.advance"
        })
        .collect::<Vec<_>>();
    assert!(
        marker_events.iter().any(|event| {
            event["payload"]["position"]["event_id"] == sent["event_id"]
                && event["payload"]["read_scope"]["ref"] == thread_root_ref
        }),
        "events query did not include accepted read cursor marker: {markers}"
    );

    let revised = alice
        .submit_event(
            &space_id,
            "ck.message.revise",
            json!({
                "body": "edited interaction",
                "content": {"body": "edited interaction"},
                "target_event_id": sent["event_id"],
                "thread_id": "ck:thread:interaction",
            }),
        )
        .await?;
    assert_ne!(revised["event_id"], sent["event_id"]);

    let redacted = alice
        .submit_event(
            &space_id,
            "ck.message.redact",
            json!({
                "target_event_id": sent["event_id"],
            }),
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
