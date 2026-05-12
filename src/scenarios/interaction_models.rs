use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{ContrixServer, expect_json, expect_status};

pub async fn message_revision_reaction_marker_and_subscribe_work() -> Result<()> {
    let server = ContrixServer::spawn("interaction-messages").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client(
            "did:web:bob-interaction.example",
            "@bob-interaction",
            "dev_bob",
        )
        .await?;
    let carol = server
        .register_client(
            "did:web:carol-interaction.example",
            "@carol-interaction",
            "dev_carol",
        )
        .await?;
    let dave = server
        .register_client(
            "did:web:dave-interaction.example",
            "@dave-interaction",
            "dev_dave",
        )
        .await?;

    let space_id = alice.create_space("Interaction Model Space").await?;
    for member in [&bob, &carol, &dave] {
        alice.add_member(&space_id, member).await?;
    }

    let sent = alice
        .send_message(&space_id, "cx:thread:interaction", "hello interaction")
        .await?;

    expect_status(
        server.http().get(server.url(&format!(
            "/api/v1/events/subscribe?spaces={space_id}&limit=1"
        ))),
        StatusCode::NOT_FOUND,
    )
    .await?;

    let subscribe = expect_json(
        alice.get(&format!(
            "/api/v1/events/subscribe?spaces={space_id}&limit=10"
        )),
        StatusCode::OK,
    )
    .await?;
    assert!(
        subscribe["frames"]
            .as_array()
            .unwrap()
            .iter()
            .any(|frame| frame["payload"]["event_id"] == sent["event_id"])
    );

    let reaction = bob
        .submit_event(
            &space_id,
            "cx.reaction.add",
            json!({
            "actor": bob.actor,
            "event_id": sent["event_id"],
            "key": "like"
            }),
        )
        .await?;
    assert_eq!(reaction["event_id"], sent["event_id"]);

    let removed_reaction = carol
        .submit_event(
            &space_id,
            "cx.reaction.remove",
            json!({
            "actor": carol.actor,
            "event_id": sent["event_id"],
            "key": "like"
            }),
        )
        .await?;
    assert_eq!(removed_reaction["status"], "accepted");

    let marker = expect_json(
        dave.post("/api/v1/read-markers").json(&json!({
            "space_id": space_id,
            "event_id": sent["event_id"],
            "scope_id": "cx:thread:interaction"
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(marker["event_id"], sent["event_id"]);
    assert_eq!(marker["scope_id"], "cx:thread:interaction");

    let markers = expect_json(
        dave.get(&format!("/api/v1/read-markers?space_id={space_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(markers["markers"].as_array().unwrap().len(), 1);
    assert_eq!(markers["markers"][0]["event_id"], sent["event_id"]);

    let revised = alice
        .submit_event(
            &space_id,
            "cx.message.revise",
            json!({
                "body": "edited interaction",
                "content": {"body": "edited interaction"},
                "target_event_id": sent["event_id"],
                "thread_id": "cx:thread:interaction",
            }),
        )
        .await?;
    assert_ne!(revised["event_id"], sent["event_id"]);

    let redacted = alice
        .submit_event(
            &space_id,
            "cx.message.redact",
            json!({
                "target_event_id": sent["event_id"],
            }),
        )
        .await?;
    assert_eq!(redacted["status"], "accepted");

    Ok(())
}
