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
            "/api/v1/sync/subscribe?space_id={space_id}&limit=1"
        ))),
        StatusCode::NOT_FOUND,
    )
    .await?;

    let subscribe = expect_json(
        alice.get(&format!(
            "/api/v1/sync/subscribe?space_id={space_id}&limit=10"
        )),
        StatusCode::OK,
    )
    .await?;
    assert!(
        subscribe["frames"]
            .as_array()
            .unwrap()
            .iter()
            .any(|frame| frame["payload"]["operation_id"] == sent["operation_id"])
    );

    let reaction = expect_json(
        bob.post("/api/v1/reactions").json(&json!({
            "space_id": space_id,
            "event_id": sent["event_id"],
            "key": "like"
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(reaction["event_id"], sent["event_id"]);
    assert_eq!(reaction["actor"], bob.actor);
    assert_eq!(reaction["active"], true);

    let removed_reaction = expect_json(
        carol.delete("/api/v1/reactions").json(&json!({
            "space_id": space_id,
            "event_id": sent["event_id"],
            "key": "like"
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(removed_reaction["actor"], carol.actor);
    assert_eq!(removed_reaction["active"], false);

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

    let revised = expect_json(
        alice.post("/api/v1/messages/revise").json(&json!({
            "event_id": sent["event_id"],
            "content": {"body": "edited interaction"}
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(revised["revision_of"], sent["event_id"]);
    assert_ne!(revised["event_id"], sent["event_id"]);

    let thread_after_revise = expect_json(
        alice.get("/api/v1/index/thread?thread_id=cx:thread:interaction"),
        StatusCode::OK,
    )
    .await?;
    assert!(
        thread_after_revise["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| {
                event["event_id"] == revised["event_id"]
                    && event["content"]["body"] == "edited interaction"
            })
    );

    let redacted = expect_json(
        alice.post("/api/v1/messages/redact").json(&json!({
            "event_id": sent["event_id"]
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(redacted["redacted"], true);
    assert_eq!(redacted["event_id"], sent["event_id"]);

    let thread_after_redact = expect_json(
        alice.get("/api/v1/index/thread?thread_id=cx:thread:interaction"),
        StatusCode::OK,
    )
    .await?;
    assert!(
        thread_after_redact["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|event| event["event_id"] != sent["event_id"])
    );
    assert!(
        thread_after_redact["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event_id"] == revised["event_id"])
    );

    Ok(())
}

pub async fn entity_relation_and_view_endpoints_work() -> Result<()> {
    let server = ContrixServer::spawn("interaction-models").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client("did:web:bob-entity.example", "@bob-entity", "dev_bob")
        .await?;
    let carol = server
        .register_client("did:web:carol-entity.example", "@carol-entity", "dev_carol")
        .await?;
    let dave = server
        .register_client("did:web:dave-entity.example", "@dave-entity", "dev_dave")
        .await?;
    let eve = server
        .register_client("did:web:eve-entity.example", "@eve-entity", "dev_eve")
        .await?;
    let space_id = alice.create_space("Entity Relation View Space").await?;
    for member in [&bob, &carol, &dave, &eve] {
        alice.add_member(&space_id, member).await?;
    }

    expect_status(
        alice.post("/api/v1/entities").json(&json!({
            "space_id": space_id,
            "entity_type": "todo",
            "title": "Invalid"
        })),
        StatusCode::BAD_REQUEST,
    )
    .await?;

    let channel = expect_json(
        alice.post("/api/v1/entities").json(&json!({
            "space_id": space_id,
            "entity_type": "cx.channel",
            "title": "Support",
            "content": {"status": "active"},
            "fields": {"kind": "channel"}
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(channel["entity_type"], "cx.channel");

    let widget = expect_json(
        alice.post("/api/v1/entities").json(&json!({
            "space_id": space_id,
            "entity_type": "com.example.widget",
            "title": "Custom widget",
            "content": {"status": "active"},
            "fields": {"kind": "widget"}
        })),
        StatusCode::OK,
    )
    .await?;
    let widget_id = widget["entity_id"].as_str().unwrap().to_owned();

    let task_one = expect_json(
        alice.post("/api/v1/entities").json(&json!({
            "space_id": space_id,
            "entity_type": "cx.task",
            "title": "Draft spec",
            "content": {"description": "Draft spec"},
            "fields": {
                "status": "todo",
                "due_at": "2026-05-01T00:00:00Z",
                "priority": 2
            }
        })),
        StatusCode::OK,
    )
    .await?;
    let task_two = expect_json(
        alice.post("/api/v1/entities").json(&json!({
            "space_id": space_id,
            "entity_type": "cx.task",
            "title": "Ship reducer",
            "content": {"description": "Ship reducer"},
            "fields": {
                "status": "done",
                "due_at": "2026-05-02T00:00:00Z",
                "priority": 1
            }
        })),
        StatusCode::OK,
    )
    .await?;

    let channels = expect_json(
        alice.get(&format!(
            "/api/v1/entities?space_id={space_id}&entity_type=cx.channel"
        )),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(channels["entities"].as_array().unwrap().len(), 1);

    let fetched_widget = expect_json(
        alice.get(&format!("/api/v1/entities/{widget_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(fetched_widget["entity_type"], "com.example.widget");

    let updated_widget = expect_json(
        server
            .http()
            .patch(bob.url(&format!("/api/v1/entities/{widget_id}")))
            .bearer_auth(&bob.token)
            .json(&json!({
                "title": "Custom widget updated",
                "content": {"status": "updated"},
                "fields": {"kind": "widget", "version": 2}
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(updated_widget["title"], "Custom widget updated");
    assert_eq!(updated_widget["fields"]["version"], 2);

    let relation = expect_json(
        carol.post("/api/v1/relations").json(&json!({
            "space_id": space_id,
            "relation_kind": "depends_on",
            "from": task_one["entity_id"],
            "to": task_two["entity_id"],
            "fields": {"weight": 1}
        })),
        StatusCode::OK,
    )
    .await?;
    let relation_id = relation["relation_id"].as_str().unwrap().to_owned();
    assert_eq!(relation["relation_kind"], "depends_on");

    let relations = expect_json(
        alice.get(&format!(
            "/api/v1/relations?space_id={space_id}&kind=depends_on"
        )),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(relations["relations"].as_array().unwrap().len(), 1);

    let kanban = expect_json(
        alice.post("/api/v1/views").json(&json!({
            "space_id": space_id,
            "kind": "kanban",
            "title": "Task board",
            "entity_type": "cx.task",
            "options": {"group_by": "status"}
        })),
        StatusCode::OK,
    )
    .await?;
    let kanban_view_id = kanban["view_id"].as_str().unwrap().to_owned();
    assert_eq!(kanban["projection"]["kind"], "kanban");
    assert_eq!(kanban["projection"]["group_by"], "status");
    assert_eq!(kanban["projection"]["columns"].as_array().unwrap().len(), 2);

    let calendar = expect_json(
        alice.post("/api/v1/views").json(&json!({
            "space_id": space_id,
            "kind": "calendar",
            "entity_type": "cx.task",
            "options": {"date_field": "due_at"}
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(calendar["projection"]["kind"], "calendar");
    assert_eq!(
        calendar["projection"]["events"].as_array().unwrap().len(),
        2
    );

    let timeline = expect_json(
        alice.get(&format!(
            "/api/v1/views/{kanban_view_id}?space_id={space_id}&entity_type=cx.task&kind=timeline"
        )),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(timeline["projection"]["kind"], "timeline");
    assert_eq!(timeline["projection"]["items"].as_array().unwrap().len(), 2);

    expect_status(
        alice.post("/api/v1/views").json(&json!({
            "space_id": space_id,
            "kind": "graph",
            "entity_type": "cx.task"
        })),
        StatusCode::BAD_REQUEST,
    )
    .await?;

    let deleted_relation = expect_json(
        dave.delete(&format!("/api/v1/relations/{relation_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(deleted_relation["deleted"], true);

    let relations_after_delete = expect_json(
        alice.get(&format!(
            "/api/v1/relations?space_id={space_id}&kind=depends_on"
        )),
        StatusCode::OK,
    )
    .await?;
    assert!(
        relations_after_delete["relations"]
            .as_array()
            .unwrap()
            .is_empty()
    );

    let deleted_widget = expect_json(
        eve.delete(&format!("/api/v1/entities/{widget_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(deleted_widget["deleted"], true);

    expect_status(
        alice.get(&format!("/api/v1/entities/{widget_id}")),
        StatusCode::NOT_FOUND,
    )
    .await?;

    Ok(())
}
