use anyhow::{Result, anyhow};
use contrix_sdk::{Operation, OperationId, SpaceId};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{TestServerGroup, dev_login, expect_json, signed_commit};

pub async fn backfill_pages_recover_messages_missing_from_limited_client_page() -> Result<()> {
    let group = TestServerGroup::single("event-backfill").await?;
    let server = group.server(0);
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client("did:web:bob-backfill.example", "@bob-backfill", "dev_bob")
        .await?;

    let space_id = alice.create_space("Backfill Recovery Space").await?;
    alice.add_member(&space_id, &bob).await?;

    let sent = vec![
        alice
            .send_message(&space_id, "cx:thread:backfill", "first event before gap")
            .await?,
        alice
            .send_message(&space_id, "cx:thread:backfill", "second event inside gap")
            .await?,
        alice
            .send_message(&space_id, "cx:thread:backfill", "third event after gap")
            .await?,
    ];
    let expected_message_ids = sent
        .iter()
        .map(|event| {
            event["event_id"]
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| anyhow!("send response missing event_id: {event}"))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut cursor = None;
    let mut collected = Vec::new();
    for _ in 0..12 {
        let path = match cursor.as_deref() {
            Some(cursor) => {
                format!("/api/v1/sync/backfill?space_id={space_id}&limit=1&cursor={cursor}")
            }
            None => format!("/api/v1/sync/backfill?space_id={space_id}&limit=1"),
        };
        let page = expect_json(alice.get(&path), StatusCode::OK).await?;
        collected.extend(json_array(&page, "events")?.iter().cloned());
        if !page["limited"].as_bool().unwrap_or(false) {
            break;
        }
        cursor = page["next_cursor"].as_str().map(ToOwned::to_owned);
    }

    let recovered_message_ids = collected
        .iter()
        .filter(|event| event["event_type"] == "cx.message.create")
        .filter_map(|event| event["event_id"].as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    assert_eq!(recovered_message_ids, expected_message_ids);

    let bob_sync = bob.sync().await?;
    let synced_message_ids = json_array(&bob_sync["spaces"][&space_id]["timeline"], "events")?
        .iter()
        .filter_map(|event| event["event_id"].as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    for expected in expected_message_ids {
        assert!(synced_message_ids.contains(&expected));
    }

    Ok(())
}

pub async fn repo_entity_state_operations_are_submitted_and_backfilled() -> Result<()> {
    let group = TestServerGroup::single("entity-state").await?;
    let server = group.server(0);
    let alice = dev_login(server, "did:web:alice.example", "dev_alice").await?;
    let space_id = "cx:space:entity-state";
    let entity_id = "cx:entity:task-01";

    let create = entity_operation(
        "cx:operation:entity-create-01",
        "cx:event:entity-create-01",
        space_id,
        "cx.entity.create",
        json!({
            "id": entity_id,
            "entity_id": entity_id,
            "entity_type": "task",
            "title": "Backfilled task",
            "state": "active",
            "fields": {"status": "open"}
        }),
    )?;
    let update = entity_operation(
        "cx:operation:entity-update-01",
        "cx:event:entity-update-01",
        space_id,
        "cx.entity.update",
        json!({
            "id": entity_id,
            "entity_id": entity_id,
            "entity_type": "task",
            "title": "Backfilled task updated",
            "state": "archived",
            "fields": {"status": "archived"}
        }),
    )?;
    let delete = entity_operation(
        "cx:operation:entity-delete-01",
        "cx:event:entity-delete-01",
        space_id,
        "cx.entity.delete",
        json!({
            "id": entity_id,
            "entity_id": entity_id,
            "entity_type": "task",
            "state": "deleted"
        }),
    )?;
    let operations = vec![create.clone(), update.clone(), delete.clone()];
    let commit = signed_commit(
        "cx:commit:entity-state-01",
        "did:web:alice.example",
        1,
        &operations,
        None,
    )?;

    let submitted = expect_json(
        server
            .http()
            .post(server.url("/api/v1/repo/submit-commit"))
            .json(&json!({
                "repo_id": "did:web:alice.example",
                "expected_head": null,
                "operations": operations,
                "commit": commit
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(submitted["status"], "accepted");

    let backfill = expect_json(
        server
            .http()
            .get(server.url(&format!(
                "/api/v1/sync/backfill?space_id={space_id}&limit=10"
            )))
            .bearer_auth(&alice),
        StatusCode::OK,
    )
    .await?;
    let entity_events = json_array(&backfill, "events")?
        .iter()
        .filter(|event| {
            event["payload"]["entity_id"] == entity_id || event["payload"]["id"] == entity_id
        })
        .cloned()
        .collect::<Vec<_>>();
    let event_types = entity_events
        .iter()
        .map(|event| event["event_type"].as_str().unwrap_or_default().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        event_types,
        vec!["cx.entity.create", "cx.entity.update", "cx.entity.delete"]
    );
    assert_eq!(entity_events[0]["payload"]["state"], "active");
    assert_eq!(entity_events[1]["payload"]["state"], "archived");
    assert_eq!(entity_events[2]["payload"]["state"], "deleted");

    Ok(())
}

fn entity_operation(
    operation_id: &str,
    event_id: &str,
    space_id: &str,
    object_type: &str,
    mut payload: Value,
) -> Result<Operation> {
    payload["event_id"] = json!(event_id);
    Ok(Operation::create(
        OperationId::new(operation_id.to_owned())?,
        SpaceId::new(space_id.to_owned())?,
        object_type,
        payload,
    ))
}

fn json_array<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    value[field]
        .as_array()
        .ok_or_else(|| anyhow!("{field} is not an array: {value}"))
}
