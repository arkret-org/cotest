use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{TestServerGroup, event_envelope, expect_json};

pub async fn duplicate_event_submit_is_idempotent_and_projects_once() -> Result<()> {
    let group = TestServerGroup::single("event-idempotency-replay").await?;
    let server = group.server(0);
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let space_id = alice.create_space("Event Idempotency Replay").await?;
    let event = event_envelope(
        &alice.actor,
        &space_id,
        "cx.message.create",
        json!({
            "flow_id": "cx:flow:01999999-0000-7000-8000-00000000feed",
            "track": "discussion",
            "content": {
                "kind": "cx.content.text",
                "body": "idempotent replay body",
                "format": "plain",
            },
        }),
    );

    let first = expect_json(alice.post("/api/v1/events").json(&event), StatusCode::OK).await?;
    assert_eq!(first["status"], "accepted");
    let event_id = first["event_id"]
        .as_str()
        .ok_or_else(|| anyhow!("accepted response missing event_id: {first}"))?;
    assert_eq!(event_id, json_string(&event, "event_id")?);

    let duplicate = expect_json(alice.post("/api/v1/events").json(&event), StatusCode::OK).await?;
    assert_eq!(duplicate["status"], "duplicate");
    assert_eq!(duplicate["event_id"], first["event_id"]);
    assert_eq!(duplicate["receipt"]["idempotent"], true);

    let listed = expect_json(
        alice
            .get(&format!("/api/v1/events?spaces={space_id}"))
            .query(&[("limit", "100")]),
        StatusCode::OK,
    )
    .await?;
    let matching_events = listed["events"]
        .as_array()
        .ok_or_else(|| anyhow!("events query response missing events array: {listed}"))?
        .iter()
        .filter(|event| event["event_id"].as_str() == Some(event_id))
        .count();
    assert_eq!(
        matching_events, 1,
        "events query should project the idempotent event exactly once: {listed}"
    );

    Ok(())
}

fn json_string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| anyhow!("{field} is not a string: {value}"))
}
