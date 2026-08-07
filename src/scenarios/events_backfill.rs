use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::fixtures::TestActorBuilder;
use crate::harness::{TestServerGroup, expect_json};

pub async fn backfill_pages_recover_messages_missing_from_limited_client_page() -> Result<()> {
    let group = TestServerGroup::single("event-backfill").await?;
    let server = group.server(0);
    // Alice is seeded as the existing demo identity (the harness pre-registers
    // `did:web:alice.example` at server boot), so the builder shape uses
    // `demo_client` directly here. Bob is freshly created via the builder so
    // we can demonstrate the new fixture surface in a real scenario.
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let bob = TestActorBuilder::new(server, "@bob-backfill")
        .with_did("did:web:bob-backfill.example")
        .with_device("ak:device:01904100-0000-7000-8000-0000000000b0")
        .create()
        .await?;
    let bob_client = bob.client();

    let realm_id = alice.create_realm("Backfill Recovery Realm").await?;
    alice.add_member(&realm_id, bob_client).await?;

    let sent = [
        alice
            .send_message(&realm_id, "ak:thread:backfill", "first event before gap")
            .await?,
        alice
            .send_message(&realm_id, "ak:thread:backfill", "second event inside gap")
            .await?,
        alice
            .send_message(&realm_id, "ak:thread:backfill", "third event after gap")
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
        let body = json!({"realms": [realm_id], "limit": 1, "after": cursor});
        let page = expect_json(
            alice.query("/_arkret/self/events").json(&body),
            StatusCode::OK,
        )
        .await?;
        collected.extend(json_array(&page, "events")?.iter().cloned());
        if !page["has_more"]
            .as_bool()
            .or_else(|| page["limited"].as_bool())
            .unwrap_or(false)
        {
            break;
        }
        cursor = page["next_cursor"].as_str().map(ToOwned::to_owned);
    }

    let recovered_message_ids = collected
        .iter()
        .filter(|event| event_kind(event) == Some("ak.message.create"))
        .filter_map(|event| event["event_id"].as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    assert_eq!(
        recovered_message_ids, expected_message_ids,
        "events backfill did not recover projected messages from collected pages: {collected:#?}"
    );

    let bob_sync = bob_client.sync().await?;
    let synced_message_ids = json_array(&bob_sync["realms"][&realm_id]["timeline"], "events")?
        .iter()
        .filter_map(|event| event["event_id"].as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    for expected in expected_message_ids {
        assert!(synced_message_ids.contains(&expected));
    }

    Ok(())
}

fn event_kind(event: &Value) -> Option<&str> {
    event["kind"]
        .as_str()
        .or_else(|| event["event_kind"].as_str())
}

fn json_array<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    value[field]
        .as_array()
        .ok_or_else(|| anyhow!("{field} is not an array: {value}"))
}
