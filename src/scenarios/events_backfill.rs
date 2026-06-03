use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::Value;

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
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = TestActorBuilder::new(server, "@bob-backfill")
        .with_did("did:web:bob-backfill.example")
        .with_device("dev_bob")
        .create()
        .await?;
    let bob_client = bob.client();

    let space_id = alice.create_realm("Backfill Recovery Space").await?;
    alice.add_member(&space_id, bob_client).await?;

    let sent = [
        alice
            .send_message(&space_id, "ck:thread:backfill", "first event before gap")
            .await?,
        alice
            .send_message(&space_id, "ck:thread:backfill", "second event inside gap")
            .await?,
        alice
            .send_message(&space_id, "ck:thread:backfill", "third event after gap")
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
                format!("/_cokret/self/events?realms={space_id}&limit=1&after={cursor}")
            }
            None => format!("/_cokret/self/events?realms={space_id}&limit=1"),
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
        .filter(|event| event["event_kind"] == "ck.message.create")
        .filter_map(|event| event["event_id"].as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    assert_eq!(
        recovered_message_ids, expected_message_ids,
        "events backfill did not recover projected messages from collected pages: {collected:#?}"
    );

    let bob_sync = bob_client.sync().await?;
    let synced_message_ids = json_array(&bob_sync["realms"][&space_id]["timeline"], "events")?
        .iter()
        .filter_map(|event| event["event_id"].as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    for expected in expected_message_ids {
        assert!(synced_message_ids.contains(&expected));
    }

    Ok(())
}

fn json_array<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>> {
    value[field]
        .as_array()
        .ok_or_else(|| anyhow!("{field} is not an array: {value}"))
}
