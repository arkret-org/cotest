//! Account-private cursor convergence on genuinely paired accepted devices.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::device_messages::RecipientDelivery;
use arkret_models_collaboration::objects::read_receipts::{
    ReadCursorAdvanceRequestBody, ReadCursorList, ReadCursorPosition, ReadMarkerResponseBody,
};
use arkret_wire::{ActorId, EventAdmissionSubmission, EventId, ReadCursorScope, RealmId};
use serde_json::json;

use crate::harness::TestActorClient;

pub(crate) async fn list(client: &TestActorClient, realm: &RealmId) -> Result<ReadCursorList> {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("realm_id", realm.as_str())
        .finish();
    Ok(client
        .sdk()
        .get(&format!("/_arkret/self/read-cursors?{query}"))
        .await?)
}

pub(crate) async fn advance(
    client: &TestActorClient,
    realm: &RealmId,
    scope: &ReadCursorScope,
    position: &ReadCursorPosition,
) -> Result<ReadMarkerResponseBody> {
    let principal = client
        .principal
        .as_ref()
        .context("cursor requires the actual accepted Device")?;
    let event = client.author_event(realm.as_str(),"ak.read_cursor.advance",json!({
        "schema":"ak.schema.read_cursor.v1","actor_id":ActorId::account(arkret_wire::AccountId::new(principal.core_id.clone(), client.service_id().parse()?)),
        "device_id":principal.device_id,"realm_id":realm,"read_scope":scope,"position":position
    })).await?;
    let outcome: ReadMarkerResponseBody = client
        .sdk()
        .advance_read_cursor(&client.verify_publication(ReadCursorAdvanceRequestBody {
            advance_event: EventAdmissionSubmission::new(event.clone()),
        })?)
        .await?;
    ensure!(
        outcome.realm_id == *realm
            && outcome.actor_id == event.actor_id
            && outcome.read_scope == *scope,
        "cursor outcome changed its actor-private key"
    );
    // A stale advance may legitimately return the earlier winner; the update
    // time must always belong to that winning signed Event, not wall time.
    if outcome.position == *position && outcome.device_id == principal.device_id {
        ensure!(
            outcome.updated_at == event.created_at,
            "cursor projection invented a second timestamp"
        );
    }
    Ok(outcome)
}

pub(crate) fn position(event_id: EventId, tick: u16) -> Result<ReadCursorPosition> {
    Ok(serde_json::from_value(
        json!({"event_id":event_id,"hlc":format!("{:012x}-{tick:04x}-a13f9c2e", chrono::Utc::now().timestamp_millis())}),
    )?)
}

async fn observe(
    client: &TestActorClient,
    realm: &RealmId,
    expected: &ReadCursorPosition,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let frames = super::account_stream_api::frames(client, None, None, true).await?;
        for frame in frames {
            if let Some(queue) = frame.to_device {
                for delivery in queue.deliveries {
                    if let RecipientDelivery::DeviceMessage { device_message } = delivery
                        && device_message.kind.as_str() == "ak.read_cursor.update"
                        && device_message.content["realm_id"] == realm.as_str()
                        && device_message.content["position"] == json!(expected)
                    {
                        ensure!(
                            device_message.content["schema"] == "ak.schema.read_cursor_update.v1",
                            "fanout restated the authored cursor as its update projection"
                        );
                        return Ok(());
                    }
                }
            }
        }
        ensure!(
            Instant::now() < deadline,
            "accepted sibling did not observe the exact winning private marker within 30s"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

pub async fn canonical_private_read_marker_api_migration() -> Result<()> {
    let fixture = super::_helpers::canonical_api::fixture("private-marker").await?;
    let outsider = super::_helpers::canonical_api::fixture("marker-outsider").await?;
    let sibling = fixture.pair_sibling().await?;
    let first = &fixture.client;
    let realm = first.create_realm("private marker convergence").await?;
    let realm = RealmId::new(realm)?;
    let strand = first.default_strand_id(realm.as_str())?;
    ensure!(
        list(first, &realm).await?.markers.is_empty()
            && list(&outsider.client, &realm).await?.markers.is_empty(),
        "new actor-private marker key was not empty"
    );
    let scope: ReadCursorScope = serde_json::from_value(json!({"kind":"realm"}))?;
    let mut positions = Vec::new();
    for (tick, label) in [(1, "first"), (2, "second"), (3, "highest")] {
        let sent = first.send_message(realm.as_str(), &strand, label).await?;
        positions.push(position(crate::harness::submitted_event_id(&sent)?, tick)?);
    }
    let first_outcome = advance(first, &realm, &scope, &positions[0]).await?;
    ensure!(
        first_outcome.position == positions[0],
        "single-device marker did not read back its accepted position"
    );
    observe(&sibling, &realm, &positions[0]).await?;
    ensure!(
        list(&outsider.client, &realm).await?.markers.is_empty(),
        "private advance changed another principal's marker"
    );
    let started = Instant::now();
    for position in &positions[1..] {
        advance(first, &realm, &scope, position).await?;
    }
    observe(&sibling, &realm, &positions[2]).await?;
    ensure!(
        started.elapsed() < Duration::from_secs(30),
        "sibling exceeded the declared convergence window"
    );
    let stored = list(&sibling, &realm).await?;
    ensure!(
        stored.markers.len() == 1 && stored.markers[0].position == positions[2],
        "rapid advances did not merge to the highest committed position"
    );
    advance(&sibling, &realm, &scope, &positions[1]).await?;
    ensure!(
        list(first, &realm).await?.markers[0].position == positions[2],
        "late older Device write regressed the marker"
    );
    // Same accepted target and HLC exercises the deterministic Device tie-break.
    let (lower, higher) = if first.device_id < sibling.device_id {
        (first, &sibling)
    } else {
        (&sibling, first)
    };
    let tie = position(positions[2].event_id.clone(), u16::MAX)?;
    advance(lower, &realm, &scope, &tie).await?;
    let higher_outcome = advance(higher, &realm, &scope, &tie).await?;
    ensure!(
        higher_outcome.device_id.as_str() == higher.device_id,
        "equal-HLC marker did not choose the lexicographically higher accepted Device"
    );
    observe(lower, &realm, &tie).await?;
    let forward = first
        .send_message(realm.as_str(), &strand, "mark all read from sibling")
        .await?;
    let forward = position(crate::harness::submitted_event_id(&forward)?, 0)?;
    advance(&sibling, &realm, &scope, &forward).await?;
    observe(first, &realm, &forward).await?;
    ensure!(
        list(first, &realm).await?.markers[0].position == forward
            && list(&outsider.client, &realm).await?.markers.is_empty(),
        "paired mark-all-read did not remain actor-private"
    );
    println!(
        "private_marker: canonical pairing, byte-identical accepted authorization, both-way fanout, 30s convergence, causal non-regression, equal-HLC Device tie-break, outsider isolation verified"
    );
    Ok(())
}
