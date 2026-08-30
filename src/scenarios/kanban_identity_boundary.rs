//! Cross-layer regression for the Event draft / final identity boundary.
//!
//! Inkson's typed builders now hand back writes with NO Event identity: a
//! `LocalOperation` holds a semantic `EventIntent` plus a holder-local
//! operation id, and the one `event_id` is derived at the finalize boundary,
//! after the actor chain, HLC and CBA members are complete. This scenario
//! drives that exact producer material through a live soland and pins the
//! lifecycle the UI depends on:
//!
//! 1. **optimistic** — before authoring, the write exposes no `event_id` and no derived object id;
//!    the only key is the holder-local operation id, which is deliberately not an Arkret
//!    identifier.
//! 2. **receipt** — the accepted `event_id` is the authored one, verbatim, and the List / Card ids
//!    are `retype(event_id)` of their own creates.
//! 3. **backfill** — the events read view carries exactly one create per object, and echoes
//!    `unsigned.local_operation_idempotency_alias` verbatim, which is what joins a live-sync
//!    backfill row to the optimistic row instead of materializing a second object.
//! 4. **retry** — a byte-identical resubmit is an idempotent duplicate of the SAME `event_id`: one
//!    user operation, not a second one.

use anyhow::{Result, anyhow};
use arkret_wire::Event;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{TestActorClient, TestServerGroup, events_query_for_realm, expect_json};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

pub async fn kanban_creates_keep_one_identity_across_receipt_backfill_and_retry() -> Result<()> {
    let group = TestServerGroup::single("kanban-identity-boundary").await?;
    let server = group.server(0);
    let alice_did = actor_did_for_service_did(server.service_did(), "alice-kanban-id")?;
    let alice = server
        .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-00000000ab01")
        .await?;
    let realm_id = create_test_realm(&alice, "Kanban Identity Boundary").await?;
    // The typed builders resolve the envelope `station_id` from the
    // client's selected Station, exactly as the real app does at
    // sign-in.
    inkson::operation::set_authoring_station_id(Some(
        arkret::DidCoreId::new(alice.service_id().to_owned())
            .map_err(|error| anyhow!("service DID core id: {error}"))?,
    ));

    // ---- board, then list: each id exists only once its create is accepted --
    let board = inkson::operation::ak_ops::space_create(
        &realm_id,
        &alice.actor,
        "board",
        "Boundary board",
        None,
        None,
    )
    .map_err(|error| anyhow!("inkson board builder: {error:#}"))?
    .build_sdk_event("cotest")
    .map_err(|error| anyhow!("inkson board build: {error:#}"))?;
    let (board_event_id, _) = submit_operation(&alice, &realm_id, &board).await?;
    let board_space_id = arkret::SpaceId::from_event_id(&board_event_id).to_string();

    let list = inkson::operation::ak_ops::space_create(
        &realm_id,
        &alice.actor,
        "list",
        "Boundary list",
        Some(&board_space_id),
        Some("a0"),
    )
    .map_err(|error| anyhow!("inkson list builder: {error:#}"))?
    .build_sdk_event("cotest")
    .map_err(|error| anyhow!("inkson list build: {error:#}"))?;
    let (list_event_id, list_envelope) = submit_operation(&alice, &realm_id, &list).await?;
    let list_space_id = arkret::SpaceId::from_event_id(&list_event_id).to_string();

    // ---- the card names the ACCEPTED containers -----------------------------
    // Before authoring, the write has no object id of its own to leak: the
    // holder-local handle is the operation id, and it is not an Arkret id.
    let card = inkson::operation::ak_ops::kanban_card_strand_create(
        &realm_id,
        &alice.actor,
        &board_space_id,
        &list_space_id,
        "Boundary card",
        "a0",
    )
    .map_err(|error| anyhow!("inkson card builder: {error:#}"))?
    .build_sdk_event("cotest")
    .map_err(|error| anyhow!("inkson card build: {error:#}"))?;
    assert_eq!(
        card.local_target_ref(),
        None,
        "a create must not expose a pre-authoring object id"
    );
    assert!(
        !card.local_operation_id().as_str().starts_with("ak:"),
        "the holder-local operation id must not impersonate an Arkret identifier"
    );
    let (card_event_id, _) = submit_operation(&alice, &realm_id, &card).await?;
    let card_strand_id = arkret::StrandId::from_event_id(&card_event_id).to_string();

    // ---- retry: byte-identical resubmit is the SAME user operation ----------
    let retry = expect_json(
        alice
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(
                list_envelope.clone(),
                "",
            )?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        retry["status"], "duplicate",
        "a byte-identical retry must be an idempotent duplicate: {retry}"
    );
    assert_eq!(
        duplicate_event_id(&retry),
        Some(list_event_id.as_str()),
        "the duplicate must name the SAME accepted Event: {retry}"
    );

    // ---- backfill: one create per object, alias echoed verbatim -------------
    let listed = expect_json(
        alice
            .query("/_arkret/self/events")
            .json(&events_query_for_realm(&realm_id, 200)?),
        StatusCode::OK,
    )
    .await?;
    let rows = listed["events"]
        .as_array()
        .ok_or_else(|| anyhow!("events read returned no rows: {listed}"))?;
    for (kind, event_id, operation) in [
        ("ak.space.create", &board_event_id, &board),
        ("ak.space.create", &list_event_id, &list),
        ("ak.strand.create", &card_event_id, &card),
    ] {
        let matching: Vec<&Value> = rows
            .iter()
            .filter(|row| {
                row["kind"].as_str() == Some(kind)
                    && row["event_id"].as_str() == Some(event_id.as_str())
            })
            .collect();
        assert_eq!(
            matching.len(),
            1,
            "backfill must carry exactly one {kind} named {event_id}"
        );
        // The alias is the holder-local reconciliation key: the server echoes
        // it verbatim, and it never becomes a protocol identity.
        assert_eq!(
            matching[0]["unsigned"]["local_operation_idempotency_alias"].as_str(),
            Some(operation.local_operation_id().as_str()),
            "the backfill row must echo the producer's holder-local alias verbatim"
        );
    }
    // No second object materialized for any of the three writes: nothing else
    // in the realm carries their holder-local aliases.
    for operation in [&board, &list, &card] {
        let alias_rows = rows
            .iter()
            .filter(|row| {
                row["unsigned"]["local_operation_idempotency_alias"].as_str()
                    == Some(operation.local_operation_id().as_str())
            })
            .count();
        assert_eq!(
            alias_rows, 1,
            "each user operation must appear exactly once in the backfill"
        );
    }

    // ---- the card's payload names the accepted containers -------------------
    let card_row = rows
        .iter()
        .find(|row| row["event_id"].as_str() == Some(card_event_id.as_str()))
        .ok_or_else(|| anyhow!("card create missing from backfill"))?;
    assert_eq!(
        card_row["payload"]["object"]["metadata"]["fields"]["list_space_id"].as_str(),
        Some(list_space_id.as_str()),
        "the card must reference the ACCEPTED List id, never a draft-derived one"
    );
    assert!(
        card_strand_id.starts_with("ak:strand:"),
        "the accepted Card id is retype(event_id) of its own create"
    );
    Ok(())
}

/// Author and submit one inkson-built write the way the client pipeline does:
/// the intent is positioned on the accepted actor chain, finalized ONCE, the
/// holder-local alias rides `unsigned`, and the receipt is the authored id.
async fn submit_operation(
    alice: &TestActorClient,
    realm_id: &str,
    operation: &inkson::operation::LocalOperation,
) -> Result<(arkret_identifiers::EventId, Event)> {
    let mut event = alice
        .author_event(
            realm_id,
            operation.kind().as_str(),
            serde_json::to_value(operation.payload())?,
        )
        .await?;
    // Holder-local reconciliation only: `unsigned` is outside the digest
    // preimage, so attaching it cannot move the identity authored above.
    event.unsigned.insert(
        "local_operation_idempotency_alias".to_owned(),
        Value::String(operation.local_operation_id().to_string()),
    );
    let authored_event_id = event.event_id.clone();
    let accepted = expect_json(
        alice
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(event.clone(), "")?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        accepted["status"], "accepted",
        "the authored create must be accepted: {accepted}"
    );
    let accepted_id = crate::harness::submitted_event_id(&accepted)?;
    assert_eq!(
        accepted_id.as_str(),
        authored_event_id.as_str(),
        "the receipt must name the authored identity verbatim"
    );
    Ok((authored_event_id, event))
}

fn duplicate_event_id(response: &Value) -> Option<&str> {
    response["duplicate"][0]
        .as_str()
        .or_else(|| response["accepted"][0].as_str())
}

async fn create_test_realm(alice: &TestActorClient, title: &str) -> Result<String> {
    let response = alice
        .create_realm_with(json!({
            "title": title,
            "summary": title,
            "public": true,
            "discoverability": "public",
            "join_rule": "public",
            "history_access": "all_history_for_current_members",
            "plaintext_visible_services": [alice.service_id()]
        }))
        .await?;
    response["realm_id"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("Realm create response has no realm_id"))
}
