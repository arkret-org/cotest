//! Cross-layer regression for the Event draft / final identity boundary.
//!
//! Inkson's typed builders now hand back writes with NO Event identity: a
//! `LocalOperation` holds a semantic `EventIntent` plus a holder-local
//! operation id, and the one `event_id` is derived at the finalize boundary,
//! after the actor chain, HLC and CBS members are complete. This scenario
//! drives that exact producer material through a live soland and pins the
//! lifecycle the UI depends on:
//!
//! 1. **optimistic** — before authoring, the write exposes no `event_id` and no derived object id;
//!    the only key is the holder-local operation id, which is deliberately not an Arkret
//!    identifier.
//! 2. **receipt** — the accepted `event_id` is the authored one, verbatim, and the List / Card ids
//!    are `retype(event_id)` of their own creates.
//! 3. **backfill** — each authored Event ID resolves to exactly one accepted RealmCommit in its
//!    scope stream. The holder joins its local operation handle to that canonical Event ID when it
//!    receives the submit receipt.
//! 4. **retry** — a byte-identical resubmit is an idempotent duplicate of the SAME `event_id`: one
//!    user operation, not a second one.

use anyhow::{Result, anyhow};
use arkret_wire::Event;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{TestActorClient, TestServerGroup, expect_json};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

pub async fn kanban_creates_keep_one_identity_across_receipt_backfill_and_retry() -> Result<()> {
    let group = TestServerGroup::single("kanban-identity-boundary").await?;
    let server = group.server(0);
    let alice_did = actor_did_for_service_did(server.service_did(), "alice-kanban-id")?;
    let alice = server
        .standard_client(&alice_did, "ak:device:01904100-0000-7000-8000-00000000ab01")
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
    let (board_event_id, board_envelope) = submit_operation(&alice, &realm_id, &board).await?;
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

    // ---- create the card, then place its accepted id -------------------------
    // Before authoring, the write has no object id of its own to leak: the
    // holder-local handle is the operation id, and it is not an Arkret id.
    let card = inkson::operation::ak_ops::kanban_card_strand_create(
        &realm_id,
        &alice.actor,
        "Boundary card",
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
    let (card_event_id, card_envelope) = submit_operation(&alice, &realm_id, &card).await?;
    let card_strand_id = arkret::StrandId::from_event_id(&card_event_id).to_string();
    let card_move = inkson::operation::ak_ops::strand_position_update(
        &realm_id,
        &alice.actor,
        "ak.strand.move",
        &board_space_id,
        &card_strand_id,
        Value::Null,
        json!({"list_space_id": list_space_id, "rank": "a0"}),
    )
    .map_err(|error| anyhow!("inkson card move builder: {error:#}"))?
    .build_sdk_event("cotest")
    .map_err(|error| anyhow!("inkson card move build: {error:#}"))?;
    let (card_move_event_id, card_move_envelope) =
        submit_operation(&alice, &realm_id, &card_move).await?;

    let placed = strand_row(&alice, &realm_id, &card_strand_id).await?;
    assert_eq!(placed["board_space_id"], board_space_id);
    assert_eq!(placed["list_space_id"], list_space_id);
    assert_eq!(placed["rank"], "a0");

    let card_reorder = inkson::operation::ak_ops::strand_position_update(
        &realm_id,
        &alice.actor,
        "ak.strand.reorder",
        &board_space_id,
        &card_strand_id,
        json!({"list_space_id": list_space_id, "rank": "a0"}),
        json!({"list_space_id": list_space_id, "rank": "b0"}),
    )
    .map_err(|error| anyhow!("inkson card reorder builder: {error:#}"))?
    .build_sdk_event("cotest")
    .map_err(|error| anyhow!("inkson card reorder build: {error:#}"))?;
    let (card_reorder_event_id, card_reorder_envelope) =
        submit_operation(&alice, &realm_id, &card_reorder).await?;
    let reordered = strand_row(&alice, &realm_id, &card_strand_id).await?;
    assert_eq!(reordered["rank"], "b0");

    let second_list = inkson::operation::ak_ops::space_create(
        &realm_id,
        &alice.actor,
        "list",
        "Boundary destination list",
        Some(&board_space_id),
        Some("b0"),
    )
    .map_err(|error| anyhow!("inkson destination list builder: {error:#}"))?
    .build_sdk_event("cotest")
    .map_err(|error| anyhow!("inkson destination list build: {error:#}"))?;
    let (second_list_event_id, second_list_envelope) =
        submit_operation(&alice, &realm_id, &second_list).await?;
    let second_list_space_id = arkret::SpaceId::from_event_id(&second_list_event_id).to_string();
    let cross_list_move = inkson::operation::ak_ops::strand_position_update(
        &realm_id,
        &alice.actor,
        "ak.strand.move",
        &board_space_id,
        &card_strand_id,
        json!({"list_space_id": list_space_id, "rank": "b0"}),
        json!({"list_space_id": second_list_space_id, "rank": "a0"}),
    )
    .map_err(|error| anyhow!("inkson cross-list move builder: {error:#}"))?
    .build_sdk_event("cotest")
    .map_err(|error| anyhow!("inkson cross-list move build: {error:#}"))?;
    let (cross_list_move_event_id, cross_list_move_envelope) =
        submit_operation(&alice, &realm_id, &cross_list_move).await?;
    let moved = strand_row(&alice, &realm_id, &card_strand_id).await?;
    assert_eq!(moved["board_space_id"], board_space_id);
    assert_eq!(moved["list_space_id"], second_list_space_id);
    assert_eq!(moved["rank"], "a0");

    let stale_move = inkson::operation::ak_ops::strand_position_update(
        &realm_id,
        &alice.actor,
        "ak.strand.move",
        &board_space_id,
        &card_strand_id,
        json!({"list_space_id": list_space_id, "rank": "b0"}),
        json!({"list_space_id": second_list_space_id, "rank": "c0"}),
    )
    .map_err(|error| anyhow!("inkson stale move builder: {error:#}"))?
    .build_sdk_event("cotest")
    .map_err(|error| anyhow!("inkson stale move build: {error:#}"))?;
    let stale_event = alice
        .author_event(
            &realm_id,
            stale_move.kind().as_str(),
            serde_json::to_value(stale_move.payload())?,
        )
        .await?;
    let stale_event_id = stale_event.event_id.clone();
    let refused = expect_json(
        alice
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(stale_event, "")?),
        StatusCode::CONFLICT,
    )
    .await?;
    assert_eq!(refused["type"], "https://arkret.org/problems/cas_conflict");
    assert_eq!(strand_row(&alice, &realm_id, &card_strand_id).await?, moved);
    let scan = alice
        .sdk()
        .scan_commit_stream_to_head(
            card_move_envelope.realm_id.clone(),
            arkret_wire::CommitStreamRef::from_scope(
                &card_move_envelope.scope_ref,
                Some(card_move_envelope.realm_id.clone()),
            )?,
            None,
            1000,
        )
        .await?;
    assert!(
        scan.committed_events
            .iter()
            .all(|item| item.commit().event_ref != stale_event_id),
        "stale position CAS must not create a RealmCommit"
    );

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
    let reorder_retry = expect_json(
        alice
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(
                card_reorder_envelope.clone(),
                "",
            )?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(reorder_retry["status"], "duplicate");
    assert_eq!(
        duplicate_event_id(&reorder_retry),
        Some(card_reorder_event_id.as_str())
    );

    // ---- backfill: exact committed Event and one Commit per scope stream --
    let mut local_to_event = std::collections::BTreeMap::new();
    for (kind, event_id, operation, envelope) in [
        ("ak.space.create", &board_event_id, &board, &board_envelope),
        ("ak.space.create", &list_event_id, &list, &list_envelope),
        ("ak.strand.create", &card_event_id, &card, &card_envelope),
        (
            "ak.strand.move",
            &card_move_event_id,
            &card_move,
            &card_move_envelope,
        ),
        (
            "ak.strand.reorder",
            &card_reorder_event_id,
            &card_reorder,
            &card_reorder_envelope,
        ),
        (
            "ak.space.create",
            &second_list_event_id,
            &second_list,
            &second_list_envelope,
        ),
        (
            "ak.strand.move",
            &cross_list_move_event_id,
            &cross_list_move,
            &cross_list_move_envelope,
        ),
    ] {
        let accepted = alice.sdk().committed_event_get(event_id).await?;
        accepted.validate_shape()?;
        let accepted_event = accepted
            .reducer_input()
            .ok_or_else(|| anyhow!("holder's authored {kind} Event was withheld"))?;
        assert_eq!(accepted_event, envelope);
        assert_eq!(accepted_event.kind.as_str(), kind);
        let stream_ref = arkret_wire::CommitStreamRef::from_scope(
            &envelope.scope_ref,
            Some(envelope.realm_id.clone()),
        )?;
        let scan = alice
            .sdk()
            .scan_commit_stream_to_head(envelope.realm_id.clone(), stream_ref, None, 1000)
            .await?;
        assert_eq!(
            scan.committed_events
                .iter()
                .filter(|item| item.commit().event_ref == *event_id)
                .count(),
            1,
            "backfill must carry exactly one {kind} named {event_id}"
        );
        assert!(
            local_to_event
                .insert(
                    operation.local_operation_id().to_string(),
                    event_id.to_string()
                )
                .is_none(),
            "holder-local operation id was reused"
        );
    }
    assert_eq!(local_to_event.len(), 7);

    // ---- placement references only the accepted Strand and containers -------
    let card_row = serde_json::to_value(&card_envelope)?;
    assert!(
        card_row["payload"]["object"]["metadata"]["fields"]
            .get("list_space_id")
            .is_none()
    );
    let move_row = serde_json::to_value(&card_move_envelope)?;
    assert_eq!(move_row["payload"]["strand_id"], card_strand_id);
    assert_eq!(move_row["payload"]["target_space_id"], list_space_id);
    assert!(
        card_strand_id.starts_with("ak:strand:"),
        "the accepted Card id is retype(event_id) of its own create"
    );
    Ok(())
}

async fn strand_row(alice: &TestActorClient, realm_id: &str, strand_id: &str) -> Result<Value> {
    let listed = expect_json(
        alice.get(&format!("/_arkret/self/realms/{realm_id}/strands")),
        StatusCode::OK,
    )
    .await?;
    listed["strands"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["strand_id"] == strand_id))
        .cloned()
        .ok_or_else(|| anyhow!("accepted Card missing from canonical Strand list: {listed}"))
}

/// Author and submit one inkson-built write the way the client pipeline does:
/// the intent is positioned on the accepted actor chain, finalized ONCE, the
/// the receipt maps the holder-local operation to the authored Event ID.
async fn submit_operation(
    alice: &TestActorClient,
    realm_id: &str,
    operation: &inkson::operation::LocalOperation,
) -> Result<(arkret_identifiers::EventId, Event)> {
    let event = alice
        .author_event(
            realm_id,
            operation.kind().as_str(),
            serde_json::to_value(operation.payload())?,
        )
        .await?;
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
