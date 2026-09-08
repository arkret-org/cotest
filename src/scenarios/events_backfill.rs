use anyhow::{Result, anyhow, bail};
use arkret_models_collaboration::event_query::EventsQueryPostRequestBody;
use reqwest::StatusCode;
use serde_json::Value;

use crate::fixtures::TestActorBuilder;
use crate::harness::{
    TestActorClient, TestServerGroup, expect_api_error, expect_json, submitted_event_id,
};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

pub async fn backfill_pages_recover_messages_missing_from_limited_client_page() -> Result<()> {
    let group = TestServerGroup::single("event-backfill").await?;
    let server = group.server(0);
    // Alice is seeded as the existing demo identity (the harness pre-registers
    // the demo principal at server boot), so the builder shape uses
    // `demo_client` directly here. Bob is freshly created via the builder so
    // we can demonstrate the new fixture surface in a real scenario.
    let alice_did = actor_did_for_service_did(server.service_did(), "alice-backfill")?;
    let alice = server
        .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let bob_did = actor_did_for_service_did(server.service_did(), "bob-backfill")?;
    let bob = TestActorBuilder::new(server, "@bob-backfill")
        .with_did(&bob_did)
        .with_device("ak:device:01904100-0000-7000-8000-0000000000b0")
        .create()
        .await?;
    let bob_client = bob.client();

    let realm_id = alice.create_realm("Backfill Recovery Realm").await?;
    let strand_id = alice.default_strand_id(&realm_id)?;
    alice.add_member(&realm_id, bob_client).await?;

    let sent = [
        alice
            .send_message(&realm_id, &strand_id, "first event before gap")
            .await?,
        alice
            .send_message(&realm_id, &strand_id, "second event inside gap")
            .await?,
        alice
            .send_message(&realm_id, &strand_id, "third event after gap")
            .await?,
    ];
    let expected_message_ids = sent
        .iter()
        .map(|event| submitted_event_id(event).map(|event_id| event_id.to_string()))
        .collect::<Result<Vec<_>>>()?;

    let mut cursor = None;
    let mut collected = Vec::new();
    let mut reached_end = false;
    for _ in 0..256 {
        let body = EventsQueryPostRequestBody {
            realm_ids: vec![arkret_identifiers::RealmId::new(realm_id.clone())?],
            before: cursor.clone().map(arkret_wire::Cursor::new).transpose()?,
            limit: Some(1),
            ..Default::default()
        };
        let page = expect_json(
            alice.query("/_arkret/self/events").json(&body),
            StatusCode::OK,
        )
        .await?;
        collected.extend(json_array(&page, "events")?.iter().cloned());
        if !page["has_more"]
            .as_bool()
            .ok_or_else(|| anyhow!("events page is missing has_more: {page}"))?
        {
            reached_end = true;
            break;
        }
        let next_cursor = page["prev_cursor"]
            .as_str()
            .ok_or_else(|| anyhow!("events page has_more=true without prev_cursor: {page}"))?;
        if cursor.as_deref() == Some(next_cursor) {
            bail!("events pagination cursor did not advance: {next_cursor}");
        }
        cursor = Some(next_cursor.to_owned());
    }
    if !reached_end {
        bail!("events backfill exceeded the 256-page safety bound");
    }

    collected.reverse();
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

// Complement: csapi/room_relations_test.go TestRelationsPaginationSync and
// csapi/room_messages_test.go. Arkret: service-http-binding §3.3 and
// client-sync §11.1; before/after are absolute directions, not offsets.
pub async fn backfill_remains_gap_free_while_new_events_arrive() -> Result<()> {
    let (_group, alice, realm_id, expected) = pagination_fixture("backfill-during-writes").await?;
    let scope = scan_scope(&realm_id, 2)?;
    let first = scan_page(&alice, &scope).await?;
    assert_eq!(first["has_more"], true);
    let first_ids = page_message_ids(&first)?;
    assert_eq!(
        first_ids,
        expected[4..].iter().rev().cloned().collect::<Vec<_>>()
    );
    let newest = required_cursor(&first, "next_cursor")?;
    let mut oldest = required_cursor(&first, "prev_cursor")?;
    let strand = alice.default_strand_id(&realm_id)?;
    let mut fresh = Vec::new();
    for index in 0..2 {
        fresh.push(
            submitted_event_id(
                &alice
                    .send_message(&realm_id, &strand, &format!("new {index}"))
                    .await?,
            )?
            .to_string(),
        );
    }

    let mut recovered = first_ids;
    let mut ended = false;
    for _ in 0..64 {
        let page = scan_page(
            &alice,
            &EventsQueryPostRequestBody {
                before: Some(arkret_wire::Cursor::new(oldest.clone())?),
                ..scope.clone()
            },
        )
        .await?;
        assert!(json_array(&page, "events")?.len() <= 2);
        recovered.extend(page_message_ids(&page)?);
        if page["has_more"] == false {
            ended = true;
            break;
        }
        let next = required_cursor(&page, "prev_cursor")?;
        assert_ne!(oldest, next, "history cursor failed to advance");
        oldest = next;
    }
    assert!(ended, "backfill did not reach the history end");
    assert_eq!(
        recovered,
        expected.into_iter().rev().collect::<Vec<_>>(),
        "new writes changed the old-page boundary"
    );
    let forward = scan_page(
        &alice,
        &EventsQueryPostRequestBody {
            after: Some(arkret_wire::Cursor::new(newest)?),
            limit: Some(10),
            ..scope
        },
    )
    .await?;
    assert_eq!(
        page_message_ids(&forward)?,
        fresh.into_iter().rev().collect::<Vec<_>>()
    );
    Ok(())
}

pub async fn event_cursor_allows_page_size_change_without_replaying_the_boundary() -> Result<()> {
    let (_group, alice, realm_id, expected) = pagination_fixture("cursor-page-size").await?;
    let scope = scan_scope(&realm_id, 1)?;
    let first = scan_page(&alice, &scope).await?;
    assert_eq!(page_message_ids(&first)?, vec![expected[5].clone()]);
    let continuation = EventsQueryPostRequestBody {
        before: Some(arkret_wire::Cursor::new(required_cursor(
            &first,
            "prev_cursor",
        )?)?),
        limit: Some(3),
        ..scope
    };
    let second = scan_page(&alice, &continuation).await?;
    let wanted = expected[2..5].iter().rev().cloned().collect::<Vec<_>>();
    assert_eq!(page_message_ids(&second)?, wanted);
    let replay = scan_page(&alice, &continuation).await?;
    assert_eq!(
        page_message_ids(&replay)?,
        wanted,
        "reading a page must not consume its cursor"
    );
    Ok(())
}

pub async fn event_cursor_binds_scope_and_order(change_order: bool) -> Result<()> {
    let (_group, alice, realm_id, expected) = pagination_fixture(if change_order {
        "cursor-order"
    } else {
        "cursor-selector"
    })
    .await?;
    let other_realm = alice.create_realm("second readable Realm").await?;
    let other_strand = alice.default_strand_id(&other_realm)?;
    let other_event = submitted_event_id(
        &alice
            .send_message(&other_realm, &other_strand, "other Realm sentinel")
            .await?,
    )?
    .to_string();
    assert_eq!(
        page_message_ids(&scan_page(&alice, &scan_scope(&other_realm, 100)?).await?)?,
        vec![other_event]
    );
    let scope = scan_scope(&realm_id, 2)?;
    let first = scan_page(&alice, &scope).await?;
    let continuation = EventsQueryPostRequestBody {
        before: Some(arkret_wire::Cursor::new(required_cursor(
            &first,
            "prev_cursor",
        )?)?),
        ..scope
    };
    let mut wrong = continuation.clone();
    if change_order {
        wrong.order = Some("ascending".to_owned());
    } else {
        wrong.realm_ids = vec![arkret_identifiers::RealmId::new(other_realm)?];
    }
    expect_api_error(
        alice.query("/_arkret/self/events").json(&wrong),
        StatusCode::BAD_REQUEST,
        "cursor_integrity_invalid",
    )
    .await?;
    let resumed = scan_page(&alice, &continuation).await?;
    assert_eq!(
        page_message_ids(&resumed)?,
        expected[2..4].iter().rev().cloned().collect::<Vec<_>>()
    );
    Ok(())
}

pub async fn event_cursor_normalizes_selector_order() -> Result<()> {
    let (_group, alice, realm_id, _) = pagination_fixture("cursor-set-order").await?;
    let second = alice.create_realm("second selector").await?;
    let mut scope = scan_scope(&realm_id, 2)?;
    scope
        .realm_ids
        .push(arkret_identifiers::RealmId::new(second)?);
    let first = scan_page(&alice, &scope).await?;
    let mut continuation = EventsQueryPostRequestBody {
        before: Some(arkret_wire::Cursor::new(required_cursor(
            &first,
            "prev_cursor",
        )?)?),
        ..scope
    };
    let expected = scan_page(&alice, &continuation).await?;
    assert!(
        !json_array(&expected, "events")?.is_empty(),
        "fixture must have a second page"
    );
    continuation.realm_ids.reverse();
    let reordered = scan_page(&alice, &continuation).await?;
    assert_eq!(
        json_array(&reordered, "events")?,
        json_array(&expected, "events")?,
        "set-equivalent selector order changed the page"
    );
    Ok(())
}

// A valid cursor is not authority: even a second member with access to the
// same history cannot use another account's handle (encoding §8.3.1).
pub async fn event_cursor_cannot_be_reused_by_another_authorized_member() -> Result<()> {
    let (group, alice, realm_id, _) = pagination_fixture("cursor-member-binding").await?;
    let server = group.server(0);
    let bob_did = actor_did_for_service_did(server.service_did(), "cursor-member-bob")?;
    let bob = server
        .demo_client(&bob_did, "ak:device:01904100-0000-7000-8000-0000000000b0")
        .await?;
    alice.add_member(&realm_id, &bob).await?;
    let strand = alice.default_strand_id(&realm_id)?;
    let sentinel = submitted_event_id(
        &alice
            .send_message(&realm_id, &strand, "both members can read")
            .await?,
    )?
    .to_string();
    let scope = scan_scope(&realm_id, 1)?;
    assert_eq!(
        page_message_ids(&scan_page(&bob, &scope).await?)?,
        vec![sentinel]
    );
    let first = scan_page(&alice, &scope).await?;
    let continuation = EventsQueryPostRequestBody {
        before: Some(arkret_wire::Cursor::new(required_cursor(
            &first,
            "prev_cursor",
        )?)?),
        ..scope
    };
    expect_api_error(
        bob.query("/_arkret/self/events").json(&continuation),
        StatusCode::BAD_REQUEST,
        "cursor_integrity_invalid",
    )
    .await?;
    assert!(!json_array(&scan_page(&alice, &continuation).await?, "events")?.is_empty());
    Ok(())
}

pub async fn event_scan_rejects_barrier_and_stream_cursor_role_confusion() -> Result<()> {
    let (group, alice, realm_id, _) = pagination_fixture("cursor-purpose").await?;
    let strand = alice.default_strand_id(&realm_id)?;
    let accepted = alice
        .send_message(&realm_id, &strand, "barrier sentinel")
        .await?;
    let barrier = required_cursor(&accepted, "cursor")?;
    let scope = scan_scope(&realm_id, 2)?;
    let page = expect_json(
        alice
            .query("/_arkret/self/events")
            .header("X-Arkret-Wait-For", &barrier)
            .json(&scope),
        StatusCode::OK,
    )
    .await?;
    assert!(page_message_ids(&page)?.contains(&submitted_event_id(&accepted)?.to_string()));
    let wrong_position = EventsQueryPostRequestBody {
        after: Some(arkret_wire::Cursor::new(barrier.clone())?),
        ..scope.clone()
    };
    expect_api_error(
        alice.query("/_arkret/self/events").json(&wrong_position),
        StatusCode::BAD_REQUEST,
        "param_invalid",
    )
    .await?;
    let stream = required_cursor(&page, "prev_cursor")?;
    expect_api_error(
        alice
            .query("/_arkret/self/events")
            .header("X-Arkret-Wait-For", &stream)
            .json(&scope),
        StatusCode::BAD_REQUEST,
        "param_invalid",
    )
    .await?;
    let valid = expect_json(
        alice
            .query("/_arkret/self/events")
            .header("X-Arkret-Wait-For", &barrier)
            .json(&scope),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(page_message_ids(&valid)?, page_message_ids(&page)?);

    // Well-formed barriers still require stored handle authorization. A
    // second account has a readable query of its own but cannot borrow Alice's
    // barrier; accepting the header without resolving it would miss this case.
    let server = group.server(0);
    let bob_did = actor_did_for_service_did(server.service_did(), "barrier-other-account")?;
    let bob = server
        .demo_client(&bob_did, "ak:device:01904100-0000-7000-8000-0000000000b1")
        .await?;
    let bob_realm = bob.create_realm("independent barrier reader").await?;
    let bob_scope = scan_scope(&bob_realm, 2)?;
    scan_page(&bob, &bob_scope).await?;
    expect_api_error(
        bob.query("/_arkret/self/events")
            .header("X-Arkret-Wait-For", &barrier)
            .json(&bob_scope),
        StatusCode::BAD_REQUEST,
        "cursor_integrity_invalid",
    )
    .await?;
    Ok(())
}

async fn pagination_fixture(
    label: &str,
) -> Result<(TestServerGroup, TestActorClient, String, Vec<String>)> {
    let group = TestServerGroup::single(label).await?;
    let server = group.server(0);
    let did = actor_did_for_service_did(server.service_did(), label)?;
    let alice = server
        .demo_client(&did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let realm_id = alice.create_realm(label).await?;
    let strand = alice.default_strand_id(&realm_id)?;
    let mut ids = Vec::new();
    let mut barrier = String::new();
    for index in 0..6 {
        let accepted = alice
            .send_message(&realm_id, &strand, &format!("pagination message {index}"))
            .await?;
        ids.push(submitted_event_id(&accepted)?.to_string());
        barrier = required_cursor(&accepted, "cursor")?;
    }
    let visible = expect_json(
        alice
            .query("/_arkret/self/events")
            .header("X-Arkret-Wait-For", &barrier)
            .json(&scan_scope(&realm_id, 100)?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        page_message_ids(&visible)?,
        ids.iter().rev().cloned().collect::<Vec<_>>()
    );
    Ok((group, alice, realm_id, ids))
}

fn scan_scope(realm_id: &str, limit: u32) -> Result<EventsQueryPostRequestBody> {
    Ok(EventsQueryPostRequestBody {
        realm_ids: vec![arkret_identifiers::RealmId::new(realm_id.to_owned())?],
        order: Some("descending".to_owned()),
        limit: Some(limit),
        ..Default::default()
    })
}

async fn scan_page(client: &TestActorClient, body: &EventsQueryPostRequestBody) -> Result<Value> {
    let page = expect_json(
        client.query("/_arkret/self/events").json(body),
        StatusCode::OK,
    )
    .await?;
    assert!(page["has_more"].is_boolean(), "scan omitted has_more");
    assert!(
        json_array(&page, "events")?.len() <= body.limit.unwrap_or(100) as usize,
        "scan exceeded limit"
    );
    Ok(page)
}

fn required_cursor(value: &Value, field: &str) -> Result<String> {
    let cursor = value[field]
        .as_str()
        .ok_or_else(|| anyhow!("response omitted {field}"))?;
    assert!(cursor.starts_with("ak:cursor:"));
    Ok(cursor.to_owned())
}

fn page_message_ids(page: &Value) -> Result<Vec<String>> {
    json_array(page, "events")?
        .iter()
        .filter(|event| event["kind"] == "ak.message.create")
        .map(|event| {
            event["event_id"]
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| anyhow!("message omitted event_id"))
        })
        .collect()
}
