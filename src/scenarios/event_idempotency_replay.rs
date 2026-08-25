use std::time::Duration;

use anyhow::{Result, anyhow};
use arkret_wire::Event;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    TestActorClient, TestServerGroup, events_query_for_realm, eventually, expect_json,
    message_create_text_payload_for_strand, message_redact_payload, message_revise_text_payload,
    parse_strand_id,
};
use crate::scenarios::identity_test_support::actor_did_for_service_full_id;

pub async fn duplicate_event_submit_is_idempotent_and_projects_once() -> Result<()> {
    let group = TestServerGroup::single("event-idempotency-replay").await?;
    let server = group.server(0);
    let alice_did = actor_did_for_service_full_id(server.service_full_id(), "alice-replay")?;
    let alice = server
        .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let realm_id = create_test_realm(&alice, "Event Idempotency Replay").await?;
    let event = alice
        .author_event(
            &realm_id,
            "ak.message.create",
            message_create_text_payload_for_strand(
                parse_strand_id("ak:strand:AfkYrmvXKOcZ35LtMRF3a6ChsEVcSVo3oRdQEsL9Sra2")?,
                "idempotent replay body",
            )?,
        )
        .await?;

    let first = expect_json(
        alice
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(event.clone(), "")?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(first["status"], "accepted");
    let event_id = submitted_event_id(&first)
        .ok_or_else(|| anyhow!("accepted response missing event_id: {first}"))?;
    assert_eq!(event_id, event.event_id.as_str());

    let duplicate = expect_json(
        alice
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(event.clone(), "")?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(duplicate["status"], "duplicate");
    assert_eq!(submitted_event_id(&duplicate), Some(event_id));

    let listed = expect_json(
        alice
            .query("/_arkret/self/events")
            .json(&events_query_for_realm(&realm_id, 100)?),
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

pub async fn duplicate_edit_and_redaction_replay_project_once() -> Result<()> {
    let group = TestServerGroup::single("event-idempotency-edit-redact").await?;
    let server = group.server(0);
    let alice_did = actor_did_for_service_full_id(server.service_full_id(), "alice-edit-redact")?;
    let alice = server
        .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let realm_id = create_test_realm(&alice, "Event Idempotency Edit Redact").await?;
    let create_event = alice
        .author_event(
            &realm_id,
            "ak.message.create",
            message_create_text_payload_for_strand(
                parse_strand_id("ak:strand:AfkYrmvXKOcZ35LtMRF3a6ChsEVcSVo3oRdQEsL9Sra2")?,
                "message before edit/redact replay",
            )?,
        )
        .await?;

    let created = submit_and_duplicate(&alice, &create_event).await?;
    let create_event_id = submitted_event_id(&created)
        .ok_or_else(|| anyhow!("create response missing event id: {created}"))?;
    assert_projected_kind_count(
        &alice,
        &realm_id,
        "ak.message.create",
        1,
        submission_barrier(&created)?,
    )
    .await?;

    let revise_event = alice
        .author_event(
            &realm_id,
            "ak.message.revise",
            message_revise_text_payload(create_event_id, "message after idempotent edit replay")?,
        )
        .await?;
    let revised = submit_and_duplicate(&alice, &revise_event).await?;
    let revise_event_id = submitted_event_id(&revised)
        .ok_or_else(|| anyhow!("revise response missing event id: {revised}"))?;
    let revise_barrier = submission_barrier(&revised)?;
    assert_projected_event_count(&alice, &realm_id, revise_event_id, 1, revise_barrier).await?;
    assert_projected_kind_count(&alice, &realm_id, "ak.message.revise", 1, revise_barrier).await?;

    let seal_before_redaction = current_realm_seal(&alice, &realm_id).await?;
    let redact_event = alice
        .author_event(
            &realm_id,
            "ak.message.redact",
            message_redact_payload(create_event_id, Some("idempotent_redaction_replay"))?,
        )
        .await?;
    let redacted = submit_and_duplicate(&alice, &redact_event).await?;
    let redact_event_id = submitted_event_id(&redacted)
        .ok_or_else(|| anyhow!("redact response missing event id: {redacted}"))?;
    wait_for_next_realm_seal(&alice, &realm_id, &seal_before_redaction).await?;
    let visible_after_redaction =
        list_realm_events_after(&alice, &realm_id, submission_barrier(&redacted)?).await?;
    assert_eq!(
        event_count(&visible_after_redaction, create_event_id)?,
        1,
        "redaction must retain the original create slot as a tombstone: {visible_after_redaction}"
    );
    assert_eq!(
        event_count(&visible_after_redaction, redact_event_id)?,
        0,
        "redaction event itself should remain hidden from projected timeline: {visible_after_redaction}"
    );
    assert_eq!(
        event_count(&visible_after_redaction, revise_event_id)?,
        1,
        "duplicate redaction replay should not duplicate the visible edit-chain projection: {visible_after_redaction}"
    );
    assert_event_is_redacted_tombstone(
        &visible_after_redaction,
        create_event_id,
        "message before edit/redact replay",
    )?;
    assert_event_is_redacted_tombstone(
        &visible_after_redaction,
        revise_event_id,
        "message after idempotent edit replay",
    )?;
    assert_eq!(
        event_kind_count(&visible_after_redaction, "ak.message.revise")?,
        1,
        "edit-chain projection should remain single after redaction replay: {visible_after_redaction}"
    );

    Ok(())
}

async fn current_realm_seal(alice: &TestActorClient, realm_id: &str) -> Result<String> {
    let frontier = alice.realm_seal_frontier(realm_id).await?;
    frontier["frontier"]["seal_basis"]["leaves"][0]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("Realm frontier has no sole Seal leaf: {frontier}"))
}

async fn wait_for_next_realm_seal(
    alice: &TestActorClient,
    realm_id: &str,
    predecessor: &str,
) -> Result<()> {
    eventually(
        "redaction-covering Realm Seal",
        Duration::from_secs(30),
        Duration::from_millis(100),
        || async {
            let successor = current_realm_seal(alice, realm_id).await?;
            if successor == predecessor {
                return Err(anyhow!("message redaction is not sealed yet"));
            }
            Ok(())
        },
    )
    .await
}

/// Creates a Realm and returns the id the genesis Event derived.
///
/// A Realm id is `retype(event_id)` of its own create, so a caller cannot
/// choose one: naming a fixture id here and asserting the response echoes it
/// compares a placeholder against the real derived id.
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
    Ok(response["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow!("Realm create response has no realm_id"))?
        .to_owned())
}

async fn submit_and_duplicate(alice: &TestActorClient, event: &Event) -> Result<Value> {
    let first = expect_json(
        alice
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(event.clone(), "")?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(first["status"], "accepted");
    let event_id = Some(event.event_id.as_str());
    assert_eq!(submitted_event_id(&first), event_id);

    let duplicate = expect_json(
        alice
            .post("/_arkret/self/events")
            .json(&crate::publication::initial_submission(event.clone(), "")?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(duplicate["status"], "duplicate");
    assert_eq!(submitted_event_id(&duplicate), event_id);
    assert_eq!(duplicate["canonical_digest"], first["canonical_digest"]);

    Ok(first)
}

async fn list_realm_events_after(
    alice: &TestActorClient,
    realm_id: &str,
    barrier: &str,
) -> Result<Value> {
    expect_json(
        alice
            .query("/_arkret/self/events")
            .header("X-Arkret-Wait-For", barrier)
            .json(&events_query_for_realm(realm_id, 100)?),
        StatusCode::OK,
    )
    .await
}

fn submission_barrier(response: &Value) -> Result<&str> {
    response["cursor"]
        .as_str()
        .ok_or_else(|| anyhow!("event submission response missing barrier cursor: {response}"))
}

async fn assert_projected_event_count(
    alice: &TestActorClient,
    realm_id: &str,
    event_id: &str,
    expected: usize,
    barrier: &str,
) -> Result<()> {
    let listed = list_realm_events_after(alice, realm_id, barrier).await?;
    let actual = event_count(&listed, event_id)?;
    assert_eq!(
        actual, expected,
        "projected event {event_id} count mismatch: {listed}"
    );
    Ok(())
}

async fn assert_projected_kind_count(
    alice: &TestActorClient,
    realm_id: &str,
    kind: &str,
    expected: usize,
    barrier: &str,
) -> Result<()> {
    let listed = list_realm_events_after(alice, realm_id, barrier).await?;
    let actual = event_kind_count(&listed, kind)?;
    assert_eq!(
        actual, expected,
        "projected kind {kind} count mismatch: {listed}"
    );
    Ok(())
}

fn event_count(listed: &Value, event_id: &str) -> Result<usize> {
    Ok(projected_events(listed)?
        .iter()
        .filter(|event| event["event_id"].as_str() == Some(event_id))
        .count())
}

fn event_kind_count(listed: &Value, kind: &str) -> Result<usize> {
    Ok(projected_events(listed)?
        .iter()
        .filter(|event| {
            event["kind"]
                .as_str()
                .or_else(|| event["event_kind"].as_str())
                == Some(kind)
        })
        .count())
}

fn assert_event_is_redacted_tombstone(
    listed: &Value,
    event_id: &str,
    leaked_body: &str,
) -> Result<()> {
    let event = projected_events(listed)?
        .iter()
        .find(|event| event["event_id"].as_str() == Some(event_id))
        .ok_or_else(|| anyhow!("projected event {event_id} missing: {listed}"))?;
    assert_eq!(
        event["view_kind"],
        json!("redacted_event_view"),
        "projected event {event_id} must use the RedactedEventView contract: {event}"
    );
    assert_eq!(
        event["redaction_reason"],
        json!("redacted"),
        "projected event {event_id} must identify an explicit redaction: {event}"
    );
    assert_eq!(
        event["reducer_input"],
        json!(false),
        "a RedactedEventView must never be usable as reducer input: {event}"
    );
    let hidden_fields = event["hidden_fields"]
        .as_array()
        .ok_or_else(|| anyhow!("projected event {event_id} missing hidden_fields: {event}"))?;
    assert!(
        hidden_fields.iter().any(|field| field == "payload"),
        "projected event {event_id} must declare its payload hidden: {event}"
    );
    assert!(
        event.get("payload").is_none() && event.get("content").is_none(),
        "projected event {event_id} retained payload/content outside the redacted view: {event}"
    );
    assert!(
        !serde_json::to_string(event)?.contains(leaked_body),
        "projected event {event_id} still contains redacted plaintext: {event}"
    );
    Ok(())
}

fn projected_events(listed: &Value) -> Result<&Vec<Value>> {
    listed["events"]
        .as_array()
        .ok_or_else(|| anyhow!("events query response missing events array: {listed}"))
}

fn submitted_event_id(response: &Value) -> Option<&str> {
    response
        .get("accepted")
        .and_then(Value::as_array)
        .and_then(|accepted| accepted.first())
        .and_then(Value::as_str)
        .or_else(|| {
            response
                .get("duplicate")
                .and_then(Value::as_array)
                .and_then(|duplicate| duplicate.first())
                .and_then(Value::as_str)
        })
}
