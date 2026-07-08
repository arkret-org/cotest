use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    TestActorClient, TestServerGroup, event_envelope, expect_json,
    message_create_text_payload_for_strand, message_redact_payload, message_revise_text_payload,
    parse_strand_id,
};

pub async fn duplicate_event_submit_is_idempotent_and_projects_once() -> Result<()> {
    let group = TestServerGroup::single("event-idempotency-replay").await?;
    let server = group.server(0);
    let alice = server
        .demo_client(
            "did:web:alice.example",
            "ck:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let realm_id = create_test_realm(
        &alice,
        "ck:realm:01999999-0000-7000-8000-00000000e101",
        "Event Idempotency Replay",
    )
    .await?;
    let event = event_envelope(
        &alice.actor,
        &realm_id,
        "ck.message.create",
        message_create_text_payload_for_strand(
            parse_strand_id("ck:strand:01999999-0000-7000-8000-00000000feed")?,
            "idempotent replay body",
        )?,
    );

    let first = expect_json(
        alice.post("/_cokret/self/events").json(&event),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(first["status"], "accepted");
    let event_id = submitted_event_id(&first)
        .ok_or_else(|| anyhow!("accepted response missing event_id: {first}"))?;
    assert_eq!(event_id, json_string(&event, "event_id")?);

    let duplicate = expect_json(
        alice.post("/_cokret/self/events").json(&event),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(duplicate["status"], "duplicate");
    assert_eq!(submitted_event_id(&duplicate), Some(event_id));

    let listed = expect_json(
        alice
            .get("/_cokret/self/events")
            .query(&[("realms", realm_id.as_str()), ("limit", "100")]),
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
    let alice = server
        .demo_client(
            "did:web:alice-edit-redact.example",
            "ck:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let realm_id = create_test_realm(
        &alice,
        "ck:realm:01999999-0000-7000-8000-00000000e102",
        "Event Idempotency Edit Redact",
    )
    .await?;
    let create_event = event_envelope(
        &alice.actor,
        &realm_id,
        "ck.message.create",
        message_create_text_payload_for_strand(
            parse_strand_id("ck:strand:01999999-0000-7000-8000-00000000feed")?,
            "message before edit/redact replay",
        )?,
    );

    let created = submit_and_duplicate(&alice, &create_event).await?;
    let create_event_id = submitted_event_id(&created)
        .ok_or_else(|| anyhow!("create response missing event id: {created}"))?;
    assert_projected_kind_count(&alice, &realm_id, "ck.message.create", 1).await?;

    let revise_event = event_envelope(
        &alice.actor,
        &realm_id,
        "ck.message.revise",
        message_revise_text_payload(create_event_id, "message after idempotent edit replay")?,
    );
    let revised = submit_and_duplicate(&alice, &revise_event).await?;
    let revise_event_id = submitted_event_id(&revised)
        .ok_or_else(|| anyhow!("revise response missing event id: {revised}"))?;
    assert_projected_event_count(&alice, &realm_id, revise_event_id, 1).await?;
    assert_projected_kind_count(&alice, &realm_id, "ck.message.revise", 1).await?;

    let redact_event = event_envelope(
        &alice.actor,
        &realm_id,
        "ck.message.redact",
        message_redact_payload(create_event_id, Some("idempotent_redaction_replay"))?,
    );
    let redacted = submit_and_duplicate(&alice, &redact_event).await?;
    let redact_event_id = submitted_event_id(&redacted)
        .ok_or_else(|| anyhow!("redact response missing event id: {redacted}"))?;
    let visible_after_redaction = list_realm_events(&alice, &realm_id).await?;
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
        event_kind_count(&visible_after_redaction, "ck.message.revise")?,
        1,
        "edit-chain projection should remain single after redaction replay: {visible_after_redaction}"
    );

    Ok(())
}

async fn create_test_realm(alice: &TestActorClient, realm_id: &str, title: &str) -> Result<String> {
    let event = event_envelope(
        &alice.actor,
        realm_id,
        "ck.realm.create",
        json!({
            "object": {
                "id": realm_id,
                "schema": "ck.schema.realm.v1",
                "title": title,
                "summary": title,
                "trust_domain": "ck:trust_domain:event-idempotency.cotest.local",
                "created_by": &alice.actor,
                "schema_refs": ["ck.schema.realm.v1"],
                "default_discoverability": "public",
                "default_join_rule": "public",
                "history_visibility": "world_readable",
                "encryption_profile": "none",
                "security_class": "standard",
                "federation_policy": "open",
                "notary_profile": "single_did",
                "digest_algorithm": "sha256",
                "plaintext_visible_services": [alice.service_did()],
                "notary": {
                    "type": "single_did",
                    "did": &alice.actor,
                    "recovery_members": ["did:web:recovery-anchorer.cotest.local"],
                    "controller_organization": "did:web:event-idempotency.cotest.local",
                    "recovery_controller_organizations": ["did:web:recovery-org.cotest.local"]
                },
                "created_at": "2026-05-02T00:00:00Z"
            }
        }),
    );
    let response = expect_json(
        alice.post("/_cokret/self/events").json(&event),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(response["status"], "accepted");
    Ok(realm_id.to_owned())
}

async fn submit_and_duplicate(alice: &TestActorClient, event: &Value) -> Result<Value> {
    let first = expect_json(
        alice.post("/_cokret/self/events").json(event),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(first["status"], "accepted");
    let event_id = event["event_id"].as_str();
    assert_eq!(submitted_event_id(&first), event_id);

    let duplicate = expect_json(
        alice.post("/_cokret/self/events").json(event),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(duplicate["status"], "duplicate");
    assert_eq!(submitted_event_id(&duplicate), event_id);
    assert_eq!(duplicate["canonical_digest"], first["canonical_digest"]);

    Ok(first)
}

async fn list_realm_events(alice: &TestActorClient, realm_id: &str) -> Result<Value> {
    expect_json(
        alice
            .get("/_cokret/self/events")
            .query(&[("realms", realm_id), ("limit", "100")]),
        StatusCode::OK,
    )
    .await
}

async fn assert_projected_event_count(
    alice: &TestActorClient,
    realm_id: &str,
    event_id: &str,
    expected: usize,
) -> Result<()> {
    let listed = list_realm_events(alice, realm_id).await?;
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
) -> Result<()> {
    let listed = list_realm_events(alice, realm_id).await?;
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
    let payload = event
        .get("payload")
        .or_else(|| event.get("content"))
        .ok_or_else(|| anyhow!("projected event {event_id} missing payload/content: {event}"))?;
    assert_eq!(
        payload["redacted"],
        json!(true),
        "projected event {event_id} must be marked redacted: {event}"
    );
    assert_eq!(
        payload["state"],
        json!("redacted"),
        "projected event {event_id} must be a redaction tombstone: {event}"
    );
    assert_ne!(
        payload["content"]["body"], leaked_body,
        "projected event {event_id} leaked the redacted body: {event}"
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
        .get("event_id")
        .and_then(Value::as_str)
        .or_else(|| {
            response
                .get("accepted")
                .and_then(Value::as_array)
                .and_then(|accepted| accepted.first())
                .and_then(Value::as_str)
        })
        .or_else(|| {
            response
                .get("duplicate")
                .and_then(Value::as_array)
                .and_then(|duplicate| duplicate.first())
                .and_then(Value::as_str)
        })
}

fn json_string<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| anyhow!("{field} is not a string: {value}"))
}
