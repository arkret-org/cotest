use std::collections::BTreeSet;

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{ContrixServer, TestActorClient, expect_json, expect_status};

const ALICE_DID: &str = "did:web:cotest-collab-alice.example";
const BOB_DID: &str = "did:web:cotest-collab-bob.example";
const BOB_HANDLE: &str = "@cotest-collab-bob";

pub async fn account_contact_space_message_sync_workflow() -> Result<()> {
    let server = ContrixServer::spawn("collaboration-workflow").await?;
    let alice = server
        .register_client(ALICE_DID, "@cotest-collab-alice", "dev_alice")
        .await?;
    let bob = server
        .register_client(BOB_DID, BOB_HANDLE, "dev_bob")
        .await?;

    expect_status(
        server
            .http()
            .post(server.url("/api/v1/account/register"))
            .json(&json!({
                "did": BOB_DID,
                "handle": BOB_HANDLE,
                "device_id": "dev_bob2"
            })),
        StatusCode::CONFLICT,
    )
    .await?;

    let hidden_bob = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/search-users"))
            .json(&json!({"query": BOB_HANDLE.trim_start_matches('@')})),
        StatusCode::OK,
    )
    .await?;
    let hidden_results = hidden_bob["results"].as_array().unwrap();
    assert!(
        !hidden_results
            .iter()
            .any(|result| result["subject"].as_str() == Some(BOB_DID))
    );

    let me = expect_json(
        server
            .http()
            .get(server.url("/api/v1/account/me"))
            .bearer_auth(&bob.token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(me["did"], BOB_DID);

    let requested = expect_json(
        alice
            .post("/api/v1/contacts/request")
            .json(&json!({"target": BOB_DID})),
        StatusCode::CREATED,
    )
    .await?;
    assert_eq!(requested["status"], "pending");

    let accepted = expect_json(
        bob.post("/api/v1/contacts/respond")
            .json(&json!({"requester": ALICE_DID, "action": "accept"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(accepted["status"], "accepted");

    let visible_bob = expect_json(
        alice
            .post("/api/v1/directory/search-users")
            .json(&json!({"query": BOB_HANDLE.trim_start_matches('@')})),
        StatusCode::OK,
    )
    .await?;
    assert!(
        visible_bob["results"]
            .as_array()
            .unwrap()
            .iter()
            .any(|result| result["subject"].as_str() == Some(BOB_DID))
    );

    let space_id = create_collaboration_realm(&alice).await?;
    let created_space = expect_json(
        alice.get(&format!("/api/v1/spaces/{space_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(created_space["owner"], ALICE_DID);

    expect_status(
        server
            .http()
            .post(server.url("/api/v1/directory/resolve-realm"))
            .json(&json!({"realm_id": space_id})),
        StatusCode::NOT_FOUND,
    )
    .await?;

    let member_join = alice
        .submit_event(
            &space_id,
            "cx.member.state",
            json!({
                "actor_id": BOB_DID,
                "membership": "join",
                "delivery_status": "unroutable"
            }),
        )
        .await?;
    assert_eq!(member_join["status"], "accepted");
    let with_bob = expect_json(
        alice.get(&format!("/api/v1/spaces/{space_id}")),
        StatusCode::OK,
    )
    .await?;
    assert!(
        with_bob["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member == BOB_DID)
    );

    let sent = alice
        .send_message(
            &space_id,
            "cx:thread:collaboration",
            "hello from collaboration workflow",
        )
        .await?;
    assert_eq!(sent["status"], "accepted");
    assert!(sent["event_id"].as_str().unwrap().starts_with("cx:event:"));

    let bob_sync = bob.sync().await?;
    let bob_events = timeline_events(&bob_sync, &space_id)?;
    assert!(
        bob_events
            .iter()
            .any(|event| event["event_id"] == sent["event_id"]),
        "bob sync did not include alice message {sent}; sync: {bob_sync}"
    );

    let bob_reply = bob
        .send_message(
            &space_id,
            "cx:thread:collaboration",
            "hello alice from collaboration workflow",
        )
        .await?;
    assert_eq!(bob_reply["status"], "accepted");
    assert!(
        bob_reply["event_id"]
            .as_str()
            .unwrap()
            .starts_with("cx:event:")
    );

    let alice_sync = alice.sync().await?;
    let alice_timeline = timeline_events(&alice_sync, &space_id)?;
    assert!(
        alice_timeline
            .iter()
            .any(|event| event["event_id"] == bob_reply["event_id"]),
        "alice sync did not include bob reply {bob_reply}; sync: {alice_sync}"
    );
    assert!(
        alice_timeline
            .iter()
            .any(|event| event_body(event) == Some("hello alice from collaboration workflow")),
        "alice sync did not include bob reply body; sync: {alice_sync}"
    );

    let snapshot = expect_json(
        server
            .http()
            .get(server.url(&format!("/api/v1/snapshot/head?realm_id={space_id}"))),
        StatusCode::OK,
    )
    .await?;
    assert!(
        snapshot["snapshot_ref"]
            .as_str()
            .unwrap()
            .starts_with("cx:snapshot:")
    );
    assert!(
        snapshot["frontier"]["message_count"]
            .as_u64()
            .is_some_and(|count| count >= 1)
    );

    let member_ban = alice
        .submit_event(
            &space_id,
            "cx.member.state",
            json!({
                "actor_id": BOB_DID,
                "membership": "ban",
                "delivery_status": "unroutable"
            }),
        )
        .await?;
    assert_eq!(member_ban["status"], "accepted");
    let removed = expect_json(
        alice.get(&format!("/api/v1/spaces/{space_id}")),
        StatusCode::OK,
    )
    .await?;
    assert!(
        !removed["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member == BOB_DID)
    );

    let lifecycle = expect_json(
        alice
            .get("/api/v1/events")
            .query(&[("realms", space_id.as_str()), ("limit", "100")]),
        StatusCode::OK,
    )
    .await?;
    let event_kinds: BTreeSet<_> = lifecycle["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|event| {
            event["event_kind"]
                .as_str()
                .or_else(|| event["kind"].as_str())
                .map(ToOwned::to_owned)
        })
        .collect();
    assert!(event_kinds.contains("cx.realm.create"));
    assert!(event_kinds.contains("cx.member.state"));
    assert!(event_kinds.contains("cx.message.create"));

    let logout = expect_json(
        server
            .http()
            .post(server.url("/api/v1/auth/logout"))
            .bearer_auth(&bob.token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(logout["revoked"], true);

    expect_status(
        server
            .http()
            .get(server.url("/api/v1/account/me"))
            .bearer_auth(&bob.token),
        StatusCode::UNAUTHORIZED,
    )
    .await?;

    Ok(())
}

async fn create_collaboration_realm(alice: &TestActorClient) -> Result<String> {
    let realm_id = "cx:realm:01904100-0000-7000-8000-c011ab000001".to_owned();
    let created = alice
        .submit_event(
            &realm_id,
            "cx.realm.create",
            json!({
                "object": {
                    "id": &realm_id,
                    "schema": "cx.schema.realm.v1",
                    "title": "Collaboration Workflow Space",
                    "summary": "single server collaboration",
                    "trust_domain": "cx:trust_domain:collaboration-workflow.cotest.local",
                    "created_by": &alice.actor,
                    "schema_refs": ["cx.schema.realm.v1"],
                    "default_discoverability": "invite_only",
                    "default_join_rule": "invite",
                    "history_visibility": "shared",
                    "encryption_profile": "none",
                    "security_class": "standard",
                    "federation_policy": "restricted",
                    "anchor_profile": "single_did",
                    "digest_algorithm": "sha256",
                    "plaintext_visible_services": [alice.service_did()],
                    "anchorer": {
                        "type": "single_did",
                        "did": &alice.actor,
                        "recovery_members": ["did:web:recovery-anchorer.cotest.local"],
                        "controller_organization": "did:web:collaboration-workflow.cotest.local",
                        "recovery_controller_organizations": ["did:web:recovery-org.cotest.local"]
                    },
                    "created_at": "2026-05-02T00:00:00Z"
                }
            }),
        )
        .await?;
    assert_eq!(created["status"], "accepted");
    Ok(realm_id)
}

fn timeline_events<'a>(delta: &'a Value, realm_id: &str) -> Result<&'a Vec<Value>> {
    delta
        .get("realms")
        .or_else(|| delta.get("spaces"))
        .and_then(|realms| realms.get(realm_id))
        .and_then(|realm| realm.get("timeline"))
        .and_then(|timeline| timeline.get("events"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow::anyhow!("sync delta missing timeline events for {realm_id}: {delta}")
        })
}

fn event_body(event: &Value) -> Option<&str> {
    event
        .pointer("/content/body")
        .or_else(|| event.pointer("/payload/content/body"))
        .or_else(|| event.pointer("/payload/body"))
        .and_then(Value::as_str)
}
