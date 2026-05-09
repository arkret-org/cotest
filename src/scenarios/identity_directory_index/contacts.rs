use std::time::Duration;

use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    ContrixServer, eventually, expect_audit_action, expect_json,
    expect_response, expect_status,
};

pub async fn contacts_invites_listing_export_and_audit_work() -> Result<()> {
    let server = ContrixServer::spawn("directory-workflow").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client("did:web:bob-directory.example", "@bob-directory", "dev_bob")
        .await?;

    expect_json(
        alice
            .post("/api/v1/contacts/request")
            .json(&json!({"target": bob.actor})),
        StatusCode::CREATED,
    )
    .await?;
    expect_json(
        bob.post("/api/v1/contacts/respond").json(&json!({
            "requester": alice.actor,
            "action": "accept"
        })),
        StatusCode::OK,
    )
    .await?;

    let contacts = expect_json(bob.get("/api/v1/contacts"), StatusCode::OK).await?;
    assert_eq!(contacts["contacts"].as_array().unwrap().len(), 1);

    let invite_space = expect_json(
        alice.post("/api/v1/spaces").json(&json!({
            "title": "Invite Token Space",
            "discoverability": "invite_only",
            "invitees": [bob.actor.clone()]
        })),
        StatusCode::CREATED,
    )
    .await?;
    let invite_space_id = invite_space["space_id"].as_str().unwrap().to_owned();

    let invites = expect_json(bob.get("/api/v1/authz/invites"), StatusCode::OK).await?;
    assert_eq!(invites["invites"].as_array().unwrap().len(), 1);
    assert_eq!(invites["invites"][0]["space_id"], invite_space_id);
    let invite_token = invites["invites"][0]["invite_token"].as_str().unwrap();

    expect_status(
        server
            .http()
            .post(server.url("/api/v1/directory/resolve-space"))
            .json(&json!({"invite_token": "cx:invite-token:invalid"})),
        StatusCode::NOT_FOUND,
    )
    .await?;

    let invite_resolve = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/resolve-space"))
            .json(&json!({"invite_token": invite_token})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(invite_resolve["space_preview"]["space_id"], invite_space_id);

    let listed_space = expect_json(
        alice.post("/api/v1/spaces").json(&json!({
            "title": "Listed Directory Space",
            "discoverability": "listed"
        })),
        StatusCode::CREATED,
    )
    .await?;
    let listed_space_id = listed_space["space_id"].as_str().unwrap().to_owned();
    let listed_search = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/search-spaces"))
            .json(&json!({"query": "Listed Directory Space"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(listed_search["results"][0]["space_id"], listed_space_id);

    let unlisted_space = expect_json(
        alice.post("/api/v1/spaces").json(&json!({
            "title": "Unlisted Directory Space",
            "discoverability": "unlisted"
        })),
        StatusCode::CREATED,
    )
    .await?;
    let unlisted_space_id = unlisted_space["space_id"].as_str().unwrap().to_owned();
    let unlisted_search = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/search-spaces"))
            .json(&json!({"query": "Unlisted Directory Space"})),
        StatusCode::OK,
    )
    .await?;
    assert!(unlisted_search["results"].as_array().unwrap().is_empty());

    let unlisted_resolve = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/resolve-space"))
            .json(&json!({"space_id": unlisted_space_id})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        unlisted_resolve["space_preview"]["space_id"],
        unlisted_space["space_id"]
    );

    let shared_space_id = alice.create_space("Workflow Export Space").await?;
    alice.add_member(&shared_space_id, &bob).await?;
    let sent = alice
        .send_message(
            &shared_space_id,
            "cx:thread:directory-workflow",
            "hello directory workflow",
        )
        .await?;

    let notifications = eventually(
        "notification projection",
        Duration::from_secs(2),
        Duration::from_millis(50),
        || {
            let server = &server;
            let bob_actor = bob.actor.clone();
            let event_id = sent["event_id"].as_str().unwrap().to_owned();
            async move {
                let body = expect_json(
                    server
                        .http()
                        .get(server.url(&format!("/api/v1/index/notifications?actor={bob_actor}"))),
                    StatusCode::OK,
                )
                .await?;
                if body["unread_count"]
                    .as_u64()
                    .is_some_and(|count| count >= 1)
                    && body["notifications"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|notification| notification["event_ref"] == event_id)
                {
                    Ok(body)
                } else {
                    Err(anyhow!("notification for {event_id} not projected yet"))
                }
            }
        },
    )
    .await?;
    assert!(
        notifications["unread_count"]
            .as_u64()
            .is_some_and(|count| count >= 1)
    );

    let exported = expect_json(
        alice.get(&format!("/api/v1/spaces/{shared_space_id}/export")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(exported["schema"], "cx.export.space.v1");
    assert!(
        exported["operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation["operation_id"] == sent["operation_id"])
    );

    let waited_sync = expect_response(
        alice
            .post("/api/v1/sync")
            .header("x-contrix-wait-for", sent["sync_token"].as_str().unwrap())
            .json(&json!({})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        waited_sync
            .headers
            .get("x-contrix-wait-for-satisfied")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    let waited_sync = waited_sync.json()?;
    assert_eq!(
        waited_sync["spaces"][&shared_space_id]["timeline"]["events"][0]["event_id"],
        sent["event_id"]
    );

    expect_status(
        alice
            .post("/api/v1/sync")
            .header("x-contrix-wait-for", "not-a-sync-token")
            .json(&json!({})),
        StatusCode::BAD_REQUEST,
    )
    .await?;

    let audit_events =
        expect_json(alice.get("/api/v1/audit/events?limit=20"), StatusCode::OK).await?;
    let _ = expect_audit_action(&audit_events, "space.create")?;

    expect_status(
        alice.get(&format!("/api/v1/audit/events?actor={}", bob.actor)),
        StatusCode::FORBIDDEN,
    )
    .await?;

    Ok(())
}

