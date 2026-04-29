mod support;

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;
use serial_test::serial;

use support::{ServerxInstance, dev_login, expect_json, expect_status, register_account};

#[tokio::test]
#[serial]
async fn account_contact_space_message_sync_workflow() -> Result<()> {
    let server = ServerxInstance::spawn("collaboration-workflow").await?;
    let alice = dev_login(&server, "did:web:alice.example", "dev_alice").await?;
    let bob = register_account(&server, "did:web:bob.example", "@bob", "dev_bob").await?;

    expect_status(
        server
            .http()
            .post(server.url("/api/v1/account/register"))
            .json(&json!({
                "did": "did:web:bob.example",
                "handle": "@bob",
                "device_id": "dev_bob2"
            })),
        StatusCode::CONFLICT,
    )
    .await?;

    let hidden_bob = expect_json(
        server
            .http()
            .get(server.url("/api/v1/directory/search-users?q=bob")),
        StatusCode::OK,
    )
    .await?;
    assert!(hidden_bob["results"].as_array().unwrap().is_empty());

    let me = expect_json(
        server
            .http()
            .get(server.url("/api/v1/account/me"))
            .bearer_auth(&bob),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(me["did"], "did:web:bob.example");

    let requested = expect_json(
        server
            .http()
            .post(server.url("/api/v1/contacts/request"))
            .bearer_auth(&alice)
            .json(&json!({"target": "did:web:bob.example"})),
        StatusCode::CREATED,
    )
    .await?;
    assert_eq!(requested["status"], "pending");

    let accepted = expect_json(
        server
            .http()
            .post(server.url("/api/v1/contacts/respond"))
            .bearer_auth(&bob)
            .json(&json!({"requester": "did:web:alice.example", "action": "accept"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(accepted["status"], "accepted");

    let visible_bob = expect_json(
        server
            .http()
            .get(server.url("/api/v1/directory/search-users?q=bob"))
            .bearer_auth(&alice),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(visible_bob["results"][0]["did"], "did:web:bob.example");

    let created_space = expect_json(
        server
            .http()
            .post(server.url("/api/v1/spaces"))
            .bearer_auth(&alice)
            .json(&json!({
                "title": "Collaboration Workflow Space",
                "summary": "single server collaboration",
                "public": false
            })),
        StatusCode::CREATED,
    )
    .await?;
    let space_id = created_space["space_id"].as_str().unwrap().to_owned();
    assert_eq!(created_space["owner"], "did:web:alice.example");

    expect_status(
        server
            .http()
            .post(server.url("/api/v1/directory/resolve-space"))
            .json(&json!({"space_id": space_id})),
        StatusCode::NOT_FOUND,
    )
    .await?;

    let with_bob = expect_json(
        server
            .http()
            .post(server.url(&format!("/api/v1/spaces/{space_id}/members")))
            .bearer_auth(&alice)
            .json(&json!({"member": "did:web:bob.example"})),
        StatusCode::OK,
    )
    .await?;
    assert!(
        with_bob["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member == "did:web:bob.example")
    );

    let sent = expect_json(
        server
            .http()
            .post(server.url("/api/v1/messages/send"))
            .bearer_auth(&alice)
            .json(&json!({
                "space_id": space_id,
                "thread_id": "cx:thread:collaboration",
                "content": {"body": "hello from collaboration workflow"},
                "encrypted": false
            })),
        StatusCode::CREATED,
    )
    .await?;
    assert!(
        sent["operation_id"]
            .as_str()
            .unwrap()
            .starts_with("cx:operation:")
    );

    let thread = expect_json(
        server
            .http()
            .get(server.url("/api/v1/index/thread?thread_id=cx:thread:collaboration"))
            .bearer_auth(&bob),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        thread["events"][0]["content"]["body"],
        "hello from collaboration workflow"
    );

    let search = expect_json(
        server
            .http()
            .post(server.url("/api/v1/index/search"))
            .bearer_auth(&bob)
            .json(&json!({
                "query": "collaboration",
                "space_ids": [space_id],
                "entity_types": ["message"]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(search["results"][0]["event_id"], sent["event_id"]);

    let bob_sync = expect_json(
        server
            .http()
            .post(server.url("/api/v1/sync"))
            .bearer_auth(&bob)
            .json(&json!({})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        bob_sync["spaces"][&space_id]["timeline"]["events"][0]["event_id"],
        sent["event_id"]
    );

    let snapshot = expect_json(
        server
            .http()
            .get(server.url(&format!("/api/v1/sync/snapshot-head?space_id={space_id}"))),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(snapshot["frontier"]["message_count"], 1);

    let kicked = expect_json(
        server
            .http()
            .delete(server.url(&format!(
                "/api/v1/spaces/{space_id}/members/did:web:bob.example"
            )))
            .bearer_auth(&alice),
        StatusCode::OK,
    )
    .await?;
    assert!(
        !kicked["members"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member == "did:web:bob.example")
    );

    let deleted = expect_json(
        server
            .http()
            .delete(server.url(&format!("/api/v1/spaces/{space_id}")))
            .bearer_auth(&alice),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(deleted["deleted"], true);

    let lifecycle = expect_json(
        server
            .http()
            .get(server.url(&format!("/api/v1/sync/backfill?space_id={space_id}"))),
        StatusCode::OK,
    )
    .await?;
    let actions: std::collections::BTreeSet<_> = lifecycle["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["event_type"] == "space.lifecycle")
        .map(|event| event["payload"]["action"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        actions,
        ["create", "delete", "member.add", "member.remove"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    );

    let logout = expect_json(
        server
            .http()
            .post(server.url("/api/v1/auth/logout"))
            .bearer_auth(&bob),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(logout["revoked"], true);

    expect_status(
        server
            .http()
            .get(server.url("/api/v1/account/me"))
            .bearer_auth(&bob),
        StatusCode::UNAUTHORIZED,
    )
    .await?;

    Ok(())
}
