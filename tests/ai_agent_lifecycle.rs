mod support;

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;
use serial_test::serial;

use support::{TestServerGroup, expect_api_error, expect_json};

#[tokio::test]
#[serial]
#[ignore]
async fn owner_adds_agent_agent_emits_event_and_owner_deletes_it() -> Result<()> {
    // TODO(serverx): expose AI agent lifecycle routes.
    let group = TestServerGroup::single("agent-lifecycle").await?;
    let server = group.server(0);
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let space_id = alice.create_space("Agent Lifecycle Space").await?;

    let agent = expect_json(
        alice
            .post(&format!("/api/v1/spaces/{space_id}/agents"))
            .json(&json!({
                "agent_id": "did:web:planner-agent.example",
                "display_name": "Planner",
                "model": "test-agent",
                "capabilities": ["event.send", "entity.read", "entity.write"],
                "memory_scope": "space"
            })),
        StatusCode::CREATED,
    )
    .await?;
    assert_eq!(agent["space_id"], space_id);
    assert_eq!(agent["agent_id"], "did:web:planner-agent.example");
    assert_eq!(agent["state"], "active");

    let emitted = expect_json(
        alice
            .post(&format!(
                "/api/v1/spaces/{space_id}/agents/did:web:planner-agent.example/events"
            ))
            .json(&json!({
                "event_type": "cx.agent.suggestion",
                "content": {
                    "body": "Create the project checklist",
                    "confidence": 0.9
                }
            })),
        StatusCode::CREATED,
    )
    .await?;
    assert_eq!(emitted["sender"], "did:web:planner-agent.example");

    let thread = expect_json(
        alice.get(&format!(
            "/api/v1/index/thread?thread_id={}",
            emitted["thread_id"].as_str().unwrap()
        )),
        StatusCode::OK,
    )
    .await?;
    assert!(
        thread["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event_id"] == emitted["event_id"])
    );

    let deleted = expect_json(
        alice.delete(&format!(
            "/api/v1/spaces/{space_id}/agents/did:web:planner-agent.example"
        )),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(deleted["deleted"], true);

    Ok(())
}

#[tokio::test]
#[serial]
#[ignore]
async fn agent_permissions_limit_space_and_memory_access() -> Result<()> {
    // TODO(serverx): enforce AI agent capability and memory boundaries.
    let group = TestServerGroup::single("agent-permissions").await?;
    let server = group.server(0);
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client("did:web:bob-agent.example", "@bob-agent", "dev_bob")
        .await?;
    let space_id = alice.create_space("Agent Permission Space").await?;
    alice.add_member(&space_id, &bob).await?;

    expect_api_error(
        bob.post(&format!("/api/v1/spaces/{space_id}/agents"))
            .json(&json!({
                "agent_id": "did:web:unauthorized-agent.example",
                "display_name": "Unauthorized",
                "capabilities": ["event.send"]
            })),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    expect_json(
        alice
            .post(&format!("/api/v1/spaces/{space_id}/agents"))
            .json(&json!({
                "agent_id": "did:web:reader-agent.example",
                "display_name": "Reader",
                "capabilities": ["entity.read"],
                "memory_scope": "space"
            })),
        StatusCode::CREATED,
    )
    .await?;

    expect_api_error(
        alice
            .post(&format!(
                "/api/v1/spaces/{space_id}/agents/did:web:reader-agent.example/events"
            ))
            .json(&json!({
                "event_type": "cx.agent.write_attempt",
                "content": {"body": "should be denied"}
            })),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    expect_api_error(
        bob.get(&format!(
            "/api/v1/spaces/{space_id}/agents/did:web:reader-agent.example/memory"
        )),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    Ok(())
}

#[tokio::test]
#[serial]
#[ignore]
async fn non_owner_cannot_delete_agent() -> Result<()> {
    // TODO(serverx): enforce AI agent delete permission checks.
    let group = TestServerGroup::single("agent-delete-permissions").await?;
    let server = group.server(0);
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client(
            "did:web:bob-agent-delete.example",
            "@bob-agent-delete",
            "dev_bob",
        )
        .await?;
    let space_id = alice.create_space("Agent Delete Permission Space").await?;
    alice.add_member(&space_id, &bob).await?;

    expect_json(
        alice
            .post(&format!("/api/v1/spaces/{space_id}/agents"))
            .json(&json!({
                "agent_id": "did:web:planner-agent.example",
                "display_name": "Planner",
                "capabilities": ["event.send"]
            })),
        StatusCode::CREATED,
    )
    .await?;

    expect_api_error(
        bob.delete(&format!(
            "/api/v1/spaces/{space_id}/agents/did:web:planner-agent.example"
        )),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    Ok(())
}

#[tokio::test]
#[serial]
#[ignore]
async fn agent_lifecycle_and_events_federate_between_servers() -> Result<()> {
    // TODO(serverx): federate AI agent lifecycle, permissions, memory scope, and agent events.
    let group = TestServerGroup::multi("agent-federation", 2).await?;
    let server_a = group.server(0);
    let server_b = group.server(1);
    let alice = server_a
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server_b
        .register_client("did:web:bob-agent-fed.example", "@bob-agent-fed", "dev_bob")
        .await?;
    let space_id = alice.create_space("Federated Agent Space").await?;

    expect_json(
        alice
            .post(&format!("/api/v1/spaces/{space_id}/agents"))
            .json(&json!({
                "agent_id": "did:web:planner-agent.example",
                "display_name": "Planner",
                "capabilities": ["event.send", "entity.read"],
                "memory_scope": "space",
                "federate": true
            })),
        StatusCode::CREATED,
    )
    .await?;

    let event = expect_json(
        alice
            .post(&format!(
                "/api/v1/spaces/{space_id}/agents/did:web:planner-agent.example/events"
            ))
            .json(&json!({
                "event_type": "cx.agent.suggestion",
                "content": {"body": "federated agent event"}
            })),
        StatusCode::CREATED,
    )
    .await?;

    let pulled = expect_json(
        server_b.http().get(server_b.url(&format!(
            "/api/v1/federation/pull-operations?space_id={space_id}"
        ))),
        StatusCode::OK,
    )
    .await?;
    assert!(
        pulled["operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation["object_type"] == "agent.lifecycle"
                || operation["object_type"] == "agent.event")
    );

    let bob_sync = bob.sync().await?;
    assert!(
        bob_sync["spaces"][&space_id]["timeline"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|synced| synced["event_id"] == event["event_id"])
    );

    Ok(())
}
