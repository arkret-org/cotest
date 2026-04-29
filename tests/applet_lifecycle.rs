mod support;

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;
use serial_test::serial;

use support::{TestServerGroup, expect_api_error, expect_json};

#[tokio::test]
#[serial]
#[ignore]
async fn owner_installs_lists_and_deletes_space_applet() -> Result<()> {
    // TODO(serverx): expose applet lifecycle routes.
    let group = TestServerGroup::single("applet-lifecycle").await?;
    let server = group.server(0);
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let space_id = alice.create_space("Applet Lifecycle Space").await?;

    let installed = expect_json(
        alice
            .post(&format!("/api/v1/spaces/{space_id}/applets"))
            .json(&json!({
                "applet_id": "cx:applet:board",
                "manifest": {
                    "name": "Board",
                    "version": "1.0.0",
                    "entrypoint": "https://applets.example/board/index.html",
                    "permissions": ["space.read", "event.send", "entity.write"]
                },
                "configuration": {
                    "default_view": "kanban"
                }
            })),
        StatusCode::CREATED,
    )
    .await?;
    assert_eq!(installed["space_id"], space_id);
    assert_eq!(installed["applet_id"], "cx:applet:board");
    assert_eq!(installed["state"], "active");
    assert_eq!(installed["installed_by"], "did:web:alice.example");

    let listed = expect_json(
        alice.get(&format!("/api/v1/spaces/{space_id}/applets")),
        StatusCode::OK,
    )
    .await?;
    assert!(
        listed["applets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|applet| applet["applet_id"] == "cx:applet:board")
    );

    let deleted = expect_json(
        alice.delete(&format!(
            "/api/v1/spaces/{space_id}/applets/cx:applet:board"
        )),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(deleted["deleted"], true);

    expect_api_error(
        alice.get(&format!(
            "/api/v1/spaces/{space_id}/applets/cx:applet:board"
        )),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    Ok(())
}

#[tokio::test]
#[serial]
#[ignore]
async fn applet_installation_requires_owner_or_capability() -> Result<()> {
    // TODO(serverx): enforce applet install/delete capability checks.
    let group = TestServerGroup::single("applet-permissions").await?;
    let server = group.server(0);
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client("did:web:bob-applet.example", "@bob-applet", "dev_bob")
        .await?;
    let space_id = alice.create_space("Applet Permission Space").await?;
    alice.add_member(&space_id, &bob).await?;

    expect_api_error(
        bob.post(&format!("/api/v1/spaces/{space_id}/applets"))
            .json(&json!({
                "applet_id": "cx:applet:board",
                "manifest": {"name": "Board", "version": "1.0.0"}
            })),
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;

    expect_api_error(
        bob.delete(&format!(
            "/api/v1/spaces/{space_id}/applets/cx:applet:board"
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
async fn applet_events_are_projected_to_sync_index_and_backfill() -> Result<()> {
    // TODO(serverx): project applet install/delete and applet-emitted events.
    let group = TestServerGroup::single("applet-events").await?;
    let server = group.server(0);
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let space_id = alice.create_space("Applet Event Space").await?;

    expect_json(
        alice
            .post(&format!("/api/v1/spaces/{space_id}/applets"))
            .json(&json!({
                "applet_id": "cx:applet:board",
                "manifest": {
                    "name": "Board",
                    "version": "1.0.0",
                    "permissions": ["event.send", "entity.write"]
                }
            })),
        StatusCode::CREATED,
    )
    .await?;

    let emitted = expect_json(
        alice
            .post(&format!(
                "/api/v1/spaces/{space_id}/applets/cx:applet:board/events"
            ))
            .json(&json!({
                "event_type": "cx.applet.board.card.create",
                "entity_id": "cx:entity:card-01",
                "content": {
                    "title": "Card from applet",
                    "state": "active"
                }
            })),
        StatusCode::CREATED,
    )
    .await?;
    assert_eq!(emitted["space_id"], space_id);
    assert_eq!(emitted["applet_id"], "cx:applet:board");

    let sync = alice.sync().await?;
    assert!(
        sync["spaces"][&space_id]["timeline"]["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event_id"] == emitted["event_id"])
    );

    let search = expect_json(
        alice.post("/api/v1/index/search").json(&json!({
            "query": "Card from applet",
            "space_ids": [space_id],
            "entity_types": ["applet_event", "entity"]
        })),
        StatusCode::OK,
    )
    .await?;
    assert!(!search["results"].as_array().unwrap().is_empty());

    let backfill = expect_json(
        alice.get(&format!("/api/v1/sync/backfill?space_id={space_id}")),
        StatusCode::OK,
    )
    .await?;
    assert!(
        backfill["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|event| event["event_id"] == emitted["event_id"])
    );

    Ok(())
}

#[tokio::test]
#[serial]
#[ignore]
async fn applet_lifecycle_federates_between_servers() -> Result<()> {
    // TODO(serverx): federate applet lifecycle and applet-emitted events.
    let group = TestServerGroup::multi("applet-federation", 2).await?;
    let server_a = group.server(0);
    let server_b = group.server(1);
    let alice = server_a
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server_b
        .register_client(
            "did:web:bob-applet-fed.example",
            "@bob-applet-fed",
            "dev_bob",
        )
        .await?;
    let space_id = alice.create_space("Federated Applet Space").await?;

    let installed = expect_json(
        alice
            .post(&format!("/api/v1/spaces/{space_id}/applets"))
            .json(&json!({
                "applet_id": "cx:applet:board",
                "manifest": {
                    "name": "Board",
                    "version": "1.0.0",
                    "permissions": ["event.send", "entity.write"]
                },
                "federate": true
            })),
        StatusCode::CREATED,
    )
    .await?;
    assert_eq!(installed["state"], "active");

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
            .any(|operation| operation["object_type"] == "applet.lifecycle")
    );

    let bob_sync = bob.sync().await?;
    assert!(
        bob_sync["spaces"][&space_id]["state"]["applets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|applet| applet["applet_id"] == "cx:applet:board")
    );

    Ok(())
}
