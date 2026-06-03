use anyhow::Result;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    CokretServer, account_subscribe_delta_from_text, expect_audit_action, expect_json,
    expect_response, expect_status,
};

pub async fn contacts_invites_listing_export_and_audit_work() -> Result<()> {
    let server = CokretServer::spawn("directory-workflow").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client("did:web:bob-directory.example", "@bob-directory", "dev_bob")
        .await?;

    expect_json(
        alice
            .post("/_cokret/self/contacts/request")
            .json(&json!({"target": bob.actor})),
        StatusCode::CREATED,
    )
    .await?;
    expect_json(
        bob.post("/_cokret/self/contacts/respond").json(&json!({
            "requester": alice.actor,
            "action": "accept"
        })),
        StatusCode::OK,
    )
    .await?;

    let contacts = expect_json(bob.get("/_cokret/self/contacts"), StatusCode::OK).await?;
    assert_eq!(contacts["contacts"].as_array().unwrap().len(), 1);

    let invite_space = alice
        .create_realm_with(json!({
            "title": "Invite Token Space",
            "discoverability": "invite_only",
            "invitees": [bob.actor.clone()]
        }))
        .await?;
    let invite_space_id = invite_space["realm_id"].as_str().unwrap().to_owned();
    let invite_event = alice
        .submit_event(
            &invite_space_id,
            "ck.invite.create",
            json!({
                "invitee": bob.actor,
                "expires_at": "2026-12-31T00:00:00Z"
            }),
        )
        .await?;
    assert_eq!(
        invite_event["status"],
        "accepted",
        "invite event was not accepted: {}",
        serde_json::to_string_pretty(&invite_event)?
    );

    let invites = expect_json(bob.get("/_cokret/self/authz/invites"), StatusCode::OK).await?;
    assert_eq!(
        invites["invites"].as_array().unwrap().len(),
        1,
        "expected one invite for bob: {}",
        serde_json::to_string_pretty(&invites)?
    );
    assert_eq!(invites["invites"][0]["space_id"], invite_space_id);
    let invite_token = invites["invites"][0]["invite_token"].as_str().unwrap();

    expect_status(
        server
            .http()
            .post(server.url("/_cokret/find/directory/resolve-realm"))
            .json(&json!({"invite_token": "ck:invite-token:invalid"})),
        StatusCode::NOT_FOUND,
    )
    .await?;

    let invite_resolve = expect_json(
        server
            .http()
            .post(server.url("/_cokret/find/directory/resolve-realm"))
            .json(&json!({"invite_token": invite_token})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(invite_resolve["space_preview"]["realm_id"], invite_space_id);

    let listed_space = alice
        .create_realm_with(json!({
            "title": "Listed Directory Space",
            "discoverability": "listed"
        }))
        .await?;
    let listed_space_id = listed_space["realm_id"].as_str().unwrap().to_owned();
    let listed_search = expect_json(
        server
            .http()
            .post(server.url("/_cokret/find/directory/search-realms"))
            .json(&json!({"query": "Listed Directory Space"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(listed_search["results"][0]["realm_id"], listed_space_id);

    let unlisted_space = alice
        .create_realm_with(json!({
            "title": "Unlisted Directory Space",
            "discoverability": "unlisted"
        }))
        .await?;
    let unlisted_space_id = unlisted_space["realm_id"].as_str().unwrap().to_owned();
    let unlisted_search = expect_json(
        server
            .http()
            .post(server.url("/_cokret/find/directory/search-realms"))
            .json(&json!({"query": "Unlisted Directory Space"})),
        StatusCode::OK,
    )
    .await?;
    assert!(unlisted_search["results"].as_array().unwrap().is_empty());

    let unlisted_resolve = expect_json(
        server
            .http()
            .post(server.url("/_cokret/find/directory/resolve-realm"))
            .json(&json!({"realm_id": unlisted_space_id})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        unlisted_resolve["space_preview"]["realm_id"],
        unlisted_space["realm_id"]
    );

    let shared_space_id = alice.create_realm("Workflow Export Space").await?;
    alice.add_member(&shared_space_id, &bob).await?;
    let sent = alice
        .send_message(
            &shared_space_id,
            "ck:thread:directory-workflow",
            "hello directory workflow",
        )
        .await?;

    let exported = expect_json(
        alice.get(&format!("/_cokret/self/spaces/{shared_space_id}/export")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(exported["schema"], "cx.export.space.v1");
    let sent_operation_id =
        sent["event_id"]
            .as_str()
            .unwrap()
            .replacen("ck:event:", "ck:operation:", 1);
    assert!(
        exported["operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation["operation_id"] == sent_operation_id)
    );

    let waited_sync = expect_response(
        alice
            .get("/_cokret/self/account/subscribe?catchup=true")
            .header("x-cokret-wait-for", sent["sync_token"].as_str().unwrap())
            .header("accept", "application/x-ndjson"),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        waited_sync
            .headers
            .get("x-cokret-wait-for-satisfied")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    let waited_sync = account_subscribe_delta_from_text(&waited_sync.text())?;
    let waited_events = waited_sync["realms"][&shared_space_id]["timeline"]["events"]
        .as_array()
        .unwrap();
    assert!(
        waited_events
            .iter()
            .any(|event| event["event_id"] == sent["event_id"]),
        "waited sync did not include submitted message event: {waited_sync}"
    );

    expect_status(
        alice
            .get("/_cokret/self/account/subscribe?catchup=true")
            .header("x-cokret-wait-for", "not-a-sync-token")
            .header("accept", "application/x-ndjson"),
        StatusCode::BAD_REQUEST,
    )
    .await?;

    let audit_events = expect_json(
        alice.get("/_cokret/self/audit/events?limit=20"),
        StatusCode::OK,
    )
    .await?;
    let _ = expect_audit_action(&audit_events, "events.submit")?;

    expect_status(
        alice.get(&format!("/_cokret/self/audit/events?actor={}", bob.actor)),
        StatusCode::FORBIDDEN,
    )
    .await?;

    Ok(())
}
