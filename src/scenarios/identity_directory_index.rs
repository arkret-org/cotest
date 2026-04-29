use std::{collections::BTreeSet, time::Duration};

use anyhow::{Result, anyhow};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    ContrixServer, eventually, expect_api_error, expect_audit_action, expect_json,
    expect_response, expect_status,
};

const DEMO_SPACE_ID: &str = "cx:space:01js0sp0000000000000000000";

pub async fn identity_surface_and_receipts_work() -> Result<()> {
    let server = ContrixServer::spawn("identity-surface").await?;

    let describe = expect_json(
        server.http().get(server.url("/api/v1/identity/describe")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(describe["protocol_version"], "1.0");

    let resolved = expect_json(
        server
            .http()
            .post(server.url("/api/v1/identity/resolve"))
            .json(&json!({"did": "did:web:alice.example"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(resolved["did_document"]["id"], "did:web:alice.example");

    let document = expect_json(
        server
            .http()
            .get(server.url("/api/v1/identity/document?did=did:web:alice.example")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(document["did_document"]["id"], "did:web:alice.example");

    let log = expect_json(
        server
            .http()
            .get(server.url("/api/v1/identity/log?did=did:web:alice.example")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(log["has_more"], false);

    let submitted = expect_json(
        server
            .http()
            .post(server.url("/api/v1/identity/submit-did-operation"))
            .json(&json!({
                "did": "did:web:alice.example",
                "seq": 1,
                "patch": {
                    "did_document": {
                        "id": "did:web:alice.example",
                        "verification_method": [{
                            "id": "did:web:alice.example#key-1",
                            "type": "JsonWebKey2020",
                            "controller": "did:web:alice.example",
                            "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "dev"}
                        }],
                        "authentication": ["did:web:alice.example#key-1"],
                        "service": [{
                            "id": "#soland",
                            "type": "ContrixPrincipalServer",
                            "serviceEndpoint": "https://alice.example"
                        }]
                    }
                },
                "proofs": [{"kid": "did:web:alice.example#key-1", "sig": "dev"}]
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(submitted["status"], "accepted");
    assert_eq!(submitted["seq"], 1);

    let resolved_after_submit = expect_json(
        server
            .http()
            .post(server.url("/api/v1/identity/resolve"))
            .json(&json!({"did": "did:web:alice.example"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        resolved_after_submit["key_log_head"],
        submitted["head_event_hash"]
    );
    assert_eq!(resolved_after_submit["seq"], 1);
    assert_eq!(
        resolved_after_submit["did_document"]["authentication"][0],
        "did:web:alice.example#key-1"
    );

    let log_after_submit = expect_json(
        server
            .http()
            .get(server.url("/api/v1/identity/log?did=did:web:alice.example")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(log_after_submit["events"].as_array().unwrap().len(), 1);
    assert_eq!(log_after_submit["events"][0]["seq"], 1);

    let receipts = expect_json(
        server
            .http()
            .get(server.url("/api/v1/identity/receipts?did=did:web:alice.example")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(receipts["threshold_met"], true);
    assert_eq!(
        receipts["receipts"][0]["head_event_hash"],
        submitted["head_event_hash"]
    );

    Ok(())
}

pub async fn discovery_and_index_demo_projection_shapes_work() -> Result<()> {
    let server = ContrixServer::spawn("discovery-index").await?;

    let sync_describe = expect_json(
        server.http().get(server.url("/api/v1/sync/describe")),
        StatusCode::OK,
    )
    .await?;
    for profile in ["board", "chat", "topic"] {
        assert!(
            sync_describe["supported_sync_profiles"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == profile),
            "missing supported sync profile {profile}"
        );
    }

    expect_status(
        server
            .http()
            .post(server.url("/api/v1/sync"))
            .json(&json!({"profile": "invalid"})),
        StatusCode::BAD_REQUEST,
    )
    .await?;

    let chat_sync = expect_json(
        server
            .http()
            .post(server.url("/api/v1/sync"))
            .json(&json!({"profile": "chat"})),
        StatusCode::OK,
    )
    .await?;
    assert!(
        chat_sync["spaces"]
            .as_object()
            .unwrap()
            .contains_key(DEMO_SPACE_ID)
    );

    let directory = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/search-spaces"))
            .json(&json!({"query": "demo", "limit": 10})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(directory["results"].as_array().unwrap().len(), 1);

    let resolved_space = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/resolve-space"))
            .json(&json!({"space_id": DEMO_SPACE_ID})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(resolved_space["space_preview"]["space_id"], DEMO_SPACE_ID);

    let organizations = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/search-organizations"))
            .json(&json!({"query": "contrix", "limit": 10})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        organizations["results"][0]["organization_id"],
        "cx:org:demo"
    );

    let organization = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/resolve-organization"))
            .json(&json!({"organization_id": "cx:org:demo"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(organization["organization"]["handle"], "@contrix-demo");
    assert_eq!(organization["spaces"].as_array().unwrap().len(), 1);

    let actors = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/search-actors"))
            .json(&json!({"query": "alice"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(actors["results"][0]["did"], "did:web:alice.example");

    let users = expect_json(
        server
            .http()
            .get(server.url("/api/v1/directory/search-users?q=alice")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(users["results"][0]["handle"], "@alice");

    let handle = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/resolve-handle"))
            .json(&json!({"handle": "alice"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(handle["did"], "did:web:alice.example");

    expect_api_error(
        server
            .http()
            .get(server.url("/api/v1/directory/search-users?limit=0")),
        StatusCode::BAD_REQUEST,
        "invalid_param",
    )
    .await?;

    let entity = expect_json(
        server
            .http()
            .get(server.url(&format!("/api/v1/index/entity?entity_id={DEMO_SPACE_ID}"))),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(entity["entity"]["kind"], "space");

    let index = expect_json(
        server
            .http()
            .post(server.url("/api/v1/index/query"))
            .json(&json!({"space_ids": [DEMO_SPACE_ID]})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(index["results"].as_array().unwrap().len(), 1);

    let thread = expect_json(
        server
            .http()
            .get(server.url("/api/v1/index/thread?thread_id=cx:thread:demo")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(thread["thread"]["thread_id"], "cx:thread:demo");
    assert!(thread["events"].as_array().unwrap().is_empty());

    let notifications = expect_json(
        server
            .http()
            .get(server.url("/api/v1/index/notifications?actor=did:web:alice.example")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(notifications["unread_count"], 0);

    let inbox = expect_json(
        server.http().get(server.url("/api/v1/index/inbox")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(inbox["rooms"].as_array().unwrap().len(), 1);

    let search = expect_json(
        server
            .http()
            .post(server.url("/api/v1/index/search"))
            .json(&json!({"query": "demo", "entity_types": ["space"], "limit": 5})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(search["results"].as_array().unwrap().len(), 1);

    let hierarchy = expect_json(
        server.http().get(server.url(&format!(
            "/api/v1/index/space-hierarchy?root_space_id={DEMO_SPACE_ID}"
        ))),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(hierarchy["root_space_id"], DEMO_SPACE_ID);

    Ok(())
}

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

pub async fn directory_discoverability_and_actor_privacy_work() -> Result<()> {
    let server = ContrixServer::spawn("directory-privacy").await?;
    let alice = server
        .demo_client("did:web:alice.example", "dev_alice")
        .await?;
    let bob = server
        .register_client("did:web:bob-privacy.example", "@bob-privacy", "dev_bob")
        .await?;

    let public_space = expect_json(
        alice.post("/api/v1/spaces").json(&json!({
            "title": "Visibility Matrix Public",
            "discoverability": "public"
        })),
        StatusCode::CREATED,
    )
    .await?;
    let listed_space = expect_json(
        alice.post("/api/v1/spaces").json(&json!({
            "title": "Visibility Matrix Listed",
            "discoverability": "listed"
        })),
        StatusCode::CREATED,
    )
    .await?;
    let restricted_space = expect_json(
        alice.post("/api/v1/spaces").json(&json!({
            "title": "Visibility Matrix Restricted",
            "discoverability": "restricted"
        })),
        StatusCode::CREATED,
    )
    .await?;
    let unlisted_space = expect_json(
        alice.post("/api/v1/spaces").json(&json!({
            "title": "Visibility Matrix Unlisted",
            "discoverability": "unlisted"
        })),
        StatusCode::CREATED,
    )
    .await?;
    let invite_only_space = expect_json(
        alice.post("/api/v1/spaces").json(&json!({
            "title": "Visibility Matrix Invite Only",
            "discoverability": "invite_only",
            "invitees": [bob.actor.clone()]
        })),
        StatusCode::CREATED,
    )
    .await?;
    let secret_space = expect_json(
        alice.post("/api/v1/spaces").json(&json!({
            "title": "Visibility Matrix Secret",
            "discoverability": "secret"
        })),
        StatusCode::CREATED,
    )
    .await?;

    let public_space_id = public_space["space_id"].as_str().unwrap().to_owned();
    let listed_space_id = listed_space["space_id"].as_str().unwrap().to_owned();
    let restricted_space_id = restricted_space["space_id"].as_str().unwrap().to_owned();
    let unlisted_space_id = unlisted_space["space_id"].as_str().unwrap().to_owned();
    let invite_only_space_id = invite_only_space["space_id"].as_str().unwrap().to_owned();
    let secret_space_id = secret_space["space_id"].as_str().unwrap().to_owned();

    let anonymous_search = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/search-spaces"))
            .json(&json!({"query": "Visibility Matrix", "limit": 20})),
        StatusCode::OK,
    )
    .await?;
    let anonymous_search_ids: BTreeSet<_> = anonymous_search["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|space| space["space_id"].as_str().map(ToOwned::to_owned))
        .collect();
    assert_eq!(
        anonymous_search_ids,
        BTreeSet::from([
            public_space_id.clone(),
            listed_space_id.clone(),
            restricted_space_id.clone(),
        ])
    );

    for resolvable_space_id in [
        &public_space_id,
        &listed_space_id,
        &restricted_space_id,
        &unlisted_space_id,
    ] {
        let resolved = expect_json(
            server
                .http()
                .post(server.url("/api/v1/directory/resolve-space"))
                .json(&json!({"space_id": resolvable_space_id.as_str()})),
            StatusCode::OK,
        )
        .await?;
        assert_eq!(
            resolved["space_preview"]["space_id"],
            resolvable_space_id.as_str()
        );
    }

    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/directory/resolve-space"))
            .json(&json!({"space_id": invite_only_space_id.clone()})),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    expect_api_error(
        server
            .http()
            .post(server.url("/api/v1/directory/resolve-space"))
            .json(&json!({"space_id": secret_space_id.clone()})),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    let invites = expect_json(bob.get("/api/v1/authz/invites"), StatusCode::OK).await?;
    let invite_token = invites["invites"]
        .as_array()
        .unwrap()
        .iter()
        .find(|invite| invite["space_id"].as_str() == Some(invite_only_space_id.as_str()))
        .and_then(|invite| invite["invite_token"].as_str())
        .ok_or_else(|| anyhow!("missing invite token for invite-only space"))?;
    let invite_only_resolved = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/resolve-space"))
            .json(&json!({
                "space_id": invite_only_space_id.clone(),
                "invite_token": invite_token
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        invite_only_resolved["space_preview"]["space_id"],
        invite_only_space_id
    );

    let secret_resolved = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/resolve-space"))
            .json(&json!({
                "space_id": secret_space_id.clone(),
                "signed_link": "cotest-signed-link"
            })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(secret_resolved["space_preview"]["space_id"], secret_space_id);

    let all_space_ids = vec![
        public_space_id.clone(),
        listed_space_id.clone(),
        restricted_space_id.clone(),
        unlisted_space_id.clone(),
        invite_only_space_id.clone(),
        secret_space_id.clone(),
    ];
    let anonymous_index = expect_json(
        server
            .http()
            .post(server.url("/api/v1/index/query"))
            .json(&json!({"space_ids": all_space_ids})),
        StatusCode::OK,
    )
    .await?;
    let anonymous_index_ids: BTreeSet<_> = anonymous_index["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["space_id"].as_str().map(ToOwned::to_owned))
        .collect();
    assert_eq!(anonymous_index_ids, BTreeSet::from([public_space_id.clone()]));

    let alice_index = expect_json(
        alice.post("/api/v1/index/query").json(&json!({
            "space_ids": [
                public_space_id,
                listed_space_id,
                restricted_space_id,
                unlisted_space_id,
                invite_only_space_id,
                secret_space_id
            ]
        })),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(alice_index["results"].as_array().unwrap().len(), 6);

    let anonymous_bob_actors = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/search-actors"))
            .json(&json!({"query": "bob-privacy"})),
        StatusCode::OK,
    )
    .await?;
    assert!(anonymous_bob_actors["results"].as_array().unwrap().is_empty());

    let anonymous_bob_users = expect_json(
        server
            .http()
            .get(server.url("/api/v1/directory/search-users?q=bob-privacy")),
        StatusCode::OK,
    )
    .await?;
    assert!(anonymous_bob_users["results"].as_array().unwrap().is_empty());

    let anonymous_alice = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/search-actors"))
            .json(&json!({"query": "alice"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(anonymous_alice["results"][0]["did"], "did:web:alice.example");

    let alice_before_contact = expect_json(
        alice
            .post("/api/v1/directory/search-actors")
            .json(&json!({"query": "bob-privacy"})),
        StatusCode::OK,
    )
    .await?;
    assert!(alice_before_contact["results"].as_array().unwrap().is_empty());

    let bob_self = expect_json(
        bob.post("/api/v1/directory/search-actors")
            .json(&json!({"query": "bob-privacy"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(bob_self["results"][0]["did"], bob.actor);

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

    let alice_after_contact = expect_json(
        alice
            .post("/api/v1/directory/search-actors")
            .json(&json!({"query": "bob-privacy"})),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(alice_after_contact["results"][0]["did"], bob.actor);

    let alice_user_after_contact = expect_json(
        alice.get("/api/v1/directory/search-users?q=bob-privacy"),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(alice_user_after_contact["results"][0]["handle"], "@bob-privacy");

    let anonymous_after_contact = expect_json(
        server
            .http()
            .post(server.url("/api/v1/directory/search-actors"))
            .json(&json!({"query": "bob-privacy"})),
        StatusCode::OK,
    )
    .await?;
    assert!(anonymous_after_contact["results"].as_array().unwrap().is_empty());

    Ok(())
}
