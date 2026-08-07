use std::collections::BTreeSet;

use anyhow::Result;
use arkret_models_collaboration::governance::membership_invite::MembershipPayloadState;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    ArkretServer, TestActorClient, expect_json, expect_status, member_join_payload_value,
    member_transition_payload,
};

const ALICE_DID: &str = "did:web:cotest-collab-alice.example";
const BOB_DID: &str = "did:web:cotest-collab-bob.example";
const BOB_HANDLE: &str = "@cotest-collab-bob";

pub async fn account_contact_space_message_sync_workflow() -> Result<()> {
    let server = ArkretServer::spawn("collaboration-workflow").await?;
    let alice = server
        .register_client(
            ALICE_DID,
            "@cotest-collab-alice",
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await?;
    let bob = server
        .register_client(
            BOB_DID,
            BOB_HANDLE,
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;

    let bob_second_device = expect_json(
        server
            .account_registration_request()
            .json(&crate::harness::NonProtocolTestBody::new(json!({
                "principal_id": BOB_DID,
                "display_name": BOB_HANDLE.trim_start_matches('@'),
                "device_id": "ak:device:01904100-0000-7000-8000-0000000000b2"
            }))),
        StatusCode::OK,
    )
    .await?;
    let bob_devices = bob_second_device["devices"]
        .as_array()
        .expect("bob devices array");
    assert!(bob_devices.iter().any(|device| {
        device["device_id"].as_str() == Some("ak:device:01904100-0000-7000-8000-0000000000b2")
    }));

    let hidden_bob = expect_json(
        server
            .http()
            .post(server.url("/_arkret/find/directory/search-users"))
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectorySearchUsersRequestBody,
            >(
                json!({"query": BOB_HANDLE.trim_start_matches('@')})
            )?),
        StatusCode::OK,
    )
    .await?;
    let hidden_results = hidden_bob["users"]
        .as_array()
        .expect("search-users response users");
    assert!(
        !hidden_results
            .iter()
            .any(|result| result["did"].as_str() == Some(BOB_DID))
    );

    let me = expect_json(
        server
            .http()
            .get(server.url("/_arkret/self/account/viewer"))
            .bearer_auth(&bob.token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(me["principal_id"], BOB_DID);

    let request_receipt = alice.request_contact(BOB_DID).await?;
    assert_eq!(request_receipt.core.holder.subject_id().as_str(), ALICE_DID);
    assert_eq!(request_receipt.core.peer.subject_id().as_str(), BOB_DID);
    bob.accept_contact(request_receipt).await?;

    let visible_bob = expect_json(
        alice
            .post("/_arkret/find/directory/search-users")
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectorySearchUsersRequestBody,
            >(
                json!({"query": BOB_HANDLE.trim_start_matches('@')})
            )?),
        StatusCode::OK,
    )
    .await?;
    assert!(
        visible_bob["users"]
            .as_array()
            .expect("search-users response users")
            .iter()
            .any(|result| result["did"].as_str() == Some(BOB_DID))
    );

    let realm_id = create_collaboration_realm(&alice).await?;
    let created_space = expect_json(
        alice.get(&format!("/_arkret/self/realms/{realm_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(created_space["owner"], ALICE_DID);

    expect_status(
        server
            .http()
            .post(server.url("/_arkret/find/directory/resolve-realm"))
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectoryResolveRealmRequestBody,
            >(json!({"realm_id": realm_id}))?),
        StatusCode::NOT_FOUND,
    )
    .await?;

    let member_join = alice
        .submit_event(
            &realm_id,
            "ak.member.state",
            member_join_payload_value(&realm_id, BOB_DID)?,
        )
        .await?;
    assert_eq!(member_join["status"], "accepted");
    let with_bob = expect_json(
        alice.get(&format!("/_arkret/self/realms/{realm_id}")),
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
            &realm_id,
            "ak:thread:collaboration",
            "hello from collaboration workflow",
        )
        .await?;
    assert_eq!(sent["status"], "accepted");
    assert!(sent["event_id"].as_str().unwrap().starts_with("ak:event:"));

    let bob_sync = bob.sync().await?;
    let bob_events = timeline_events(&bob_sync, &realm_id)?;
    assert!(
        bob_events
            .iter()
            .any(|event| event["event_id"] == sent["event_id"]),
        "bob sync did not include alice message {sent}; sync: {bob_sync}"
    );

    // Membership derives read access only; Bob needs a covering grant to author.
    alice
        .grant_realm_actions_to_client(&realm_id, &bob, &["ak.message.create"])
        .await?;
    let bob_reply = bob
        .send_message(
            &realm_id,
            "ak:thread:collaboration",
            "hello alice from collaboration workflow",
        )
        .await?;
    assert_eq!(bob_reply["status"], "accepted");
    assert!(
        bob_reply["event_id"]
            .as_str()
            .unwrap()
            .starts_with("ak:event:")
    );

    let alice_sync = alice.sync().await?;
    let alice_timeline = timeline_events(&alice_sync, &realm_id)?;
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
        alice
            .get("/_arkret/self/snapshot/head")
            .query(&[("realm_id", realm_id.as_str())]),
        StatusCode::OK,
    )
    .await?;
    // Spec rename: the snapshot manifest's own identifier field is `id`
    // (`snapshot_ref` is only used at external reference positions).
    assert!(snapshot["id"].as_str().unwrap().starts_with("ak:snapshot:"));
    // `ak.self.snapshot.read.manifest_head` returns the full signed
    // `ak.schema.snapshot.v1` manifest whose frontier is
    // {event_ids, timeline_hlc}.
    assert!(
        snapshot["frontier"]["event_ids"]
            .as_array()
            .is_some_and(|ids| !ids.is_empty())
    );

    let member_ban = alice
        .submit_event(
            &realm_id,
            "ak.member.state",
            member_transition_payload(&realm_id, BOB_DID, MembershipPayloadState::Ban, None)?,
        )
        .await?;
    assert_eq!(member_ban["status"], "accepted");
    let removed = expect_json(
        alice.get(&format!("/_arkret/self/realms/{realm_id}")),
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
            .query("/_arkret/self/events")
            .json(&json!({"realms": [realm_id], "limit": 100})),
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
    assert!(event_kinds.contains("ak.realm.create"));
    assert!(event_kinds.contains("ak.member.state"));
    assert!(event_kinds.contains("ak.message.create"));

    let logout = expect_json(
        server
            .http()
            .post(server.url("/_arkret/gate/account/session-grants/revoke"))
            .bearer_auth(&bob.token),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(logout["revoked_count"], 1);

    expect_status(
        server
            .http()
            .get(server.url("/_arkret/self/account/viewer"))
            .bearer_auth(&bob.token),
        StatusCode::UNAUTHORIZED,
    )
    .await?;

    Ok(())
}

async fn create_collaboration_realm(alice: &TestActorClient) -> Result<String> {
    let realm_id = "ak:realm:01904100-0000-8000-8000-c011ab000001".to_owned();
    let created = alice
        .create_realm_with(json!({
            "realm_id": &realm_id,
            "title": "Collaboration Workflow Space",
            "summary": "single server collaboration",
            "discoverability": "invite_only",
            "join_rule": "invite",
            "history_visibility": "shared",
            "encryption_profile": "none",
            "plaintext_visible_services": [alice.service_id()]
        }))
        .await?;
    assert_eq!(created["realm_id"], realm_id);
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
