use std::collections::BTreeSet;

use anyhow::Result;
use arkret_models_collaboration::governance::membership_invite::MembershipPayloadState;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{TestActorClient, expect_json, expect_status, member_transition_payload};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, spawn_with_harness_account_authority,
};

const BOB_HANDLE: &str = "@collab-bob";

pub async fn account_contact_space_message_sync_workflow() -> Result<()> {
    let server = spawn_with_harness_account_authority("collaboration-workflow", &[]).await?;
    let alice_did = actor_did_for_service_did(server.service_did(), "collab-alice")?;
    let alice = server
        .standard_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let bob_did = actor_did_for_service_did(server.service_did(), "collab-bob")?;
    let bob = server
        .standard_register_client_with_localpart(
            &bob_did,
            BOB_HANDLE,
            BOB_HANDLE.trim_start_matches('@'),
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;

    let alice_core_id = crate::harness::actor_core_id(&alice.actor)?;
    let bob_did = arkret_identifiers::Did::new(bob.actor.clone())?;
    let bob_core_id = arkret_identifiers::project_did_to_core_id(&bob_did)?;

    let me = expect_json(
        bob.authorize(
            server
                .http()
                .get(server.url("/_arkret/self/account/viewer")),
        ),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(me["principal_id"], bob_core_id.as_str());

    let request_receipt = alice.request_contact(&bob.actor).await?;
    assert_eq!(
        request_receipt
            .core
            .holder
            .contact_actor_id()
            .signing_principal_id()
            .as_str(),
        alice_core_id
    );
    assert_eq!(
        request_receipt
            .core
            .peer
            .contact_actor_id()
            .signing_principal_id()
            .as_str(),
        bob_core_id.as_str()
    );
    bob.accept_contact(&alice).await?;

    let realm_id = create_collaboration_realm(&alice).await?;
    let strand_id = alice.default_strand_id(&realm_id)?;
    let created_space = expect_json(
        alice.get(&format!("/_arkret/self/realms/{realm_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(created_space["owner_id"], alice_core_id);

    let member_join = alice.add_member(&realm_id, &bob).await?;
    assert_eq!(member_join["status"], "committed");
    let with_bob = bob.sync().await?;
    assert!(
        with_bob["realm_list"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["realm_id"] == realm_id && row["membership"] == "join")
    );

    let sent = alice
        .send_message(&realm_id, &strand_id, "hello from collaboration workflow")
        .await?;
    assert_eq!(sent["status"], "committed");
    let sent_event_id = crate::harness::submitted_event_id(&sent)?;
    assert!(sent_event_id.as_str().starts_with("ak:event:"));

    let bob_events = committed_events(&bob, &realm_id).await?;
    assert!(
        bob_events
            .iter()
            .any(|event| event["event_id"].as_str() == Some(sent_event_id.as_str())),
        "Bob committed scan did not include Alice message {sent}; scan: {bob_events:?}"
    );

    // Membership derives read access only; Bob needs a covering grant to author.
    alice
        .grant_realm_actions_to_client(&realm_id, &bob, &["ak.message.create"])
        .await?;
    let bob_reply = bob
        .send_message(
            &realm_id,
            &strand_id,
            "hello alice from collaboration workflow",
        )
        .await?;
    assert_eq!(bob_reply["status"], "committed");
    let bob_reply_event_id = crate::harness::submitted_event_id(&bob_reply)?;
    assert!(bob_reply_event_id.as_str().starts_with("ak:event:"));

    let alice_timeline = committed_events(&alice, &realm_id).await?;
    assert!(
        alice_timeline
            .iter()
            .any(|event| event["event_id"].as_str() == Some(bob_reply_event_id.as_str())),
        "Alice committed scan did not include Bob reply {bob_reply}; scan: {alice_timeline:?}"
    );
    assert!(
        alice_timeline
            .iter()
            .any(|event| event_body(event) == Some("hello alice from collaboration workflow")),
        "Alice committed scan did not include Bob reply body: {alice_timeline:?}"
    );

    let snapshot = expect_json(
        alice
            .get("/_arkret/self/realm-state-snapshot/head")
            .query(&[("realm_id", realm_id.as_str())]),
        StatusCode::OK,
    )
    .await?;
    assert!(
        snapshot["snapshot_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("ak:realm_snapshot:")),
        "signed snapshot omitted its identifier: {snapshot}"
    );
    // Current snapshot manifests carry exact visible stream heads at one cut.
    assert!(
        snapshot["visible_stream_heads"]
            .as_array()
            .is_some_and(|heads| !heads.is_empty()),
        "signed snapshot omitted its visible stream heads: {snapshot}"
    );

    let member_ban = alice
        .submit_event(
            &realm_id,
            "ak.member.state",
            member_transition_payload(&realm_id, &bob.actor, MembershipPayloadState::Ban, None)?,
        )
        .await?;
    assert_eq!(member_ban["status"], "committed");
    let removed = bob.sync().await?;
    assert!(
        !removed["realm_list"]["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["realm_id"] == realm_id && row["membership"] == "join")
    );

    let lifecycle = committed_events(&alice, &realm_id).await?;
    let event_kinds: BTreeSet<_> = lifecycle
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

    Ok(())
}

pub async fn standard_session_grant_revoke_invalidates_current_session() -> Result<()> {
    let server = spawn_with_harness_account_authority("standard-session-revoke", &[]).await?;
    let bob_did = actor_did_for_service_did(server.service_did(), "standard-revoke-bob")?;
    let bob = server
        .standard_client(&bob_did, "ak:device:01904100-0000-7000-8000-0000000000b1")
        .await?;
    let authority_origin = server
        .harness_account_authority_origin()
        .ok_or_else(|| anyhow::anyhow!("standard grant issuer ledger is unavailable"))?;
    let revoke_url = format!("{authority_origin}/_arkret/gate/account/session-grants/revoke");
    expect_status(
        server.http().post(&revoke_url),
        StatusCode::UNAUTHORIZED,
    )
    .await?;
    let logout = expect_json(
        bob.authorize(server.http().post(&revoke_url)),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(logout["revoked_count"], 1);
    expect_status(
        bob.authorize(server.http().post(&revoke_url)),
        StatusCode::CONFLICT,
    )
    .await?;
    // This request reaches the Station, which must recheck the exact token
    // against the Account Authority ledger after the public revoke operation.
    expect_status(
        bob.authorize(
            server
                .http()
                .get(server.url("/_arkret/self/account/viewer")),
        ),
        StatusCode::UNAUTHORIZED,
    )
    .await?;
    Ok(())
}

async fn create_collaboration_realm(alice: &TestActorClient) -> Result<String> {
    let created = alice
        .create_realm_with(json!({
            "title": "Collaboration Workflow Space",
            "summary": "single server collaboration",
            "discoverability": "invite_only",
            "join_rule": "invite",
            "history_access": "all_history_for_current_members",
            "encryption_profile": "none",
            "plaintext_visible_services": [alice.service_id()]
        }))
        .await?;
    let realm_id = created["realm_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("realm create response has no realm_id: {created}"))?;
    Ok(arkret_identifiers::RealmId::new(realm_id.to_owned())?
        .as_str()
        .to_owned())
}

async fn committed_events(client: &TestActorClient, realm_id: &str) -> Result<Vec<Value>> {
    let realm = arkret_wire::RealmId::new(realm_id.to_owned())?;
    let scanned = client
        .sdk()
        .scan_commit_stream_to_head(
            realm.clone(),
            arkret_wire::CommitStreamRef::Realm { realm_id: realm },
            None,
            200,
        )
        .await?;
    scanned
        .committed_events
        .iter()
        .filter_map(|item| item.reducer_input())
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn event_body(event: &Value) -> Option<&str> {
    event
        .pointer("/content/body")
        .or_else(|| event.pointer("/payload/content/body"))
        .or_else(|| event.pointer("/payload/body"))
        .and_then(Value::as_str)
}
