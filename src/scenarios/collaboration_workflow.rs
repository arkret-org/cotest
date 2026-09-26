use std::collections::BTreeSet;

use anyhow::{Context, Result};
use arkret_models_collaboration::governance::membership_invite::MembershipPayloadState;
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    TestActorClient, events_query_for_realm, expect_json, expect_status, member_join_payload_value,
    member_transition_payload,
};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, seal_current_principal_control_frontier,
    spawn_with_harness_account_authority,
};

const BOB_HANDLE: &str = "@collab-bob";

pub async fn account_contact_space_message_sync_workflow() -> Result<()> {
    let server = spawn_with_harness_account_authority("collaboration-workflow", &[]).await?;
    let alice_did = actor_did_for_service_did(server.service_did(), "collab-alice")?;
    let alice = server
        .standard_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let alice_device_key = alice
        .principal
        .as_ref()
        .context("alice carries her provisioned principal")?
        .device_signing_key
        .clone();
    let bob_did = actor_did_for_service_did(server.service_did(), "collab-bob")?;
    let bob = server
        .standard_register_client_with_localpart(
            &bob_did,
            BOB_HANDLE,
            BOB_HANDLE.trim_start_matches('@'),
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;
    let bob_device_key = bob
        .principal
        .as_ref()
        .context("bob carries his provisioned principal")?
        .device_signing_key
        .clone();

    let alice_core_id = crate::harness::actor_core_id(&alice.actor)?;
    let bob_did = arkret_identifiers::Did::new(bob.actor.clone())?;
    let bob_core_id = arkret_identifiers::project_did_to_core_id(&bob_did)?;
    let bob_account = arkret_wire::AccountId::new(bob_core_id.clone(), server.service_id().clone());
    let bob_actor = serde_json::to_value(arkret_wire::ActorId::account(bob_account.clone()))?;

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
    seal_current_principal_control_frontier(&alice, &alice_device_key).await?;
    bob.accept_contact(&alice).await?;
    seal_current_principal_control_frontier(&bob, &bob_device_key).await?;

    let realm_id = create_collaboration_realm(&alice).await?;
    let strand_id = alice.default_strand_id(&realm_id)?;
    let created_space = expect_json(
        alice.get(&format!("/_arkret/self/realms/{realm_id}")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(created_space["owner_id"], alice_core_id);

    let member_join = alice
        .submit_event(
            &realm_id,
            "ak.member.state",
            member_join_payload_value(&realm_id, &bob.actor)?,
        )
        .await?;
    assert_eq!(member_join["status"], "accepted");
    let with_bob = expect_json(
        alice.get(&format!("/_arkret/self/realms/{realm_id}")),
        StatusCode::OK,
    )
    .await?;
    assert!(
        with_bob["member_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member == &bob_actor)
    );

    let sent = alice
        .send_message(&realm_id, &strand_id, "hello from collaboration workflow")
        .await?;
    assert_eq!(sent["status"], "accepted");
    let sent_event_id = crate::harness::submitted_event_id(&sent)?;
    assert!(sent_event_id.as_str().starts_with("ak:event:"));

    let bob_sync = bob.sync().await?;
    let bob_events = timeline_events(&bob_sync, &realm_id)?;
    assert!(
        bob_events
            .iter()
            .any(|event| event["event_id"].as_str() == Some(sent_event_id.as_str())),
        "bob sync did not include alice message {sent}; sync: {bob_sync}"
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
    assert_eq!(bob_reply["status"], "accepted");
    let bob_reply_event_id = crate::harness::submitted_event_id(&bob_reply)?;
    assert!(bob_reply_event_id.as_str().starts_with("ak:event:"));

    let alice_sync = alice.sync().await?;
    let alice_timeline = timeline_events(&alice_sync, &realm_id)?;
    assert!(
        alice_timeline
            .iter()
            .any(|event| event["event_id"].as_str() == Some(bob_reply_event_id.as_str())),
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
            .get("/_arkret/self/realm-state-snapshot/head")
            .query(&[("realm_id", realm_id.as_str())]),
        StatusCode::OK,
    )
    .await?;
    // Spec rename: the snapshot manifest's own identifier field is `id`
    // (`realm_state_snapshot_ref` is only used at external reference positions).
    assert!(
        snapshot["id"]
            .as_str()
            .unwrap()
            .starts_with("ak:realm_state_snapshot:")
    );
    // `ak.self.realm_state_snapshot.read.manifest_head.v1` returns the full signed
    // `ak.schema.realm_state_snapshot.v1` manifest whose frontier is
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
            member_transition_payload(&realm_id, &bob.actor, MembershipPayloadState::Ban, None)?,
        )
        .await?;
    assert_eq!(member_ban["status"], "accepted");
    let removed = expect_json(
        alice.get(&format!("/_arkret/self/realms/{realm_id}")),
        StatusCode::OK,
    )
    .await?;
    assert!(
        !removed["member_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|member| member == &bob_actor)
    );

    let lifecycle = expect_json(
        alice
            .query("/_arkret/self/events")
            .json(&events_query_for_realm(&realm_id, 100)?),
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
        bob.authorize(
            server
                .http()
                .post(server.url("/_arkret/gate/account/session-grants/revoke")),
        ),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(logout["revoked_count"], 1);

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
