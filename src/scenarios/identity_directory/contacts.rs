use anyhow::{Context, Result, anyhow};
use arkret_canonical::canonical_sha256;
use arkret_models_collaboration::governance::invite_addressing::IntroductionEvidence;
use arkret_wire::{CommitStreamRef, RealmId};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    dispatch_accepted_invite_and_await_delivery, expect_audit_action, expect_json, expect_status,
    invite_create_payload, submitted_event_id,
};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, spawn_with_harness_account_authority,
};

pub async fn contacts_invites_listing_export_and_audit_work() -> Result<()> {
    let server = spawn_with_harness_account_authority("directory-workflow", &[]).await?;
    let alice_did = actor_did_for_service_did(server.service_did(), "directory-alice")?;
    let alice = server
        .standard_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let bob_did = actor_did_for_service_did(server.service_did(), "directory-bob")?;
    let bob = server
        .standard_register_client(
            &bob_did,
            "@bob-directory",
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;
    alice
        .request_contact(&bob.actor)
        .await
        .context("Alice requests Contact")?;
    bob.accept_contact(&alice)
        .await
        .context("Bob accepts Contact")?;

    let contacts = expect_json(bob.get("/_arkret/self/contacts"), StatusCode::OK).await?;
    assert_eq!(contacts["contacts"].as_array().unwrap().len(), 1);

    let invite_realm = alice
        .create_realm_with(json!({
            "title": "Invite Token Realm",
            "discoverability": "invite_only",
            "invitees": [bob.actor.clone()]
        }))
        .await?;
    let invite_realm_id = invite_realm["realm_id"].as_str().unwrap().to_owned();
    let introduction_evidence = IntroductionEvidence::ExplicitAddress;
    let invite_expires_at = chrono::DateTime::parse_from_rfc3339("2026-12-31T00:00:00.000Z")?
        .with_timezone(&chrono::Utc);
    let invite_event = alice
        .submit_event(
            &invite_realm_id,
            "ak.invite.create",
            invite_create_payload(
                bob.actor.as_str(),
                server.service_id().as_str(),
                canonical_sha256(&introduction_evidence)?,
                invite_expires_at,
            )?,
        )
        .await?;
    assert_eq!(
        invite_event["status"],
        "committed",
        "invite event was not accepted: {}",
        serde_json::to_string_pretty(&invite_event)?
    );
    let invite_event_id = submitted_event_id(&invite_event)?;
    let invite_id = arkret_identifiers::InviteId::from_event_id(&invite_event_id).to_string();
    dispatch_accepted_invite_and_await_delivery(
        &alice,
        &bob,
        invite_event_id.as_str(),
        &invite_id,
        introduction_evidence,
    )
    .await?;

    // The shared Event alone is not holder-private delivery. The invite only
    // appears after the accepted dispatch materializes Bob's invite-delivery
    // account-data cell.
    let invites = expect_json(bob.get("/_arkret/self/authz/invites"), StatusCode::OK).await?;
    assert_eq!(
        invites["invites"].as_array().unwrap().len(),
        1,
        "expected one invite for bob: {}",
        serde_json::to_string_pretty(&invites)?
    );
    assert_eq!(invites["invites"][0]["realm_id"], invite_realm_id);
    // governance-objects.md §5.3 — the invite token is private delivery
    // material and MUST NOT appear on the Invite read model; the invitee
    // receives it through the invite-addressing.md §7 private delivery flow.
    assert!(
        invites["invites"][0].get("invite_token").is_none(),
        "invite read model must not surface the private delivery token: {invites}"
    );
    assert_eq!(invites["invites"][0]["id"], invite_id);

    let shared_realm_id = alice.create_realm("Workflow Export Realm").await?;
    let shared_strand_id = alice.default_strand_id(&shared_realm_id)?;
    alice.add_member(&shared_realm_id, &bob).await?;
    let sent = alice
        .send_message(
            &shared_realm_id,
            &shared_strand_id,
            "hello directory workflow",
        )
        .await?;
    let sent_event_id = submitted_event_id(&sent)?;

    let exported = expect_json(
        alice.get(&format!("/_arkret/self/realms/{shared_realm_id}/export")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(exported["schema"], "ak.export.realm.v1");
    let exported_event = exported["events"]
        .as_array()
        .ok_or_else(|| anyhow!("Realm export omitted events array: {exported}"))?
        .iter()
        .find(|event| event["event_id"].as_str() == Some(sent_event_id.as_str()))
        .ok_or_else(|| anyhow!("Realm export omitted submitted Event {sent_event_id}"))?;
    let sent_operation_id = exported_event["operation_id"]
        .as_str()
        .ok_or_else(|| anyhow!("exported Event {sent_event_id} omitted operation_id"))?;
    assert!(
        exported["operations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|operation| operation["operation_id"] == sent_operation_id)
    );

    let realm = RealmId::new(shared_realm_id.clone())?;
    let scanned = alice
        .sdk()
        .scan_commit_stream_to_head(
            realm.clone(),
            CommitStreamRef::Realm { realm_id: realm },
            None,
            100,
        )
        .await?;
    assert!(
        scanned
            .committed_events
            .iter()
            .filter_map(|item| item.reducer_input())
            .any(|event| event.event_id == sent_event_id),
        "committed Realm scan did not include submitted message Event"
    );

    let audit_events = expect_json(
        alice.get("/_soland/admin/audit/events?limit=20"),
        StatusCode::OK,
    )
    .await?;
    // The local admin audit log records administrative session/account
    // actions. Realm Events are proven by their signed Commit stream above.
    let _ = expect_audit_action(&audit_events, "account.register")?;

    expect_status(
        alice.get(&format!("/_soland/admin/audit/events?actor={}", bob.actor)),
        StatusCode::FORBIDDEN,
    )
    .await?;

    Ok(())
}
