use anyhow::{Context, Result, anyhow};
use arkret_canonical::canonical_sha256;
use arkret_models_collaboration::governance::invite_addressing::IntroductionEvidence;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{
    account_subscribe_delta_from_text, dispatch_accepted_invite_and_read_token,
    expect_audit_action, expect_json, expect_response, expect_status, invite_create_payload,
};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_full_id, seal_current_principal_control_frontier,
    spawn_with_harness_account_authority,
};

pub async fn contacts_invites_listing_export_and_audit_work() -> Result<()> {
    let server = spawn_with_harness_account_authority("directory-workflow", &[]).await?;
    let alice_did = actor_did_for_service_full_id(server.service_full_id(), "directory-alice")?;
    let alice = server
        .demo_client(&alice_did, "ak:device:01904100-0000-7000-8000-0000000000a1")
        .await?;
    let alice_device_key = alice
        .principal
        .as_ref()
        .context("alice carries her provisioned principal")?
        .device_signing_key
        .clone();
    let bob_did = actor_did_for_service_full_id(server.service_full_id(), "directory-bob")?;
    let bob = server
        .register_client(
            &bob_did,
            "@bob-directory",
            "ak:device:01904100-0000-7000-8000-0000000000b0",
        )
        .await?;
    let bob_device_key = bob
        .principal
        .as_ref()
        .context("bob carries his provisioned principal")?
        .device_signing_key
        .clone();

    let request_receipt = alice.request_contact(&bob.actor).await?;
    seal_current_principal_control_frontier(&alice, &alice_device_key).await?;
    bob.accept_contact(request_receipt).await?;
    seal_current_principal_control_frontier(&bob, &bob_device_key).await?;

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
    let introduction_evidence = IntroductionEvidence::SamePrincipalServer;
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
        "accepted",
        "invite event was not accepted: {}",
        serde_json::to_string_pretty(&invite_event)?
    );

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
    let invite_id = invites["invites"][0]["id"]
        .as_str()
        .ok_or_else(|| anyhow!("invite list entry omitted its id: {invites}"))?
        .to_owned();
    let invite_event_id = invite_event["event_id"]
        .as_str()
        .ok_or_else(|| anyhow!("invite submit outcome omitted event_id: {invite_event}"))?;
    let invite_token = dispatch_accepted_invite_and_read_token(
        &alice,
        &bob,
        invite_event_id,
        &invite_id,
        introduction_evidence,
    )
    .await?;

    expect_status(
        server
            .http()
            .post(server.url("/_arkret/find/directory/resolve-realm"))
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectoryResolveRealmRequestBody,
            >(
                json!({"invite_token": "ak:invite-token:invalid"})
            )?),
        StatusCode::NOT_FOUND,
    )
    .await?;

    let invite_resolve = expect_json(
        server
            .http()
            .post(server.url("/_arkret/find/directory/resolve-realm"))
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectoryResolveRealmRequestBody,
            >(json!({"invite_token": invite_token}))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(invite_resolve["realm_preview"]["realm_id"], invite_realm_id);

    let listed_realm = alice
        .create_realm_with(json!({
            "title": "Listed Directory Realm",
            "discoverability": "listed"
        }))
        .await?;
    let listed_realm_id = listed_realm["realm_id"].as_str().unwrap().to_owned();
    let listed_search = expect_json(
        server
            .http()
            .post(server.url("/_arkret/find/directory/search-realms"))
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectorySearchRealmsRequestBody,
            >(json!({"query": "Listed Directory Realm"}))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(listed_search["realms"][0]["realm_id"], listed_realm_id);

    let unlisted_realm = alice
        .create_realm_with(json!({
            "title": "Unlisted Directory Realm",
            "discoverability": "unlisted"
        }))
        .await?;
    let unlisted_realm_id = unlisted_realm["realm_id"].as_str().unwrap().to_owned();
    let unlisted_search = expect_json(
        server
            .http()
            .post(server.url("/_arkret/find/directory/search-realms"))
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectorySearchRealmsRequestBody,
            >(json!({"query": "Unlisted Directory Realm"}))?),
        StatusCode::OK,
    )
    .await?;
    assert!(unlisted_search["realms"].as_array().unwrap().is_empty());

    let unlisted_resolve = expect_json(
        server
            .http()
            .post(server.url("/_arkret/find/directory/resolve-realm"))
            .json(&serde_json::from_value::<
                arkret_models_discovery::DirectoryResolveRealmRequestBody,
            >(json!({"realm_id": unlisted_realm_id}))?),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        unlisted_resolve["realm_preview"]["realm_id"],
        unlisted_realm["realm_id"]
    );

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

    let exported = expect_json(
        alice.get(&format!("/_arkret/self/realms/{shared_realm_id}/export")),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(exported["schema"], "ak.export.realm.v1");
    let sent_event_id = sent["event_id"]
        .as_str()
        .ok_or_else(|| anyhow!("message submit outcome omitted event_id: {sent}"))?;
    let exported_event = exported["events"]
        .as_array()
        .ok_or_else(|| anyhow!("Realm export omitted events array: {exported}"))?
        .iter()
        .find(|event| event["event_id"].as_str() == Some(sent_event_id))
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

    let waited_sync = expect_response(
        alice
            .get("/_arkret/self/account/subscribe?catchup=true")
            .header("x-arkret-wait-for", sent["cursor"].as_str().unwrap())
            .header("accept", "application/x-ndjson"),
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        waited_sync
            .headers
            .get("x-arkret-wait-for-satisfied")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    let waited_sync = account_subscribe_delta_from_text(&waited_sync.text())?;
    let waited_events = waited_sync["realms"][&shared_realm_id]["timeline"]["events"]
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
            .get("/_arkret/self/account/subscribe?catchup=true")
            .header("x-arkret-wait-for", "not-a-sync-token")
            .header("accept", "application/x-ndjson"),
        StatusCode::BAD_REQUEST,
    )
    .await?;

    let audit_events = expect_json(
        alice.get("/_soland/admin/audit/events?limit=20"),
        StatusCode::OK,
    )
    .await?;
    let _ = expect_audit_action(&audit_events, "events.submit")?;

    expect_status(
        alice.get(&format!("/_soland/admin/audit/events?actor={}", bob.actor)),
        StatusCode::FORBIDDEN,
    )
    .await?;

    Ok(())
}
