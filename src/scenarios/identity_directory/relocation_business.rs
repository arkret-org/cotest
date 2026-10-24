//! A fixed Account Station survives independent DID hosting relocation.
use anyhow::{Context, Result, ensure};
use arkret_models_identity::{
    CurrentPrincipalRequestBody, CurrentPrincipalResponseBody, DidOperationSubmitRequestBody,
    PrincipalResolutionAuditEvidence, PrincipalResolutionAuditRequestBody,
    PrincipalResolutionUpdatePayload, ResolutionCommitment,
};
use arkret_signatures::webvh::{
    PrincipalRotationInput, WebvhRelocationInput, prepare_principal_portability_update,
    prepare_webvh_relocation,
};
use arkret_wire::{AccountId, CurrentRevision, EventAdmissionSubmission};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    ArkretServer, CanonicalJsonBody, TestActorClient, event_envelope_for_device, expect_api_error,
    expect_json, message_create_text_payload, next_typed_id,
    refresh_typed_event_proof_with_signing_seed,
};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, prepared_test_principal_inception,
};

fn public(seed: &[u8; 32]) -> String {
    arkret_canonical::ed25519_pubkey_to_did_key_multibase(
        ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .as_bytes(),
    )
}

async fn publish(server: &ArkretServer, body: &DidOperationSubmitRequestBody) -> Result<()> {
    let outcome = expect_json(
        server
            .http()
            .post(server.url("/_arkret/root/identity/submit-did-operation"))
            .canonical_json(body)?,
        StatusCode::OK,
    )
    .await?;
    ensure!(
        matches!(outcome["status"].as_str(), Some("accepted" | "duplicate")),
        "native publication: {outcome}"
    );
    Ok(())
}

async fn audit(
    client: &TestActorClient,
    account: &AccountId,
    depth: u16,
    after: Option<arkret_wire::EventId>,
) -> Result<PrincipalResolutionAuditEvidence> {
    let result = expect_json(
        client
            .post("/_arkret/self/identity/resolution-audit/query")
            .canonical_json(&PrincipalResolutionAuditRequestBody {
                account_id: account.clone(),
                history_depth: Some(depth),
                after_resolution_event_ref: after,
            })?,
        StatusCode::OK,
    )
    .await?;
    let result: PrincipalResolutionAuditEvidence = serde_json::from_value(result)?;
    result.validate()?;
    Ok(result)
}

fn resolution_submission(
    client: &TestActorClient,
    revision: CurrentRevision,
    entry: &Value,
) -> Result<EventAdmissionSubmission> {
    let principal = client.principal.as_ref().context("registered principal")?;
    let payload = PrincipalResolutionUpdatePayload {
        expected_revision: revision,
        next: ResolutionCommitment {
            did: entry["state"]["id"]
                .as_str()
                .context("native DID")?
                .parse()?,
            method_history_head: arkret_canonical::canonical_sha256(entry)?,
            version_id: entry["versionId"]
                .as_str()
                .context("native version")?
                .into(),
        },
    };
    let event = event_envelope_for_device(
        &client.actor,
        &client.device_id,
        &principal_station(client)?,
        principal.pcr_realm_id.as_str(),
        "ak.identity.resolution.update",
        serde_json::to_value(payload)?,
    );
    Ok(EventAdmissionSubmission {
        event,
        approval_signatures: None,
    })
}

fn principal_station(client: &TestActorClient) -> Result<arkret_wire::DidCoreId> {
    Ok(client.service_id().parse()?)
}
fn revision(commit: &arkret_wire::RealmCommit) -> CurrentRevision {
    CurrentRevision {
        commit_id: commit.commit_id.clone(),
        stream_position: commit.stream_position,
    }
}

pub async fn account_business_survives_did_host_outage_and_signed_resolution_updates() -> Result<()>
{
    let hosting = [("COLAND_EMBEDDED_WEBVH_PROVIDER_ENABLED", "1")];
    let mut old = ArkretServer::spawn_with_env("resolution-business-old-host", &hosting).await?;
    let mut station =
        ArkretServer::spawn_with_env("resolution-business-account-station", &hosting).await?;
    let new = ArkretServer::spawn_with_env("resolution-business-new-host", &hosting).await?;
    let account_station = station.service_id().clone();
    let owner_did = actor_did_for_service_did(station.service_did(), "resolution-owner")?;
    let owner = station
        .standard_register_client(
            &owner_did,
            "@resolution-owner",
            "ak:device:01904100-0000-7000-8000-000000000161",
        )
        .await?;
    let member_did = actor_did_for_service_did(old.service_did(), "resolution-member")?;
    let member = station
        .standard_register_client(
            &member_did,
            "@resolution-member",
            "ak:device:01904100-0000-7000-8000-000000000162",
        )
        .await?;
    let principal = member.principal.as_ref().context("member PCR")?.clone();
    let account = AccountId::new(principal.core_id.clone(), account_station.clone());
    let inception = prepared_test_principal_inception(&member_did)?;
    for host in [&old, &new] {
        publish(host, &inception.submit_body).await?;
    }
    let initial = audit(&member, &account, 0, None).await?;
    ensure!(initial.current_resolution_event == initial.principal_genesis_event);
    let mut entries = vec![inception.log_entry.clone()];
    let at = chrono::Utc::now() - chrono::Duration::seconds(10);
    let enabled = prepare_principal_portability_update(
        &PrincipalRotationInput {
            did: &member_did,
            local_id: &inception.local_id,
            previous_entries: &entries,
            version_created_at: at,
            current_root_seed:
                &crate::scenarios::identity_test_support::test_principal_next_root_seed(
                    &member_did,
                )?,
            next_root_public_key_multibase: &public(&[171; 32]),
            state: &inception.log_entry["state"],
        },
        true,
    )?;
    for host in [&old, &station, &new] {
        publish(host, &enabled.submit_body).await?;
    }
    entries.push(enabled.log_entry);
    let first = resolution_submission(
        &member,
        revision(&initial.current_resolution_commit),
        entries.last().unwrap(),
    )?;
    expect_json(
        member.post("/_arkret/self/events").canonical_json(&first)?,
        StatusCode::OK,
    )
    .await?;
    let first_audit = audit(&member, &account, 256, None).await?;
    ensure!(first_audit.current_resolution_event == first.event);
    let realm = owner
        .create_realm("DID relocation keeps business authority")
        .await?;
    let strand = owner.default_strand_id(&realm)?;
    owner.add_member(&realm, &member).await?;
    let grant = owner
        .grant_realm_actions_to_client(&realm, &member, &["ak.message.create"])
        .await?;
    member
        .send_message(&realm, &strand, "before hosting outage")
        .await?;
    old.stop_external_process().await?;
    member
        .send_message(&realm, &strand, "independent DID host is offline")
        .await?;
    let new_base = new.base_url();
    let method_host = arkret_signatures::webvh::webvh_authority_pair(
        new_base.host_str().context("new host authority")?,
        new_base.port(),
    )
    .0;
    let target = format!(
        "did:webvh:{}:{}:webvh:{}",
        member_did.split(':').nth(2).unwrap(),
        method_host,
        inception.local_id
    );
    let mut state = entries.last().unwrap()["state"].clone();
    fn rename(value: &mut Value, old: &str, new: &str) {
        match value {
            Value::String(v) => *v = v.replace(old, new),
            Value::Array(v) => v.iter_mut().for_each(|x| rename(x, old, new)),
            Value::Object(v) => v.values_mut().for_each(|x| rename(x, old, new)),
            _ => {}
        }
    }
    rename(&mut state, &member_did, &target);
    state["alsoKnownAs"] = json!([member_did]);
    let moved = prepare_webvh_relocation(&WebvhRelocationInput {
        current_did: &member_did,
        target_did: &target,
        previous_entries: &entries,
        version_created_at: at + chrono::Duration::seconds(1),
        current_update_seed: &[171; 32],
        next_update_public_key_multibase: &public(&[172; 32]),
        state: &state,
    })?;
    for host in [&new, &station] {
        publish(host, &moved.submit_body).await?;
    }
    entries.push(moved.log_entry);
    let stale = resolution_submission(
        &member,
        revision(&initial.current_resolution_commit),
        entries.last().unwrap(),
    )?;
    expect_api_error(
        member.post("/_arkret/self/events").canonical_json(&stale)?,
        StatusCode::CONFLICT,
        "failed_precondition",
    )
    .await?;
    ensure!(
        audit(&member, &account, 0, None)
            .await?
            .current_resolution_event
            == first.event
    );
    let second = resolution_submission(
        &member,
        revision(&first_audit.current_resolution_commit),
        entries.last().unwrap(),
    )?;
    expect_json(
        member
            .post("/_arkret/self/events")
            .canonical_json(&second)?,
        StatusCode::OK,
    )
    .await?;
    let duplicate = expect_json(
        member
            .post("/_arkret/self/events")
            .canonical_json(&second)?,
        StatusCode::OK,
    )
    .await?;
    ensure!(
        duplicate["status"] == "duplicate",
        "exact PCR replay: {duplicate}"
    );
    let bounded = audit(&member, &account, 0, None).await?;
    ensure!(
        !bounded.history_complete
            && bounded.next_audit_cursor.as_ref() == Some(&first.event.event_id)
    );
    ensure!(
        bounded.predecessor_resolution_events.is_empty()
            && bounded.method_history_evidence.is_some()
    );
    let full = audit(&member, &account, 256, None).await?;
    ensure!(
        full.history_complete && full.predecessor_resolution_events == vec![first.event.clone()]
    );
    let exclusive = audit(&member, &account, 1, Some(first.event.event_id.clone())).await?;
    ensure!(exclusive.history_complete && exclusive.predecessor_resolution_events.is_empty());
    let request = CurrentPrincipalRequestBody {
        request_id: next_typed_id("request").parse()?,
        account_id: account.clone(),
    };
    let current = expect_json(
        member
            .post("/_arkret/self/account/current-principal")
            .canonical_json(&request)?,
        StatusCode::OK,
    )
    .await?;
    ensure!(current.get("method_history_evidence").is_none());
    let current: CurrentPrincipalResponseBody = serde_json::from_value(current)?;
    current.validate_for_request(&request)?;
    ensure!(
        current.resolution_projection.did.as_str() == target
            && current.principal_control_realm_id == principal.pcr_realm_id
    );
    member
        .send_message(
            &realm,
            &strand,
            "same member and grant after DID relocation",
        )
        .await?;
    station.restart_external_process().await?;
    ensure!(station.service_id() == &account_station);
    ensure!(
        audit(&member, &account, 256, None)
            .await?
            .current_resolution_event
            == second.event
    );
    member
        .send_message(
            &realm,
            &strand,
            "same authority after Account Station restart",
        )
        .await?;
    old.start_external_process().await?;
    publish(&old, &moved.submit_body).await?;
    let other_did = actor_did_for_service_did(new.service_did(), "resolution-new-core")?;
    let other = station
        .standard_register_client(
            &other_did,
            "@resolution-new-core",
            "ak:device:01904100-0000-7000-8000-000000000163",
        )
        .await?;
    ensure!(other.principal.as_ref().unwrap().core_id != principal.core_id);
    expect_api_error(
        other
            .post("/_arkret/self/account/current-principal")
            .canonical_json(&request)?,
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    let mut forged = event_envelope_for_device(
        &other.actor,
        &other.device_id,
        &account_station,
        &realm,
        "ak.message.create",
        message_create_text_payload(&strand, "a new core cannot inherit the old member grant")?,
    );
    forged.semantic_refs = vec![arkret_wire::SemanticRef::authorized_by_grant(
        grant.parse()?,
    )];
    refresh_typed_event_proof_with_signing_seed(
        &mut forged,
        other
            .principal
            .as_ref()
            .unwrap()
            .device_signing_key
            .to_bytes(),
    )?;
    expect_api_error(
        other
            .post("/_arkret/self/events")
            .canonical_json(&EventAdmissionSubmission {
                event: forged.clone(),
                approval_signatures: None,
            })?,
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;
    // An explicit new membership still cannot transfer another core's grant.
    owner.add_member(&realm, &other).await?;
    expect_api_error(
        other
            .post("/_arkret/self/events")
            .canonical_json(&EventAdmissionSubmission {
                event: forged,
                approval_signatures: None,
            })?,
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;
    member
        .send_message(
            &realm,
            &strand,
            "original member remains authorized after new-core rejection",
        )
        .await?;
    Ok(())
}
