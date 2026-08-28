//! Live acceptance for Principal Server actor-private invite fanout.
//!
//! The durable source of truth for invite delivery and quarantine is the
//! holder's account-data CAS register. `ak.account_data.update` is only a
//! wake-up hint, so this scenario checks both sides of every write:
//!
//! 1. `ak.account.invite_delivery` after a notify decision;
//! 2. `ak.account.invite_quarantine` after a quarantine decision; and
//! 3. the same quarantine cell after a matching consent revoke invalidates it.
//!
//! Both active holder devices independently read account-data list/resource
//! state and their own live queue. Every envelope is deserialized through the
//! SDK's closed `DeviceMessageEnvelope` XOR and must carry the local Principal
//! Server as sender, the holder as both sender and recipient principal, and the
//! exact revision/content returned by account-data CAS.

use anyhow::{Context, Result, anyhow, bail, ensure};
use arkret_identifiers::{ConsentId, DidCoreId, InviteId};
use arkret_models_collaboration::account_lifecycle::{
    ConsentCellView, ConsentGrantRequestBody, ConsentRevokeRequestBody,
};
use arkret_models_collaboration::events_payloads::ConsentGrantPayload;
use arkret_models_collaboration::governance::invite_addressing::{
    IntroductionEvidence, InviteAddress, InviteReceivePolicy, SelfInviteDispatchRequestBody,
};
use arkret_models_collaboration::governance_payloads::{ConsentObservedDot, ConsentRevokePayload};
use arkret_models_collaboration::sync_frames::account_sync::{
    ActorPrivateAccountDataOperation, DeviceMessageContent, DeviceMessageSender,
    DeviceMessagesAckRequestBody, DeviceMessagesGetOutcome,
};
use arkret_models_identity::ServiceResolutionCarrier;
use arkret_models_identity::account::{AccountDataList, AccountDataRow};
use arkret_wire::{AccountDataKey, ConsentScope, EventInitialSubmission, InviteReceiveAction};
use chrono::{Duration as ChronoDuration, Utc};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    TestActorClient, TestServerGroup, actor_core_id, expect_json, invite_create_payload,
    next_typed_id,
};
use crate::scenarios::identity_test_support::{
    actor_did_for_service_did, seal_current_principal_control_frontier,
};

#[derive(Debug)]
struct DispatchedInvite {
    outcome: Value,
    invite_id: InviteId,
}

async fn set_explicit_address_behavior(
    holder: &TestActorClient,
    behavior: InviteReceiveAction,
) -> Result<()> {
    let current = expect_json(
        holder.get("/_arkret/self/invite-receive-policy"),
        StatusCode::OK,
    )
    .await?;
    let mut policy: InviteReceivePolicy = serde_json::from_value(current)
        .context("invite-receive-policy response is not an InviteReceivePolicy")?;
    if !policy
        .holder_allowed_introduction_kinds
        .iter()
        .any(|kind| kind == "explicit_address")
    {
        policy
            .holder_allowed_introduction_kinds
            .push("explicit_address".to_owned());
    }
    policy.explicit_address_behavior = behavior;
    let updated = expect_json(
        holder
            .put("/_arkret/self/invite-receive-policy")
            .json(&policy),
        StatusCode::OK,
    )
    .await?;
    let updated: InviteReceivePolicy = serde_json::from_value(updated)
        .context("updated invite-receive-policy is not an InviteReceivePolicy")?;
    ensure!(
        updated.explicit_address_behavior == policy.explicit_address_behavior,
        "Principal Server changed explicit_address_behavior"
    );
    Ok(())
}

async fn create_and_dispatch_explicit_invite(
    inviter: &TestActorClient,
    holder: &TestActorClient,
    label: &str,
) -> Result<DispatchedInvite> {
    let evidence = IntroductionEvidence::ExplicitAddress;
    let realm_id = inviter.create_realm(label).await?;
    let payload = invite_create_payload(
        &holder.actor,
        inviter.service_id(),
        arkret_canonical::canonical_sha256(&evidence)?,
        Utc::now() + ChronoDuration::days(7),
    )?;
    let accepted = inviter
        .submit_event(&realm_id, "ak.invite.create", payload)
        .await?;
    let event_id = crate::harness::submitted_event_id(&accepted)?;
    let service_id = DidCoreId::new(inviter.service_id().to_owned())?;
    let service_resolution = ServiceResolutionCarrier::CurrentRecordUrl {
        current_record_url: format!(
            "https://cotest.invalid{}",
            arkret_models_identity::canonical_service_current_record_path(&service_id)
        ),
        pinned_record_digest: None,
    };
    let request = SelfInviteDispatchRequestBody {
        schema: arkret_wire::SchemaId::INVITE_DELIVERY_REQUEST_V1.to_owned(),
        invite_event_id: event_id.clone(),
        invite_address: InviteAddress::principal_server(
            DidCoreId::new(actor_core_id(&holder.actor)?)?,
            service_id,
            service_resolution,
        ),
        introduction_evidence: evidence,
        idempotency_key: event_id.to_string(),
    };
    let outcome = expect_json(
        inviter
            .post("/_arkret/self/invites/dispatch")
            .json(&request),
        StatusCode::OK,
    )
    .await?;
    Ok(DispatchedInvite {
        outcome,
        invite_id: InviteId::from_event_id(&event_id),
    })
}

async fn account_data_row(holder: &TestActorClient, key: &str) -> Result<AccountDataRow> {
    // Service-written invite cells are registered plaintext account data. The
    // holder-readable list is their canonical read surface; the single-key
    // resource route deliberately accepts only encrypted private-key patterns.
    let listed_value =
        expect_json(holder.get("/_arkret/self/account_data"), StatusCode::OK).await?;
    let listed: AccountDataList = serde_json::from_value(listed_value)
        .context("account-data list is not an AccountDataList")?;
    listed
        .account_data_entries
        .into_iter()
        .find(|entry| entry.account_data_key == key)
        .ok_or_else(|| anyhow!("account-data list omitted {key}"))
}

async fn account_data_row_on_both_devices(
    primary: &TestActorClient,
    secondary: &TestActorClient,
    key: &str,
) -> Result<AccountDataRow> {
    let primary_row = account_data_row(primary, key).await?;
    let secondary_row = account_data_row(secondary, key).await?;
    ensure!(
        secondary_row.account_data_key == primary_row.account_data_key
            && secondary_row.revision == primary_row.revision
            && secondary_row.content == primary_row.content
            && secondary_row.updated_at == primary_row.updated_at,
        "active holder devices disagree on account-data {key}: primary={} secondary={}",
        serde_json::to_string(&primary_row)?,
        serde_json::to_string(&secondary_row)?
    );
    Ok(primary_row)
}

fn contains_retired_server_device(value: &Value) -> bool {
    match value {
        Value::String(value) => value.starts_with("server:"),
        Value::Array(values) => values.iter().any(contains_retired_server_device),
        Value::Object(values) => values.values().any(contains_retired_server_device),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
}

async fn assert_service_account_data_fanout(
    holder: &TestActorClient,
    expected_service_id: &str,
    expected_row: &AccountDataRow,
) -> Result<()> {
    let polled = expect_json(holder.get("/_arkret/self/device_messages"), StatusCode::OK).await?;
    let outcome: DeviceMessagesGetOutcome = serde_json::from_value(polled.clone())
        .with_context(|| format!("to-device response is not closed SDK wire data: {polled}"))?;
    let holder_core_id = actor_core_id(&holder.actor)?;
    let mut matched = None;
    for envelope in &outcome.messages {
        if envelope.kind.as_str() != "ak.account_data.update" {
            continue;
        }
        let DeviceMessageContent::AccountDataUpdate(update) = &envelope.content else {
            continue;
        };
        let update = update.clone();
        if update.account_data_key == expected_row.account_data_key
            && update.revision == expected_row.revision
        {
            matched = Some((envelope, update));
            break;
        }
    }
    let (envelope, update) = matched.ok_or_else(|| {
        anyhow!(
            "no account-data fanout for {} revision {}: {}",
            expected_row.account_data_key,
            expected_row.revision,
            serde_json::to_string_pretty(&polled).unwrap_or_default()
        )
    })?;
    ensure!(
        matches!(
            &envelope.sender,
            DeviceMessageSender::Service { sender_id }
                if sender_id.as_str() == expected_service_id
        ),
        "actor-private account-data fanout did not use the local Service sender"
    );
    ensure!(
        envelope.sender_principal_id.as_str() == holder_core_id
            && envelope.recipient_principal_id.as_str() == holder_core_id,
        "Service fanout principal must be the holder on both sides"
    );
    ensure!(
        envelope.recipient_device_id.as_str() == holder.device_id,
        "Service fanout reached the wrong holder device"
    );
    ensure!(
        update.operation == ActorPrivateAccountDataOperation::Put
            && update.content.as_ref() == Some(&expected_row.content)
            && update.updated_at == expected_row.updated_at,
        "to-device revision/content differs from account-data CAS row"
    );

    let envelope_value = serde_json::to_value(envelope)?;
    ensure!(
        envelope_value.get("sender_device_id").is_none(),
        "Service fanout must not synthesize sender_device_id: {envelope_value}"
    );
    ensure!(
        !contains_retired_server_device(&envelope_value),
        "Service fanout must not contain a retired server:* fake device: {envelope_value}"
    );

    let ack_token = outcome
        .ack_token
        .context("non-empty to-device response omitted ack_token")?;
    let ack: arkret_models_collaboration::sync_frames::account_sync::DeviceMessagesAckOutcome =
        serde_json::from_value(
            expect_json(
                holder
                    .post("/_arkret/self/device_messages/ack")
                    .json(&DeviceMessagesAckRequestBody { ack_token }),
                StatusCode::OK,
            )
            .await?,
        )?;
    ensure!(ack.pruned_count == 1, "to-device ack pruned no message");
    Ok(())
}

async fn grant_then_revoke_invite_consent(
    holder: &TestActorClient,
    peer: &TestActorClient,
) -> Result<ConsentCellView> {
    let principal = holder
        .principal
        .as_ref()
        .context("holder was not provisioned with a Principal Control Realm")?;
    let holder_core_id = principal.core_id.clone();
    let peer_core_id = DidCoreId::new(actor_core_id(&peer.actor)?)?;
    let consent_id = ConsentId::new(next_typed_id("consent"))?;
    let grant_payload = ConsentGrantPayload {
        consent_id: consent_id.clone(),
        peer_id: peer_core_id,
        consent_scope: ConsentScope::Invite,
        not_before: None,
        expires_at: Some(Utc::now() + ChronoDuration::days(1)),
        constraints: None,
        evidence_ref: None,
        reason: Some("cotest_invite_quarantine_invalidation".to_owned()),
    };
    let grant_event = holder
        .author_event(
            principal.pcr_realm_id.as_str(),
            "ak.consent.grant",
            serde_json::to_value(grant_payload)?,
        )
        .await?;
    let grant_event_id = grant_event.event_id.clone();
    let grant_submission: EventInitialSubmission =
        crate::publication::initial_submission(grant_event, "")?;
    let granted = expect_json(
        holder
            .post(&format!(
                "/_arkret/self/consent/cells/{}/grant",
                holder_core_id.as_str()
            ))
            .json(&ConsentGrantRequestBody {
                grant_event: grant_submission,
            }),
        StatusCode::OK,
    )
    .await?;
    let granted: ConsentCellView = serde_json::from_value(granted)
        .context("consent grant response is not a ConsentCellView")?;
    let expected_dot = format!("{}:0", grant_event_id.as_str());
    ensure!(
        granted
            .active_grant_dots
            .iter()
            .any(|dot| dot == &expected_dot),
        "consent grant projection omitted its Event-derived dot: {granted:?}"
    );
    let device_signing_key = holder
        .principal
        .as_ref()
        .context("holder was not provisioned with a device signing key")?
        .device_signing_key
        .clone();
    seal_current_principal_control_frontier(holder, &device_signing_key).await?;

    let revoke_payload = ConsentRevokePayload {
        consent_id,
        observed_dot_ids: granted
            .active_grant_dots
            .iter()
            .cloned()
            .map(ConsentObservedDot::new)
            .collect::<arkret_wire::Result<Vec<_>>>()?,
        revoked_at: Some(Utc::now()),
        reason: Some("cotest_invite_quarantine_invalidation".to_owned()),
    };
    let revoke_event = holder
        .author_event(
            principal.pcr_realm_id.as_str(),
            "ak.consent.revoke",
            serde_json::to_value(revoke_payload)?,
        )
        .await?;
    let revoke_submission: EventInitialSubmission =
        crate::publication::initial_submission(revoke_event, "")?;
    let revoked = expect_json(
        holder
            .post(&format!(
                "/_arkret/self/consent/cells/{}/revoke",
                holder_core_id.as_str()
            ))
            .json(&ConsentRevokeRequestBody {
                revoke_event: revoke_submission,
            }),
        StatusCode::OK,
    )
    .await?;
    serde_json::from_value(revoked).context("consent revoke response is not a ConsentCellView")
}

/// Execute all three Principal Server CAS materializer fanout branches against
/// a live Soland process.
pub async fn invite_service_fanout_live_run() -> Result<()> {
    let group = TestServerGroup::single("invite-service-fanout-live").await?;
    let server = group.server(0);
    let inviter = server
        .demo_client(
            &actor_did_for_service_did(server.service_did(), "alice-invite-service-fanout")?,
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await
        .context("bootstrap inviter client")?;
    let holder_did = actor_did_for_service_did(server.service_did(), "bob-invite-service-fanout")?;
    let holder = server
        .register_client(
            &holder_did,
            "bob-invite-service-fanout",
            "ak:device:01904100-0000-7000-8000-0000000000b1",
        )
        .await
        .context("bootstrap holder client")?;
    let holder_secondary = server
        .demo_client(
            &holder_did,
            "ak:device:01904100-0000-7000-8000-0000000000b2",
        )
        .await
        .context("bootstrap secondary active holder device")?;

    set_explicit_address_behavior(&holder, InviteReceiveAction::Notify)
        .await
        .context("set notify receive policy")?;
    let delivered =
        create_and_dispatch_explicit_invite(&inviter, &holder, "Invite Service Fanout Notify")
            .await
            .context("create and dispatch notify invite")?;
    ensure!(
        delivered.outcome["status"] == "accepted",
        "notify dispatch was not accepted: {}",
        delivered.outcome
    );
    let delivery_row = account_data_row_on_both_devices(
        &holder,
        &holder_secondary,
        AccountDataKey::ACCOUNT_INVITE_DELIVERY,
    )
    .await
    .context("read invite delivery CAS row on both active devices")?;
    ensure!(
        delivery_row.content["entries"]
            .as_array()
            .is_some_and(|entries| entries.iter().any(|entry| {
                entry["invite_id"].as_str() == Some(delivered.invite_id.as_str())
            })),
        "invite_delivery cell omitted the dispatched invite: {}",
        delivery_row.content
    );
    assert_service_account_data_fanout(&holder, server.service_id().as_str(), &delivery_row)
        .await?;
    assert_service_account_data_fanout(
        &holder_secondary,
        server.service_id().as_str(),
        &delivery_row,
    )
    .await?;

    set_explicit_address_behavior(&holder, InviteReceiveAction::Quarantine)
        .await
        .context("set quarantine receive policy")?;
    let quarantined =
        create_and_dispatch_explicit_invite(&inviter, &holder, "Invite Service Fanout Quarantine")
            .await
            .context("create and dispatch quarantined invite")?;
    ensure!(
        quarantined.outcome["status"] == "deferred"
            && quarantined.outcome.get("disclosed_outcome").is_none(),
        "quarantine must be an opaque deferred outcome: {}",
        quarantined.outcome
    );
    let quarantine_row = account_data_row_on_both_devices(
        &holder,
        &holder_secondary,
        AccountDataKey::ACCOUNT_INVITE_QUARANTINE,
    )
    .await?;
    ensure!(
        quarantine_row.content["schema"] == "ak.schema.invite_quarantine.v1"
            && quarantine_row.content["entries"]
                .as_array()
                .is_some_and(|entries| !entries.is_empty()),
        "invite_quarantine cell is not the closed non-empty v1 shape: {}",
        quarantine_row.content
    );
    assert_service_account_data_fanout(&holder, server.service_id().as_str(), &quarantine_row)
        .await?;
    assert_service_account_data_fanout(
        &holder_secondary,
        server.service_id().as_str(),
        &quarantine_row,
    )
    .await?;

    let revoked = grant_then_revoke_invite_consent(&holder, &inviter).await?;
    ensure!(
        revoked.active_grant_dots.is_empty(),
        "consent revoke left active grant dots: {revoked:?}"
    );
    let invalidated_row = account_data_row_on_both_devices(
        &holder,
        &holder_secondary,
        AccountDataKey::ACCOUNT_INVITE_QUARANTINE,
    )
    .await?;
    ensure!(
        invalidated_row.revision == quarantine_row.revision + 1,
        "consent revoke did not CAS-advance invite_quarantine revision"
    );
    ensure!(
        invalidated_row.content["entries"]
            .as_array()
            .is_some_and(Vec::is_empty)
            && invalidated_row.content["last_invalidation"]["reason"] == "consent_revoke"
            && invalidated_row.content["last_invalidation"]["removed_entries"] == json!(1),
        "consent revoke did not persist the closed quarantine invalidation: {}",
        invalidated_row.content
    );
    assert_service_account_data_fanout(&holder, server.service_id().as_str(), &invalidated_row)
        .await?;
    assert_service_account_data_fanout(
        &holder_secondary,
        server.service_id().as_str(),
        &invalidated_row,
    )
    .await?;

    for active_holder in [&holder, &holder_secondary] {
        let drained = expect_json(
            active_holder.get("/_arkret/self/device_messages"),
            StatusCode::OK,
        )
        .await?;
        let drained: DeviceMessagesGetOutcome = serde_json::from_value(drained)?;
        if !drained.messages.is_empty() {
            bail!(
                "acked actor-private fanout queue did not drain for {}: {drained:?}",
                active_holder.device_id
            );
        }
    }
    Ok(())
}
