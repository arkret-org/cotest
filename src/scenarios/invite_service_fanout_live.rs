//! Live acceptance for Station actor-private invite fanout.
//!
//! The durable source of truth for invite delivery and quarantine is the
//! holder's account-data revision guard. `ak.account_data.update` is only a
//! wake-up hint, so this scenario checks both sides of every write:
//!
//! 1. `ak.account.invite_delivery` after a notify decision;
//! 2. `ak.account.holder_quarantine` after a quarantine decision; and
//! 3. the same quarantine cell after a matching consent revoke invalidates it.
//!
//! Both active holder devices independently read account-data list/resource
//! state and their own live queue. Every envelope is deserialized through the
//! SDK's recipient-delivery branch and must carry the local Station as sender,
//! the holder account as recipient, and the exact revision/content returned by
//! account-data CAS. The notify branch also
//! keeps an account-subscribe long poll open before dispatch and proves that the
//! durable fanout wakes it with the invite-delivery update.

use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use arkret_identifiers::{ConsentId, DidCoreId, InviteId};
use arkret_models_collaboration::consent_operations::{
    ConsentGrantRequestBody, ConsentRevokeRequestBody, ConsentView,
};
use arkret_models_collaboration::device_messages::{
    DeviceMessageEnvelope, DeviceMessageSender, DeviceMessagesAckRequestBody,
    DeviceMessagesGetOutcome, RecipientDelivery,
};
use arkret_models_collaboration::events_payloads::ConsentGrantPayload;
use arkret_models_collaboration::events_payloads::consent::ConsentPeer;
use arkret_models_collaboration::governance::invite_addressing::{
    IntroductionEvidence, InviteAddress, InviteReceivePolicy, SelfInviteDispatchRequestBody,
};
use arkret_models_collaboration::governance_payloads::ConsentRevokePayload;
use arkret_models_identity::ServiceResolutionCarrier;
use arkret_models_identity::account::{AccountDataList, AccountDataRow};
use arkret_wire::{
    AccountDataKey, AccountId, ActorId, ConsentScope, EventAdmissionSubmission, InviteReceiveAction,
};
use chrono::{Duration as ChronoDuration, Utc};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::harness::{
    TestActorClient, TestServerGroup, actor_core_id, expect_account_subscribe_delta, expect_json,
    invite_create_payload, next_typed_id,
};
use crate::scenarios::identity_test_support::actor_did_for_service_did;

fn account_data_update_matches(envelope: &DeviceMessageEnvelope, row: &AccountDataRow) -> bool {
    envelope.kind.as_str() == "ak.account_data.update"
        && envelope.content.get("operation").and_then(Value::as_str) == Some("put")
        && envelope
            .content
            .get("account_data_key")
            .and_then(Value::as_str)
            == Some(row.account_data_key.as_str())
        && envelope.content.get("revision").and_then(Value::as_u64) == Some(row.revision)
        && envelope.content.get("content") == Some(&row.content)
        && envelope.content.get("updated_at").and_then(Value::as_str)
            == Some(arkret_canonical::format_timestamp_canonical(row.updated_at).as_str())
}

#[derive(Debug)]
pub(crate) struct DispatchedInvite {
    pub(crate) outcome: Value,
    #[allow(dead_code)]
    pub(crate) invite_id: InviteId,
}

#[derive(Debug)]
pub(crate) struct PreparedInvite {
    pub(crate) request: SelfInviteDispatchRequestBody,
    #[allow(dead_code)]
    pub(crate) invite_id: InviteId,
}

pub(crate) async fn set_explicit_address_behavior(
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
    if !policy
        .holder_allowed_introduction_kinds
        .iter()
        .any(|kind| kind == "same_station")
    {
        policy
            .holder_allowed_introduction_kinds
            .push("same_station".to_owned());
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
        "Station changed explicit_address_behavior"
    );
    Ok(())
}

pub(crate) async fn prepare_explicit_invite(
    inviter: &TestActorClient,
    holder: &TestActorClient,
    label: &str,
) -> Result<PreparedInvite> {
    prepare_invite_with_evidence(
        inviter,
        holder,
        label,
        IntroductionEvidence::ExplicitAddress,
    )
    .await
}

async fn prepare_invite_with_evidence(
    inviter: &TestActorClient,
    holder: &TestActorClient,
    label: &str,
    evidence: IntroductionEvidence,
) -> Result<PreparedInvite> {
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
    let service_resolution = ServiceResolutionCarrier::ResolutionUrl {
        resolution_url: format!(
            "https://cotest.invalid{}",
            arkret_models_identity::canonical_service_resolution_path(&service_id)
        ),
    };
    let request = SelfInviteDispatchRequestBody {
        schema: arkret_wire::SchemaId::INVITE_DELIVERY_REQUEST_V1.to_owned(),
        invite_event_id: event_id.clone(),
        invite_address: InviteAddress::station(
            DidCoreId::new(actor_core_id(&holder.actor)?)?,
            service_id,
            service_resolution,
        ),
        introduction_evidence: evidence,
        idempotency_key: event_id.to_string(),
    };
    Ok(PreparedInvite {
        request,
        invite_id: InviteId::from_event_id(&event_id),
    })
}

pub(crate) async fn dispatch_explicit_invite(
    inviter: &TestActorClient,
    prepared: PreparedInvite,
) -> Result<DispatchedInvite> {
    let outcome = expect_json(
        inviter
            .post("/_arkret/self/invites/dispatch")
            .json(&prepared.request),
        StatusCode::OK,
    )
    .await?;
    Ok(DispatchedInvite {
        outcome,
        invite_id: prepared.invite_id,
    })
}

pub(crate) async fn create_and_dispatch_explicit_invite(
    inviter: &TestActorClient,
    holder: &TestActorClient,
    label: &str,
) -> Result<DispatchedInvite> {
    dispatch_explicit_invite(
        inviter,
        prepare_explicit_invite(inviter, holder, label).await?,
    )
    .await
}

pub(crate) async fn account_data_row(
    holder: &TestActorClient,
    key: &str,
) -> Result<AccountDataRow> {
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
    for delivery in &outcome.deliveries {
        let RecipientDelivery::DeviceMessage {
            device_message: envelope,
        } = delivery
        else {
            continue;
        };
        if account_data_update_matches(envelope, expected_row) {
            matched = Some(envelope);
            break;
        }
    }
    let envelope = matched.ok_or_else(|| {
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
            DeviceMessageSender::Station { sender_id }
                if sender_id.as_str() == expected_service_id
        ),
        "actor-private account-data fanout did not use the local Service sender"
    );
    ensure!(
        envelope.recipient_account_id.principal_id.as_str() == holder_core_id
            && envelope.recipient_account_id.station_id.as_str() == expected_service_id,
        "Service fanout recipient AccountId must identify the exact holder account"
    );
    ensure!(
        envelope.recipient_device_id.as_str() == holder.device_id,
        "Service fanout reached the wrong holder device"
    );
    ensure!(
        account_data_update_matches(envelope, expected_row),
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
    let ack: arkret_models_collaboration::device_messages::DeviceMessagesAckOutcome =
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

async fn grant_invite_consent(
    holder: &TestActorClient,
    peer: &TestActorClient,
) -> Result<(ConsentView, arkret_wire::Event)> {
    let principal = holder
        .principal
        .as_ref()
        .context("holder was not provisioned with a Principal Control Realm")?;
    let peer_principal = peer
        .principal
        .as_ref()
        .context("peer was not provisioned with a Principal Control Realm")?;
    let _holder_core_id = principal.core_id.clone();
    let consent_id = ConsentId::new(next_typed_id("consent"))?;
    let grant_payload = ConsentGrantPayload {
        consent_id: consent_id.clone(),
        peer: ConsentPeer::Actor {
            actor_id: ActorId::account(AccountId::new(
                peer_principal.core_id.clone(),
                DidCoreId::new(peer.service_id())?,
            )),
        },
        consent_scope: ConsentScope::Invite,
        not_before: None,
        expires_at: Some(Utc::now() + ChronoDuration::days(1)),
        constraints: None,
        evidence_ref: None,
        reason: Some("cotest_holder_quarantine_invalidation".to_owned()),
    };
    let grant_event = holder
        .author_event(
            principal.pcr_realm_id.as_str(),
            "ak.consent.grant",
            serde_json::to_value(grant_payload)?,
        )
        .await?;
    let grant_submission = EventAdmissionSubmission::new(grant_event.clone());
    let granted = expect_json(
        holder
            .post("/_arkret/self/consent/results/grant")
            .json(&ConsentGrantRequestBody {
                grant_event: grant_submission,
            }),
        StatusCode::OK,
    )
    .await?;
    let granted: ConsentView =
        serde_json::from_value(granted).context("consent grant response is not a ConsentView")?;
    ensure!(
        granted.state == arkret_models_collaboration::consent_operations::ConsentState::Active,
        "consent grant did not produce active current state: {granted:?}"
    );

    Ok((granted, grant_event))
}

async fn revoke_invite_consent(
    holder: &TestActorClient,
    granted: ConsentView,
) -> Result<ConsentView> {
    let principal = holder.principal.as_ref().context("holder has no PCR")?;
    let revoke_payload = ConsentRevokePayload {
        consent_id: granted.consent_id,
        expected_revision: granted.revision,
        revoked_at: Some(Utc::now()),
        reason: Some("cotest_holder_quarantine_invalidation".to_owned()),
    };
    let revoke_event = holder
        .author_event(
            principal.pcr_realm_id.as_str(),
            "ak.consent.revoke",
            serde_json::to_value(revoke_payload)?,
        )
        .await?;
    let revoke_submission = EventAdmissionSubmission::new(revoke_event);
    let revoked = expect_json(
        holder
            .post("/_arkret/self/consent/results/revoke")
            .json(&ConsentRevokeRequestBody {
                revoke_event: revoke_submission,
            }),
        StatusCode::OK,
    )
    .await?;
    serde_json::from_value(revoked).context("consent revoke response is not a ConsentView")
}

async fn grant_then_revoke_invite_consent(
    holder: &TestActorClient,
    peer: &TestActorClient,
) -> Result<ConsentView> {
    let (granted, _) = grant_invite_consent(holder, peer).await?;
    revoke_invite_consent(holder, granted).await
}

async fn assert_notify_invite_wakes_account_subscribe(
    inviter: &TestActorClient,
    holder: &TestActorClient,
    expected_service_id: &str,
    label: &str,
) -> Result<AccountDataRow> {
    set_explicit_address_behavior(holder, InviteReceiveAction::Notify)
        .await
        .context("set notify receive policy")?;
    let prepared = prepare_explicit_invite(inviter, holder, label)
        .await
        .context("prepare notify invite before opening account subscribe")?;
    let baseline = expect_account_subscribe_delta(
        holder.get("/_arkret/self/account/subscribe?catchup=true"),
        StatusCode::OK,
    )
    .await
    .context("establish holder account-subscribe baseline")?;
    let cursor = baseline["cursor"]
        .as_str()
        .ok_or_else(|| anyhow!("holder account-subscribe baseline omitted cursor: {baseline}"))?
        .to_owned();
    let inviter_for_dispatch = inviter.clone();
    let dispatch = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        dispatch_explicit_invite(&inviter_for_dispatch, prepared).await
    });
    let wake_started = Instant::now();
    let invite_delta = expect_account_subscribe_delta(
        holder.get(&format!(
            "/_arkret/self/account/subscribe?catchup=true&after={cursor}"
        )),
        StatusCode::OK,
    );
    let (invite_delta, delivered) = tokio::join!(invite_delta, dispatch);
    let wake_elapsed = wake_started.elapsed();
    let delivered = delivered
        .context("invite dispatch task panicked")?
        .context("create and dispatch notify invite")?;
    let invite_delta = match invite_delta {
        Ok(delta) => delta,
        Err(error) => {
            let queued = expect_json(holder.get("/_arkret/self/device_messages"), StatusCode::OK)
                .await
                .unwrap_or(Value::Null);
            return Err(error).with_context(|| {
                format!(
                    "wait for invite-delivery account-subscribe wakeup; dispatch outcome was {}; queued device messages were {queued}",
                    delivered.outcome
                )
            });
        }
    };
    ensure!(
        wake_elapsed < Duration::from_secs(3),
        "invite delivery did not wake the holder account subscribe promptly: {wake_elapsed:?}"
    );
    ensure!(
        delivered.outcome["status"] == "accepted",
        "notify dispatch was not accepted: {}",
        delivered.outcome
    );
    let delivery_row = account_data_row(holder, AccountDataKey::ACCOUNT_INVITE_DELIVERY)
        .await
        .context("read invite delivery CAS row")?;
    // An Account frame carries its own `to_device` container, not the
    // device_messages GET outcome (which alone owes `has_more`).
    let subscribe_messages: arkret_models_collaboration::sync_frames::account_subscribe::RecipientDeliveryContainer = serde_json::from_value(
        invite_delta
            .get("to_device")
            .cloned()
            .ok_or_else(|| anyhow!("invite wake delta omitted to_device: {invite_delta}"))?,
    )
    .with_context(|| format!("invite wake delta has invalid to_device data: {invite_delta}"))?;
    ensure!(
        subscribe_messages.deliveries.iter().any(|delivery| {
            matches!(
                delivery,
                RecipientDelivery::DeviceMessage { device_message }
                    if account_data_update_matches(device_message, &delivery_row)
            )
        }),
        "account subscribe woke without the durable invite-delivery update: {invite_delta}"
    );
    ensure!(
        delivery_row.content["delivery_entries"]
            .as_array()
            .is_some_and(|entries| entries.iter().any(|entry| {
                entry["invite_id"].as_str() == Some(delivered.invite_id.as_str())
            })),
        "invite_delivery cell omitted the dispatched invite from delivery_entries: {}",
        delivery_row.content
    );
    assert_service_account_data_fanout(holder, expected_service_id, &delivery_row).await?;
    Ok(delivery_row)
}

/// Prove the user-visible notify path with one registered holder device. This
/// scenario deliberately needs no secondary-device pairing handoff bundle.
pub async fn invite_notification_wakeup_live_run() -> Result<()> {
    let group = TestServerGroup::single("invite-notification-wakeup-live").await?;
    let server = group.server(0);
    let inviter = server
        .standard_client(
            &actor_did_for_service_did(server.service_did(), "alice-invite-notification-wakeup")?,
            "ak:device:01904100-0000-7000-8000-0000000000c1",
        )
        .await
        .context("bootstrap inviter client")?;
    let holder_did =
        actor_did_for_service_did(server.service_did(), "bob-invite-notification-wakeup")?;
    let holder = server
        .standard_register_client(
            &holder_did,
            "bob-invite-notification-wakeup",
            "ak:device:01904100-0000-7000-8000-0000000000d1",
        )
        .await
        .context("bootstrap holder client")?;
    assert_notify_invite_wakes_account_subscribe(
        &inviter,
        &holder,
        server.service_id().as_str(),
        "Invite Notification Wakeup",
    )
    .await?;
    Ok(())
}

/// Execute all three Station CAS materializer fanout branches against
/// a live Coland process.
pub async fn invite_service_fanout_live_run() -> Result<()> {
    let group = TestServerGroup::single("invite-service-fanout-live").await?;
    let server = group.server(0);
    let inviter = server
        .standard_client(
            &actor_did_for_service_did(server.service_did(), "alice-invite-service-fanout")?,
            "ak:device:01904100-0000-7000-8000-0000000000a1",
        )
        .await
        .context("bootstrap inviter client")?;
    let holder_did = actor_did_for_service_did(server.service_did(), "bob-invite-service-fanout")?;
    let holder = server
        .standard_register_client(
            &holder_did,
            "bob-invite-service-fanout",
            "ak:device:01904100-0000-7000-8000-0000000000b1",
        )
        .await
        .context("bootstrap holder client")?;
    let holder_secondary = server
        .standard_client(
            &holder_did,
            "ak:device:01904100-0000-7000-8000-0000000000b2",
        )
        .await
        .context("bootstrap secondary active holder device")?;

    let delivery_row = assert_notify_invite_wakes_account_subscribe(
        &inviter,
        &holder,
        server.service_id().as_str(),
        "Invite Service Fanout Notify",
    )
    .await?;
    let secondary_delivery_row =
        account_data_row(&holder_secondary, AccountDataKey::ACCOUNT_INVITE_DELIVERY)
            .await
            .context("read invite delivery CAS row on secondary active device")?;
    ensure!(
        secondary_delivery_row.revision == delivery_row.revision
            && secondary_delivery_row.content == delivery_row.content
            && secondary_delivery_row.updated_at == delivery_row.updated_at,
        "secondary holder device disagrees on invite delivery CAS row"
    );
    assert_service_account_data_fanout(
        &holder_secondary,
        server.service_id().as_str(),
        &secondary_delivery_row,
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
        AccountDataKey::ACCOUNT_HOLDER_QUARANTINE,
    )
    .await?;
    ensure!(
        quarantine_row.content["schema"] == "ak.schema.holder_quarantine.v1"
            && quarantine_row.content["quarantine_entries"]
                .as_array()
                .is_some_and(|entries| !entries.is_empty()),
        "holder_quarantine cell is not the closed non-empty v1 shape: {}",
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
        revoked.state == arkret_models_collaboration::consent_operations::ConsentState::Revoked,
        "consent revoke did not produce revoked current state: {revoked:?}"
    );
    let invalidated_row = account_data_row_on_both_devices(
        &holder,
        &holder_secondary,
        AccountDataKey::ACCOUNT_HOLDER_QUARANTINE,
    )
    .await?;
    ensure!(
        invalidated_row.revision == quarantine_row.revision + 1,
        "consent revoke did not CAS-advance holder_quarantine revision"
    );
    ensure!(
        invalidated_row.content["quarantine_entries"]
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
        if !drained.deliveries.is_empty() {
            bail!(
                "acked actor-private fanout queue did not drain for {}: {drained:?}",
                active_holder.device_id
            );
        }
    }
    Ok(())
}

/// One live holder current chain with an actual invite admission consumer.
pub async fn consent_current_and_invite_gate_live_run() -> Result<()> {
    use arkret_models_collaboration::consent_operations::ConsentList;
    let group = TestServerGroup::single("consent-current-invite-gate").await?;
    let server = group.server(0);
    let inviter = server
        .standard_client(
            &actor_did_for_service_did(server.service_did(), "consent-inviter")?,
            "ak:device:01904100-0000-7000-8000-0000000000e1",
        )
        .await?;
    let holder = server
        .standard_register_client(
            &actor_did_for_service_did(server.service_did(), "consent-holder")?,
            "consent-holder",
            "ak:device:01904100-0000-7000-8000-0000000000e2",
        )
        .await?;
    let current = expect_json(
        holder.get("/_arkret/self/invite-receive-policy"),
        StatusCode::OK,
    )
    .await?;
    let mut policy: InviteReceivePolicy = serde_json::from_value(current)?;
    policy.consent_profile = arkret_wire::ConsentProfile::RequireExplicitConsent;
    expect_json(
        holder
            .put("/_arkret/self/invite-receive-policy")
            .json(&policy),
        StatusCode::OK,
    )
    .await?;
    let (granted, grant_event) = grant_invite_consent(&holder, &inviter).await?;
    let retry_body = ConsentGrantRequestBody {
        grant_event: EventAdmissionSubmission::new(grant_event.clone()),
    };
    let duplicate: ConsentView = serde_json::from_value(
        expect_json(
            holder
                .post("/_arkret/self/consent/results/grant")
                .json(&retry_body),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        duplicate == granted,
        "HTTP grant replay changed its original committed result"
    );
    expect_json(
        inviter
            .post("/_arkret/self/consent/results/grant")
            .json(&retry_body),
        StatusCode::FORBIDDEN,
    )
    .await?;
    let listed: ConsentList = serde_json::from_value(
        expect_json(holder.get("/_arkret/self/consent/results"), StatusCode::OK).await?,
    )?;
    ensure!(
        listed.consents == vec![granted.clone()],
        "list does not contain exact committed Consent"
    );
    let read: ConsentView = serde_json::from_value(
        expect_json(
            holder.get("/_arkret/self/consent/result").query(&[
                ("peer", serde_json::to_string(&granted.peer)?),
                ("consent_scope", "invite".to_owned()),
            ]),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        read == granted,
        "get does not return exact current revision"
    );
    let peer_list: ConsentList = serde_json::from_value(
        expect_json(inviter.get("/_arkret/self/consent/results"), StatusCode::OK).await?,
    )?;
    ensure!(
        peer_list.consents.is_empty(),
        "peer sees holder private Consent"
    );
    let evidence = IntroductionEvidence::ConsentGrant {
        consent_grant_ref: grant_event.event_id.clone(),
        consent_id: Some(granted.consent_id.to_string()),
    };
    let prepared =
        prepare_invite_with_evidence(&inviter, &holder, "Consent active invite", evidence.clone())
            .await?;
    dispatch_explicit_invite(&inviter, prepared).await?;
    let notified = account_data_row(&holder, AccountDataKey::ACCOUNT_INVITE_DELIVERY).await?;
    let mut stale_revision = granted.revision.clone();
    stale_revision.stream_position += 1;
    let stale_event = holder
        .author_event(
            holder
                .principal
                .as_ref()
                .context("holder PCR")?
                .pcr_realm_id
                .as_str(),
            "ak.consent.revoke",
            serde_json::to_value(ConsentRevokePayload {
                consent_id: granted.consent_id.clone(),
                expected_revision: stale_revision,
                revoked_at: None,
                reason: None,
            })?,
        )
        .await?;
    let stale = expect_json(
        holder
            .post("/_arkret/self/consent/results/revoke")
            .json(&ConsentRevokeRequestBody {
                revoke_event: EventAdmissionSubmission::new(stale_event),
            }),
        StatusCode::CONFLICT,
    )
    .await?;
    ensure!(
        stale["type"] == "https://arkret.org/problems/cas_conflict",
        "stale Consent did not keep its registered CAS error"
    );
    let revoked = revoke_invite_consent(&holder, granted.clone()).await?;
    ensure!(
        revoked.state == arkret_models_collaboration::consent_operations::ConsentState::Revoked,
        "revoke did not close current"
    );
    let old_result: ConsentView = serde_json::from_value(
        expect_json(
            holder
                .post("/_arkret/self/consent/results/grant")
                .json(&retry_body),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        old_result == granted,
        "exact old grant replay lost the original result"
    );
    let current: ConsentList = serde_json::from_value(
        expect_json(holder.get("/_arkret/self/consent/results"), StatusCode::OK).await?,
    )?;
    ensure!(
        current.consents == vec![revoked],
        "old grant replay reactivated current Consent"
    );
    let prepared =
        prepare_invite_with_evidence(&inviter, &holder, "Consent revoked invite", evidence).await?;
    let dropped = dispatch_explicit_invite(&inviter, prepared).await?;
    ensure!(
        dropped.outcome["status"] == "deferred"
            && dropped.outcome.get("disclosed_outcome").is_none(),
        "revoked Consent delivery leaked a decision"
    );
    let unchanged = account_data_row(&holder, AccountDataKey::ACCOUNT_INVITE_DELIVERY).await?;
    ensure!(
        unchanged.revision == notified.revision && unchanged.content == notified.content,
        "revoked Consent changed holder invite delivery"
    );
    Ok(())
}
