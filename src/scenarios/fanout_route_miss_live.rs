//! Two-Soland live closure for durable Realm fanout route misses.

use std::collections::BTreeSet;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use arkret_models_collaboration::governance::membership_invite::{
    MembershipPayload, MembershipPayloadState,
};
use arkret_models_collaboration::http_bodies::{
    EventDeliveryStatusOutcome, EventDeliveryStatusRequestBody, EventDeliveryTargetState,
    EventsResolveOutcome, EventsResolveRequestBody, EventsSubmitOutcome,
};
use arkret_models_identity::delivery_binding::{
    BindingScope, BindingSource, DeliveryMode, DeliveryStatus, MemberDeliveryBinding,
    RecipientServiceKind,
};
use arkret_models_identity::{
    AuthenticatedServiceResolution, ServiceResolutionCarrier, ServiceResolutionRecord,
};
use arkret_wire::{DidCoreId, DidFullId, Event, EventId, EventKind, Hash};
use chrono::Utc;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{TestActorClient, TestServerGroup, expect_json, member_join_payload};
use crate::scenarios::identity_test_support::{
    HARNESS_ACCOUNT_AUTHORITY_ORIGIN, actor_did_for_service_full_id, harness_account_authority_id,
};

const INSTALL_PATH: &str = "/_arkret/_conformance/realm-fixture/install";
const DELIVERY_STATUS_PATH: &str = "/_arkret/self/events/delivery-status";
const EVENTS_RESOLVE_PATH: &str = "/_arkret/self/events/resolve";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002002";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002003";

pub async fn run_fanout_route_miss_live() -> Result<()> {
    let (source_database_url, _source_ephemeral) = match std::env::var(
        "COTEST_FANOUT_SOURCE_DATABASE_URL",
    ) {
        Ok(url) if !url.trim().is_empty() => (url, None),
        _ => {
            let source_ephemeral =
                crate::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres()?;
            let Some(database) = source_ephemeral.as_ref() else {
                eprintln!(
                    "skipping fanout route-miss live E2E: set COTEST_FANOUT_SOURCE_DATABASE_URL or make Docker/Postgres available"
                );
                return Ok(());
            };
            (database.connect_url.clone(), source_ephemeral)
        }
    };
    let (target_database_url, _target_ephemeral) = match std::env::var(
        "COTEST_FANOUT_TARGET_DATABASE_URL",
    ) {
        Ok(url) if !url.trim().is_empty() => (url, None),
        _ => {
            let target_ephemeral =
                crate::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres()?;
            let Some(database) = target_ephemeral.as_ref() else {
                eprintln!(
                    "skipping fanout route-miss live E2E: set COTEST_FANOUT_TARGET_DATABASE_URL or make a second Docker/Postgres available"
                );
                return Ok(());
            };
            (database.connect_url.clone(), target_ephemeral)
        }
    };
    let account_authority_id = harness_account_authority_id().to_string();
    let node_envs = vec![
        vec![
            ("DATABASE_URL".to_owned(), source_database_url),
            ("SOLAND_FEDERATION_OUTBOUND".to_owned(), "1".to_owned()),
            (
                "SOLAND_ACCOUNT_AUTHORITY_URL".to_owned(),
                HARNESS_ACCOUNT_AUTHORITY_ORIGIN.to_owned(),
            ),
            (
                "SOLAND_ACCOUNT_AUTHORITY_SERVICE_ID".to_owned(),
                account_authority_id.clone(),
            ),
        ],
        vec![
            ("DATABASE_URL".to_owned(), target_database_url),
            ("SOLAND_FEDERATION_OUTBOUND".to_owned(), "1".to_owned()),
            (
                "SOLAND_ACCOUNT_AUTHORITY_URL".to_owned(),
                HARNESS_ACCOUNT_AUTHORITY_ORIGIN.to_owned(),
            ),
            (
                "SOLAND_ACCOUNT_AUTHORITY_SERVICE_ID".to_owned(),
                account_authority_id,
            ),
        ],
    ];
    let Some(mut group) =
        TestServerGroup::try_multi_external_with_node_envs("fanout-route-miss", &node_envs).await?
    else {
        eprintln!("skipping fanout route-miss live E2E: prebuilt Soland is unavailable");
        return Ok(());
    };

    let alice_did =
        actor_did_for_service_full_id(group.server(0).service_full_id(), "fanout-alice")?;
    let bob_did = actor_did_for_service_full_id(group.server(1).service_full_id(), "fanout-bob")?;
    let alice = group
        .server(0)
        .register_client(&alice_did, "fanout-alice", ALICE_DEVICE)
        .await?;
    let bob = group
        .server(1)
        .register_client(&bob_did, "fanout-bob", BOB_DEVICE)
        .await?;
    let target_record = current_service_record(group.server(1)).await?;
    let bootstrap = alice
        .create_realm_bootstrap_with(json!({
            "title": "Fanout route miss",
            "summary": "Fanout route miss",
            "public": false,
            "plaintext_visible_services": [alice.service_id()],
            "delivery_binding_policy": {
                "allowed_binding_sources": ["did_document_default"],
                "did_document_default_allowed": true,
                "allowed_recipient_services": ["*"],
                "unroutable_membership_allowed": true
            }
        }))
        .await?;
    let realm_id = bootstrap["realm_id"]
        .as_str()
        .context("fanout bootstrap realm_id")?
        .to_owned();
    let bootstrap_outcome: EventsSubmitOutcome =
        serde_json::from_value(bootstrap["event_response"].clone())?;
    let bootstrap_events = resolve_events(&alice, bootstrap_outcome.accepted).await?;
    install_fixture_events(group.server(1), &bootstrap_events).await?;

    let bob_join = member_payload(
        &realm_id,
        &bob_did,
        group.server(1).service_id().clone(),
        &target_record,
        MembershipPayloadState::Join,
    )?;
    wait_for_bootstrap_seal(&alice, &realm_id).await?;
    let bob_join_id = submit_and_settle_member_transition(&alice, &realm_id, bob_join).await?;
    wait_for_resolved_event(&bob, &bob_join_id).await?;

    group.server_mut(1).stop_external_process().await?;
    let first = alice
        .submit_event(
            &realm_id,
            EventKind::MemberState.as_str(),
            member_join_payload(&realm_id, "did:web:fanout-carol.example"),
        )
        .await?;
    let first_event_id = crate::harness::submitted_event_id(&first)?;
    ensure!(
        first["pending_delivery_count"] == 1,
        "route miss did not return accepted+pending without topology: {first}"
    );
    ensure!(
        first.get("targets").is_none() && first.get("service_id").is_none(),
        "submit response leaked target topology: {first}"
    );
    let initial = wait_for_target_state(
        &alice,
        &first_event_id,
        EventDeliveryTargetState::PendingRoute,
    )
    .await?;
    let target_id = initial.targets[0].target_id.clone();
    ensure!(
        initial.targets[0].service_id.as_ref() == Some(group.server(1).service_id()),
        "Realm controller could not see its exact member delivery binding"
    );

    group.server_mut(0).restart_external_process().await?;
    let alice = group
        .server(0)
        .demo_client(&alice_did, ALICE_DEVICE)
        .await?;
    let restarted = wait_for_target_state(
        &alice,
        &first_event_id,
        EventDeliveryTargetState::PendingRoute,
    )
    .await?;
    ensure!(
        restarted.targets[0].target_id == target_id,
        "restart changed the durable opaque target id"
    );

    group.server_mut(1).start_external_process().await?;
    let delivered =
        wait_for_target_state(&alice, &first_event_id, EventDeliveryTargetState::Delivered).await?;
    ensure!(
        delivered.pending_delivery_count() == 0,
        "delivered Event retained a pending count"
    );
    let bob = group.server(1).demo_client(&bob_did, BOB_DEVICE).await?;
    ensure!(
        resolve_events(&bob, vec![first_event_id.clone()])
            .await?
            .iter()
            .any(|event| event.event_id == first_event_id),
        "target Soland did not persist the recovered delivery"
    );

    group.server_mut(1).stop_external_process().await?;
    let second = alice
        .submit_event(
            &realm_id,
            EventKind::MemberState.as_str(),
            member_join_payload(&realm_id, "did:web:fanout-david.example"),
        )
        .await?;
    let second_event_id = crate::harness::submitted_event_id(&second)?;
    let bob_leave = member_payload(
        &realm_id,
        &bob_did,
        group.server(1).service_id().clone(),
        &target_record,
        MembershipPayloadState::Leave,
    )?;
    submit_and_settle_member_transition(&alice, &realm_id, bob_leave).await?;
    let cancelled = wait_for_target_state(
        &alice,
        &second_event_id,
        EventDeliveryTargetState::CancelledAuthorityLost,
    )
    .await?;
    let cancelled_target_id = cancelled.targets[0].target_id.clone();

    let bob_rejoin = member_payload(
        &realm_id,
        &bob_did,
        group.server(1).service_id().clone(),
        &target_record,
        MembershipPayloadState::Join,
    )?;
    submit_and_settle_member_transition(&alice, &realm_id, bob_rejoin).await?;
    group.server_mut(1).start_external_process().await?;
    tokio::time::sleep(Duration::from_secs(7)).await;
    let after_rejoin = delivery_status(&alice, &second_event_id).await?;
    ensure!(
        after_rejoin.targets.len() == 1
            && after_rejoin.targets[0].target_id == cancelled_target_id
            && after_rejoin.targets[0].status == EventDeliveryTargetState::CancelledAuthorityLost,
        "rejoin revived a terminal old fanout intent: {after_rejoin:?}"
    );
    let bob = group.server(1).demo_client(&bob_did, BOB_DEVICE).await?;
    ensure!(
        resolve_events_allow_missing(&bob, vec![second_event_id])
            .await?
            .events
            .is_empty(),
        "authority-cancelled Event reached the target Soland"
    );

    Ok(())
}

async fn wait_for_bootstrap_seal(client: &TestActorClient, realm_id: &str) -> Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    loop {
        match client.realm_seal_frontier(realm_id).await {
            Ok(frontier)
                if frontier["frontier"]["control_event_set_root"].as_str()
                    != Some(
                        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    ) =>
            {
                return Ok(());
            }
            Ok(_) | Err(_) if std::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(frontier) => bail!("Realm bootstrap Seal stayed empty: {frontier}"),
            Err(error) => return Err(error).context("Realm bootstrap Seal was unavailable"),
        }
    }
}

async fn current_service_record(
    server: &crate::harness::ArkretServer,
) -> Result<ServiceResolutionRecord> {
    let path = arkret_models_identity::canonical_service_current_record_path(server.service_id());
    let resolution: AuthenticatedServiceResolution = serde_json::from_value(
        expect_json(server.http().get(server.url(&path)), StatusCode::OK).await?,
    )
    .context("decode authenticated target service resolution")?;
    Ok(resolution.service_resolution_record)
}

async fn install_fixture_events(
    server: &crate::harness::ArkretServer,
    events: &[Event],
) -> Result<()> {
    let outcome = expect_json(
        server.http().post(server.url(INSTALL_PATH)).json(
            &crate::harness::NonProtocolTestBody::new(json!({"events": events})),
        ),
        StatusCode::OK,
    )
    .await?;
    ensure!(
        outcome["accepted_event_count"].as_u64() == Some(events.len() as u64)
            && outcome["projected_event_count"].as_u64() == Some(events.len() as u64),
        "Realm fixture installation was incomplete: {outcome}"
    );
    Ok(())
}

fn member_payload(
    realm_id: &str,
    member: &str,
    member_service: DidCoreId,
    target_record: &ServiceResolutionRecord,
    membership: MembershipPayloadState,
) -> Result<serde_json::Value> {
    let realm_id = arkret_wire::RealmId::new(realm_id.to_owned())?;
    let member = arkret_wire::project_full_id_to_core_id(&DidFullId::new(member.to_owned())?)?;
    if membership == MembershipPayloadState::Join {
        let binding = MemberDeliveryBinding {
            recipient_service_id: member_service.clone(),
            recipient_service_kind: RecipientServiceKind::PrincipalServer,
            binding_scope: BindingScope::Realm,
            binding_source: BindingSource::DidDocumentDefault,
            delivery_modes: BTreeSet::from([DeliveryMode::Events]),
            service_resolution: ServiceResolutionCarrier::CurrentRecordUrl {
                current_record_url: target_record
                    .record
                    .current_record_url
                    .replacen("http://", "https://", 1),
                pinned_record_digest: None,
            },
            did_document_digest: Some(Hash::new(format!("sha256:{}", "2".repeat(64)))?),
            resolved_at: Utc::now(),
            service_acceptance_ref: None,
            holder_proof_ref: None,
            policy_event_ref: None,
            expires_at: None,
        };
        Ok(MembershipPayload::join(
            realm_id.clone(),
            member.clone(),
            DeliveryStatus::Routable,
            "fanout route-miss fixture",
        )
        .with_delivery_binding(binding)
        .to_value()?)
    } else {
        Ok(
            MembershipPayload::transition(membership, member, "fanout authority ended")
                .with_realm_id(realm_id.clone())
                .to_value()?,
        )
    }
}

async fn submit_and_settle_member_transition(
    client: &TestActorClient,
    realm_id: &str,
    payload: serde_json::Value,
) -> Result<EventId> {
    let before = client.realm_seal_frontier(realm_id).await?;
    let before = before["frontier"]["seal_basis"]["leaves"][0]
        .as_str()
        .context("member transition predecessor Seal")?;
    let response = client
        .submit_event(realm_id, EventKind::MemberState.as_str(), payload)
        .await?;
    let event_id = crate::harness::submitted_event_id(&response)?;
    let proposal_digest = response["control_proposal_acks"][0]["proposal_digest"]
        .as_str()
        .context("member transition Control Proposal Ack")?;
    client
        .await_control_proposal_settled(realm_id, proposal_digest, before)
        .await?;
    Ok(event_id)
}

async fn wait_for_resolved_event(client: &TestActorClient, event_id: &EventId) -> Result<()> {
    let mut last = None;
    for _ in 0..60 {
        let outcome = resolve_events_allow_missing(client, vec![event_id.clone()]).await?;
        if outcome
            .events
            .iter()
            .any(|event| &event.event_id == event_id)
        {
            return Ok(());
        }
        last = Some(outcome);
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err(anyhow!(
        "federated Event {event_id} did not reach the target; last outcome: {last:?}"
    ))
}

async fn resolve_events(client: &TestActorClient, event_ids: Vec<EventId>) -> Result<Vec<Event>> {
    let outcome = resolve_events_allow_missing(client, event_ids).await?;
    if !outcome.missing.is_empty() || !outcome.unauthorized.is_empty() {
        bail!("expected Events were not resolvable: {outcome:?}");
    }
    Ok(outcome.events)
}

async fn resolve_events_allow_missing(
    client: &TestActorClient,
    event_ids: Vec<EventId>,
) -> Result<EventsResolveOutcome> {
    let request = EventsResolveRequestBody {
        event_ids,
        event_digests: Vec::new(),
        include_payload: Some(true),
        history_traversal_access: None,
        max_response_bytes: None,
    };
    serde_json::from_value(
        expect_json(
            client.query(EVENTS_RESOLVE_PATH).json(&request),
            StatusCode::OK,
        )
        .await?,
    )
    .context("decode Event resolve outcome")
}

async fn delivery_status(
    client: &TestActorClient,
    event_id: &EventId,
) -> Result<EventDeliveryStatusOutcome> {
    let request = EventDeliveryStatusRequestBody {
        event_id: event_id.clone(),
    };
    let outcome: EventDeliveryStatusOutcome = serde_json::from_value(
        expect_json(
            client.query(DELIVERY_STATUS_PATH).json(&request),
            StatusCode::OK,
        )
        .await?,
    )?;
    outcome.validate_for_request(&request)?;
    Ok(outcome)
}

async fn wait_for_target_state(
    client: &TestActorClient,
    event_id: &EventId,
    expected: EventDeliveryTargetState,
) -> Result<EventDeliveryStatusOutcome> {
    let mut last = None;
    for _ in 0..60 {
        let outcome = delivery_status(client, event_id).await?;
        if outcome.targets.len() == 1 && outcome.targets[0].status == expected {
            return Ok(outcome);
        }
        last = Some(outcome);
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err(anyhow!(
        "fanout target did not reach {expected:?}; last outcome: {last:?}"
    ))
}
