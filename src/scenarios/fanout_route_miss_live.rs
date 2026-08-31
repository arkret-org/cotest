//! Two-Soland live closure for durable Realm fanout route misses.

use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use arkret_models_collaboration::event_sync::EventsSubmitFederationBatchRequestBody;
use arkret_models_collaboration::governance::membership_invite::{
    MembershipPayload, MembershipPayloadState,
};
use arkret_models_collaboration::http_bodies::{
    EventDeliveryStatusOutcome, EventDeliveryStatusRequestBody, EventDeliveryTargetState,
    EventsResolveOutcome, EventsResolveRequestBody, EventsSubmitOutcome,
};
use arkret_wire::{AccountId, ActorId, Did, DidCoreId, Event, EventId, EventKind};
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{TestActorClient, TestServerGroup, expect_json};
use crate::scenarios::identity_test_support::{
    HARNESS_ACCOUNT_AUTHORITY_ORIGIN, actor_did_for_service_did, harness_account_authority_id,
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
                ensure!(
                    std::env::var("COTEST_REQUIRE_LIVE").as_deref() != Ok("1"),
                    "required live federation: source PostgreSQL unavailable"
                );
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
                ensure!(
                    std::env::var("COTEST_REQUIRE_LIVE").as_deref() != Ok("1"),
                    "required live federation: target PostgreSQL unavailable"
                );
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
            ("DATABASE_URL".to_owned(), source_database_url.clone()),
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
        ensure!(
            std::env::var("COTEST_REQUIRE_LIVE").as_deref() != Ok("1"),
            "required live federation: prebuilt Soland unavailable"
        );
        eprintln!("skipping fanout route-miss live E2E: prebuilt Soland is unavailable");
        return Ok(());
    };
    group.server(0).assert_tls_trust_boundaries().await?;
    group.server(1).assert_tls_trust_boundaries().await?;

    let alice_did = actor_did_for_service_did(group.server(0).service_did(), "fanout-alice")?;
    // Deliberately reuse one DID: Station-local account authority must not collapse it.
    let bob_did = alice_did.clone();
    let alice = group
        .server(0)
        .register_client(&alice_did, "fanout-alice", ALICE_DEVICE)
        .await?;
    let bob = group
        .server(1)
        .register_client(&bob_did, "fanout-bob", BOB_DEVICE)
        .await?;
    let alice_principal = alice.principal.as_ref().context("source PCR bootstrap")?;
    let bob_principal = bob.principal.as_ref().context("target PCR bootstrap")?;
    ensure!(alice_principal.core_id == bob_principal.core_id);
    ensure!(
        alice_principal.pcr_realm_id != bob_principal.pcr_realm_id,
        "same DID on distinct Stations inherited one PCR lineage"
    );
    let wrong_station_session =
        group
            .server(1)
            .client_with_token(&alice_did, ALICE_DEVICE, alice.token.clone())?;
    let cross_session = wrong_station_session
        .get("/_arkret/self/account/viewer")
        .send()
        .await?;
    ensure!(
        matches!(
            cross_session.status(),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
        ),
        "source Station session was not rejected by target Station: {}",
        cross_session.status()
    );
    let bootstrap = alice
        .create_realm_bootstrap_with(json!({
            "title": "Fanout route miss",
            "summary": "Fanout route miss",
            "public": false,
            "plaintext_visible_services": [alice.service_id()]
        }))
        .await?;
    let realm_id = bootstrap["realm_id"]
        .as_str()
        .context("fanout bootstrap realm_id")?
        .to_owned();
    let bootstrap_outcome: EventsSubmitOutcome =
        serde_json::from_value(bootstrap["event_response"].clone())?;
    let bootstrap_events = resolve_events(&alice, bootstrap_outcome.accepted.clone()).await?;
    install_fixture_events(
        group.server(1),
        &bootstrap_events,
        &bootstrap_outcome.control_proposal_acks,
    )
    .await?;

    let bob_join = member_payload(
        &realm_id,
        &bob_did,
        group.server(1).service_id().clone(),
        MembershipPayloadState::Join,
    )?;
    wait_for_bootstrap_seal(&alice, &realm_id).await?;
    let bob_join_id = submit_and_settle_member_transition(&alice, &realm_id, bob_join).await?;
    let bob_join_delivery = delivery_status(&alice, &bob_join_id).await?;
    ensure!(
        !bob_join_delivery.targets.is_empty(),
        "Bob's routable join did not create a durable federation target: {bob_join_delivery:?}"
    );
    wait_for_resolved_event(&bob, &alice, &bob_join_id).await?;

    group.server_mut(1).stop_external_process().await?;
    let first = alice
        .submit_event(
            &realm_id,
            EventKind::MemberState.as_str(),
            member_payload(
                &realm_id,
                "did:web:fanout-carol.example",
                group.server(0).service_id().clone(),
                MembershipPayloadState::Join,
            )?,
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
        "Realm controller could not see the Station routed by Bob's ActorId"
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
            member_payload(
                &realm_id,
                "did:web:fanout-david.example",
                group.server(0).service_id().clone(),
                MembershipPayloadState::Join,
            )?,
        )
        .await?;
    let second_event_id = crate::harness::submitted_event_id(&second)?;
    let bob_leave = member_payload(
        &realm_id,
        &bob_did,
        group.server(1).service_id().clone(),
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
    let cancelled_intent = durable_fanout_intent(
        &source_database_url,
        &realm_id,
        &second_event_id,
        group.server(1).service_id(),
    )
    .await?;
    assert_cancelled_intent_unchanged(&cancelled_intent, &cancelled_intent)?;

    let bob_rejoin = member_payload(
        &realm_id,
        &bob_did,
        group.server(1).service_id().clone(),
        MembershipPayloadState::Join,
    )?;
    let bob_rejoin_id = submit_and_settle_member_transition(&alice, &realm_id, bob_rejoin).await?;
    let rejoin_intent = durable_fanout_intent(
        &source_database_url,
        &realm_id,
        &bob_rejoin_id,
        group.server(1).service_id(),
    )
    .await?;
    let rejoined_actor = ActorId::account(AccountId::new(
        arkret_wire::project_did_to_core_id(&Did::new(bob_did.clone())?)?,
        group.server(1).service_id().clone(),
    ));
    assert_rejoin_history_intent(
        &cancelled_intent,
        &rejoin_intent,
        &bob_rejoin_id,
        &second_event_id,
        &rejoined_actor,
    )?;
    group.server_mut(1).start_external_process().await?;
    wait_for_target_state(&alice, &bob_rejoin_id, EventDeliveryTargetState::Delivered).await?;
    let after_rejoin = delivery_status(&alice, &second_event_id).await?;
    ensure!(
        after_rejoin.targets.len() == 1
            && after_rejoin.targets[0].target_id == cancelled_target_id
            && after_rejoin.targets[0].status == EventDeliveryTargetState::CancelledAuthorityLost,
        "rejoin revived a terminal old fanout intent: {after_rejoin:?}"
    );
    let old_after_rejoin = durable_fanout_intent(
        &source_database_url,
        &realm_id,
        &second_event_id,
        group.server(1).service_id(),
    )
    .await?;
    assert_cancelled_intent_unchanged(&cancelled_intent, &old_after_rejoin)?;
    let delivered_rejoin = durable_fanout_intent(
        &source_database_url,
        &realm_id,
        &bob_rejoin_id,
        group.server(1).service_id(),
    )
    .await?;
    ensure!(delivered_rejoin["state"] == "delivered");
    for field in ["id", "idempotency_key", "realm_fanout", "payload_json"] {
        ensure!(
            rejoin_intent[field] == delivered_rejoin[field],
            "new rejoin intent changed frozen {field} during delivery"
        );
    }
    let bob = group.server(1).demo_client(&bob_did, BOB_DEVICE).await?;
    // Cancellation terminates the old obligation, not the signed Control
    // Event's availability as governance history under a new membership.
    // The new Join batch includes its actor-chain predecessors and has its
    // own current witness. Prove that source instead of forbidding history.
    let history =
        resolve_events(&bob, vec![bob_rejoin_id.clone(), second_event_id.clone()]).await?;
    ensure!(
        history.iter().any(|event| event.event_id == bob_rejoin_id)
            && history
                .iter()
                .any(|event| event.event_id == second_event_id),
        "new authorized rejoin batch did not materialize its Control Event history"
    );
    eprintln!(
        "fanout cancellation verified: old intent {} stayed cancelled with attempts={}, \
         semantic_attempts={}, completed_at={} and byte-identical frozen payload; \
         distinct rejoin intent {} delivered {} with predecessor {}",
        cancelled_intent["id"],
        cancelled_intent["attempts"],
        cancelled_intent["semantic_attempts"],
        cancelled_intent["completed_at"],
        delivered_rejoin["id"],
        bob_rejoin_id,
        second_event_id,
    );

    Ok(())
}

/// Diagnostic read of this live scenario's source database, not a protocol
/// surface. The public delivery-status DTO intentionally omits retry metadata.
/// Capture the entire row so a cancelled intent cannot mutate an unlisted
/// field while its public terminal state happens to remain unchanged.
async fn durable_fanout_intent(
    database_url: &str,
    realm_id: &str,
    source_event_id: &EventId,
    peer_id: &DidCoreId,
) -> Result<serde_json::Value> {
    let database_url = database_url.to_owned();
    let realm_id = realm_id.to_owned();
    let source_event_id = source_event_id.to_string();
    let peer_id = peer_id.to_string();
    tokio::task::spawn_blocking(move || -> Result<serde_json::Value> {
        let mut client = postgres::Client::connect(&database_url, postgres::NoTls)?;
        let mut transaction = client.build_transaction().read_only(true).start()?;
        let rows = transaction.query(
            "SELECT to_jsonb(outbox)::text FROM federation_outbox AS outbox \
             WHERE peer_id = $1 AND realm_fanout->>'realm_id' = $2 \
             AND (realm_fanout->'source_event_ids') ? $3",
            &[&peer_id, &realm_id, &source_event_id],
        )?;
        ensure!(
            rows.len() == 1,
            "expected one frozen intent for {source_event_id} at {peer_id}, found {}",
            rows.len()
        );
        let snapshot = serde_json::from_str(rows[0].get::<_, &str>(0))?;
        transaction.commit()?;
        Ok(snapshot)
    })
    .await
    .context("join durable fanout diagnostic read")?
}

fn assert_cancelled_intent_unchanged(
    before: &serde_json::Value,
    after: &serde_json::Value,
) -> Result<()> {
    ensure!(
        before["state"] == "cancelled_authority_lost"
            && before["completed_at"].is_i64()
            && before["attempts"].is_i64()
            && before["semantic_attempts"].is_i64(),
        "old intent did not durably finish cancellation"
    );
    ensure!(
        before == after,
        "terminal cancelled intent {} changed after rejoin (attempts {} -> {}, \
         semantic attempts {} -> {}, completed_at {} -> {})",
        before["id"],
        before["attempts"],
        after["attempts"],
        before["semantic_attempts"],
        after["semantic_attempts"],
        before["completed_at"],
        after["completed_at"],
    );
    Ok(())
}

fn assert_rejoin_history_intent(
    cancelled: &serde_json::Value,
    rejoin: &serde_json::Value,
    rejoin_event_id: &EventId,
    dependency_event_id: &EventId,
    rejoined_actor: &ActorId,
) -> Result<()> {
    ensure!(
        rejoin["id"] != cancelled["id"]
            && rejoin["idempotency_key"] != cancelled["idempotency_key"],
        "new membership reused the cancelled intent identity"
    );
    let binding: soland_storage::RealmFanoutBinding =
        serde_json::from_value(rejoin["realm_fanout"].clone())?;
    binding.validate().map_err(anyhow::Error::msg)?;
    ensure!(
        binding.source_event_ids == vec![rejoin_event_id.to_string()]
            && binding.authority_witnesses.len() == 1
            && binding.authority_witnesses[0].member_id == *rejoined_actor
            && binding.authority_witnesses[0].membership_event_ref == rejoin_event_id.as_str(),
        "new history delivery did not freeze the exact new membership generation"
    );
    let body: EventsSubmitFederationBatchRequestBody = serde_json::from_str(
        rejoin["payload_json"]
            .as_str()
            .context("rejoin intent payload")?,
    )?;
    let events = body
        .events
        .iter()
        .map(|entry| (entry.event.event_id.clone(), &entry.event))
        .collect::<std::collections::BTreeMap<_, _>>();
    ensure!(
        events.len() == body.events.len(),
        "new history batch duplicated Event ids"
    );
    let dependency = events
        .get(dependency_event_id)
        .context("new rejoin batch omitted old Control Event")?;
    ensure!(dependency.kind.is_control_plane());
    let rejoin_event = events
        .get(rejoin_event_id)
        .context("new rejoin batch omitted its root Event")?;
    ensure!(rejoin_event.kind == EventKind::MemberState);
    let membership: MembershipPayload =
        serde_json::from_value(serde_json::to_value(&rejoin_event.payload)?)?;
    ensure!(
        membership.membership == MembershipPayloadState::Join
            && membership.member_id == *rejoined_actor,
        "new history batch root did not join the exact receiver account"
    );
    let mut pending = rejoin_event.prev_refs.clone();
    let mut visited = std::collections::BTreeSet::new();
    while let Some(event_id) = pending.pop() {
        if !visited.insert(event_id.clone()) {
            continue;
        }
        if &event_id == dependency_event_id {
            return Ok(());
        }
        if let Some(event) = events.get(&event_id) {
            pending.extend(event.prev_refs.iter().cloned());
        }
    }
    bail!("old Control Event was not in the new rejoin's actual predecessor closure")
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

async fn install_fixture_events(
    server: &crate::harness::ArkretServer,
    events: &[Event],
    control_proposal_acks: &[arkret_wire::ControlProposalAck],
) -> Result<()> {
    let outcome = expect_json(
        server.http().post(server.url(INSTALL_PATH)).json(
            &crate::harness::NonProtocolTestBody::new(json!({
                "events": events,
                "control_proposal_acks": control_proposal_acks
            })),
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
    membership: MembershipPayloadState,
) -> Result<serde_json::Value> {
    let realm_id = arkret_wire::RealmId::new(realm_id.to_owned())?;
    let member = arkret_wire::project_did_to_core_id(&Did::new(member.to_owned())?)?;
    let member = ActorId::account(AccountId::new(member, member_service));
    if membership == MembershipPayloadState::Join {
        let payload =
            MembershipPayload::join(realm_id.clone(), member, "fanout route-miss fixture")
                .to_value()?;
        arkret_schema_conformance::event_payload_validator_catalog()?
            .validate_payload(EventKind::MemberState.as_str(), &payload)
            .context("fanout membership payload must satisfy the registered schema")?;
        Ok(payload)
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
    let response = client
        .submit_event(realm_id, EventKind::MemberState.as_str(), payload)
        .await?;
    let event_id = crate::harness::submitted_event_id(&response)?;
    client
        .await_event_seal_coverage(realm_id, &event_id)
        .await?;
    Ok(event_id)
}

async fn wait_for_resolved_event(
    target: &TestActorClient,
    source: &TestActorClient,
    event_id: &EventId,
) -> Result<()> {
    let mut last_resolve = None;
    let mut last_delivery = None;
    for _ in 0..60 {
        let outcome = resolve_events_allow_missing(target, vec![event_id.clone()]).await?;
        if outcome
            .events
            .iter()
            .any(|event| &event.event_id == event_id)
        {
            return Ok(());
        }
        last_resolve = Some(outcome);
        last_delivery = Some(delivery_status(source, event_id).await?);
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err(anyhow!(
        "federated Event {event_id} did not reach the target; last resolve outcome: \
         {last_resolve:?}; last source delivery status: {last_delivery:?}"
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
    // A route miss can already be on its fifth transport attempt when the
    // target finishes restarting. The registered exponential backoff then
    // schedules the next attempt roughly three minutes later, so the live
    // convergence window must extend beyond that valid retry boundary.
    for _ in 0..180 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_intent_snapshot_rejects_retry_or_frozen_binding_mutation() {
        let cancelled = json!({
            "id": "old-intent",
            "state": "cancelled_authority_lost",
            "attempts": 3,
            "semantic_attempts": 0,
            "completed_at": 1234,
            "idempotency_key": "old-key",
            "realm_fanout": {"authority_witnesses": ["old-generation"]},
            "payload_json": "original signed payload",
            "lease_token": null
        });
        assert_cancelled_intent_unchanged(&cancelled, &cancelled).unwrap();
        for (field, replacement) in [
            ("attempts", json!(4)),
            ("semantic_attempts", json!(1)),
            ("completed_at", json!(1235)),
            ("state", json!("delivered")),
            ("id", json!("replacement-intent")),
            ("idempotency_key", json!("replacement-key")),
            (
                "realm_fanout",
                json!({"authority_witnesses": ["new-generation"]}),
            ),
            ("payload_json", json!("replacement payload")),
            ("lease_token", json!("reclaimed-after-cancellation")),
        ] {
            let mut changed = cancelled.clone();
            changed[field] = replacement;
            assert!(
                assert_cancelled_intent_unchanged(&cancelled, &changed).is_err(),
                "snapshot ignored changed {field}"
            );
        }
    }
}
