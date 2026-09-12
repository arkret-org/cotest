//! Two-Soland live closure for durable Realm fanout route misses.

use std::path::PathBuf;
use std::process::Command;
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
use arkret_models_identity::{
    AccountDeviceSenderKind, CurrentAccountDeviceSelector, CurrentAdmissionMode,
    CurrentSignerKeyOutcome, SignerKeyQueryOutcome, SignerKeyQuerySelector,
    SignerKeysQueryRequestBody,
};
use arkret_wire::{
    AccountId, ActorId, Did, DidCoreId, DidUrl, Event, EventId, EventKind, Hash, RealmId,
    RequestId, ScopeRef, SealId, SignalClass, SignalEncryptedPayload, SignalEnvelope, SignalKeyRef,
    SignalProof,
};
use chrono::Utc;
use reqwest::StatusCode;
use serde_json::json;

use crate::harness::{TestActorClient, TestServerGroup, expect_json};
use crate::scenarios::identity_test_support::{
    HARNESS_ACCOUNT_AUTHORITY_ORIGIN, actor_did_for_service_did,
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
    let (target_database_url, target_ephemeral) = match std::env::var(
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
    let target_database_is_harness_owned = target_ephemeral.is_some()
        || std::env::var("COTEST_FANOUT_TARGET_DATABASE_EPHEMERAL").as_deref() == Ok("1");
    let node_envs = vec![
        vec![
            ("DATABASE_URL".to_owned(), source_database_url.clone()),
            ("SOLAND_FEDERATION_OUTBOUND".to_owned(), "1".to_owned()),
            (
                "SOLAND_FEDERATION_FRONTIER_INTERVAL_SECONDS".to_owned(),
                "60".to_owned(),
            ),
            (
                "SOLAND_ACCOUNT_AUTHORITY_URL".to_owned(),
                HARNESS_ACCOUNT_AUTHORITY_ORIGIN.to_owned(),
            ),
        ],
        vec![
            ("DATABASE_URL".to_owned(), target_database_url.clone()),
            ("SOLAND_FEDERATION_OUTBOUND".to_owned(), "1".to_owned()),
            (
                "SOLAND_FEDERATION_FRONTIER_INTERVAL_SECONDS".to_owned(),
                "60".to_owned(),
            ),
            (
                "SOLAND_ACCOUNT_AUTHORITY_URL".to_owned(),
                HARNESS_ACCOUNT_AUTHORITY_ORIGIN.to_owned(),
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
    let wrong_station_session = group.server(1).client_with_token(
        &alice_did,
        ALICE_DEVICE,
        alice.expect_dev_bearer().to_owned(),
    )?;
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

    // Bring the target back while its membership is revoked. Its retained
    // database is an older authorized view and still knows the Realm, so the
    // immediate frontier pass attempts a real service-signed peer read. The
    // source must re-evaluate current authorization, return the protocol's
    // existence-concealing `not_found`, refuse disclosure, and
    // leave the Event that was accepted after the target went offline absent.
    group.server_mut(1).start_external_process().await?;
    wait_for_frontier_exchange_error(
        &target_database_url,
        &realm_id,
        group.server(0).service_id(),
        "http_status:404",
    )
    .await?;
    let revoked_bob = group.server(1).demo_client(&bob_did, BOB_DEVICE).await?;
    let revoked_read =
        resolve_events_allow_missing(&revoked_bob, vec![second_event_id.clone()]).await?;
    ensure!(
        revoked_read.events.is_empty()
            && revoked_read.missing == vec![second_event_id.to_string()]
            && revoked_read.unauthorized.is_empty(),
        "revoked target learned an Event through stale federation authority: {revoked_read:?}"
    );
    eprintln!("live frontier matrix: permission revocation fail-closed passed");
    group.server_mut(1).stop_external_process().await?;

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

    // Fault injection for the frontier repair path: accept and Seal an
    // Ack-required Control Event while the target is offline, then mark its
    // frozen outbox intent delivered without performing transport. Once the
    // target returns, the only protocol route left for the missing Event is
    // peer frontier discovery followed by peer resolve and shared federation
    // admission. The frozen push body proves this Event needs the original
    // Control Proposal Ack; a bare Event or receiver-minted replacement would
    // fail the admission contract.
    group.server_mut(1).stop_external_process().await?;
    let carol_leave = member_payload(
        &realm_id,
        "did:web:fanout-carol.example",
        group.server(0).service_id().clone(),
        MembershipPayloadState::Leave,
    )?;
    let frontier_backfill_id =
        submit_and_settle_member_transition(&alice, &realm_id, carol_leave).await?;
    let frontier_backfill_intent = durable_fanout_intent(
        &source_database_url,
        &realm_id,
        &frontier_backfill_id,
        group.server(1).service_id(),
    )
    .await?;
    let frontier_backfill_body: EventsSubmitFederationBatchRequestBody = serde_json::from_str(
        frontier_backfill_intent["payload_json"]
            .as_str()
            .context("frontier backfill intent payload")?,
    )?;
    let frontier_backfill_submission = frontier_backfill_body
        .events
        .iter()
        .find(|submission| submission.event.event_id == frontier_backfill_id)
        .context("frontier backfill intent omitted its source Control Event")?;
    ensure!(
        frontier_backfill_submission.event.kind.is_control_plane()
            && frontier_backfill_submission.control_proposal_ack.is_some()
            && frontier_backfill_submission
                .ackless_self_principal_admission_evidence
                .is_none(),
        "frontier repair fixture did not produce an Ack-required Control carrier"
    );
    mark_fanout_intent_delivered_without_transport(
        &source_database_url,
        &realm_id,
        &frontier_backfill_id,
        group.server(1).service_id(),
    )
    .await?;
    group.server_mut(1).start_external_process().await?;
    let bob = group.server(1).demo_client(&bob_did, BOB_DEVICE).await?;
    wait_for_resolved_event(&bob, &alice, &frontier_backfill_id).await?;
    let target_frontier_exchange = wait_for_frontier_exchange_success(
        &target_database_url,
        &realm_id,
        group.server(0).service_id(),
    )
    .await?;
    ensure!(
        target_frontier_exchange["status"] == "healthy"
            && target_frontier_exchange["consecutive_failures"] == 0,
        "target frontier repair did not settle after Control evidence replay: \
         {target_frontier_exchange}"
    );

    // This Realm deliberately grants plaintext visibility only to the source
    // service while retaining a routed member on the target Station. Restart
    // the source so the proactive worker takes a fresh two-Station snapshot;
    // the peer-relative visibility difference must finish as success/reset,
    // never as a raw-root mismatch failure or peer_stale.
    group.server_mut(0).restart_external_process().await?;
    let frontier_exchange = wait_for_frontier_exchange_success(
        &source_database_url,
        &realm_id,
        group.server(1).service_id(),
    )
    .await?;
    ensure!(
        frontier_exchange["status"] == "healthy"
            && frontier_exchange["consecutive_failures"] == 0
            && frontier_exchange["last_success_at"].is_number(),
        "peer-relative frontier exchange did not settle as success/reset: {frontier_exchange}"
    );
    eprintln!("live frontier matrix: peer-relative visibility passed");

    // The remaining delivery/recovery matrix uses a Realm that deliberately
    // discloses plaintext to both Stations. Keep it separate from the
    // visibility-scope case above so a legitimate scope difference cannot
    // accidentally turn a recovery assertion into a no-op.
    let baseline_bootstrap = alice
        .create_realm_bootstrap_with(json!({
            "title": "Frontier delivery baseline",
            "summary": "Frontier delivery baseline",
            "public": false,
            "plaintext_visible_services": [
                group.server(0).service_id(),
                group.server(1).service_id()
            ]
        }))
        .await?;
    let baseline_realm_id = baseline_bootstrap["realm_id"]
        .as_str()
        .context("baseline bootstrap realm_id")?
        .to_owned();
    let baseline_bootstrap_outcome: EventsSubmitOutcome =
        serde_json::from_value(baseline_bootstrap["event_response"].clone())?;
    let baseline_bootstrap_events =
        resolve_events(&alice, baseline_bootstrap_outcome.accepted.clone()).await?;
    install_fixture_events(
        group.server(1),
        &baseline_bootstrap_events,
        &baseline_bootstrap_outcome.control_proposal_acks,
    )
    .await?;
    wait_for_bootstrap_seal(&alice, &baseline_realm_id).await?;
    let baseline_join_id = submit_and_settle_member_transition(
        &alice,
        &baseline_realm_id,
        member_payload(
            &baseline_realm_id,
            &bob_did,
            group.server(1).service_id().clone(),
            MembershipPayloadState::Join,
        )?,
    )
    .await?;
    wait_for_target_state(
        &alice,
        &baseline_join_id,
        EventDeliveryTargetState::Delivered,
    )
    .await?;
    let mut bob = group.server(1).demo_client(&bob_did, BOB_DEVICE).await?;
    wait_for_resolved_event(&bob, &alice, &baseline_join_id).await?;
    let baseline_strand_id = alice.create_default_strand(&baseline_realm_id).await?;

    // Outcome-loss duplicate: first complete a real delivery, then stop the
    // source and roll back only its terminal outbox bookkeeping. The target
    // retains the committed Event. On restart the byte-identical request must
    // receive a top-level duplicate outcome, and only that exact per-item
    // confirmation may complete the source intent again.
    let duplicate_submit = alice
        .send_message(
            &baseline_realm_id,
            &baseline_strand_id,
            "outcome loss duplicate",
        )
        .await?;
    let duplicate_event_id = crate::harness::submitted_event_id(&duplicate_submit)?;
    wait_for_target_state(
        &alice,
        &duplicate_event_id,
        EventDeliveryTargetState::Delivered,
    )
    .await?;
    wait_for_resolved_event(&bob, &alice, &duplicate_event_id).await?;
    let duplicate_delivered = durable_fanout_intent(
        &source_database_url,
        &baseline_realm_id,
        &duplicate_event_id,
        group.server(1).service_id(),
    )
    .await?;
    ensure!(duplicate_delivered["state"] == "delivered");
    group.server_mut(0).stop_external_process().await?;
    rewind_delivered_fanout_intent_for_outcome_loss(
        &source_database_url,
        &baseline_realm_id,
        &duplicate_event_id,
        group.server(1).service_id(),
    )
    .await?;
    group.server_mut(0).start_external_process().await?;
    wait_for_target_state(
        &alice,
        &duplicate_event_id,
        EventDeliveryTargetState::Delivered,
    )
    .await?;
    let duplicate_recovered = durable_fanout_intent(
        &source_database_url,
        &baseline_realm_id,
        &duplicate_event_id,
        group.server(1).service_id(),
    )
    .await?;
    assert_outcome_loss_duplicate(
        &duplicate_delivered,
        &duplicate_recovered,
        &duplicate_event_id,
    )?;
    ensure!(
        canonical_event_count(&target_database_url, &duplicate_event_id).await? == 1,
        "duplicate retry created more than one target canonical Event"
    );
    eprintln!("live frontier matrix: outcome-loss duplicate passed");

    // Destination old-backup recovery: snapshot the harness-owned target
    // database, deliver a new Event to both PostgreSQL stores, then restore the
    // target to the older snapshot while the source intent remains delivered.
    // Restarting the unchanged Station identity must permit authorized
    // frontier/resolve backfill; historical delivery state is not retention.
    let backup = if target_database_is_harness_owned {
        group.server_mut(1).stop_external_process().await?;
        let backup = dump_postgres_database(&target_database_url).await?;
        group.server_mut(1).start_external_process().await?;
        Some(backup)
    } else {
        ensure!(
            std::env::var("COTEST_REQUIRE_LIVE").as_deref() != Ok("1"),
            "required live old-backup recovery needs a harness-owned target PostgreSQL"
        );
        eprintln!(
            "skipping destructive old-backup restore on caller-owned COTEST_FANOUT_TARGET_DATABASE_URL"
        );
        None
    };
    if let Some(backup) = backup {
        bob = group.server(1).demo_client(&bob_did, BOB_DEVICE).await?;
        let backup_submit = alice
            .send_message(
                &baseline_realm_id,
                &baseline_strand_id,
                "destination old backup backfill",
            )
            .await?;
        let backup_event_id = crate::harness::submitted_event_id(&backup_submit)?;
        wait_for_target_state(
            &alice,
            &backup_event_id,
            EventDeliveryTargetState::Delivered,
        )
        .await?;
        wait_for_resolved_event(&bob, &alice, &backup_event_id).await?;
        let source_before_restore = durable_fanout_intent(
            &source_database_url,
            &baseline_realm_id,
            &backup_event_id,
            group.server(1).service_id(),
        )
        .await?;
        group.server_mut(1).stop_external_process().await?;
        restore_postgres_database(&target_database_url, &backup).await?;
        ensure!(
            canonical_event_count(&target_database_url, &backup_event_id).await? == 0,
            "restored target backup unexpectedly retained the later Event"
        );
        group.server_mut(1).start_external_process().await?;
        bob = group.server(1).demo_client(&bob_did, BOB_DEVICE).await?;
        wait_for_resolved_event(&bob, &alice, &backup_event_id).await?;
        ensure!(
            canonical_event_count(&target_database_url, &backup_event_id).await? == 1,
            "old-backup frontier recovery did not restore exactly one canonical Event"
        );
        let source_after_restore = durable_fanout_intent(
            &source_database_url,
            &baseline_realm_id,
            &backup_event_id,
            group.server(1).service_id(),
        )
        .await?;
        ensure!(
            source_before_restore == source_after_restore
                && source_after_restore["state"] == "delivered",
            "destination restore reopened or mutated the source delivery intent"
        );
        eprintln!("live frontier matrix: destination old-backup recovery passed");
    }

    // Local page-budget exhaustion: install a valid 405-Event actor chain only
    // on the source while the target is stopped. Soland peers clamp scan pages
    // to 100 rows, so four pages leave a continuation point. A durable
    // checkpoint with a cursor proves the scan hit its local page bound; the
    // exchange must remain healthy with zero failures and no peer blame.
    // Dependency closure may still admit Events outside those scan pages, so
    // Event presence is deliberately not used as a proxy for scan work.
    group.server_mut(1).stop_external_process().await?;
    clear_frontier_checkpoint(
        &target_database_url,
        &baseline_realm_id,
        group.server(0).service_id(),
    )
    .await?;
    let budget_event_ids = install_frontier_budget_events(
        &alice,
        group.server(0),
        &baseline_realm_id,
        &baseline_strand_id,
        405,
    )
    .await?;
    mark_fanout_intent_delivered_without_transport(
        &source_database_url,
        &baseline_realm_id,
        budget_event_ids.first().context("budget Event head")?,
        group.server(1).service_id(),
    )
    .await?;
    ensure!(
        canonical_event_count(
            &target_database_url,
            budget_event_ids.last().context("budget Event tail")?,
        )
        .await?
            == 0,
        "target old view already contained the budget tail Event"
    );
    group.server_mut(1).start_external_process().await?;
    let checkpoint = wait_for_frontier_checkpoint(
        &target_database_url,
        &baseline_realm_id,
        group.server(0).service_id(),
    )
    .await?;
    ensure!(
        checkpoint["cursor"].is_string(),
        "bounded frontier pass did not persist a continuation cursor: {checkpoint}"
    );
    let budget_after = frontier_exchange_snapshot(
        &target_database_url,
        &baseline_realm_id,
        group.server(0).service_id(),
    )
    .await?;
    ensure!(
        budget_after["status"] == "healthy"
            && budget_after["consecutive_failures"] == 0
            && budget_after["last_error"].is_null(),
        "local frontier page budget was charged to the peer: {budget_after}"
    );
    eprintln!("live frontier matrix: local budget exhaustion without peer blame passed");
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

/// Live two-Station cold-recipient path. This intentionally uses the same
/// mutually wired Soland processes and accepted Realm/member/device state as
/// durable federation tests; no signer evidence is injected into the
/// recipient before it calls the self proxy.
pub async fn run_current_signer_evidence_live() -> Result<()> {
    let (source_database_url, _source_ephemeral) = match std::env::var(
        "COTEST_CURRENT_SIGNER_SOURCE_DATABASE_URL",
    ) {
        Ok(url) if !url.trim().is_empty() => (url, None),
        _ => {
            let source_ephemeral =
                crate::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres()?;
            let Some(database) = source_ephemeral.as_ref() else {
                ensure!(
                    std::env::var("COTEST_REQUIRE_LIVE").as_deref() != Ok("1"),
                    "required live current-signer evidence: source PostgreSQL unavailable"
                );
                eprintln!(
                    "skipping current-signer evidence live E2E: source PostgreSQL is unavailable"
                );
                return Ok(());
            };
            (database.connect_url.clone(), source_ephemeral)
        }
    };
    let (target_database_url, _target_ephemeral) = match std::env::var(
        "COTEST_CURRENT_SIGNER_TARGET_DATABASE_URL",
    ) {
        Ok(url) if !url.trim().is_empty() => (url, None),
        _ => {
            let target_ephemeral =
                crate::scenarios::_helpers::coauth_bootstrap::spawn_ephemeral_postgres()?;
            let Some(database) = target_ephemeral.as_ref() else {
                ensure!(
                    std::env::var("COTEST_REQUIRE_LIVE").as_deref() != Ok("1"),
                    "required live current-signer evidence: target PostgreSQL unavailable"
                );
                eprintln!(
                    "skipping current-signer evidence live E2E: target PostgreSQL is unavailable"
                );
                return Ok(());
            };
            (database.connect_url.clone(), target_ephemeral)
        }
    };
    let node_envs = vec![
        vec![
            ("DATABASE_URL".to_owned(), source_database_url),
            ("SOLAND_FEDERATION_OUTBOUND".to_owned(), "1".to_owned()),
            (
                "SOLAND_ACCOUNT_AUTHORITY_URL".to_owned(),
                HARNESS_ACCOUNT_AUTHORITY_ORIGIN.to_owned(),
            ),
        ],
        vec![
            ("DATABASE_URL".to_owned(), target_database_url),
            ("SOLAND_FEDERATION_OUTBOUND".to_owned(), "1".to_owned()),
            (
                "SOLAND_ACCOUNT_AUTHORITY_URL".to_owned(),
                HARNESS_ACCOUNT_AUTHORITY_ORIGIN.to_owned(),
            ),
        ],
    ];
    let Some(mut group) =
        TestServerGroup::try_multi_external_with_node_envs("current-signer-evidence", &node_envs)
            .await?
    else {
        ensure!(
            std::env::var("COTEST_REQUIRE_LIVE").as_deref() != Ok("1"),
            "required live current-signer evidence: prebuilt Soland unavailable"
        );
        eprintln!("skipping current-signer evidence live E2E: prebuilt Soland is unavailable");
        return Ok(());
    };

    let alice_did = actor_did_for_service_did(group.server(0).service_did(), "evidence-alice")?;
    let bob_did = actor_did_for_service_did(group.server(1).service_did(), "evidence-bob")?;
    let alice = group
        .server(0)
        .register_client(&alice_did, "evidence-alice", ALICE_DEVICE)
        .await?;
    let bob = group
        .server(1)
        .register_client(&bob_did, "evidence-bob", BOB_DEVICE)
        .await?;
    let alice_principal = alice.principal.as_ref().context("source PCR bootstrap")?;
    let bob_principal = bob.principal.as_ref().context("recipient PCR bootstrap")?;
    let alice_account = AccountId::new(
        alice_principal.core_id.clone(),
        group.server(0).service_id().clone(),
    );
    let bob_account = AccountId::new(
        bob_principal.core_id.clone(),
        group.server(1).service_id().clone(),
    );

    let bootstrap = alice
        .create_realm_bootstrap_with(json!({
            "title": "Current signer evidence",
            "summary": "Cold recipient evidence",
            "public": false,
            "plaintext_visible_services": [alice.service_id()]
        }))
        .await?;
    let realm_id = bootstrap["realm_id"]
        .as_str()
        .context("evidence bootstrap realm_id")?
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
    wait_for_bootstrap_seal(&alice, &realm_id).await?;
    let bob_join = member_payload(
        &realm_id,
        &bob_did,
        group.server(1).service_id().clone(),
        MembershipPayloadState::Join,
    )?;
    let bob_join_id = submit_and_settle_member_transition(&alice, &realm_id, bob_join).await?;
    // The external-process harness deliberately runs federation workers on
    // their startup recovery path. Restart the authority after the durable
    // join intent is committed so the cold-recipient test exercises the same
    // real outbox replay path as the fanout durability scenarios.
    group.server_mut(0).restart_external_process().await?;
    wait_for_resolved_event(&bob, &alice, &bob_join_id).await?;

    let envelope = cold_signal_envelope(
        RealmId::new(realm_id)?,
        ActorId::account(alice_account.clone()),
        alice_principal.device_id.clone(),
        DidUrl::new(format!(
            "{}#{}",
            alice_principal.did, alice_principal.device_id
        ))
        .map_err(anyhow::Error::msg)?,
    )?;
    let request = SignerKeysQueryRequestBody {
        request_id: RequestId::new("ak:request:019b0000-0000-7000-8000-000000000101")?,
        realm_id: envelope.realm_id.clone(),
        recipient_account_id: bob_account.clone(),
        queries: vec![SignerKeyQuerySelector::CurrentAccountDevice(
            CurrentAccountDeviceSelector {
                verification_mode: CurrentAdmissionMode::CurrentAdmission,
                sender_kind: AccountDeviceSenderKind::AccountDevice,
                actor: envelope.sender_actor_id.clone(),
                device_id: alice_principal.device_id.clone(),
                verification_method: envelope.proof.verification_method.clone(),
            },
        )],
    };
    request.validate()?;

    // The only acquisition is Bob@Station-B -> self proxy -> peer authority
    // Station-A. Bob has never queried or cached Alice's signer beforehand.
    let outcome = bob.sdk().signer_keys_query(&request).await?;
    outcome.validate_for_request(&request)?;
    ensure!(
        outcome.results.len() == 1,
        "cold sender omitted its current result"
    );
    let SignerKeyQueryOutcome::Current(CurrentSignerKeyOutcome { selector, key, .. }) =
        &outcome.results[0]
    else {
        bail!("origin Station did not resolve the current sender");
    };
    ensure!(selector == &request.queries[0]);
    ensure!(selector.actor() == &envelope.sender_actor_id);
    ensure!(selector.verification_method() == &envelope.proof.verification_method);
    // The self result is the recipient Station's authority decision. Actual
    // producer signatures still require this exact key, without replaying its
    // peer attestation or governance dependency closure on the client.
    key.validate()?;

    let mut wrong_station = request.clone();
    wrong_station.request_id = RequestId::new("ak:request:019b0000-0000-7000-8000-000000000102")?;
    let SignerKeyQuerySelector::CurrentAccountDevice(CurrentAccountDeviceSelector {
        actor, ..
    }) = &mut wrong_station.queries[0]
    else {
        unreachable!()
    };
    let ActorId::Account { account_id } = actor else {
        unreachable!("account-device selector keeps an account ActorId");
    };
    account_id.station_id = group.server(1).service_id().clone();
    let wrong_outcome = bob.sdk().signer_keys_query(&wrong_station).await?;
    wrong_outcome.validate_for_request(&wrong_station)?;
    ensure!(
        matches!(
            &wrong_outcome.results[0],
            SignerKeyQueryOutcome::Unavailable(_)
        ),
        "wrong authority Station did not return unavailable"
    );
    let mut misbound = outcome.clone();
    let SignerKeyQueryOutcome::Current(CurrentSignerKeyOutcome {
        selector: SignerKeyQuerySelector::CurrentAccountDevice(selector), ..
    }) = &mut misbound.results[0]
    else {
        unreachable!();
    };
    selector.actor = ActorId::account(bob_account);
    ensure!(
        misbound.validate_for_request(&request).is_err(),
        "current key for another Actor remained usable"
    );
    Ok(())
}

fn cold_signal_envelope(
    realm_id: RealmId,
    sender_actor_id: ActorId,
    sender_device_id: arkret_wire::DeviceId,
    verification_method: DidUrl,
) -> Result<SignalEnvelope> {
    let sent_at = Utc::now();
    let mut envelope = SignalEnvelope {
        realm_id: realm_id.clone(),
        scope_ref: ScopeRef::Realm { realm_id },
        sender_actor_id,
        sender_device_id: Some(sender_device_id),
        seal_ref: SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64)))?,
        signal_class: SignalClass::Session,
        sent_at,
        expires_at: sent_at + chrono::Duration::seconds(30),
        encrypted_payload: SignalEncryptedPayload {
            scheme: arkret_wire::SIGNAL_AEAD_SCHEME.to_owned(),
            key_ref: SignalKeyRef {
                algorithm: "MLS-EXPORTER-AEAD".to_owned(),
                group_state_ref: crate::fixture_event_id("cold-signal-group-state").to_string(),
            },
            purpose: arkret_wire::SIGNAL_AEAD_PURPOSE.to_owned(),
            aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
            epoch: 1,
            nonce: "AAAAAAAAAAAAAAAA".to_owned(),
            ciphertext: "Q29sZFJlY2lwaWVudEV2aWRlbmNl".to_owned(),
            aad_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
        },
        proof: SignalProof {
            kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
            verification_method,
            envelope_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            domain: None,
            audience: None,
            jws: "a..b".to_owned(),
        },
    };
    envelope.encrypted_payload.aad_digest = envelope.expected_aad_digest()?;
    envelope.proof.envelope_digest = envelope.envelope_digest()?;
    envelope.validate_structural()?;
    Ok(envelope)
}

async fn wait_for_frontier_exchange_success(
    database_url: &str,
    realm_id: &str,
    peer_id: &DidCoreId,
) -> Result<serde_json::Value> {
    let database_url = database_url.to_owned();
    let realm_id = realm_id.to_owned();
    let peer_id = peer_id.to_string();
    tokio::task::spawn_blocking(move || -> Result<serde_json::Value> {
        let mut client = postgres::Client::connect(&database_url, postgres::NoTls)?;
        let deadline = std::time::Instant::now() + Duration::from_secs(90);
        loop {
            if let Some(row) = client.query_opt(
                "SELECT status, consecutive_failures, last_success_at, last_frontier_root, last_error \
                 FROM federation_frontier_exchange WHERE realm_id = $1 AND peer_id = $2",
                &[&realm_id, &peer_id],
            )? {
                let status: String = row.get(0);
                let consecutive_failures: i32 = row.get(1);
                let last_success_at: Option<i64> = row.get(2);
                let last_frontier_root: Option<String> = row.get(3);
                let last_error: Option<String> = row.get(4);
                let snapshot = json!({
                    "status": status,
                    "consecutive_failures": consecutive_failures,
                    "last_success_at": last_success_at,
                    "last_frontier_root": last_frontier_root,
                    "last_error": last_error,
                });
                if status == "healthy" && consecutive_failures == 0 && last_success_at.is_some() {
                    return Ok(snapshot);
                }
                if std::time::Instant::now() >= deadline {
                    bail!("frontier exchange did not recover before deadline: {snapshot}");
                }
            } else if std::time::Instant::now() >= deadline {
                bail!(
                    "frontier exchange row was not created for Realm {realm_id} and peer {peer_id}"
                );
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    })
    .await?
}

async fn wait_for_frontier_exchange_error(
    database_url: &str,
    realm_id: &str,
    peer_id: &DidCoreId,
    expected_error: &str,
) -> Result<serde_json::Value> {
    let database_url = database_url.to_owned();
    let realm_id = realm_id.to_owned();
    let peer_id = peer_id.to_string();
    let expected_error = expected_error.to_owned();
    tokio::task::spawn_blocking(move || -> Result<serde_json::Value> {
        let mut client = postgres::Client::connect(&database_url, postgres::NoTls)?;
        let deadline = std::time::Instant::now() + Duration::from_secs(90);
        loop {
            if let Some(row) = client.query_opt(
                "SELECT status, consecutive_failures, last_success_at, last_frontier_root, last_error \
                 FROM federation_frontier_exchange WHERE realm_id = $1 AND peer_id = $2",
                &[&realm_id, &peer_id],
            )? {
                let snapshot = json!({
                    "status": row.get::<_, String>(0),
                    "consecutive_failures": row.get::<_, i32>(1),
                    "last_success_at": row.get::<_, Option<i64>>(2),
                    "last_frontier_root": row.get::<_, Option<String>>(3),
                    "last_error": row.get::<_, Option<String>>(4),
                });
                if snapshot["last_error"].as_str() == Some(expected_error.as_str())
                    && snapshot["consecutive_failures"].as_i64().unwrap_or_default() >= 1
                {
                    return Ok(snapshot);
                }
                if std::time::Instant::now() >= deadline {
                    bail!(
                        "frontier exchange did not expose {expected_error} before deadline: {snapshot}"
                    );
                }
            } else if std::time::Instant::now() >= deadline {
                bail!(
                    "frontier exchange row was not created for revoked Realm {realm_id} and peer {peer_id}"
                );
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    })
    .await?
}

async fn frontier_exchange_snapshot(
    database_url: &str,
    realm_id: &str,
    peer_id: &DidCoreId,
) -> Result<serde_json::Value> {
    let database_url = database_url.to_owned();
    let realm_id = realm_id.to_owned();
    let peer_id = peer_id.to_string();
    tokio::task::spawn_blocking(move || -> Result<serde_json::Value> {
        let mut client = postgres::Client::connect(&database_url, postgres::NoTls)?;
        let row = client
            .query_opt(
                "SELECT status, consecutive_failures, last_success_at, last_frontier_root, last_error \
                 FROM federation_frontier_exchange WHERE realm_id = $1 AND peer_id = $2",
                &[&realm_id, &peer_id],
            )?
            .context("frontier exchange baseline row")?;
        Ok(json!({
            "status": row.get::<_, String>(0),
            "consecutive_failures": row.get::<_, i32>(1),
            "last_success_at": row.get::<_, Option<i64>>(2),
            "last_frontier_root": row.get::<_, Option<String>>(3),
            "last_error": row.get::<_, Option<String>>(4),
        }))
    })
    .await?
}

async fn clear_frontier_checkpoint(
    database_url: &str,
    realm_id: &str,
    peer_id: &DidCoreId,
) -> Result<()> {
    let database_url = database_url.to_owned();
    let realm_id = realm_id.to_owned();
    let peer_id = peer_id.to_string();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut client = postgres::Client::connect(&database_url, postgres::NoTls)?;
        client.execute(
            "DELETE FROM federation_frontier_reduction_checkpoint \
             WHERE realm_id = $1 AND peer_id = $2",
            &[&realm_id, &peer_id],
        )?;
        Ok(())
    })
    .await?
}

async fn wait_for_frontier_checkpoint(
    database_url: &str,
    realm_id: &str,
    peer_id: &DidCoreId,
) -> Result<serde_json::Value> {
    let database_url = database_url.to_owned();
    let realm_id = realm_id.to_owned();
    let peer_id = peer_id.to_string();
    tokio::task::spawn_blocking(move || -> Result<serde_json::Value> {
        let mut client = postgres::Client::connect(&database_url, postgres::NoTls)?;
        // Four peer pages can contain 400 signed Events. On debug Windows
        // builds, receiver-side signature, dependency, and admission checks
        // can legitimately exceed two minutes. The checkpoint must only
        // become durable after that whole chunk commits, so keep the live
        // harness patient instead of weakening the commit-before-cursor rule.
        let deadline = std::time::Instant::now() + Duration::from_secs(600);
        loop {
            if let Some(row) = client.query_opt(
                "SELECT remote_snapshot_digest, actor_set_digest, actor_id, cursor, updated_at \
                 FROM federation_frontier_reduction_checkpoint \
                 WHERE realm_id = $1 AND peer_id = $2",
                &[&realm_id, &peer_id],
            )? {
                return Ok(json!({
                    "remote_snapshot_digest": row.get::<_, String>(0),
                    "actor_set_digest": row.get::<_, String>(1),
                    "actor_id": row.get::<_, String>(2),
                    "cursor": row.get::<_, Option<String>>(3),
                    "updated_at": row.get::<_, i64>(4),
                }));
            }
            if std::time::Instant::now() >= deadline {
                bail!(
                    "bounded frontier pass did not persist a checkpoint for Realm {realm_id} and peer {peer_id}"
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    })
    .await?
}

async fn rewind_delivered_fanout_intent_for_outcome_loss(
    database_url: &str,
    realm_id: &str,
    source_event_id: &EventId,
    peer_id: &DidCoreId,
) -> Result<()> {
    let database_url = database_url.to_owned();
    let realm_id = realm_id.to_owned();
    let source_event_id = source_event_id.to_string();
    let peer_id = peer_id.to_string();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut client = postgres::Client::connect(&database_url, postgres::NoTls)?;
        let next_attempt_at = chrono::Utc::now().timestamp();
        let updated = client.execute(
            "UPDATE federation_outbox SET state = 'pending', leased_from_state = NULL, \
             next_attempt_at = $4, last_http_status = NULL, last_error_code = NULL, \
             last_response_excerpt = NULL, lease_owner = NULL, lease_token = NULL, \
             lease_expires_at = NULL, policy_version = NULL, completed_at = NULL \
             WHERE peer_id = $1 AND realm_fanout->>'realm_id' = $2 \
             AND (realm_fanout->'source_event_ids') ? $3 AND state = 'delivered'",
            &[&peer_id, &realm_id, &source_event_id, &next_attempt_at],
        )?;
        ensure!(
            updated == 1,
            "expected one delivered intent for outcome-loss rewind, updated {updated}"
        );
        Ok(())
    })
    .await
    .context("join outcome-loss outbox rewind")?
}

fn assert_outcome_loss_duplicate(
    before: &serde_json::Value,
    after: &serde_json::Value,
    event_id: &EventId,
) -> Result<()> {
    for field in [
        "id",
        "peer_id",
        "peer_url",
        "endpoint",
        "idempotency_key",
        "payload_json",
        "realm_fanout",
        "created_at",
    ] {
        ensure!(
            before[field] == after[field],
            "outcome-loss retry changed frozen outbox field {field}"
        );
    }
    ensure!(
        after["state"] == "delivered"
            && after["completed_at"].is_i64()
            && after["attempts"].as_i64().unwrap_or_default()
                > before["attempts"].as_i64().unwrap_or_default(),
        "outcome-loss retry did not complete through a new attempt: {after}"
    );
    let response: EventsSubmitOutcome = serde_json::from_str(
        after["last_response_excerpt"]
            .as_str()
            .context("duplicate retry response excerpt")?,
    )?;
    ensure!(
        response.duplicate.contains(event_id)
            && !response.accepted.contains(event_id)
            && !response.quarantine.contains(event_id)
            && !response
                .rejections
                .iter()
                .any(|rejection| rejection.id == event_id.as_str()),
        "outcome-loss retry was not completed by a top-level duplicate outcome for the exact Event: {response:?}"
    );
    Ok(())
}

async fn canonical_event_count(database_url: &str, event_id: &EventId) -> Result<i64> {
    let database_url = database_url.to_owned();
    let event_id = event_id.to_string();
    tokio::task::spawn_blocking(move || -> Result<i64> {
        let mut client = postgres::Client::connect(&database_url, postgres::NoTls)?;
        let row = client.query_one(
            "SELECT COUNT(*)::bigint FROM canonical_events WHERE envelope->>'event_id' = $1",
            &[&event_id],
        )?;
        Ok(row.get(0))
    })
    .await?
}

/// A `libpq` client tool with its diagnostic locale pinned to `C`.
///
/// This harness decides whether a restore failure is the benign cross-version
/// `SET transaction_timeout` diagnostic by reading `stderr`. PostgreSQL's client
/// tools translate their messages, so on a localized developer machine that same
/// benign failure arrives in another language and reads as a fatal restore error.
/// Pinning the locale is what makes the text match a contract rather than a
/// property of whoever is running the suite.
fn pg_tool(program: &str) -> Command {
    let mut command = Command::new(program);
    command
        .env("LC_ALL", "C")
        .env("LC_MESSAGES", "C")
        .env("LANG", "C");
    command
}

struct PostgresBackup {
    _directory: tempfile::TempDir,
    path: PathBuf,
}

async fn dump_postgres_database(database_url: &str) -> Result<PostgresBackup> {
    let database_url = database_url.to_owned();
    tokio::task::spawn_blocking(move || -> Result<PostgresBackup> {
        let directory = tempfile::tempdir().context("create PostgreSQL backup directory")?;
        let path = directory.path().join("target-old-backup.dump");
        let output = pg_tool("pg_dump")
            .arg("--format=custom")
            .arg("--no-owner")
            .arg("--no-privileges")
            .arg("--file")
            .arg(&path)
            .arg(&database_url)
            .output()
            .context("run pg_dump for target old-backup fixture")?;
        ensure!(
            output.status.success(),
            "pg_dump failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(PostgresBackup {
            _directory: directory,
            path,
        })
    })
    .await?
}

async fn restore_postgres_database(database_url: &str, backup: &PostgresBackup) -> Result<()> {
    let database_url = database_url.to_owned();
    let backup_path = backup.path.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let output = pg_tool("pg_restore")
            .arg("--clean")
            .arg("--if-exists")
            .arg("--no-owner")
            .arg("--no-privileges")
            .arg("--dbname")
            .arg(&database_url)
            .arg(&backup_path)
            .output()
            .context("run pg_restore for target old-backup fixture")?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        // A newer pg_dump archive starts with `SET transaction_timeout = 0`.
        // PostgreSQL 16 does not know that PostgreSQL 17+ session setting, but
        // omitting the zero-timeout SET does not change any restored data or
        // schema. Accept only that one cross-version diagnostic; every other
        // restore error remains fatal, and the scenario subsequently verifies
        // the restored canonical state through Soland. The match below is only
        // sound because `pg_tool` pins the diagnostic locale.
        let transaction_timeout_only = !output.status.success()
            && stderr.matches("pg_restore: error:").count() == 1
            && stderr.contains("unrecognized configuration parameter \"transaction_timeout\"")
            && stderr.contains("errors ignored on restore: 1");
        ensure!(
            output.status.success() || transaction_timeout_only,
            "pg_restore failed: {}",
            stderr
        );
        Ok(())
    })
    .await?
}

async fn install_frontier_budget_events(
    client: &TestActorClient,
    server: &crate::harness::ArkretServer,
    realm_id: &str,
    strand_id: &str,
    count: usize,
) -> Result<Vec<EventId>> {
    ensure!(
        count > 400,
        "budget fixture must exceed four 100-row peer pages"
    );
    let mut template = client
        .author_event(
            realm_id,
            arkret_wire::event_kind_str::MESSAGE_CREATE,
            crate::harness::message_create_text_payload(strand_id, "frontier budget template")?,
        )
        .await?;
    let first_actor_seq = template.actor_seq;
    let first_prev_refs = template.prev_refs.clone();
    let first_created_at = template.created_at;
    let mut previous = None;
    let mut events = Vec::with_capacity(count);
    for index in 0..count {
        template.actor_seq = first_actor_seq + index as u64;
        template.prev_refs = previous.iter().cloned().collect::<Vec<_>>();
        if index == 0 {
            template.prev_refs = first_prev_refs.clone();
        }
        template.created_at = first_created_at + chrono::Duration::milliseconds(index as i64);
        template.payload = serde_json::from_value(crate::harness::message_create_text_payload(
            strand_id,
            &format!("frontier budget row {index:04}"),
        )?)?;
        crate::harness::refresh_typed_event_proof(&mut template)?;
        previous = Some(template.event_id.clone());
        events.push(template.clone());
    }
    // Every row remains a complete producer-authored portable Event. Fixture
    // installation exercises storage/page behavior and does not add a server
    // acceptance signature.
    for chunk in events.chunks(64) {
        install_fixture_events(server, chunk, &[]).await?;
    }
    Ok(events.into_iter().map(|event| event.event_id).collect())
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

/// Test-only transport fault injection. This changes only the source outbox
/// bookkeeping while the target process is stopped; it never writes Event or
/// admission state on the target. A subsequent target-side appearance of the
/// Event therefore proves frontier repair rather than ordinary push delivery.
async fn mark_fanout_intent_delivered_without_transport(
    database_url: &str,
    realm_id: &str,
    source_event_id: &EventId,
    peer_id: &DidCoreId,
) -> Result<()> {
    let database_url = database_url.to_owned();
    let realm_id = realm_id.to_owned();
    let source_event_id = source_event_id.to_string();
    let peer_id = peer_id.to_string();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut client = postgres::Client::connect(&database_url, postgres::NoTls)?;
        let completed_at = chrono::Utc::now().timestamp_millis();
        let updated = client.execute(
            "UPDATE federation_outbox SET state = 'delivered', leased_from_state = NULL, \
             lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL, completed_at = $4 \
             WHERE peer_id = $1 AND realm_fanout->>'realm_id' = $2 \
             AND (realm_fanout->'source_event_ids') ? $3 \
             AND state IN ('pending', 'pending_route', 'leased')",
            &[&peer_id, &realm_id, &source_event_id, &completed_at],
        )?;
        ensure!(
            updated == 1,
            "expected one unfinished intent for frontier fault injection, updated {updated}"
        );
        Ok(())
    })
    .await
    .context("join frontier outbox fault injection")?
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
