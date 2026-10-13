//! Complete SDK Event admission consumed by the real Station and PG reducer.

use anyhow::{Context, Result, ensure};
use arkret_wire::{EventKind, StreamScanDirection, StreamScanRequest};
use garth::{DurableInboxStore as _, OutboundQueueStore as _};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::conformance::{CaseExecutionResult, SuiteExecutionResult};
use crate::harness::{TestActorClient, TestServerGroup, expect_api_error};
use crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores;
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, standard_client, station_env, submit_and_expect_commit,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;

const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000006801";
const NO_REPAIR: &str = "a_rejected_envelope_is_not_repaired_or_partially_applied";

async fn rejected_locally(
    store: &garth::FileStore,
    path: &std::path::Path,
    scope: &garth::CursorScope,
    event: &Value,
    positive: &garth::CommittedDelta,
) -> Result<usize> {
    let before = std::fs::read(path)?;
    let queued = json!({"request": {"event": event}, "event_id": event["event_id"],
        "state": {"state": "queued"}});
    ensure!(
        serde_json::from_value::<garth::QueuedSubmission>(queued).is_err(),
        "reconnect deserialization repaired a rejected Event into a queued submission"
    );
    let mut assertions = 2;
    if let Ok(event) = serde_json::from_value::<arkret_wire::Event>(event.clone()) {
        let mut projection = garth::RealmProjectionState::default();
        projection.apply(positive)?;
        let previous = projection.clone();
        let mut delta = positive.clone();
        if let arkret_wire::CommittedEventView::Full(full) = &mut delta.view {
            full.event = event.clone();
        }
        let error = projection
            .apply(&delta)
            .expect_err("invalid Event reached the real client reducer");
        ensure!(
            error.to_string().contains("schema_violation"),
            "wrong reducer refusal: {error}"
        );
        ensure!(
            projection == previous,
            "refused Event changed the real client projection"
        );
        ensure!(
            garth::QueuedSubmission::new(arkret_wire::AuthoritySubmitRequest::Event(
                arkret_wire::EventAdmissionSubmission::new(event.clone())
            ))
            .is_err(),
            "SDK queue factory accepted an invalid Event"
        );
        let forged = garth::QueuedSubmission {
            request:
                arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest::Event(
                    arkret_wire::EventAdmissionSubmission::new(event.clone()),
                ),
            event_id: event.event_id.clone(),
            state: garth::SubmissionState::Queued,
        };
        ensure!(
            store
                .mutate_outbound(|queue| queue.enqueue(forged, chrono::Utc::now()))
                .await
                .is_err(),
            "invalid Event reached the durable outbound queue"
        );
        ensure!(
            garth::InboundDecoder::new()
                .try_decode_event(event.clone())
                .is_err(),
            "invalid payload fell back to an undecoded Event"
        );
        ensure!(
            store
                .commit(
                    scope.clone(),
                    Some("rejected-cursor".into()),
                    vec![garth::ClientEvent::Event(Box::new(event))]
                )
                .await
                .is_err(),
            "invalid Event advanced the durable inbox or cursor"
        );
        assertions += 6;
    }
    ensure!(
        std::fs::read(path)? == before,
        "schema rejection changed native queue, inbox, cursor, cache or local state bytes"
    );
    Ok(assertions)
}

async fn scan(client: &TestActorClient, realm: &str) -> Result<Value> {
    let request = StreamScanRequest {
        realm_id: arkret_wire::RealmId::new(realm)?,
        stream_ref: arkret_wire::CommitStreamRef::Realm {
            realm_id: arkret_wire::RealmId::new(realm)?,
        },
        direction: StreamScanDirection::After(None),
        limit: 100,
    };
    Ok(serde_json::to_value(
        client.sdk().scan_commit_stream(&request).await?,
    )?)
}

async fn rejected(client: &TestActorClient, event: &Value, url: &str, realm: &str) -> Result<()> {
    let before = acceptance_rows_with_agent_stores(url, true).await?;
    let visible = scan(client, realm).await?;
    expect_api_error(
        client
            .post("/_arkret/self/events")
            .json(&json!({"event": event})),
        StatusCode::UNPROCESSABLE_ENTITY,
        "schema_violation",
    )
    .await?;
    ensure!(
        acceptance_rows_with_agent_stores(url, true).await? == before,
        "schema refusal changed Event, Commit, current, signer cache, Agent or outbox state"
    );
    ensure!(
        scan(client, realm).await? == visible,
        "schema refusal changed the production backfill query"
    );
    Ok(())
}

pub async fn run_sdk_precheck_production() -> Result<SuiteExecutionResult> {
    let (fixture, canonical) = cotest_sdk_precheck_runner::load_fixture_and_base_event()?;
    let database = database("sdk-precheck-production")?.context("real PostgreSQL required")?;
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let mut group = TestServerGroup::try_multi_external_with_node_envs(
        "sdk-precheck-production",
        &[station_env(&database.connect_url, &issuer)],
    )
    .await?
    .context("actual Coland process required")?;
    let (client, account) =
        standard_client(group.server(0), &issuer, "precheck-alice", DEVICE).await?;
    let realm =
        create_realm_with_join_rule(&client, "SDK precheck", "invite", &[group.server(0)]).await?;
    let mut payload = canonical["payload"].clone();
    payload["object"]["realm_id"] = json!(realm);
    payload["object"]["created_by"] = json!(arkret_wire::ActorId::account(account.clone()));
    // Optional references from the static legal fixture are not live authority.
    payload["object"]
        .as_object_mut()
        .context("Strand create object")?
        .remove("strand_id");
    let mut base = client
        .author_event(&realm, EventKind::StrandCreate.as_str(), payload)
        .await?;
    base.payload
        .get_mut("object")
        .and_then(Value::as_object_mut)
        .context("Strand object")?
        .insert("created_at".into(), serde_json::to_value(&base.created_at)?);
    // Canonical Event timestamps retain fixed milliseconds.
    let at = arkret_canonical::format_timestamp_canonical(base.created_at);
    base.payload.get_mut("object").unwrap()["created_at"] = json!(at);
    crate::harness::refresh_typed_event_proof(&mut base)?;
    arkret_event_draft::validate_event_for_submit(&base)?;
    let positive = submit_and_expect_commit(&client, &account, DEVICE, &base).await?;
    let live_base = serde_json::to_value(&base)?;
    let delta = garth::CommittedDelta::from_committed_event_view(
        base.realm_id.clone(),
        arkret_wire::CommittedEventView::Full(arkret_wire::CommittedEventFullView {
            event: base.clone(),
            commit: positive.clone(),
        }),
    )?;
    let native = tempfile::tempdir()?;
    let path = native.path().join("sdk-admission.json");
    let store = garth::FileStore::open(&path)?;
    let scope = garth::CursorScope::CommitStream {
        service_id: Some(account.station_id.clone()),
        stream_ref: positive.stream_ref.clone(),
    };
    let queued = garth::QueuedSubmission::new(arkret_wire::AuthoritySubmitRequest::Event(
        arkret_wire::EventAdmissionSubmission::new(base.clone()),
    ))?;
    store
        .mutate_outbound(|queue| queue.enqueue(queued, chrono::Utc::now()))
        .await?;
    store
        .commit(
            scope.clone(),
            None,
            vec![garth::ClientEvent::Event(Box::new(base.clone()))],
        )
        .await?;
    let mut cases = Vec::new();
    for case in fixture["cases"].as_array().context("canonical cases")? {
        let id = case["name"].as_str().context("canonical case name")?;
        let raw = cotest_sdk_precheck_runner::mutation_for(id, &canonical)?;
        ensure!(
            arkret_event_draft::decode_event_for_submit(raw.clone()).is_err(),
            "SDK raw gate accepted exact canonical mutation {id}"
        );
        // The exact canonical bytes and a context-valid live counterpart cross
        // the same normal HTTP ingress. Neither result is credited statically.
        rejected(&client, &raw, &database.connect_url, &realm).await?;
        let mut live = cotest_sdk_precheck_runner::mutation_for(id, &live_base)?;
        if id == "a_payload_that_fails_its_payload_class_never_reaches_the_reducer" {
            let mut typed: arkret_wire::Event = serde_json::from_value(live)?;
            crate::harness::refresh_typed_event_proof(&mut typed)?;
            live = serde_json::to_value(typed)?;
        }
        rejected(&client, &live, &database.connect_url, &realm).await?;
        let mut assertions = 7
            + rejected_locally(&store, &path, &scope, &raw, &delta).await?
            + rejected_locally(&store, &path, &scope, &live, &delta).await?;
        if id == NO_REPAIR {
            assertions += rejected_locally(&store, &path, &scope, &live, &delta).await?;
            let reopened = garth::FileStore::open(&path)?;
            assertions += rejected_locally(&reopened, &path, &scope, &live, &delta).await?;
            rejected(&client, &live, &database.connect_url, &realm).await?;
            group.server_mut(0).restart_external_process().await?;
            rejected(&client, &live, &database.connect_url, &realm).await?;
            ensure!(
                scan(&client, &realm).await?["committed_events"]
                    .as_array()
                    .context("backfill rows")?
                    .iter()
                    .any(|row| row["commit"]["commit_id"] == json!(positive.commit_id)),
                "reconnect/backfill lost the accepted positive control"
            );
            assertions += 7;
        }
        cases.push(CaseExecutionResult {
            case_id: id.to_owned(),
            assertions,
        });
    }
    Ok(SuiteExecutionResult {
        entrypoint: cotest_sdk_precheck_runner::SDK_PRECHECK_ENTRYPOINT,
        fixture: "sdk-precheck-fixture.json",
        cases,
    })
}
