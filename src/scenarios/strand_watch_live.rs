//! Real authority-cut watch CAS and exact private current reads.

use anyhow::{Context as _, Result, ensure};
use arkret_models_collaboration::events_payloads::strand::{
    StrandWatchExpectedValue, StrandWatchLevel, StrandWatchSetPayload,
};
use arkret_models_collaboration::governance::membership_invite::MembershipPayloadState;
use arkret_models_collaboration::strand_watch_operations::{
    StrandWatchCurrentOutcome, StrandWatchCurrentRequestBody, StrandWatchCurrentValue,
};
use arkret_wire::{
    ActorId, AuthorityCommitStatus, AuthoritySubmitOutcome, CommitStreamRef, CommittedEventView,
    Event, EventKind, RealmCommit, RealmId, StrandId,
};
use reqwest::StatusCode;

use crate::harness::{TestActorClient, TestServerGroup, expect_api_error, expect_json};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::_helpers::live_gate::skip_or_fail;
use crate::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, database, ensure_never_committed, grant_realm_actions,
    membership_payload, standard_client, station_env, submit_and_expect_commit,
};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;

const GROUP: &str = "strand-watch-current-live";
const ALICE_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002361";
const BOB_DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002362";

async fn read(
    client: &TestActorClient,
    request: &StrandWatchCurrentRequestBody,
) -> Result<StrandWatchCurrentOutcome> {
    let outcome: StrandWatchCurrentOutcome = serde_json::from_value(
        expect_json(
            client
                .post("/_arkret/self/strands/watch/current")
                .json(request),
            StatusCode::OK,
        )
        .await?,
    )?;
    outcome
        .validate_for_request(request)
        .map_err(anyhow::Error::msg)?;
    Ok(outcome)
}

pub async fn signed_snapshot(
    client: &TestActorClient,
    realm: &RealmId,
) -> Result<arkret_wire::RealmStateSnapshot> {
    let http = client.sdk();
    let snapshot = http.realm_state_snapshot_head(realm).await?;
    let signer =
        arkret_identity::verification_method_did(snapshot.signature.verification_method.as_str())?;
    let service = arkret_wire::project_did_to_core_id(&signer)?;
    let described = http.describe().await?;
    ensure!(
        service == described.service_id,
        "snapshot signer differs from the serving governing Station"
    );
    let resolution = http.open_service_resolution(&service).await?;
    let document = arkret_identity::authenticated_service_document_at(
        &resolution,
        &service,
        snapshot.signature.created_at,
    )?;
    arkret_identity::validate_verification_method_relationship(
        &document,
        &snapshot.signature.verification_method,
        &signer,
        arkret_identity::DidVerificationRelationship::AssertionMethod,
    )?;
    let key = arkret_identity::resolve_verification_method_key_from_document(
        &document,
        snapshot.signature.verification_method.as_str(),
    )?
    .public_key;
    let unsigned = arkret_canonical::unsigned_value(&snapshot, &["signature"])?;
    arkret_signatures::detached_object::verify_detached_object_signature(
        &snapshot.signature,
        &unsigned,
        arkret_wire::DetachedSignatureContext::RealmSnapshot,
        &key,
    )?;
    Ok(snapshot)
}

fn current(
    outcome: StrandWatchCurrentOutcome,
    commit: &RealmCommit,
    value: StrandWatchCurrentValue,
) -> Result<()> {
    let StrandWatchCurrentOutcome::Current {
        result,
        stream_head,
        ..
    } = outcome
    else {
        anyhow::bail!("written cell returned never_written");
    };
    ensure!(
        result.value == value
            && result.revision.commit_id == commit.commit_id
            && result.revision.stream_position == commit.stream_position,
        "exact watch value/revision differs from accepted Commit"
    );
    ensure!(
        stream_head.stream_position >= commit.stream_position,
        "read head predates watch"
    );
    Ok(())
}

async fn event(
    client: &TestActorClient,
    realm: &str,
    payload: &StrandWatchSetPayload,
) -> Result<Event> {
    client
        .author_event(
            realm,
            EventKind::StrandWatchSet.as_str(),
            payload.to_value()?,
        )
        .await
}

async fn refused(
    client: &TestActorClient,
    event: &Event,
    status: StatusCode,
    code: &str,
) -> Result<()> {
    let body = crate::publication::initial_submission(event.clone(), "")?;
    expect_api_error(
        client.post("/_arkret/self/events").json(&body),
        status,
        code,
    )
    .await?;
    ensure_never_committed(
        client,
        &event.event_id,
        std::time::Duration::from_millis(600),
    )
    .await
}

pub async fn run_strand_watch_current_live() -> Result<()> {
    let Some(db) = database(GROUP)? else {
        return Ok(());
    };
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let Some(group) = TestServerGroup::try_multi_external_with_node_envs(
        GROUP,
        &[station_env(&db.connect_url, &coauth)],
    )
    .await?
    else {
        return skip_or_fail(GROUP, "prebuilt Soland unavailable");
    };
    let station = group.server(0);
    let (alice, alice_account) =
        standard_client(station, &coauth, "watch-alice", ALICE_DEVICE).await?;
    let (bob, bob_account) = standard_client(station, &coauth, "watch-bob", BOB_DEVICE).await?;
    let realm =
        create_realm_with_join_rule(&alice, "Watch current CAS", "public", &[station]).await?;
    let strand = StrandId::new(alice.default_strand_id(&realm)?)?;
    let request = StrandWatchCurrentRequestBody {
        realm_id: RealmId::new(realm.clone())?,
        strand_id: strand.clone(),
        watcher_actor_id: ActorId::account(alice_account.clone()),
    };
    ensure!(
        matches!(
            read(&alice, &request).await?,
            StrandWatchCurrentOutcome::NeverWritten { .. }
        ),
        "fresh selector is not explicitly never_written"
    );
    let premature_null = StrandWatchSetPayload::set(
        strand.clone(),
        request.watcher_actor_id.clone(),
        StrandWatchLevel::All,
        None,
    )
    .with_expected_value(StrandWatchCurrentValue::Cleared(()));
    refused(
        &alice,
        &event(&alice, &realm, &premature_null).await?,
        StatusCode::CONFLICT,
        "failed_precondition",
    )
    .await?;
    ensure!(
        matches!(
            read(&alice, &request).await?,
            StrandWatchCurrentOutcome::NeverWritten { .. }
        ),
        "failed explicit-null CAS materialized a never-written cell"
    );
    let wrong_station = StrandWatchCurrentRequestBody {
        watcher_actor_id: ActorId::account(arkret_wire::AccountId::new(
            alice_account.principal_id.clone(),
            bob_account.principal_id.clone(),
        )),
        ..request.clone()
    };
    expect_api_error(
        alice
            .post("/_arkret/self/strands/watch/current")
            .json(&wrong_station),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    let unknown_strand = StrandWatchCurrentRequestBody {
        strand_id: StrandId::new(
            "ak:strand:AUPBmq7QR4lk0rsMlC7RbEozfyVLQip3G8_BtBgsac5q".to_owned(),
        )?,
        ..request.clone()
    };
    expect_api_error(
        alice
            .post("/_arkret/self/strands/watch/current")
            .json(&unknown_strand),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    let other_realm =
        create_realm_with_join_rule(&alice, "Watch foreign strand", "public", &[station]).await?;
    let wrong_realm = StrandWatchCurrentRequestBody {
        realm_id: RealmId::new(other_realm)?,
        ..request.clone()
    };
    expect_api_error(
        alice
            .post("/_arkret/self/strands/watch/current")
            .json(&wrong_realm),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    let join = bob
        .author_event(
            &realm,
            EventKind::MemberState.as_str(),
            membership_payload(
                &realm,
                bob_account.clone(),
                MembershipPayloadState::Join,
                "watch participant",
            )?,
        )
        .await?;
    submit_and_expect_commit(&bob, &bob_account, BOB_DEVICE, &join).await?;
    expect_api_error(
        bob.post("/_arkret/self/strands/watch/current")
            .json(&request),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    let bob_request = StrandWatchCurrentRequestBody {
        watcher_actor_id: ActorId::account(bob_account.clone()),
        ..request.clone()
    };
    expect_api_error(
        alice
            .post("/_arkret/self/strands/watch/current")
            .json(&bob_request),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    let initial = StrandWatchSetPayload::set(
        strand.clone(),
        request.watcher_actor_id.clone(),
        StrandWatchLevel::All,
        Some(true),
    );
    let first_event = event(&alice, &realm, &initial).await?;
    let first =
        submit_and_expect_commit(&alice, &alice_account, ALICE_DEVICE, &first_event).await?;
    let first_value = StrandWatchCurrentValue::Set(StrandWatchExpectedValue {
        level: StrandWatchLevel::All,
        level_public: Some(true),
    });
    current(read(&alice, &request).await?, &first, first_value)?;
    let first_snapshot = signed_snapshot(&alice, &request.realm_id).await?;
    ensure!(first_snapshot.current_state_entries.iter().any(|entry| matches!(entry,
        arkret_wire::TypedCurrentRow::Value { selector: arkret_wire::CurrentSelector::StrandWatch { strand_id, watcher_actor_id }, source_stream_ref, revision, value }
        if strand_id == &request.strand_id && watcher_actor_id == &request.watcher_actor_id
            && source_stream_ref == &first.stream_ref && revision.commit_id == first.commit_id
            && revision.stream_position == first.stream_position && value == &serde_json::json!({"level":"all","level_public":true})
    )), "signed snapshot omitted or changed the registered complete watch current row");

    for payload in [
        initial.clone(),
        initial
            .clone()
            .with_expected_value(StrandWatchCurrentValue::Set(StrandWatchExpectedValue {
                level: StrandWatchLevel::All,
                level_public: None,
            })),
        initial
            .clone()
            .with_expected_value(StrandWatchCurrentValue::Cleared(())),
    ] {
        refused(
            &alice,
            &event(&alice, &realm, &payload).await?,
            StatusCode::CONFLICT,
            "failed_precondition",
        )
        .await?;
        current(read(&alice, &request).await?, &first, first_value)?;
    }
    let clear = StrandWatchSetPayload::clear(strand.clone(), request.watcher_actor_id.clone())
        .with_expected_value(first_value);
    let clear_event = event(&alice, &realm, &clear).await?;
    let cleared =
        submit_and_expect_commit(&alice, &alice_account, ALICE_DEVICE, &clear_event).await?;
    ensure!(
        cleared.stream_position == first.stream_position + 1,
        "refused CAS advanced stream"
    );
    current(
        read(&alice, &request).await?,
        &cleared,
        StrandWatchCurrentValue::Cleared(()),
    )?;
    let body = crate::publication::initial_submission(clear_event.clone(), "")?;
    let replay: AuthoritySubmitOutcome = serde_json::from_value(
        expect_json(
            alice.post("/_arkret/self/events").json(&body),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(replay, AuthoritySubmitOutcome::Accepted { status: AuthorityCommitStatus::Duplicate, commit } if commit == cleared),
        "exact replay changed watch Commit"
    );
    refused(
        &alice,
        &event(&alice, &realm, &initial).await?,
        StatusCode::CONFLICT,
        "failed_precondition",
    )
    .await?;
    let restored_payload = StrandWatchSetPayload::set(
        strand.clone(),
        request.watcher_actor_id.clone(),
        StrandWatchLevel::Muted,
        None,
    )
    .with_expected_value(StrandWatchCurrentValue::Cleared(()));
    let restored_event = event(&alice, &realm, &restored_payload).await?;
    let restored =
        submit_and_expect_commit(&alice, &alice_account, ALICE_DEVICE, &restored_event).await?;
    ensure!(
        restored.stream_position == cleared.stream_position + 1,
        "replay or failed first-write advanced stream"
    );
    current(
        read(&alice, &request).await?,
        &restored,
        StrandWatchCurrentValue::Set(StrandWatchExpectedValue {
            level: StrandWatchLevel::Muted,
            level_public: None,
        }),
    )?;

    let private_scan = bob
        .sdk()
        .scan_commit_stream_to_head(
            request.realm_id.clone(),
            CommitStreamRef::Realm {
                realm_id: request.realm_id.clone(),
            },
            None,
            1000,
        )
        .await?;
    let watch_view = private_scan
        .committed_events
        .iter()
        .find(|view| view.commit().event_ref == restored_event.event_id)
        .context("joined member scan omitted watch Commit")?;
    ensure!(
        matches!(watch_view, CommittedEventView::Withheld(_)) && watch_view.commit() == &restored,
        "ordinary member scan disclosed a private muted watch Event"
    );
    let private_snapshot = signed_snapshot(&bob, &request.realm_id).await?;
    ensure!(!private_snapshot.current_state_entries.iter().any(|entry| matches!(entry,
        arkret_wire::TypedCurrentRow::Value { selector: arkret_wire::CurrentSelector::StrandWatch { strand_id, watcher_actor_id }, .. }
        if strand_id == &request.strand_id && watcher_actor_id == &request.watcher_actor_id
    )), "ordinary member signed snapshot disclosed Alice's private muted watch cell");

    let public_payload = StrandWatchSetPayload::set(
        strand.clone(),
        request.watcher_actor_id.clone(),
        StrandWatchLevel::All,
        Some(true),
    )
    .with_expected_value(StrandWatchCurrentValue::Set(StrandWatchExpectedValue {
        level: StrandWatchLevel::Muted,
        level_public: None,
    }));
    let public_event = event(&alice, &realm, &public_payload).await?;
    submit_and_expect_commit(&alice, &alice_account, ALICE_DEVICE, &public_event).await?;
    let scan = bob
        .sdk()
        .scan_commit_stream_to_head(
            request.realm_id.clone(),
            CommitStreamRef::Realm {
                realm_id: request.realm_id.clone(),
            },
            None,
            1000,
        )
        .await?;
    ensure!(
        scan.committed_events
            .iter()
            .any(|view| view.commit().event_ref == public_event.event_id
                && matches!(view, CommittedEventView::Withheld(_))),
        "public opt-in leaked a private muted CAS preimage"
    );
    let public_snapshot = signed_snapshot(&bob, &request.realm_id).await?;
    ensure!(public_snapshot.current_state_entries.iter().any(|entry| matches!(entry,
        arkret_wire::TypedCurrentRow::Value { selector: arkret_wire::CurrentSelector::StrandWatch { strand_id, watcher_actor_id }, value, .. }
        if strand_id == &request.strand_id && watcher_actor_id == &request.watcher_actor_id
            && value == &serde_json::json!({"level":"all","level_public":true})
    )), "explicit public opt-in was absent from the member snapshot");
    let next_public = StrandWatchSetPayload::set(
        strand.clone(),
        request.watcher_actor_id.clone(),
        StrandWatchLevel::Participating,
        Some(true),
    )
    .with_expected_value(StrandWatchCurrentValue::Set(StrandWatchExpectedValue {
        level: StrandWatchLevel::All,
        level_public: Some(true),
    }));
    let next_public_event = event(&alice, &realm, &next_public).await?;
    submit_and_expect_commit(&alice, &alice_account, ALICE_DEVICE, &next_public_event).await?;
    let scan = bob
        .sdk()
        .scan_commit_stream_to_head(
            request.realm_id.clone(),
            CommitStreamRef::Realm {
                realm_id: request.realm_id.clone(),
            },
            None,
            1000,
        )
        .await?;
    ensure!(
        scan.committed_events
            .iter()
            .any(|view| view.commit().event_ref == next_public_event.event_id
                && matches!(view, CommittedEventView::Full(_))),
        "fully public watch transition was withheld"
    );

    let bob_payload = StrandWatchSetPayload::set(
        strand,
        bob_request.watcher_actor_id.clone(),
        StrandWatchLevel::Participating,
        None,
    );
    let no_grant = event(&bob, &realm, &bob_payload).await?;
    refused(&bob, &no_grant, StatusCode::FORBIDDEN, "capability_denied").await?;
    grant_realm_actions(
        &alice,
        station,
        &realm,
        &bob_account,
        &["ak.strand.watch.set"],
    )
    .await?;
    let bob_event = event(&bob, &realm, &bob_payload).await?;
    let bob_commit = submit_and_expect_commit(&bob, &bob_account, BOB_DEVICE, &bob_event).await?;
    current(
        read(&bob, &bob_request).await?,
        &bob_commit,
        StrandWatchCurrentValue::Set(StrandWatchExpectedValue {
            level: StrandWatchLevel::Participating,
            level_public: None,
        }),
    )?;
    let leave = bob
        .author_event(
            &realm,
            EventKind::MemberState.as_str(),
            membership_payload(
                &realm,
                bob_account.clone(),
                MembershipPayloadState::Leave,
                "watch access revoked",
            )?,
        )
        .await?;
    let leave_commit = submit_and_expect_commit(&bob, &bob_account, BOB_DEVICE, &leave).await?;
    expect_api_error(
        bob.post("/_arkret/self/strands/watch/current")
            .json(&bob_request),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    let revoked_payload =
        bob_payload.with_expected_value(StrandWatchCurrentValue::Set(StrandWatchExpectedValue {
            level: StrandWatchLevel::Participating,
            level_public: None,
        }));
    let revoked_event = event(&bob, &realm, &revoked_payload).await?;
    refused(
        &bob,
        &revoked_event,
        StatusCode::FORBIDDEN,
        "capability_denied",
    )
    .await?;
    let final_payload =
        StrandWatchSetPayload::clear(request.strand_id.clone(), request.watcher_actor_id.clone())
            .with_expected_value(StrandWatchCurrentValue::Set(StrandWatchExpectedValue {
                level: StrandWatchLevel::Participating,
                level_public: Some(true),
            }));
    let final_event = event(&alice, &realm, &final_payload).await?;
    let final_commit =
        submit_and_expect_commit(&alice, &alice_account, ALICE_DEVICE, &final_event).await?;
    ensure!(
        final_commit.stream_position == leave_commit.stream_position + 1,
        "revoked writer advanced the Realm Commit stream"
    );
    current(
        read(&alice, &request).await?,
        &final_commit,
        StrandWatchCurrentValue::Cleared(()),
    )?;
    let visible = alice
        .sdk()
        .committed_event_get(&final_event.event_id)
        .await?;
    ensure!(
        visible.commit() == &final_commit,
        "Alice cannot read the accepted next Commit"
    );
    expect_api_error(
        alice.get(&format!(
            "/_arkret/self/committed-events/{}",
            revoked_event.event_id.as_str()
        )),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;
    Ok(())
}
