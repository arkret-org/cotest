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
        return skip_or_fail(GROUP, "prebuilt Coland unavailable");
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

/// Registered first admission through authenticated HTTP, with real device proofs.
pub async fn run_registered_watch_audit_live() -> Result<()> {
    run_registered_watch_audit(false).await
}

pub async fn run_registered_watch_audit_peer_live() -> Result<()> {
    run_registered_watch_audit(true).await
}

async fn run_registered_watch_audit(cross_station: bool) -> Result<()> {
    use arkret_models_collaboration::authority_commit::{
        AuditPairedEventUnitKind, AuditPairedEventUnitSubmission, SelfAuthoritySubmitOutcome,
        SelfAuthoritySubmitRequest,
    };
    use arkret_models_collaboration::strand_watch_operations::{
        WatchAuditReadOutcome, WatchAuditReadRequest,
    };
    use arkret_wire::{EventAdmissionSubmission, SemanticRef};
    let scenario = if cross_station {
        "registered-watch-audit-peer-live"
    } else {
        "registered-watch-audit-live"
    };
    let Some(db) = database(scenario)? else {
        return Ok(());
    };
    let peer_db = if cross_station {
        database(scenario)?
    } else {
        None
    };
    if cross_station && peer_db.is_none() {
        return skip_or_fail(scenario, "second PostgreSQL unavailable");
    }
    let coauth = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let mut environments = vec![station_env(&db.connect_url, &coauth)];
    if let Some(peer_db) = &peer_db {
        ensure!(
            db.connect_url != peer_db.connect_url,
            "stations share their database"
        );
        environments.push(station_env(&peer_db.connect_url, &coauth));
    }
    let Some(group) =
        TestServerGroup::try_multi_external_with_node_envs(scenario, &environments).await?
    else {
        return skip_or_fail(scenario, "prebuilt Coland unavailable");
    };
    let station = group.server(0);
    let governor = group.server(usize::from(cross_station));
    let (alice, alice_account) =
        standard_client(station, &coauth, "audit-watch-alice", ALICE_DEVICE).await?;
    let (bob, bob_account) =
        standard_client(station, &coauth, "audit-watch-bob", BOB_DEVICE).await?;
    let owner = if cross_station {
        Some(
            standard_client(
                governor,
                &coauth,
                "audit-watch-governor",
                "ak:device:01904100-0000-7000-8000-000000002363",
            )
            .await?,
        )
    } else {
        None
    };
    let controller = owner.as_ref().map_or(&alice, |owner| &owner.0);
    let services = if cross_station {
        vec![station, governor]
    } else {
        vec![station]
    };
    let realm =
        create_realm_with_join_rule(controller, "Registered watch audit", "public", &services)
            .await?;
    let strand = StrandId::new(controller.default_strand_id(&realm)?)?;
    let watcher = ActorId::account(bob_account.clone());
    let writer = ActorId::account(alice_account.clone());
    let joining = if cross_station {
        vec![
            (&alice, &alice_account, ALICE_DEVICE),
            (&bob, &bob_account, BOB_DEVICE),
        ]
    } else {
        vec![(&bob, &bob_account, BOB_DEVICE)]
    };
    for (index, (joining, joining_account, joining_device)) in joining.into_iter().enumerate() {
        if cross_station {
            crate::scenarios::human_device_producer_live::prepare_join(
                joining,&realm,governor,&format!("ak:request:019b0000-0000-7000-8000-{:012}",2368+index),
                arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent::MemberJoin,
            ).await?;
        }
        let joined = joining
            .author_event(
                &realm,
                EventKind::MemberState.as_str(),
                membership_payload(
                    &realm,
                    joining_account.clone(),
                    MembershipPayloadState::Join,
                    "audited watch member",
                )?,
            )
            .await?;
        submit_and_expect_commit(joining, joining_account, joining_device, &joined).await?;
    }
    grant_realm_actions(
        controller,
        governor,
        &realm,
        &alice_account,
        &[
            "ak.strand.watch.set.others",
            "ak.audit.accessed",
            "ak.realm.notification.audit",
        ],
    )
    .await?;
    grant_realm_actions(
        controller,
        governor,
        &realm,
        &bob_account,
        &["ak.strand.watch.set"],
    )
    .await?;
    let make_read = |audit| WatchAuditReadRequest {
        audit_submission: EventAdmissionSubmission::new(audit),
    };
    let audit = alice.author_event(&realm,EventKind::AuditAccessed.as_str(),serde_json::json!({
        "access_kind":"watch_audit_read","writer_actor_id":writer,"target_actor_id":watcher,
        "target_ref":strand,"purpose":"authorized frozen observation","accessed_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    })).await?;
    let request = make_read(audit.clone());
    let original: WatchAuditReadOutcome = serde_json::from_value(
        expect_json(
            alice
                .post("/_arkret/self/strands/watch/audit-read")
                .json(&request),
            StatusCode::OK,
        )
        .await?,
    )?;
    original
        .validate_for_request(&request, 0)
        .map_err(anyhow::Error::msg)?;
    ensure!(
        matches!(
            original.current,
            StrandWatchCurrentOutcome::NeverWritten { .. }
        ),
        "audit read did not freeze absence"
    );
    expect_api_error(
        bob.post("/_arkret/self/strands/watch/audit-read")
            .json(&request),
        StatusCode::NOT_FOUND,
        "not_found",
    )
    .await?;

    let payload =
        StrandWatchSetPayload::set(strand.clone(), watcher.clone(), StrandWatchLevel::All, None);
    let business = event(&alice, &realm, &payload).await?;
    let mut paired_audit=alice.author_event(&realm,EventKind::AuditAccessed.as_str(),serde_json::json!({
        "access_kind":"watch_set_others","writer_actor_id":writer,"target_actor_id":watcher,
        "target_ref":strand,"paired_event_id":business.event_id,"purpose":"authorized other watcher write",
        "accessed_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    })).await?;
    paired_audit.semantic_refs.push(SemanticRef::new(
        business.event_id.to_string(),
        "audit_pair",
    ));
    crate::harness::refresh_typed_event_proof(&mut paired_audit)?;
    let unit = AuditPairedEventUnitSubmission {
        unit_kind: AuditPairedEventUnitKind::AuditPairedEvent,
        events: [
            EventAdmissionSubmission::new(business.clone()),
            EventAdmissionSubmission::new(paired_audit.clone()),
        ],
    };
    unit.validate().map_err(anyhow::Error::msg)?;
    let body = SelfAuthoritySubmitRequest::AuditPairedEvent(unit.clone());
    let accepted: SelfAuthoritySubmitOutcome = serde_json::from_value(
        expect_json(
            alice.post("/_arkret/self/events").json(&body),
            StatusCode::OK,
        )
        .await?,
    )?;
    let SelfAuthoritySubmitOutcome::AuditPairedEvent(accepted) = accepted else {
        anyhow::bail!("paired HTTP outcome expected")
    };
    accepted
        .validate_for_request(&unit)
        .map_err(anyhow::Error::msg)?;
    if cross_station {
        let database_url = db.connect_url.clone();
        let expected = accepted.commits.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut connection = postgres::Client::connect(&database_url, postgres::NoTls)?;
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            loop {
                if let Some(row) = connection.query_opt(
                    "SELECT canonical_submission FROM registered_audit_replica_units WHERE business_event_id=$1 AND audit_event_id=$2",
                    &[&expected[0].event_ref.as_str(), &expected[1].event_ref.as_str()],
                )? {
                    let bytes: Vec<u8> = row.get(0);
                    let source: arkret_models_collaboration::authority_commit::AuditPairedEventFederationSubmission = serde_json::from_slice(&bytes)?;
                    source.validate().map_err(anyhow::Error::msg)?;
                    ensure!(source.committed_events[0].source_commit == expected[0] && source.committed_events[1].source_commit == expected[1],
                        "atomic replica changed the original source Commits");
                    return Ok(());
                }
                ensure!(std::time::Instant::now() < deadline, "paired source replication never retained its complete atomic fence");
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }).await??;
    }
    let replay: SelfAuthoritySubmitOutcome = serde_json::from_value(
        expect_json(
            alice.post("/_arkret/self/events").json(&body),
            StatusCode::OK,
        )
        .await?,
    )?;
    let SelfAuthoritySubmitOutcome::AuditPairedEvent(replay) = replay else {
        anyhow::bail!("paired HTTP replay expected")
    };
    ensure!(
        replay.commits == accepted.commits,
        "paired replay changed original Commits"
    );
    let frozen: WatchAuditReadOutcome = serde_json::from_value(
        expect_json(
            alice
                .post("/_arkret/self/strands/watch/audit-read")
                .json(&request),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        frozen == original,
        "exact audit retry exposed a later Watch value"
    );
    let own = StrandWatchCurrentRequestBody {
        realm_id: realm.parse()?,
        strand_id: strand.clone(),
        watcher_actor_id: watcher.clone(),
    };
    current(
        read(&bob, &own).await?,
        &accepted.commits[0],
        StrandWatchCurrentValue::Set(StrandWatchExpectedValue {
            level: StrandWatchLevel::All,
            level_public: None,
        }),
    )?;
    let clear = event(
        &bob,
        &realm,
        &StrandWatchSetPayload::clear(strand.clone(), watcher.clone()).with_expected_value(
            StrandWatchCurrentValue::Set(StrandWatchExpectedValue {
                level: StrandWatchLevel::All,
                level_public: None,
            }),
        ),
    )
    .await?;
    submit_and_expect_commit(&bob, &bob_account, BOB_DEVICE, &clear).await?;
    let audit=alice.author_event(&realm,EventKind::AuditAccessed.as_str(),serde_json::json!({
        "access_kind":"watch_audit_read","writer_actor_id":writer,"target_actor_id":watcher,
        "target_ref":strand,"purpose":"authorized cleared observation","accessed_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())
    })).await?;
    let cleared_request = make_read(audit);
    let cleared: WatchAuditReadOutcome = serde_json::from_value(
        expect_json(
            alice
                .post("/_arkret/self/strands/watch/audit-read")
                .json(&cleared_request),
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        matches!(cleared.current,StrandWatchCurrentOutcome::Current { result, .. } if result.value==StrandWatchCurrentValue::Cleared(())),
        "audit erased written null into absence"
    );
    Ok(())
}
