//! More than one hint page through the unmodified native Realm follower.

use arkret_wire::{ActorId, CommitStreamRef, EventKind, RealmId, StrandId};
use cotest::scenarios::circle_parent_membership_live::grant_circle_actions;
use cotest::scenarios::circle_poll_scope_live::{circle_create, circle_event};
use cotest::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, membership_payload, prepare_join, station_env,
    submit_and_expect_commit, wait_for_committed,
};
use cotest::scenarios::mls_lifecycle_live::Member;
use serde_json::json;

use super::*;

pub async fn run() -> Result<()> {
    cotest::harness::heap_future(|| run_matrix(65)).await
}

pub async fn run_busy_cut() -> Result<()> {
    cotest::harness::heap_future(|| run_matrix(2)).await
}

async fn wait_member_snapshot(
    client: &cotest::harness::TestActorClient,
    realm: &RealmId,
) -> Result<arkret_wire::RealmStateSnapshot> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        match client.sdk().realm_state_snapshot_head(realm).await {
            Ok(snapshot) => {
                let repeated = client.sdk().realm_state_snapshot_head(realm).await?;
                for emitted in [&snapshot, &repeated] {
                    let retained = client
                        .sdk()
                        .realm_state_snapshot_by_ref(realm, &emitted.snapshot_id)
                        .await?;
                    ensure!(
                        arkret_canonical::canonical_json_bytes(&serde_json::to_value(emitted)?)?
                            == arkret_canonical::canonical_json_bytes(&serde_json::to_value(
                                retained
                            )?)?,
                        "a member head must retain its complete exact by-ref original"
                    );
                }
                let same_cut = snapshot.realm_id == repeated.realm_id
                    && snapshot.governance_generation == repeated.governance_generation
                    && snapshot.visible_stream_heads == repeated.visible_stream_heads
                    && snapshot.current_state_entries == repeated.current_state_entries
                    && snapshot.retention_and_history_floor == repeated.retention_and_history_floor
                    && snapshot.signature.verification_method
                        == repeated.signature.verification_method;
                if same_cut {
                    ensure!(
                        snapshot.snapshot_id == repeated.snapshot_id,
                        "an unchanged member cut must reuse its retained original"
                    );
                }
                eprintln!(
                    "[2133-snapshot-ref] exact_roundtrips=2 same_cut_reused={}",
                    usize::from(same_cut)
                );
                ensure!(
                    snapshot
                        .retention_and_history_floor
                        .stream_floors
                        .iter()
                        .filter(|floor| matches!(floor.stream_ref, CommitStreamRef::Circle { .. }))
                        .all(|floor| floor.oldest_position > 0),
                    "the remote member must retain its since-join Circle floors"
                );
                return Ok(snapshot);
            }
            Err(arkret_http_client::Error::Api { status: 503, error })
                if error.error_code()
                    == Some(arkret_wire::ErrorCode::RealmStateSnapshotUnavailable)
                    && tokio::time::Instant::now() < deadline =>
            {
                // Native replica convergence can lag a replicated grant. Wait
                // for the complete cut used by the parent-membership lookup.
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn join_at_parent(
    client: &cotest::harness::TestActorClient,
    realm: &str,
    circle: &arkret_wire::CircleId,
    actor: &ActorId,
    parent: &arkret_wire::CurrentRevision,
) -> Result<()> {
    let join = circle_event(
        client,
        realm,
        circle,
        EventKind::CircleMemberState,
        json!({
            "circle_id":circle,"member_id":actor,"membership":"join",
            "parent_membership_revision":parent,"expected_membership":null
        }),
    )
    .await?;
    cotest::harness::expect_json(
        client
            .post(&format!("/_arkret/self/circles/{circle}/members"))
            .json(
                &arkret_models_collaboration::governance::circle::CircleMemberRequestBody {
                    member_event: arkret_wire::EventAdmissionSubmission::new(join),
                },
            ),
        reqwest::StatusCode::OK,
    )
    .await?;
    Ok(())
}

async fn run_matrix(circle_count: usize) -> Result<()> {
    let beyond_hint_page = circle_count > 64;
    let label = if beyond_hint_page {
        "multistream-native"
    } else {
        "snapshot-busy-native"
    };
    let transcript = if beyond_hint_page {
        "2133-multistream"
    } else {
        "2133-snapshot-busy"
    };
    let initial_streams = circle_count + 1;
    let log_directory = std::env::var_os("COTEST_SERVICE_LOG_DIR").map(std::path::PathBuf::from);
    let _transcript =
        cotest::transcripts::init_transcript_writer(transcript, log_directory.as_deref())?;
    let governance_database =
        database("multistream-governance")?.context("actual PostgreSQL is required")?;
    let member_database =
        database("multistream-account")?.context("independent PostgreSQL is required")?;
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = cotest::harness::TestServerGroup::try_multi_external_with_node_envs(
        label,
        &[
            station_env(&governance_database.connect_url, &issuer),
            station_env(&member_database.connect_url, &issuer),
        ],
    )
    .await?
    .context("two actual Station processes required")?;
    let governor = group.server(0);
    let server = group.server(1);
    let mut alice_member = Member::provision(
        governor,
        &issuer,
        "multistream-alice",
        "ak:device:01904100-0000-7000-8000-000000003301",
    )
    .await?;
    let mut bob_member = Member::provision(
        server,
        &issuer,
        "multistream-bob",
        "ak:device:01904100-0000-7000-8000-000000003302",
    )
    .await?;
    let mut alice = alice_member.client.clone();
    let account_id = alice_member.account.clone();
    let mut bob = bob_member.client.clone();
    let realm = create_realm_with_join_rule(
        &alice,
        "More than 64 independent streams",
        "public",
        &[governor, server],
    )
    .await?;
    let realm_id = RealmId::new(realm.clone())?;
    let actor = ActorId::account(account_id.clone());
    prepare_join(
        &bob,
        &realm,
        governor,
        "ak:request:01904100-0000-7000-8000-000000003303",
        arkret_models_collaboration::governance::realm_join_intake::RealmJoinIntent::MemberJoin,
    )
    .await?;
    let join = bob.author_event(&realm,EventKind::MemberState.as_str(),membership_payload(&realm,
        bob_member.account.clone(),arkret_models_collaboration::governance::membership_invite::MembershipPayloadState::Join,
        "native remote multistream member")?).await?;
    submit_and_expect_commit(&bob, &bob_member.account, &bob.device_id, &join).await?;
    wait_for_committed(&bob, &join.event_id).await?;
    // These exact accepted parent joins remain unchanged throughout the fixture.
    // Each signed Circle command still asks the production server to check them.
    let alice_parent = alice
        .sdk()
        .realm_state_snapshot_head(&realm_id)
        .await?
        .parent_membership_revision(&actor)
        .context("Alice accepted parent join")?;
    let bob_parent = wait_member_snapshot(&bob, &realm_id)
        .await?
        .parent_membership_revision(&bob_member.actor)
        .context("Bob accepted parent join")?;
    let mut last_reissue = tokio::time::Instant::now();
    let mut reissues = 0usize;
    for index in 0..circle_count {
        if last_reissue.elapsed() >= Duration::from_secs(180) {
            alice = governor
                .reissue_mock_native_host_session(&alice, &issuer)
                .await?;
            bob = server
                .reissue_mock_native_host_session(&bob, &issuer)
                .await?;
            alice_member.client = alice.clone();
            bob_member.client = bob.clone();
            last_reissue = tokio::time::Instant::now();
            reissues += 1;
            eprintln!(
                "[2133-multistream-session] distinct_mock_issuer_grant_pairs={reissues} predecessor_expiry_unchanged=1"
            );
        }
        let circle = circle_create(
            &alice,
            &realm,
            &actor,
            &format!("Independent {index}"),
            &format!("Stream-{index}"),
        )
        .await?;
        join_at_parent(&alice, &realm, &circle, &actor, &alice_parent).await?;
        grant_circle_actions(&alice_member, &realm, &circle, &bob_member).await?;
        join_at_parent(&bob, &realm, &circle, &bob_member.actor, &bob_parent).await?;
        if (index + 1) % 10 == 0 {
            eprintln!(
                "[2133-multistream-setup] accepted_circle_joins={}",
                index + 1
            );
        }
    }
    alice = governor
        .reissue_mock_native_host_session(&alice, &issuer)
        .await?;
    bob = server
        .reissue_mock_native_host_session(&bob, &issuer)
        .await?;
    alice_member.client = alice.clone();
    bob_member.client = bob.clone();
    reissues += 1;
    eprintln!(
        "[2133-multistream-session] distinct_mock_issuer_grant_pairs={reissues} native_observation_session_fresh=1 predecessor_expiry_unchanged=1"
    );
    let prepared = wait_member_snapshot(&bob, &realm_id).await?;
    ensure!(prepared.visible_stream_heads.len() == initial_streams);
    let streams = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let streams = bob
                .sdk()
                .realm_streams_page(&realm_id, None, 500)
                .await?
                .streams;
            if streams.len() == initial_streams {
                return Ok::<_, anyhow::Error>(streams);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .context("all actual remote Circle joins become discoverable")??;
    ensure!(
        streams.len() == initial_streams,
        "discovery did not enumerate every Circle plus Realm"
    );
    let target = streams
        .iter()
        .rev()
        .find(|s| matches!(s.stream_ref, CommitStreamRef::Circle { .. }))
        .context("last Circle stream")?
        .stream_ref
        .clone();
    ensure!(
        !beyond_hint_page || streams.iter().position(|s| s.stream_ref == target).unwrap() >= 64,
        "the target must be beyond the first hint page"
    );
    let CommitStreamRef::Circle { circle_id, .. } = &target else {
        unreachable!()
    };
    let strand = circle_event(
        &alice,
        &realm,
        circle_id,
        EventKind::StrandCreate,
        json!({"object":{
            "schema":"ak.schema.strand.v1","realm_id":realm,"scope_circle_id":circle_id,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"Outside first hint page"},"state":"active","created_by":actor
        }}),
    )
    .await?;
    submit_and_expect_commit(&alice, &account_id, &alice.device_id, &strand).await?;
    let strand_id = StrandId::from_event_id(&strand.event_id);
    let busy_stream = streams
        .iter()
        .find(|s| matches!(s.stream_ref, CommitStreamRef::Circle { .. }))
        .context("first-page busy Circle")?
        .stream_ref
        .clone();
    let CommitStreamRef::Circle {
        circle_id: busy_circle,
        ..
    } = &busy_stream
    else {
        unreachable!()
    };
    let busy_strand = circle_event(
        &alice,
        &realm,
        busy_circle,
        EventKind::StrandCreate,
        json!({"object":{
            "schema":"ak.schema.strand.v1","realm_id":realm,"scope_circle_id":busy_circle,
            "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},
            "metadata":{"title":"First-page busy hints"},"state":"active","created_by":actor
        }}),
    )
    .await?;
    submit_and_expect_commit(&alice, &account_id, &alice.device_id, &busy_strand).await?;
    let busy_strand_id = StrandId::from_event_id(&busy_strand.event_id);
    let _native =
        crate::conformance::account_blocklist_projection::native_account_session(&bob).await?;
    let current = bob
        .sdk()
        .current_principal(&arkret_models_identity::CurrentPrincipalRequestBody {
            request_id: arkret_wire::RequestId::new(format!(
                "ak:request:{}",
                crate::scenarios::mls_lifecycle_live::fresh_uuid_v7()
            ))?,
            account_id: bob_member.account.clone(),
        })
        .await?;
    let principal = bob.principal.as_ref().context("native principal")?;
    let account: inkson::config::ActiveAccountContext = serde_json::from_value(json!({
        "profile_id":"multistream-native","authority":current.account_id,
        "principal_control_realm_id":current.principal_control_realm_id,
        "resolution":current.resolution_projection,"device_id":principal.device_id,"server_url":server.base_url()
    }))?;
    let initial = alice.sdk().realm_state_snapshot_head(&realm_id).await?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("native-state.json");
    let mut local = inkson::LocalStateStore::with_path(&path);
    local.switch_active_account(&account)?;
    let local = Arc::new(std::sync::Mutex::new(local));
    let read = local.clone();
    let store = inkson::realm_events_engine::StateStoreHandle::new(
        move |reader| reader(&read.lock().unwrap()),
        move |writer| writer(&mut local.lock().unwrap()),
    );
    let metrics = server
        .did_boundary_metrics()?
        .context("actual subscription request counters")?;
    let before = metrics.snapshot().await?;
    let effect = inkson::realm_events_engine::EffectRegistry::default().register(
        inkson::realm_events_engine::EffectKey {
            owner: inkson::realm_events_engine::EffectOwner::Realm {
                account: account.profile_id.clone(),
                realm: realm.clone(),
            },
            name: "multistream-live".into(),
            generation: 0,
        },
    );
    let base = server.base_url().to_string();
    let selected = realm.clone();
    let epoch = value_cell(0u64);
    let ctx = inkson::realm_events_engine::RealmEventsEngineContext {
        websocket_rail: inkson::realm_events_engine::WebSocketRail::default(),
        base_url: inkson::realm_events_engine::ValueReader::new(move || base.clone()),
        token: value_cell(bob.session().credential().to_owned()),
        state_store: store.clone(),
        selected_realm_id: inkson::realm_events_engine::ValueReader::new(move || selected.clone()),
        route_enabled: inkson::realm_events_engine::ValueReader::new(|| true),
        realm_live_epoch: epoch.clone(),
        message_stream_hub: None,
        profiles: inkson::realm_events_engine::ValueReader::new(|| {
            inkson::config::MultiProfileConfig {
                active_profile_id: Some("multistream-native".into()),
                profiles: vec![],
            }
        }),
        effect: effect.clone(),
    };
    let http = bob.sdk();
    let runner = inkson::realm_events_engine::run_realm_events_engine_with_transport(
        0,
        inkson::realm_events_engine::ValueReader::new(|| 0),
        realm.clone(),
        ctx,
        move |_| {
            let http = http.clone();
            async move { Ok(http) }
        },
    );
    tokio::pin!(runner);
    let observation = async {
        for expected in &initial.visible_stream_heads {
            wait_head(&store, expected).await.with_context(|| {
                format!(
                    "initial stream {:?}, retained {:?}",
                    expected,
                    stored_head(&store, &expected.stream_ref)
                )
            })?;
        }
        eprintln!(
            "[2133-multistream] initial_streams={initial_streams} all_signed_heads_durable=1"
        );
        for busy in [false, true] {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(100);
            let busy_writes = std::cell::Cell::new(0usize);
            let busy_head = std::cell::RefCell::new(None);
            let target_finished = std::cell::Cell::new(false);
            // The first-page writer starts before the outside-page target and
            // remains active through its actual catch-up. Drain its last real
            // admission instead of cancelling a possibly committed request.
            let pressure = async {
                while busy && !target_finished.get() {
                    let message = circle_event(&alice,&realm,busy_circle,EventKind::MessageCreate,json!({
                        "strand_id":busy_strand_id,"track_name":"discussion",
                        "content":{"kind":"ak.content.text","body":format!("First-page busy hint {}",busy_writes.get())}
                    })).await?;
                    let accepted =
                        submit_and_expect_commit(&alice, &account_id, &alice.device_id, &message)
                            .await?;
                    let _ = busy_head.replace(Some(arkret_wire::CommitStreamHead {
                        stream_ref: busy_stream.clone(),
                        stream_position: accepted.stream_position,
                        commit_id: accepted.commit_id,
                    }));
                    busy_writes.set(busy_writes.get() + 1);
                    tokio::time::sleep(Duration::from_millis(400)).await;
                }
                Ok::<(), anyhow::Error>(())
            };
            let observe_target = async {
                while busy && busy_writes.get() == 0 {
                    ensure!(
                        tokio::time::Instant::now() < deadline,
                        "first-page pressure never started"
                    );
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                let event = circle_event(&alice,&realm,circle_id,EventKind::MessageCreate,json!({
                    "strand_id":strand_id,"track_name":"discussion",
                    "content":{"kind":"ak.content.text","body":if busy {"busy target"} else {"idle target"}}
                })).await?;
                let commit =
                    submit_and_expect_commit(&alice, &account_id, &alice.device_id, &event).await?;
                let expected = arkret_wire::CommitStreamHead {
                    stream_ref: target.clone(),
                    stream_position: commit.stream_position,
                    commit_id: commit.commit_id,
                };
                let required_busy_writes = if busy { busy_writes.get() + 1 } else { 0 };
                while stored_head(&store, &target).as_ref() != Some(&expected)
                    || busy_writes.get() < required_busy_writes
                {
                    ensure!(
                        tokio::time::Instant::now() < deadline,
                        "outside-page target starved while busy={busy}"
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                target_finished.set(true);
                Ok::<(), anyhow::Error>(())
            };
            tokio::try_join!(observe_target, pressure)?;
            ensure!(
                !busy || busy_writes.get() >= 2,
                "busy evidence requires accepted hints before and after the target"
            );
            let last_busy_head = busy_head.borrow().clone();
            if let Some(head) = last_busy_head {
                wait_head(&store, &head).await.with_context(|| {
                    format!(
                        "draining the last actual busy admission {:?}, retained {:?}",
                        head,
                        stored_head(&store, &head.stream_ref)
                    )
                })?;
                eprintln!("[2133-multistream] busy_tail_drained=1");
            }
            eprintln!(
                "[2133-multistream] busy={busy} target_beyond_64={} exact_head_installed=1 busy_writes={}",
                usize::from(beyond_hint_page),
                busy_writes.get()
            );
        }
        let circle = circle_create(
            &alice,
            &realm,
            &actor,
            "First-screen absent new stream",
            "New-stream",
        )
        .await?;
        join_at_parent(&alice, &realm, &circle, &actor, &alice_parent).await?;
        grant_circle_actions(&alice_member, &realm, &circle, &bob_member).await?;
        join_at_parent(&bob, &realm, &circle, &bob_member.actor, &bob_parent).await?;
        eprintln!("[2133-multistream] new_circle_join_accepted=1");
        let final_cut = alice.sdk().realm_state_snapshot_head(&realm_id).await?;
        let new_stream = CommitStreamRef::Circle {
            realm_id: realm_id.clone(),
            circle_id: circle,
        };
        let expected = final_cut
            .visible_stream_heads
            .iter()
            .find(|h| h.stream_ref == new_stream)
            .context("new head")?;
        wait_head(&store, expected).await.with_context(|| {
            format!(
                "new Circle {:?}, retained {:?}",
                expected,
                stored_head(&store, &expected.stream_ref)
            )
        })?;
        eprintln!("[2133-multistream] new_circle_head_durable=1");
        for head in &final_cut.visible_stream_heads {
            wait_head(&store, head).await.with_context(|| {
                format!(
                    "final independent stream {:?}, retained {:?}",
                    head,
                    stored_head(&store, &head.stream_ref)
                )
            })?;
        }
        eprintln!(
            "[2133-multistream] final_streams={} all_signed_heads_durable=1",
            initial_streams + 1
        );
        ensure!(final_cut.visible_stream_heads.len() == initial_streams + 1);
        ensure!(epoch.get() > 0);
        tokio::time::timeout(Duration::from_secs(75), async {
            loop {
                if requests(&metrics.snapshot().await?, SUBSCRIBE_OP)
                    - requests(&before, SUBSCRIBE_OP)
                    >= if beyond_hint_page { 2 } else { 1 }
                {
                    return Ok::<(), anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .context("actual HTTP subscription rollover")??;
        Ok::<(), anyhow::Error>(())
    };
    tokio::pin!(observation);
    let (result, runner_ended) = tokio::select! {
        result=&mut observation=>(result,false),
        _=&mut runner=>(Err(anyhow::anyhow!("native follower ended before matrix completion")),true),
    };
    if let Err(error) = &result {
        eprintln!("[2133-multistream-failure] observation={error:#}");
    }
    if runner_ended {
        return result;
    }
    effect.cancel();
    let cancellation = tokio::time::timeout(Duration::from_secs(8), &mut runner)
        .await
        .context("native follower cancellation");
    if let Err(error) = &cancellation {
        eprintln!("[2133-multistream-failure] cancellation={error:#}");
    }
    result?;
    cancellation?;
    let retained = store.read(|state| state.load().verified_commit_stream_cursors.clone());
    let mut cold = inkson::LocalStateStore::with_path(&path);
    cold.switch_active_account(&account)?;
    ensure!(
        cold.load().verified_commit_stream_cursors == retained,
        "cold native storage changed independent stream checkpoints"
    );
    eprintln!(
        "[2133-multistream] actual_station_processes=2 independent_databases=2 remote_governance=1 new_scope_discovered=1 http_rollover={} cold_checkpoints_preserved=1",
        usize::from(beyond_hint_page)
    );
    Ok(())
}
