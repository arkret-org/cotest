//! A native follower observes one Realm stream across independent Chat timelines.

use arkret_wire::{CommitStreamRef, EventKind, RealmId, StrandId};
use cotest::scenarios::human_device_producer_live::{
    create_realm_with_join_rule, membership_payload, prepare_join, station_env,
    submit_and_expect_commit, wait_for_committed,
};
use cotest::scenarios::mls_lifecycle_live::Member;
use serde_json::json;

use super::*;

struct LiveActors {
    alice: Member,
    bob: Member,
    reader_epoch: u64,
    core_epoch: Option<u64>,
    pin_requested: bool,
    supplied_epoch: Option<u64>,
    provide_calls: u64,
    pair_reauthentications: u64,
    writer_reauthentications: u64,
    stage: &'static str,
}

type ActorSlots = std::rc::Rc<std::cell::RefCell<LiveActors>>;

fn member_snapshot(member: &Member) -> Member {
    Member {
        client: member.client.clone(),
        account: member.account.clone(),
        actor: member.actor.clone(),
        device: member.device.clone(),
        method: member.method.clone(),
        key: member.key.clone(),
        authorize_event_id: member.authorize_event_id.clone(),
    }
}

fn require_core_epoch(actors: &ActorSlots, expected: u64) -> Result<()> {
    let actors = actors.borrow();
    ensure!(
        actors.core_epoch == Some(expected) && actors.reader_epoch == expected,
        "reader authentication changed during the fixed-session core"
    );
    Ok(())
}

fn current_reader_transport(actors: &ActorSlots) -> Result<arkret_http_client::Client> {
    let mut actors = actors.borrow_mut();
    ensure!(
        actors
            .core_epoch
            .is_none_or(|epoch| epoch == actors.reader_epoch),
        "reader authentication changed during the fixed-session core"
    );
    let http = actors.bob.client.sdk();
    ensure!(
        http.own_station_result_client()?.is_some(),
        "current reader has no live bound native source"
    );
    actors.provide_calls = actors
        .provide_calls
        .checked_add(1)
        .context("reader provider counter overflow")?;
    actors.supplied_epoch = Some(actors.reader_epoch);
    Ok(http)
}

async fn maintain_preparation_sessions(
    governor: &ArkretServer,
    server: &ArkretServer,
    issuer: &MockCoauthIntrospectionServer,
    actors: ActorSlots,
    token: inkson::realm_events_engine::ValueCell<String>,
    wake: Arc<tokio::sync::Notify>,
) -> Result<()> {
    // Keep a single-head wait plus the ordinary refresh margin in reserve.
    // This is remaining issuer lifetime, not a forced three-minute rotation.
    let renewal_margin = Duration::from_secs(120 + 60);
    loop {
        let pin = actors.borrow().pin_requested;
        let remaining = {
            let actors = actors.borrow();
            actors
                .alice
                .client
                .checked_native_session_remaining()?
                .min(actors.bob.client.checked_native_session_remaining()?)
        };
        if pin || remaining <= renewal_margin {
            let (old_alice, old_bob) = {
                let actors = actors.borrow();
                ensure!(
                    actors.core_epoch.is_none(),
                    "core reader may not reauthenticate"
                );
                (actors.alice.client.clone(), actors.bob.client.clone())
            };
            let fresh_alice = governor
                .reissue_mock_native_host_session(&old_alice, issuer)
                .await?;
            let fresh_bob = server
                .reissue_mock_native_host_session(&old_bob, issuer)
                .await?;
            {
                let mut actors = actors.borrow_mut();
                ensure!(
                    actors.core_epoch.is_none(),
                    "core reader may not reauthenticate"
                );
                actors.reader_epoch = actors
                    .reader_epoch
                    .checked_add(1)
                    .context("reader epoch overflow")?;
                actors.pair_reauthentications = actors
                    .pair_reauthentications
                    .checked_add(1)
                    .context("reauthentication counter overflow")?;
                actors.alice.client = fresh_alice;
                actors.bob.client = fresh_bob;
                token.set(actors.bob.client.session().credential().to_owned());
                if pin {
                    actors.core_epoch = Some(actors.reader_epoch);
                }
            }
            // Publish the coherent replacement first. There is no await before
            // invalidating only the old local sources; issuer records survive.
            old_alice.invalidate_local_native_session()?;
            old_bob.invalidate_local_native_session()?;
            if pin {
                return std::future::pending::<Result<()>>().await;
            }
            continue;
        }
        tokio::select! {
            _ = wake.notified() => {},
            _ = tokio::time::sleep(remaining.saturating_sub(renewal_margin)) => {},
        }
    }
}

async fn current_writer_for_author(
    governor: &ArkretServer,
    issuer: &MockCoauthIntrospectionServer,
    actors: &ActorSlots,
    core_epoch: u64,
) -> Result<Member> {
    require_core_epoch(actors, core_epoch)?;
    let old = actors.borrow().alice.client.clone();
    let fresh = governor
        .reissue_mock_native_host_session(&old, issuer)
        .await?;
    {
        let mut actors = actors.borrow_mut();
        ensure!(actors.core_epoch == Some(core_epoch) && actors.reader_epoch == core_epoch);
        actors.alice.client = fresh;
        actors.writer_reauthentications = actors
            .writer_reauthentications
            .checked_add(1)
            .context("writer authentication counter overflow")?;
    }
    old.invalidate_local_native_session()?;
    Ok(member_snapshot(&actors.borrow().alice))
}

fn successful_subscriptions(
    snapshot: &crate::scenarios::_helpers::service_metrics::MetricsSnapshot,
    require_seen: bool,
) -> Result<u64> {
    ensure!(
        snapshot.has_metric("coland_request_total"),
        "request counter is unavailable"
    );
    let mut total = 0u64;
    let mut seen_success = false;
    let mut labels = std::collections::BTreeSet::new();
    for sample in snapshot.samples().iter().filter(|sample| {
        sample.name == "coland_request_total" && sample.matches(&[("op", SUBSCRIBE_OP)])
    }) {
        ensure!(
            labels.insert(sample.labels.clone()),
            "duplicate subscription counter series"
        );
        let status = sample
            .labels
            .get("status")
            .context("subscription counter has no status label")?;
        ensure!(
            status.len() == 3 && status.bytes().all(|byte| byte.is_ascii_digit()),
            "unknown subscription status label"
        );
        ensure!(
            status
                .parse::<u16>()
                .is_ok_and(|value| (100..600).contains(&value)),
            "unknown subscription status value"
        );
        ensure!(
            sample.value.is_finite()
                && sample.value >= 0.0
                && sample.value.fract() == 0.0
                && sample.value <= (1u64 << 53) as f64,
            "invalid subscription counter value"
        );
        if status == "200" {
            seen_success = true;
            total = total
                .checked_add(sample.value as u64)
                .context("subscription counter overflow")?;
        }
    }
    ensure!(
        !require_seen || seen_success,
        "successful subscription counter is unavailable"
    );
    Ok(total)
}

fn pending_precore_opens(
    provides: u64,
    success_before: u64,
    success_at_boundary: u64,
) -> Result<u64> {
    let completed = success_at_boundary
        .checked_sub(success_before)
        .context("subscription counter regressed")?;
    provides
        .checked_sub(completed)
        .context("subscription counts exceed the single-send provider bound")
}

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
                        .filter(|floor| matches!(floor.stream_ref, CommitStreamRef::Realm { .. }))
                        .all(|floor| floor.oldest_position > 0),
                    "the remote member must retain its since-join Realm floor"
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

async fn run_matrix(chat_count: usize) -> Result<()> {
    let many_chats = chat_count > 64;
    let label = if many_chats {
        "multistream-native"
    } else {
        "snapshot-busy-native"
    };
    let transcript = if many_chats {
        "2133-multistream"
    } else {
        "2133-snapshot-busy"
    };
    let initial_streams = 1;
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
        "Independent Chat timelines",
        "public",
        &[governor, server],
    )
    .await?;
    let realm_id = RealmId::new(realm.clone())?;
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
    let mut last_reissue = tokio::time::Instant::now();
    let mut reissues = 0usize;
    let mut strands = Vec::with_capacity(chat_count);
    for index in 0..chat_count {
        if last_reissue.elapsed() >= Duration::from_secs(180) {
            alice = governor.reissue_mock_native_host_session(&alice, &issuer).await?;
            bob = server.reissue_mock_native_host_session(&bob, &issuer).await?;
            reissues += 1;
            last_reissue = tokio::time::Instant::now();
        }
        strands.push(StrandId::new(alice.create_strand(&realm, &format!("Chat {index}")).await?)?);
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
    let target = CommitStreamRef::Realm { realm_id: realm_id.clone() };
    let streams = bob.sdk().realm_streams_page(&realm_id, None, 500).await?.streams;
    ensure!(streams.len() == 1 && streams[0].stream_ref == target);
    let strand_id = strands.last().context("target Chat")?;
    let busy_strand_id = &strands[0];
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
    let success_before = successful_subscriptions(&before, false)?;
    let actors = std::rc::Rc::new(std::cell::RefCell::new(LiveActors {
        alice: alice_member,
        bob: bob_member,
        reader_epoch: 0,
        core_epoch: None,
        pin_requested: false,
        supplied_epoch: None,
        provide_calls: 0,
        pair_reauthentications: 0,
        writer_reauthentications: 0,
        stage: "preparation",
    }));
    let token = value_cell(bob.session().credential().to_owned());
    let auth_wake = Arc::new(tokio::sync::Notify::new());
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
        token: token.clone(),
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
    let reader_actors = actors.clone();
    let runner = inkson::realm_events_engine::run_realm_events_engine_with_transport(
        0,
        inkson::realm_events_engine::ValueReader::new(|| 0),
        realm.clone(),
        ctx,
        move |_| {
            let selected = current_reader_transport(&reader_actors);
            async move { selected }
        },
    );
    tokio::pin!(runner);
    let lifecycle = maintain_preparation_sessions(
        governor,
        server,
        &issuer,
        actors.clone(),
        token,
        auth_wake.clone(),
    );
    tokio::pin!(lifecycle);
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
        actors.borrow_mut().pin_requested = true;
        actors.borrow_mut().stage = "reader_pin";
        auth_wake.notify_one();
        let core_epoch = tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                let ready = {
                    let actors = actors.borrow();
                    actors
                        .core_epoch
                        .filter(|epoch| actors.supplied_epoch == Some(*epoch))
                };
                if let Some(epoch) = ready {
                    return epoch;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .context("one live follower acquires the final preparation session")?;
        actors.borrow_mut().stage = "sentinel";
        let sentinel_writer =
            current_writer_for_author(governor, &issuer, &actors, core_epoch).await?;
        let sentinel = sentinel_writer.client.author_event(
            &realm,
            EventKind::MessageCreate.as_str(),
            json!({"strand_id":busy_strand_id,"track_name":"discussion",
                "content":{"kind":"ak.content.text","body":"Authenticated observation boundary"}}),
        )
        .await?;
        let sentinel_commit = submit_and_expect_commit(
            &sentinel_writer.client,
            &account_id,
            &sentinel_writer.client.device_id,
            &sentinel,
        )
        .await?;
        wait_head(
            &store,
            &arkret_wire::CommitStreamHead {
                stream_ref: target.clone(),
                stream_position: sentinel_commit.stream_position,
                commit_id: sentinel_commit.commit_id,
            },
        )
        .await
        .context("fresh-session follower installs the real boundary Message")?;
        require_core_epoch(&actors, core_epoch)?;
        // Read the real successful response counter BEFORE the local provide
        // count. With the fixture's unchanged retry=0, every provide can open
        // at most one HTTP subscription. Exclude even late pre-core opens.
        let boundary_success = successful_subscriptions(&metrics.snapshot().await?, true)?;
        let boundary_provides = actors.borrow().provide_calls;
        let pending_opens =
            pending_precore_opens(boundary_provides, success_before, boundary_success)?;
        let required_natural_opens = pending_opens
            .checked_add(1)
            .context("rollover bound overflow")?;
        eprintln!(
            "[2133-multistream-auth] reader_epoch={core_epoch} pre_core_provides={boundary_provides} pending_open_upper_bound={pending_opens} authoritative_expiry_remaining_ms=null sentinel_exact_head_durable=1"
        );
        for (chat, count) in [(strand_id, 1), (busy_strand_id, 5)] {
            let writer = current_writer_for_author(governor, &issuer, &actors, core_epoch).await?;
            let mut last = None;
            for index in 0..count {
                let event = writer.client.author_event(&realm, EventKind::MessageCreate.as_str(),
                    cotest::harness::message_create_text_payload_for_strand(chat.clone(), &format!("Follower write {index}"))?).await?;
                let commit = submit_and_expect_commit(&writer.client, &account_id, &writer.client.device_id, &event).await?;
                ensure!(commit.stream_ref == target);
                last = Some(arkret_wire::CommitStreamHead { stream_ref: target.clone(), stream_position: commit.stream_position, commit_id: commit.commit_id });
            }
            wait_head(&store, &last.context("real message tail")?).await?;
            require_core_epoch(&actors, core_epoch)?;
        }
        let writer = current_writer_for_author(governor, &issuer, &actors, core_epoch).await?;
        writer.client.create_strand(&realm, "Chat after subscription").await?;
        let final_cut = writer.client.sdk().realm_state_snapshot_head(&realm_id).await?;
        ensure!(final_cut.visible_stream_heads.len() == 1 && final_cut.visible_stream_heads[0].stream_ref == target);
        wait_head(&store, &final_cut.visible_stream_heads[0]).await?;
        ensure!(epoch.get() > 0);
        actors.borrow_mut().stage = "rollover";
        tokio::time::timeout(Duration::from_secs(75), async {
            loop {
                require_core_epoch(&actors, core_epoch)?;
                let observed = metrics.snapshot().await?;
                let natural_opens = successful_subscriptions(&observed, true)?
                    .checked_sub(boundary_success)
                    .context("successful subscription counter regressed")?;
                if requests(&observed, SUBSCRIBE_OP) - requests(&before, SUBSCRIBE_OP)
                    >= if many_chats { 2 } else { 1 }
                    && (!many_chats || natural_opens >= required_natural_opens)
                {
                    return Ok::<(), anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await
        .context("actual HTTP subscription rollover")??;
        require_core_epoch(&actors, core_epoch)?;
        actors.borrow_mut().stage = "complete";
        let auth = actors.borrow();
        eprintln!(
            "[2133-multistream-auth] pair_reauthentications={} writer_reauthentications={} core_reader_changes=0 natural_rollover_excludes_auth_opens=1",
            auth.pair_reauthentications, auth.writer_reauthentications
        );
        Ok::<(), anyhow::Error>(())
    };
    tokio::pin!(observation);
    let (result, runner_ended) = tokio::select! {
        result=&mut observation=>(result,false),
        _=&mut runner=>(Err(anyhow::anyhow!("native follower ended before matrix completion")),true),
        result=&mut lifecycle=>(match result {
            Err(error)=>Err(error.context("fixture authentication lifecycle")),
            Ok(())=>Err(anyhow::anyhow!("authentication lifecycle ended before matrix completion")),
        },false),
    };
    if let Err(error) = &result {
        eprintln!("[2133-multistream-failure] observation={error:#}");
        let actors = actors.borrow();
        let remaining = actors.bob.client.checked_native_session_remaining().ok();
        let diagnostic = json!({"stage":actors.stage,"reader_epoch":actors.reader_epoch,
            "core_epoch":actors.core_epoch,"reader_source_live":remaining.is_some(),
            "remaining_ms":remaining.map(|value| value.as_millis()),
            "pair_reauthentications":actors.pair_reauthentications,
            "writer_reauthentications":actors.writer_reauthentications,
            "is_failed_http_cut":false});
        eprintln!("[2133-multistream-auth-failure] {diagnostic}");
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
        "[2133-multistream] actual_station_processes=2 independent_databases=2 remote_governance=1 new_chat_on_single_realm_stream=1 http_rollover={} cold_checkpoints_preserved=1",
        usize::from(many_chats)
    );
    Ok(())
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn pending_open_bound_excludes_late_precore_responses() -> Result<()> {
        ensure!(pending_precore_opens(4, 10, 13)? == 1);
        ensure!(pending_precore_opens(4, 10, 14)? == 0);
        ensure!(pending_precore_opens(3, 10, 14).is_err());
        ensure!(pending_precore_opens(3, 10, 9).is_err());
        Ok(())
    }

    #[test]
    fn successful_open_counter_rejects_unknown_duplicate_or_invalid_series() -> Result<()> {
        use crate::scenarios::_helpers::service_metrics::MetricsSnapshot;
        let sample = format!("coland_request_total{{op=\"{SUBSCRIBE_OP}\",status=\"200\"}} 3\n");
        ensure!(successful_subscriptions(&MetricsSnapshot::parse(&sample), true)? == 3);
        for body in [
            format!("coland_request_total{{op=\"{SUBSCRIBE_OP}\"}} 3"),
            format!("{sample}{sample}"),
            sample.replace(" 3", " -1"),
            sample.replace(" 3", " 1.5"),
            sample.replace("status=\"200\"", "status=\"unknown\""),
            sample.replace("status=\"200\"", "status=\"999\""),
            String::new(),
        ] {
            ensure!(successful_subscriptions(&MetricsSnapshot::parse(&body), true).is_err());
        }
        Ok(())
    }
}
