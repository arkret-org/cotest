//! Real TLS transport, accepted device, issuer ledger and shared PostgreSQL gates.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::sync_frames::websocket::*;
use arkret_wire::websocket_binding::WebSocketOperationId;
use chrono::Utc;
use cotest::scenarios::websocket_live::*;

use crate::harness::{ArkretServer, TestActorClient};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::human_device_producer_live::{database, standard_client};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;
use crate::scenarios::security_rotation_live::rotation_station_env;

fn value_cell<T: Clone + 'static>(value: T) -> inkson::realm_events_engine::ValueCell<T> {
    let value = std::rc::Rc::new(std::cell::RefCell::new(value));
    let read = value.clone();
    let write = value.clone();
    inkson::realm_events_engine::ValueCell::new(
        move || read.borrow().clone(),
        move |next| *write.borrow_mut() = next,
        move |update| update(&mut value.borrow_mut()),
    )
}

fn stored_head(
    store: &inkson::realm_events_engine::StateStoreHandle,
    stream: &arkret_wire::CommitStreamRef,
) -> Option<arkret_wire::CommitStreamHead> {
    let key = serde_json::to_string(stream).ok()?;
    store.read(|store| {
        store
            .load()
            .verified_commit_stream_cursors
            .get(&key)
            .cloned()
    })
}

async fn wait_head(
    store: &inkson::realm_events_engine::StateStoreHandle,
    expected: &arkret_wire::CommitStreamHead,
) -> Result<()> {
    tokio::time::timeout(WAIT, async {
        while stored_head(store, &expected.stream_ref).as_ref() != Some(expected) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .context("actual Inkson signed durable head reaches accepted authority")?;
    Ok(())
}

fn requests(
    snapshot: &crate::scenarios::_helpers::service_metrics::MetricsSnapshot,
    op: &str,
) -> u64 {
    snapshot.sum("coland_request_total", &[("op", op)]) as u64
}

async fn follower_socket_pump(
    mut socket: Socket,
    mut connection: inkson::realm_events_engine::SharedConnection,
    rail: inkson::realm_events_engine::WebSocketRail,
    server: &ArkretServer,
    client: &TestActorClient,
    recovery: Arc<std::sync::atomic::AtomicU8>,
) -> Result<()> {
    use std::sync::atomic::Ordering;
    let mut active_events = None;
    loop {
        if recovery.load(Ordering::SeqCst) == 1 {
            ensure!(
                active_events.is_some(),
                "live committed channel before physical disconnect"
            );
            finish(&mut socket).await?;
            rail.detach();
            let (replacement, _) = authenticated(server, client).await?;
            socket = replacement;
            connection = inkson::realm_events_engine::SharedConnection::new();
            connection.set_ready(true);
            rail.attach(connection.clone());
            recovery.store(2, Ordering::SeqCst);
        }
        while let Some(mut command) = connection.next_command() {
            if let WebSocketClientFrame::Open {
                channel_id,
                parameters: WebSocketOpenParameters::Events(parameters),
                ..
            } = &mut command
            {
                active_events = Some(channel_id.clone());
                match recovery.load(Ordering::SeqCst) {
                    2 => {
                        ensure!(
                            parameters.after.is_some(),
                            "disconnect keeps the actual durable subscription cursor"
                        );
                        parameters.after = Some(
                            arkret_hlc::Cursor::new_at(Utc::now(), 3_600_000)?
                                .with_stateful_handle("A".repeat(22))
                                .encode()?,
                        );
                        recovery.store(3, Ordering::SeqCst);
                    }
                    4 => {
                        ensure!(
                            parameters.after.is_none(),
                            "only the refused resume handle is cleared"
                        );
                        recovery.store(5, Ordering::SeqCst);
                    }
                    _ => {}
                }
            }
            send(&mut socket, &command).await?;
        }
        tokio::select! {
            frame = next(&mut socket) => {
                let frame = frame?;
                match &frame {
                    WebSocketServerFrame::ChannelError { error, .. } if recovery.load(Ordering::SeqCst) == 3 => {
                        ensure!(error.code == arkret_wire::ErrorCode::CursorIntegrityInvalid, "real SUT rejects the unrecognized typed cursor");
                        recovery.store(4, Ordering::SeqCst);
                    }
                    WebSocketServerFrame::ChannelControl { payload: WebSocketChannelControlPayload::Events(control), .. }
                        if recovery.load(Ordering::SeqCst) == 5 && control.cursor.is_some() => recovery.store(6, Ordering::SeqCst),
                    _ => {}
                }
                connection.publish(frame).map_err(|error| anyhow::anyhow!(error.to_string()))?;
            },
            _ = tokio::time::sleep(Duration::from_millis(25)) => {}
        }
    }
}

async fn observe_follower(
    server: &ArkretServer,
    alice: &TestActorClient,
    account: &inkson::config::ActiveAccountContext,
    realm: &str,
    path: &std::path::Path,
    websocket: bool,
    idle: bool,
) -> Result<()> {
    use inkson::realm_events_engine::{
        EffectKey, EffectOwner, EffectRegistry, LocalStateStore, SharedConnection,
        StateStoreHandle, ValueReader, WebSocketRail,
    };
    let mut local = LocalStateStore::with_path(path);
    local.switch_active_account(account)?;
    let local = Arc::new(std::sync::Mutex::new(local));
    let local_read = local.clone();
    let store = StateStoreHandle::new(
        move |read| read(&local_read.lock().unwrap()),
        move |write| write(&mut local.lock().unwrap()),
    );
    let expected = realm_head(alice, realm).await?;
    let before_head = stored_head(&store, &expected.stream_ref);
    let metrics = server
        .did_boundary_metrics()?
        .context("live scan/request counters required")?;
    let before = metrics.snapshot().await?;
    let rail = WebSocketRail::default();
    let recovery = Arc::new(std::sync::atomic::AtomicU8::new(0));
    let mut pump: std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + '_>> =
        if websocket {
            let description = advertised_websocket(server).await?;
            rail.set_selector(
                inkson::realm_events_engine::WebSocketTransportSelector::from_describe(
                    &description,
                ),
            );
            let (socket, _) = authenticated(server, alice).await?;
            let connection = SharedConnection::new();
            connection.set_ready(true);
            rail.attach(connection.clone());
            // Discovery and the live TLS endpoint agree before attaching the
            // same production consumer used by the app.
            Box::pin(follower_socket_pump(
                socket,
                connection,
                rail.clone(),
                server,
                alice,
                recovery.clone(),
            ))
        } else {
            Box::pin(std::future::pending())
        };
    let effect = EffectRegistry::default().register(EffectKey {
        owner: EffectOwner::Realm {
            account: account.profile_id.clone(),
            realm: realm.to_owned(),
        },
        name: "live-follower-evidence".to_owned(),
        generation: 0,
    });
    let base_url = server.base_url().to_string();
    let selected_realm = realm.to_owned();
    let epoch = value_cell(0_u64);
    let ctx = inkson::realm_events_engine::RealmEventsEngineContext {
        websocket_rail: rail.clone(),
        base_url: ValueReader::new(move || base_url.clone()),
        token: value_cell(alice.session().credential().to_owned()),
        state_store: store.clone(),
        selected_realm_id: ValueReader::new(move || selected_realm.clone()),
        route_enabled: ValueReader::new(|| true),
        realm_live_epoch: epoch.clone(),
        message_stream_hub: None,
        profiles: ValueReader::new(|| inkson::config::MultiProfileConfig {
            active_profile_id: Some("live-follower".to_owned()),
            profiles: vec![],
        }),
        effect: effect.clone(),
    };
    let sdk = alice.sdk();
    let runner = inkson::realm_events_engine::run_realm_events_engine_with_transport(
        0,
        ValueReader::new(|| 0),
        realm.to_owned(),
        ctx,
        move |_| {
            let sdk = sdk.clone();
            async move { Ok(sdk) }
        },
    );
    tokio::pin!(runner);
    let mode = if websocket { "websocket" } else { "http" };
    let observation = async {
        wait_head(&store, &expected).await?;
        // A reload already has the durable head: wait for its fresh authority
        // and signed-anchor verification, not merely the persisted position.
        if before_head.is_some() {
            tokio::time::timeout(WAIT, async {
                loop {
                    let snapshot = metrics.snapshot().await?;
                    if requests(&snapshot, SCAN_OP) > requests(&before, SCAN_OP) {
                        return Ok::<(), anyhow::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .context("reload freshly verifies and scans after signed anchor")??;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        let baseline = metrics.snapshot().await?;
        ensure!(
            baseline.has_metric(SCAN_BYTES),
            "frozen server exports actual scan bytes"
        );
        let start = Utc::now();
        let started = tokio::time::Instant::now();
        let baseline_epoch = epoch.get();
        eprintln!(
            "[follower-live] baseline complete mode={mode} reload={} start={}",
            before_head.is_some(),
            start.to_rfc3339()
        );
        if idle {
            tokio::time::sleep(Duration::from_secs(120)).await;
        }
        let end = Utc::now();
        let stable = metrics.snapshot().await?;
        let scan_count = requests(&stable, SCAN_OP) - requests(&baseline, SCAN_OP);
        let bundle_count = requests(&stable, BUNDLE_OP) - requests(&baseline, BUNDLE_OP);
        let scan_bytes = stable.sum(SCAN_BYTES, &[]) - baseline.sum(SCAN_BYTES, &[]);
        let subscribe_count = requests(&stable, SUBSCRIBE_OP) - requests(&baseline, SUBSCRIBE_OP);
        ensure!(
            scan_count == 0
                && bundle_count == 0
                && scan_bytes == 0.0
                && epoch.get() == baseline_epoch,
            "{mode} idle does not rebuild authority or rescan: scans={scan_count}, bundles={bundle_count}, bytes={scan_bytes}"
        );
        if idle {
            ensure!(started.elapsed() >= Duration::from_secs(120));
            if websocket {
                ensure!(
                    subscribe_count == 0,
                    "live WS consumer sends no HTTP subscribe"
                );
            } else {
                ensure!(
                    (3..=5).contains(&subscribe_count),
                    "HTTP long poll remains bounded: {subscribe_count}"
                );
            }
        }
        let baseline_bytes = baseline.sum(SCAN_BYTES, &[]) - before.sum(SCAN_BYTES, &[]);
        if before_head.is_some() {
            ensure!(
                baseline_bytes < 4096.0,
                "reload empty tail is bounded, bytes={baseline_bytes}"
            );
        }
        eprintln!(
            "[follower-live] mode={mode} reload={} base_url={} idle_start={} idle_end={} idle_seconds={} scan_method=POST scan_path=/_arkret/self/streams/scan bundle_method=POST bundle_path=/_arkret/open/realm-authority/bundle subscribe_method=GET subscribe_path=/_arkret/self/committed-events/subscribe physical_connections={} baseline_scan_bytes={} idle_scans={scan_count} idle_bundles={bundle_count} idle_scan_bytes={scan_bytes} idle_http_subscribes={subscribe_count} cursor_advanced=false",
            before_head.is_some(),
            server.base_url(),
            start.to_rfc3339(),
            end.to_rfc3339(),
            started.elapsed().as_secs(),
            u8::from(websocket),
            baseline_bytes
        );
        if idle {
            let strand = alice.default_strand_id(realm)?;
            let response = alice
                .send_message(realm, &strand, "Live missing-tail evidence")
                .await?;
            let outcome: arkret_models_collaboration::authority_commit::SelfAuthoritySubmitOutcome =
                serde_json::from_value(response)?;
            outcome.validate()?;
            let tail_head = realm_head(alice, realm).await?;
            wait_head(&store, &tail_head).await?;
            let tail = metrics.snapshot().await?;
            let tail_scan_count = requests(&tail, SCAN_OP) - requests(&stable, SCAN_OP);
            let tail_bytes = tail.sum(SCAN_BYTES, &[]) - stable.sum(SCAN_BYTES, &[]);
            ensure!(
                (1..=4).contains(&tail_scan_count),
                "new accepted facts use bounded missing-tail scans: {tail_scan_count}"
            );
            eprintln!(
                "[follower-live] mode={mode} missing_tail_scans={tail_scan_count} missing_tail_bytes={tail_bytes} cursor_advanced=true signed_commit_identity_matched=true"
            );
            if websocket {
                let recovery_start = metrics.snapshot().await?;
                recovery.store(1, std::sync::atomic::Ordering::SeqCst);
                tokio::time::timeout(WAIT, async {
                    while recovery.load(std::sync::atomic::Ordering::SeqCst) != 6 {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                })
                .await
                .context("actual follower reopens only the invalid cursor target")?;
                ensure!(stored_head(&store, &tail_head.stream_ref).as_ref() == Some(&tail_head));
                let recovered = metrics.snapshot().await?;
                let recovery_scans =
                    requests(&recovered, SCAN_OP) - requests(&recovery_start, SCAN_OP);
                let recovery_bytes =
                    recovered.sum(SCAN_BYTES, &[]) - recovery_start.sum(SCAN_BYTES, &[]);
                ensure!(
                    recovery_scans <= 2 && recovery_bytes < 4096.0,
                    "cursor reset retains verified history: scans={recovery_scans}, bytes={recovery_bytes}"
                );
                eprintln!(
                    "[follower-live] mode=websocket physical_disconnect_resume=1 fresh_challenge_dpop=1 real_cursor_integrity_refusal=1 targeted_cursor_reset=1 signed_head_preserved=1 recovery_scans={recovery_scans} recovery_scan_bytes={recovery_bytes} physical_connections_opened=2"
                );
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::pin!(observation);
    let result = tokio::select! {
        result = &mut observation => result,
        result = &mut pump => Err(result.err().unwrap_or_else(|| anyhow::anyhow!("physical WS pump ended during observation"))),
        _ = &mut runner => Err(anyhow::anyhow!("actual follower exited before evidence completed")),
    };
    effect.cancel();
    tokio::time::timeout(Duration::from_secs(5), &mut runner)
        .await
        .context("follower consumer retires without leaving duplicate reads")?;
    rail.detach();
    result
}

/// Runs the production Inkson follower and durable projection against a frozen TLS SUT.
/// Both modes retain the original baseline, 120-second idle, tail and reload observations.
pub async fn run_follower_idle_and_reload() -> Result<()> {
    let Some(database) = database("follower-live")? else {
        return Ok(());
    };
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let env = rotation_station_env(&issuer);
    let refs = env
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let server =
        ArkretServer::spawn_with_database_url("follower-live", &database.connect_url, &refs)
            .await?;
    let (alice, _) = standard_client(
        &server,
        &issuer,
        "follower-alice",
        "ak:device:01904100-0000-7000-8000-000000002803",
    )
    .await?;
    let _native =
        crate::conformance::account_blocklist_projection::native_account_session(&alice).await?;
    let principal = alice
        .principal
        .as_ref()
        .context("accepted device principal")?;
    let current = alice
        .sdk()
        .current_principal(&arkret_models_identity::CurrentPrincipalRequestBody {
            request_id: arkret_wire::RequestId::new(format!(
                "ak:request:{}",
                crate::scenarios::mls_lifecycle_live::fresh_uuid_v7()
            ))?,
            account_id: arkret_wire::AccountId::new(
                principal.core_id.clone(),
                server.service_id().clone(),
            ),
        })
        .await?;
    let account: inkson::config::ActiveAccountContext =
        serde_json::from_value(serde_json::json!({
            "profile_id":"live-follower","authority":current.account_id,
            "principal_control_realm_id":current.principal_control_realm_id,
            "resolution":current.resolution_projection,"device_id":principal.device_id,
            "server_url":server.base_url(),
        }))?;
    let realm = alice.create_realm("Real follower idle and reload").await?;
    let strand = alice.default_strand_id(&realm)?;
    for index in 0..4 {
        alice
            .send_message(&realm, &strand, &format!("Verified baseline {index}"))
            .await?;
    }
    let folder = tempfile::tempdir()?;
    for websocket in [false, true] {
        let path = folder
            .path()
            .join(if websocket { "ws.json" } else { "http.json" });
        observe_follower(&server, &alice, &account, &realm, &path, websocket, true).await?;
        observe_follower(&server, &alice, &account, &realm, &path, websocket, false).await?;
    }
    Ok(())
}

pub async fn run_bounded_drain() -> Result<()> {
    let Some(database) = database("websocket-drain-live")? else {
        return Ok(());
    };
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let mut env = rotation_station_env(&issuer);
    env.push((
        "COLAND_WEBSOCKET_MAX_LIFETIME_SECS".to_owned(),
        "4".to_owned(),
    ));
    let refs = env
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let server =
        ArkretServer::spawn_with_database_url("websocket-drain-live", &database.connect_url, &refs)
            .await?;
    let (alice, _) = standard_client(
        &server,
        &issuer,
        "drain-alice",
        "ak:device:01904100-0000-7000-8000-000000002804",
    )
    .await?;
    let (mut socket, _) = authenticated(&server, &alice).await?;
    open(
        &mut socket,
        "drain-account",
        WebSocketOpenParameters::Account(Default::default()),
        WebSocketOperationId::AccountStreamSubscribe,
    )
    .await?;
    open(
        &mut socket,
        "drain-signal",
        WebSocketOpenParameters::Signal(Default::default()),
        WebSocketOperationId::SignalStreamSubscribe,
    )
    .await?;
    let frame = until(&mut socket, |frame| {
        matches!(frame, WebSocketServerFrame::ConnectionControl { .. })
    })
    .await?;
    let WebSocketServerFrame::ConnectionControl { payload, .. } = frame else {
        unreachable!()
    };
    ensure!(
        payload.reconnect_after_ms > 0
            && payload.deadline > Utc::now()
            && payload.deadline - Utc::now() <= chrono::Duration::seconds(2)
    );
    send(
        &mut socket,
        &WebSocketClientFrame::Open {
            channel_id: "drain-new".to_owned(),
            operation_id: WebSocketOperationId::SignalStreamSubscribe,
            parameters: WebSocketOpenParameters::Signal(Default::default()),
        },
    )
    .await?;
    until(&mut socket,|frame|matches!(frame,WebSocketServerFrame::ChannelError { channel_id,error,.. } if channel_id=="drain-new" && error.code==arkret_wire::ErrorCode::TemporarilyUnavailable)).await?;
    closed(&mut socket, 1001).await?;
    eprintln!(
        "[websocket-live] bounded_lifetime_drain=1 stops_new_opens=1 reconnect_delay=1 close_1001=1"
    );
    Ok(())
}

const SCAN_OP: &str = arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1;

const BUNDLE_OP: &str = "POST /_arkret/open/realm-authority/bundle";

const SUBSCRIBE_OP: &str =
    arkret_wire::ServiceOperationId::SELF_COMMITTED_EVENT_STREAM_SUBSCRIBE_V1;

const SCAN_BYTES: &str = "coland_stream_scan_response_bytes_total";
