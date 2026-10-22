//! Actual account cursor revocation through a durable TLS Station and PostgreSQL.

use anyhow::{Context, Result, ensure};
use arkret_models_collaboration::sync_frames::account_subscribe::SyncRequestBody;
use arkret_models_identity::account::{AccountCursorRevokeRequestBody, CursorRevokeScope};
use arkret_wire::{ErrorCode, ReasonCode};
use base64::Engine;
use serde_json::Value;

use crate::harness::{TestActorClient, TestServerGroup};
use crate::scenarios::_helpers::bridge::MockCoauthIntrospectionServer;
use crate::scenarios::human_device_producer_live::{database, standard_client, station_env};
use crate::scenarios::identity_test_support::HARNESS_INTERNAL_AUTHORITY_SECRET;

async fn cursor(client: &TestActorClient) -> Result<String> {
    Ok(client
        .sdk()
        .account_subscribe_batch(&SyncRequestBody {
            catchup: Some(true),
            ..Default::default()
        })
        .await?
        .cursor)
}

async fn footprint(url: &str) -> Result<Value> {
    let accepted =
        crate::scenarios::_helpers::acceptance_footprint::acceptance_rows_with_agent_stores(
            url, true,
        )
        .await?;
    let url = url.to_owned();
    let cursors = tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut connection = postgres::Client::connect(&url, postgres::NoTls)?;
        let mut transaction = connection.build_transaction().isolation_level(postgres::IsolationLevel::RepeatableRead).start()?;
        let tables = transaction.query("SELECT tablename::text FROM pg_tables WHERE schemaname='public' AND (tablename LIKE '%cursor%' OR tablename LIKE '%ack%' OR tablename LIKE '%device_message%' OR tablename LIKE '%welcome%' OR tablename LIKE '%blob_download%') ORDER BY tablename", &[])?;
        let mut rows = serde_json::Map::new();
        for table in tables {
            let name: String = table.get(0);
            ensure!(name.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_'));
            let statement = format!("SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb) FROM public.{name} r");
            rows.insert(name, transaction.query_one(&statement, &[])?.get(0));
        }
        ensure!(rows.contains_key("sync_cursor_handles") && rows.contains_key("sync_cursor_revocations"));
        transaction.commit()?;
        Ok(Value::Object(rows))
    }).await??;
    Ok(serde_json::json!({"accepted": accepted, "cursor_progress_and_ack": cursors}))
}

async fn revoked(client: &TestActorClient, token: &str, url: &str) -> Result<()> {
    let before = footprint(url).await?;
    let error = client
        .sdk()
        .account_subscribe_batch(&SyncRequestBody {
            after: Some(token.to_owned()),
            catchup: Some(true),
            ..Default::default()
        })
        .await
        .expect_err("the revoked cursor cannot be consumed");
    ensure!(
        error.error_code() == Some(ErrorCode::CursorRevoked),
        "wrong refusal: {error:?}"
    );
    ensure!(
        footprint(url).await? == before,
        "refused read changed handles, business state, progress or ACK rows"
    );
    Ok(())
}

pub async fn same_device_distinct_session_cursor_revocation_live() -> Result<()> {
    let database = database("cursor-session-isolation")?.context("real PostgreSQL required")?;
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let mut group = TestServerGroup::try_multi_external_with_node_envs(
        "cursor-session-isolation",
        &[station_env(&database.connect_url, &issuer)],
    )
    .await?
    .context("actual Coland process required")?;
    let (first, _) = standard_client(
        group.server(0),
        &issuer,
        "cursor-alice",
        "ak:device:01904100-0000-7000-8000-000000004501",
    )
    .await?;
    let principal = first
        .principal
        .as_ref()
        .context("accepted founding device required")?;
    let template = crate::scenarios::bridge_contracts::session_grant::mock_session_grant_jwt(
        principal.core_id.as_str(),
        principal.device_id.as_str(),
        group.server(0).service_id().as_str(),
    );
    // Distinct opaque credentials are registered as exact Standard issuances
    // in the explicit mock AA; no client decodes claims for authorization.
    let prefix = template
        .rsplit_once('.')
        .context("fixture credential shape")?
        .0;
    let second_grant = format!(
        "{prefix}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x45; 64])
    );
    issuer.bind_founding_device_grant(
        &second_grant,
        principal.core_id.as_str(),
        principal.device_id.as_str(),
        principal.founding_authorize_event_id.as_str(),
        &principal.device_signing_key.verifying_key(),
    )?;
    let second = group
        .server(0)
        .bind_native_host_session(
            group
                .server(0)
                .client_with_founding_device_grant(principal, second_grant)?,
            &issuer,
        )
        .await?;
    let first_cursor = cursor(&first).await?;
    let second_cursor = cursor(&second).await?;
    let request = AccountCursorRevokeRequestBody {
        cursor: first_cursor.clone(),
        reason_code: ReasonCode::from_wire("user_requested"),
        revoke_scope: CursorRevokeScope::SameSession,
    };
    let before_unowned_revoke = footprint(&database.connect_url).await?;
    let refusal = second
        .sdk()
        .account_cursor_revoke(&request)
        .await
        .expect_err("another session cannot revoke this session group");
    ensure!(refusal.error_code() == Some(ErrorCode::CursorIntegrityInvalid));
    ensure!(
        footprint(&database.connect_url).await? == before_unowned_revoke,
        "unowned session-group revoke changed handles, business state or ACK rows"
    );
    let original = first.sdk().account_cursor_revoke(&request).await?;
    let before_repeat = footprint(&database.connect_url).await?;
    let repeated = first.sdk().account_cursor_revoke(&request).await?;
    ensure!(
        original == repeated && footprint(&database.connect_url).await? == before_repeat,
        "repeated revocation extended or rewrote the original instance"
    );
    revoked(&first, &first_cursor, &database.connect_url).await?;
    second
        .sdk()
        .account_subscribe_batch(&SyncRequestBody {
            after: Some(second_cursor.clone()),
            catchup: Some(true),
            ..Default::default()
        })
        .await?;
    let newly_issued = cursor(&first).await?;
    revoked(&first, &newly_issued, &database.connect_url).await?;
    group.server_mut(0).restart_external_process().await?;
    revoked(&first, &first_cursor, &database.connect_url).await?;
    second
        .sdk()
        .account_subscribe_batch(&SyncRequestBody {
            after: Some(second_cursor),
            catchup: Some(true),
            ..Default::default()
        })
        .await?;
    Ok(())
}

pub async fn waiting_http_cursor_revocation_live() -> Result<()> {
    use std::time::Duration;

    let database = database("cursor-waiting-http")?.context("real PostgreSQL required")?;
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = TestServerGroup::try_multi_external_with_node_envs(
        "cursor-waiting-http",
        &[station_env(&database.connect_url, &issuer)],
    )
    .await?
    .context("actual Coland process required")?;
    let (client, _) = standard_client(
        group.server(0),
        &issuer,
        "cursor-waiter",
        "ak:device:01904100-0000-7000-8000-000000004502",
    )
    .await?;
    let original = cursor(&client).await?;
    let mut body = client
        .sdk()
        .account_subscribe_frames(&SyncRequestBody {
            after: Some(original.clone()),
            catchup: Some(true),
            ..Default::default()
        })
        .await
        .context("valid waiting continuation before revocation")?;
    ensure!(
        tokio::time::timeout(Duration::from_millis(250), body.next_frame())
            .await
            .is_err(),
        "stable continuation emitted before revocation"
    );
    client
        .sdk()
        .account_cursor_revoke(&AccountCursorRevokeRequestBody {
            cursor: original.clone(),
            reason_code: ReasonCode::from_wire("user_requested"),
            revoke_scope: CursorRevokeScope::ThisCursor,
        })
        .await?;
    let after_revocation = footprint(&database.connect_url).await?;
    let next = tokio::time::timeout(Duration::from_secs(40), body.next_frame())
        .await
        .context("revoked waiting response must terminate within the normal idle window")?;
    ensure!(
        matches!(next, Ok(None) | Err(_)),
        "revoked waiting response published successful continuation bytes: {next:?}"
    );
    ensure!(
        footprint(&database.connect_url).await? == after_revocation,
        "waiting refusal advanced handles, business state, progress or ACK rows"
    );
    revoked(&client, &original, &database.connect_url).await?;
    println!(
        "[cursor-revocation] http_waiting=1 current_revocation_completed=1 stale_response_closed=1 exact_handle_fresh_read_cursor_revoked=1 full_refusal_footprint_unchanged=1"
    );
    Ok(())
}

pub async fn waiting_websocket_cursor_revocation_live() -> Result<()> {
    use std::time::Duration;

    use arkret_models_collaboration::sync_frames::websocket::{
        WebSocketAccountOpenParameters, WebSocketOpenParameters, WebSocketServerFrame,
    };
    use arkret_wire::websocket_binding::WebSocketOperationId;

    use crate::scenarios::websocket_live;
    let database = database("cursor-waiting-websocket")?.context("real PostgreSQL required")?;
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = TestServerGroup::try_multi_external_with_node_envs(
        "cursor-waiting-websocket",
        &[station_env(&database.connect_url, &issuer)],
    )
    .await?
    .context("actual Coland process required")?;
    let (client, _) = standard_client(
        group.server(0),
        &issuer,
        "cursor-socket",
        "ak:device:01904100-0000-7000-8000-000000004503",
    )
    .await?;
    let original = cursor(&client).await?;
    let (mut socket, _) = websocket_live::authenticated(group.server(0), &client).await?;
    websocket_live::open(
        &mut socket,
        "cursor-waiter",
        WebSocketOpenParameters::Account(WebSocketAccountOpenParameters {
            after: Some(original.clone()),
            catchup: Some(true),
            ..Default::default()
        }),
        WebSocketOperationId::AccountStreamSubscribe,
    )
    .await?;
    ensure!(
        tokio::time::timeout(
            Duration::from_millis(250),
            websocket_live::next(&mut socket)
        )
        .await
        .is_err(),
        "stable socket continuation emitted before revocation"
    );
    client
        .sdk()
        .account_cursor_revoke(&AccountCursorRevokeRequestBody {
            cursor: original.clone(),
            reason_code: ReasonCode::from_wire("user_requested"),
            revoke_scope: CursorRevokeScope::ThisCursor,
        })
        .await?;
    let after_revocation = footprint(&database.connect_url).await?;
    let error = websocket_live::next(&mut socket).await?;
    ensure!(
        matches!(&error, WebSocketServerFrame::ChannelError { channel_id, error, .. } if channel_id=="cursor-waiter" && error.code==ErrorCode::CursorRevoked),
        "waiting cursor revocation lost its canonical socket refusal: {error:?}"
    );
    ensure!(
        matches!(websocket_live::next(&mut socket).await?, WebSocketServerFrame::Closed { channel_id, .. } if channel_id=="cursor-waiter")
    );
    ensure!(
        footprint(&database.connect_url).await? == after_revocation,
        "socket waiting refusal advanced handles, business state, progress or ACK rows"
    );
    revoked(&client, &original, &database.connect_url).await?;
    websocket_live::finish(&mut socket).await?;
    println!(
        "[cursor-revocation] websocket_waiting=1 canonical_channel_error_cursor_revoked=1 channel_closed=1 full_refusal_footprint_unchanged=1"
    );
    Ok(())
}

pub async fn queued_websocket_cursor_revocation_live() -> Result<()> {
    use arkret_models_collaboration::sync_frames::websocket::{
        WebSocketAccountOpenParameters, WebSocketOpenParameters, WebSocketServerFrame,
    };
    use arkret_wire::websocket_binding::WebSocketOperationId;

    use crate::scenarios::websocket_live;
    for revoke in [false, true] {
        let name = if revoke {
            "cursor-queued-revoked"
        } else {
            "cursor-queued-positive"
        };
        let database = database(name)?.context("real PostgreSQL required")?;
        let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
            HARNESS_INTERNAL_AUTHORITY_SECRET,
        )
        .await?;
        let root = std::env::var_os("COTEST_SERVICE_LOG_DIR")
            .context("owned probe artifact directory required")?;
        let probe = tempfile::Builder::new()
            .prefix("cursor-emission-")
            .tempdir_in(root)?;
        let selected = probe.path().join("selected.json");
        let mut env = station_env(&database.connect_url, &issuer);
        env.push((
            "COLAND_CONFORMANCE_CURSOR_EMISSION_PAUSE_FILE".to_owned(),
            selected.to_string_lossy().into_owned(),
        ));
        let group = TestServerGroup::try_multi_external_with_node_envs(name, &[env])
            .await?
            .context("actual Coland process required")?;
        let (client, account) = standard_client(
            group.server(0),
            &issuer,
            "cursor-queued",
            "ak:device:01904100-0000-7000-8000-000000004504",
        )
        .await?;
        let original = cursor(&client).await?;
        let key = arkret_wire::AccountDataKey::PUSH_RULES;
        let encrypted = arkret_crypto::account_data_crypto::seal_account_data_value_with_nonce(
            &[7; 32],
            &arkret_wire::ActorId::account(account),
            key,
            &serde_json::json!({"enabled":true}),
            [9; 24],
        )?;
        let set = client
            .author_event(
                client
                    .principal
                    .as_ref()
                    .context("accepted device")?
                    .pcr_realm_id
                    .as_str(),
                "ak.account_data.set",
                serde_json::json!({"key":key,"expected_server_revision":0,"body":encrypted}),
            )
            .await?;
        let row = client
            .sdk()
            .account_data_replace(
                key,
                &client.verify_publication(
                    arkret_models_identity::account::AccountDataReplaceRequestBody {
                        set_event: arkret_wire::EventAdmissionSubmission::new(set),
                    },
                )?,
            )
            .await?;
        ensure!(row.revision == 1);
        std::fs::write(
            &selected,
            arkret_canonical::canonical_json_bytes(&vec![arkret_canonical::sha256_digest(
                original.as_bytes(),
            )])?,
        )?;
        std::fs::write(selected.with_extension("pause"), [])?;
        let (mut socket, _) = websocket_live::authenticated(group.server(0), &client).await?;
        websocket_live::open(
            &mut socket,
            "queued-cursor",
            WebSocketOpenParameters::Account(WebSocketAccountOpenParameters {
                after: Some(original.clone()),
                catchup: Some(true),
                ..Default::default()
            }),
            WebSocketOperationId::AccountStreamSubscribe,
        )
        .await?;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while !selected.with_extension("reached.json").exists() {
            ensure!(
                tokio::time::Instant::now() < deadline,
                "actual account frame never reached physical output probe"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let exact = std::fs::read(selected.with_extension("reached.json"))?;
        if revoke {
            client
                .sdk()
                .account_cursor_revoke(&AccountCursorRevokeRequestBody {
                    cursor: original.clone(),
                    reason_code: ReasonCode::from_wire("user_requested"),
                    revoke_scope: CursorRevokeScope::SameSession,
                })
                .await?;
        }
        let before_release = footprint(&database.connect_url).await?;
        std::fs::remove_file(selected.with_extension("pause"))?;
        let frame = websocket_live::next(&mut socket).await?;
        if revoke {
            ensure!(
                matches!(&frame,WebSocketServerFrame::ChannelError{channel_id,error,..} if channel_id=="queued-cursor" && error.code==ErrorCode::CursorRevoked),
                "queued revoked cursor published or misclassified frame: {frame:?}"
            );
            ensure!(
                matches!(websocket_live::next(&mut socket).await?,WebSocketServerFrame::Closed{channel_id,..} if channel_id=="queued-cursor")
            );
            ensure!(
                footprint(&database.connect_url).await? == before_release,
                "queued refusal advanced handles, business state, progress or ACK rows"
            );
            revoked(&client, &original, &database.connect_url).await?;
        } else {
            ensure!(
                arkret_canonical::canonical_json_bytes(&frame)? == exact,
                "positive scheduling control did not deliver the exact queued account frame"
            );
        }
        websocket_live::finish(&mut socket).await?;
        println!(
            "[cursor-revocation] actual_queued_account_frame=1 positive_control={} completed_group_revoke={} exact_response_refused={} full_refusal_footprint_unchanged={}",
            usize::from(!revoke),
            usize::from(revoke),
            usize::from(revoke),
            usize::from(revoke)
        );
    }
    Ok(())
}

pub async fn shared_database_two_process_cursor_revocation_live() -> Result<()> {
    let database = database("cursor-shared-processes")?.context("real PostgreSQL required")?;
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let root =
        std::env::var_os("COTEST_SERVICE_LOG_DIR").context("owned keystore directory required")?;
    let keystore = tempfile::Builder::new()
        .prefix("cursor-shared-keystore-")
        .tempdir_in(root)?;
    let mut env = station_env(&database.connect_url, &issuer);
    let (seed, _) = crate::harness::test_service_signing_key("cursor-shared-station");
    env.extend([
        ("COLAND_NOTARY_SIGNING_KEY".to_owned(), seed),
        (
            "COLAND_KEYSTORE_BACKEND".to_owned(),
            "encrypted_file".to_owned(),
        ),
        (
            "COLAND_KEYSTORE_PATH".to_owned(),
            keystore
                .path()
                .join("keystore.v1")
                .to_string_lossy()
                .into_owned(),
        ),
        (
            "COLAND_KEYSTORE_MASTER_KEY".to_owned(),
            base64::engine::general_purpose::STANDARD.encode([0x77; 32]),
        ),
    ]);
    let mut group = TestServerGroup::try_multi_external_with_node_envs(
        "cursor-shared-processes",
        &[env.clone(), env],
    )
    .await?
    .context("two actual Coland processes required")?;
    ensure!(
        group.server(0).service_id() == group.server(1).service_id(),
        "shared durable issuer loaded as different Station identities"
    );
    let (writer, _) = standard_client(
        group.server(0),
        &issuer,
        "cursor-shared",
        "ak:device:01904100-0000-7000-8000-000000004505",
    )
    .await?;
    let principal = writer
        .principal
        .as_ref()
        .context("accepted shared device")?;
    let crate::harness::ClientSession::Canonical { grant, .. } = writer.session() else {
        anyhow::bail!("actual standard session required")
    };
    let reader = group
        .server(1)
        .bind_native_host_session(
            group
                .server(1)
                .client_with_founding_device_grant(principal, grant.clone())?,
            &issuer,
        )
        .await?;
    let writer_cursor = cursor(&writer).await?;
    let reader_cursor = cursor(&reader).await?;
    writer
        .sdk()
        .account_cursor_revoke(&AccountCursorRevokeRequestBody {
            cursor: writer_cursor.clone(),
            reason_code: ReasonCode::from_wire("user_requested"),
            revoke_scope: CursorRevokeScope::SameDevice,
        })
        .await?;
    revoked(&reader, &writer_cursor, &database.connect_url).await?;
    revoked(&reader, &reader_cursor, &database.connect_url).await?;
    let fresh_reader_cursor = cursor(&reader).await?;
    revoked(&writer, &fresh_reader_cursor, &database.connect_url).await?;
    group.server_mut(1).restart_external_process().await?;
    revoked(&reader, &writer_cursor, &database.connect_url).await?;
    println!(
        "[cursor-revocation] concurrent_os_processes=2 shared_durable_issuer=1 same_device_group=1 cross_process_refusals=3 new_reader_handle_covered=1 independent_reader_process_restart=1 full_refusal_footprint_unchanged=1"
    );
    Ok(())
}

pub async fn issuance_racing_completed_revocation_live() -> Result<()> {
    issuance_racing_revocation(false, false).await
}

pub async fn issuance_racing_repeatable_read_default_live() -> Result<()> {
    issuance_racing_revocation(true, false).await
}

pub async fn realm_list_issuance_racing_revocation_live() -> Result<()> {
    issuance_racing_revocation(false, true).await
}

async fn issuance_racing_revocation(repeatable_read: bool, realm_list: bool) -> Result<()> {
    use std::time::Duration;
    let database = database("cursor-issuance-revoke-race")?.context("real PostgreSQL required")?;
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let mut group = TestServerGroup::try_multi_external_with_node_envs(
        "cursor-issuance-revoke-race",
        &[station_env(&database.connect_url, &issuer)],
    )
    .await?
    .context("actual Coland process required")?;
    let (client, _) = standard_client(
        group.server(0),
        &issuer,
        "cursor-racing",
        "ak:device:01904100-0000-7000-8000-000000004506",
    )
    .await?;
    let original = if realm_list {
        use arkret_models_collaboration::sync_frames::account_subscribe::RealmListRequest;
        for title in [
            "Issuance page alpha",
            "Issuance page beta",
            "Issuance page gamma",
        ] {
            client.create_realm(title).await?;
        }
        let response = client
            .sdk()
            .account_subscribe_batch(&SyncRequestBody {
                catchup: Some(true),
                realm_list: Some(RealmListRequest {
                    after: None,
                    limit: Some(1),
                }),
                ..Default::default()
            })
            .await?;

        response
            .frames
            .iter()
            .find_map(|frame| frame.realm_list.as_ref())
            .and_then(|page| page.next_cursor.clone())
            .context("actual Realm-list continuation")?
    } else {
        cursor(&client).await?
    };
    if repeatable_read {
        let connect = database.connect_url.clone();
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut connection = postgres::Client::connect(&connect, postgres::NoTls)?;
            let name: String = connection
                .query_one("SELECT current_database()", &[])?
                .get(0);
            ensure!(
                name.starts_with("cotest_")
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
                "owned test database identity required"
            );
            connection.batch_execute(&format!(
                "ALTER DATABASE {name} SET default_transaction_isolation='repeatable read'"
            ))?;
            Ok(())
        })
        .await??;
        group.server_mut(0).restart_external_process().await?;
    }

    let connect = database.connect_url.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let held = tokio::task::spawn_blocking(move || -> Result<()> {
        let mut connection = postgres::Client::connect(&connect, postgres::NoTls)?;
        connection.batch_execute("BEGIN; LOCK TABLE sync_cursor_handles IN SHARE MODE")?;
        ready_tx
            .send(())
            .map_err(|_| anyhow::anyhow!("issuance observer was abandoned"))?;
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        loop {
            connection.batch_execute("SELECT pg_stat_clear_snapshot()")?;
            let waiting=connection.query_one("SELECT count(*)::bigint FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query ILIKE '%INSERT INTO sync_cursor_handles%'",&[])?.get::<_,i64>(0);
            if waiting > 0 {
                break;
            }
            if std::time::Instant::now() >= deadline {
                for row in connection.query("SELECT coalesce(wait_event_type,''),coalesce(wait_event,''),left(query,120) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid()",&[])? {
                    eprintln!("issuance boundary diagnostic wait_type={} wait={} statement={}",row.get::<_,String>(0),row.get::<_,String>(1),row.get::<_,String>(2));
                }
                anyhow::bail!("actual continuation did not reach blocked handle issuance");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        entered_tx
            .send(())
            .map_err(|_| anyhow::anyhow!("issuance observer was abandoned"))?;
        let _ = release_rx.recv();
        Ok(())
    });
    ready_rx
        .await
        .context("owned handle-table lock must be established")?;
    let reader = client.clone();
    let after = original.clone();
    let pending = tokio::spawn(async move {
        reader
            .sdk()
            .account_subscribe_batch(&if realm_list {
                use arkret_models_collaboration::sync_frames::account_subscribe::RealmListRequest;
                SyncRequestBody {
                    realm_list: Some(RealmListRequest {
                        after: Some(
                            arkret_wire::Cursor::new(after).expect("validated original page token"),
                        ),
                        limit: Some(1),
                    }),
                    catchup: Some(true),
                    ..Default::default()
                }
            } else {
                SyncRequestBody {
                    after: Some(after),
                    catchup: Some(true),
                    ..Default::default()
                }
            })
            .await
    });
    if tokio::time::timeout(Duration::from_secs(20), entered_rx)
        .await
        .is_err()
    {
        pending.abort();
        let _ = release_tx.send(());
        let _ = held.await;
        anyhow::bail!("actual continuation did not reach blocked handle issuance");
    }
    ensure!(
        !pending.is_finished(),
        "continuation completed before controlled issuance"
    );
    let after_revocation: Result<Value> = async {
        client
            .sdk()
            .account_cursor_revoke(&AccountCursorRevokeRequestBody {
                cursor: original.clone(),
                reason_code: ReasonCode::from_wire("user_requested"),
                revoke_scope: CursorRevokeScope::ThisCursor,
            })
            .await?;
        footprint(&database.connect_url).await
    }
    .await;
    let _ = release_tx.send(());
    held.await??;
    let after_revocation = after_revocation?;
    let result = tokio::time::timeout(Duration::from_secs(40), pending)
        .await
        .context("interrupted continuation must finish within the normal idle window")??;
    let error =
        result.expect_err("continuation cannot consume an input after completed revocation");
    ensure!(
        error.error_code() == Some(ErrorCode::CursorRevoked),
        "issuance race lost its canonical refusal: {error:?}"
    );
    let after = footprint(&database.connect_url).await?;
    let changed = after_revocation["cursor_progress_and_ack"]
        .as_object()
        .context("cursor footprint")?
        .iter()
        .filter(|(table, rows)| after["cursor_progress_and_ack"].get(*table) != Some(*rows))
        .map(|(table, _)| table.as_str())
        .collect::<Vec<_>>();
    ensure!(
        after == after_revocation,
        "refused issuance/revoke race advanced complete handle/business/ACK state: {changed:?}"
    );
    if !realm_list {
        revoked(&client, &original, &database.connect_url).await?;
    }
    println!(
        "[cursor-revocation] blocked_real_handle_insert=1 completed_this_cursor_revoke=1 refused_continuation=1 zero_post_revoke_handle_progress=1"
    );
    Ok(())
}

pub async fn immutable_realm_pages_remain_isolated_live() -> Result<()> {
    use arkret_models_collaboration::sync_frames::account_subscribe::RealmListRequest;
    let database = database("cursor-old-page-isolation")?.context("real PostgreSQL required")?;
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = TestServerGroup::try_multi_external_with_node_envs(
        "cursor-old-page-isolation",
        &[station_env(&database.connect_url, &issuer)],
    )
    .await?
    .context("actual Coland process required")?;
    let (client, _) = standard_client(
        group.server(0),
        &issuer,
        "cursor-pager",
        "ak:device:01904100-0000-7000-8000-000000004507",
    )
    .await?;
    for title in ["Cursor page alpha", "Cursor page beta", "Cursor page gamma"] {
        client.create_realm(title).await?;
    }
    let first = client
        .sdk()
        .account_subscribe_batch(&SyncRequestBody {
            catchup: Some(true),
            realm_list: Some(RealmListRequest {
                after: None,
                limit: Some(1),
            }),
            ..Default::default()
        })
        .await?;
    let first_page = first
        .frames
        .iter()
        .find_map(|frame| frame.realm_list.as_ref())
        .context("actual Realm list page")?
        .clone();
    ensure!(first_page.items.len() == 1);
    let page_cursor = first_page
        .next_cursor
        .clone()
        .context("actual continuation from at least three Realm rows")?;
    let request = SyncRequestBody {
        catchup: Some(true),
        realm_list: Some(RealmListRequest {
            after: Some(arkret_wire::Cursor::new(page_cursor.clone())?),
            limit: Some(1),
        }),
        ..Default::default()
    };
    let original = footprint(&database.connect_url).await?;
    let next = client.sdk().account_subscribe_batch(&request).await?;
    let next_page = next
        .frames
        .iter()
        .find_map(|frame| frame.realm_list.as_ref())
        .context("actual next page")?
        .clone();
    ensure!(
        next_page.snapshot_cursor == first_page.snapshot_cursor
            && next_page.snapshot_revision == first_page.snapshot_revision
            && next_page.items.len() == 1
            && next_page.items[0].realm_id != first_page.items[0].realm_id
    );
    let replay = client.sdk().account_subscribe_batch(&request).await?;
    let replay_page = replay
        .frames
        .iter()
        .find_map(|frame| frame.realm_list.as_ref())
        .context("actual old page replay")?;
    ensure!(
        replay_page.items == next_page.items
            && replay_page.snapshot_cursor == first_page.snapshot_cursor
            && replay_page.snapshot_revision == first_page.snapshot_revision,
        "new issuance changed the old immutable page progress"
    );
    let after_replay = footprint(&database.connect_url).await?;
    let old = original["cursor_progress_and_ack"]["sync_cursor_handles"]
        .as_array()
        .context("old handles")?;
    let retained = after_replay["cursor_progress_and_ack"]["sync_cursor_handles"]
        .as_array()
        .context("retained handles")?;
    ensure!(
        old.iter().all(|row| retained.contains(row)),
        "new page issuance rewrote or deleted an original handle"
    );
    let later = next_page
        .next_cursor
        .clone()
        .context("another independent page handle")?;
    client
        .sdk()
        .account_cursor_revoke(&AccountCursorRevokeRequestBody {
            cursor: page_cursor,
            reason_code: ReasonCode::from_wire("user_requested"),
            revoke_scope: CursorRevokeScope::ThisCursor,
        })
        .await?;
    let before_refusal = footprint(&database.connect_url).await?;
    let error = client
        .sdk()
        .account_subscribe_batch(&request)
        .await
        .expect_err("revoked page cannot resume");
    ensure!(error.error_code() == Some(ErrorCode::CursorRevoked));
    ensure!(
        footprint(&database.connect_url).await? == before_refusal,
        "revoked old page advanced handles, business state, progress or ACK"
    );
    client
        .sdk()
        .account_subscribe_batch(&SyncRequestBody {
            catchup: Some(true),
            realm_list: Some(RealmListRequest {
                after: Some(arkret_wire::Cursor::new(later)?),
                limit: Some(1),
            }),
            ..Default::default()
        })
        .await?;
    println!(
        "[cursor-revocation] real_immutable_realm_list_pages=3 old_page_replay_same_snapshot=1 original_handles_unchanged=1 one_page_revoke_does_not_revoke_other_page=1 complete_refusal_footprint_unchanged=1"
    );
    Ok(())
}

pub async fn legal_expired_wire_precedes_binding_and_revocation_live() -> Result<()> {
    let database = database("cursor-expiry-precedence")?.context("real PostgreSQL required")?;
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = TestServerGroup::try_multi_external_with_node_envs(
        "cursor-expiry-precedence",
        &[station_env(&database.connect_url, &issuer)],
    )
    .await?
    .context("actual Coland process required")?;
    let (alice, _) = standard_client(
        group.server(0),
        &issuer,
        "cursor-expiring",
        "ak:device:01904100-0000-7000-8000-000000004508",
    )
    .await?;
    let (bob, _) = standard_client(
        group.server(0),
        &issuer,
        "cursor-other-owner",
        "ak:device:01904100-0000-7000-8000-000000004509",
    )
    .await?;
    let original = cursor(&alice).await?;
    alice
        .sdk()
        .account_cursor_revoke(&AccountCursorRevokeRequestBody {
            cursor: original.clone(),
            reason_code: ReasonCode::from_wire("user_requested"),
            revoke_scope: CursorRevokeScope::ThisCursor,
        })
        .await?;
    let before = footprint(&database.connect_url).await?;
    let error = bob
        .sdk()
        .account_subscribe_batch(&SyncRequestBody {
            after: Some(original.clone()),
            catchup: Some(true),
            ..Default::default()
        })
        .await
        .expect_err("another owner cannot inspect revoked status");
    ensure!(error.error_code() == Some(ErrorCode::CursorIntegrityInvalid));
    ensure!(footprint(&database.connect_url).await? == before);
    // Wire mutation belongs only to the negative test fixture. Both normal
    // clients still pass opaque strings and never derive authority from them.
    let bytes = arkret_canonical::base64url_decode(
        original
            .strip_prefix("ak:cursor:")
            .context("registered cursor syntax")?,
    )?;
    let mut known: arkret_hlc::Cursor = serde_json::from_slice(&bytes)?;
    known.issued_at = arkret_canonical::normalize_timestamp_canonical(
        chrono::Utc::now() - chrono::Duration::seconds(2),
    );
    known.expires_at = known.issued_at + chrono::Duration::seconds(1);
    let mut unknown = known.clone();
    unknown.h = arkret_hlc::generate_cursor_handle()
        .map_err(|error| anyhow::anyhow!("fixture handle: {error}"))?;
    for wire in [&known, &unknown] {
        let token = format!(
            "ak:cursor:{}",
            arkret_canonical::base64url_encode(arkret_canonical::canonical_json_bytes(wire)?)
        );
        for client in [&alice, &bob] {
            let before = footprint(&database.connect_url).await?;
            let error = client
                .sdk()
                .account_subscribe_batch(&SyncRequestBody {
                    after: Some(token.clone()),
                    catchup: Some(true),
                    ..Default::default()
                })
                .await
                .expect_err("legal expired wire cannot resume");
            ensure!(
                error.error_code() == Some(ErrorCode::CursorExpired),
                "expiry lost canonical precedence: {error:?}"
            );
            let error = client
                .sdk()
                .account_cursor_revoke(&AccountCursorRevokeRequestBody {
                    cursor: token.clone(),
                    reason_code: ReasonCode::from_wire("user_requested"),
                    revoke_scope: CursorRevokeScope::ThisCursor,
                })
                .await
                .expect_err("expired target cannot change revocation ledger");
            ensure!(error.error_code() == Some(ErrorCode::CursorExpired));
            ensure!(
                footprint(&database.connect_url).await? == before,
                "expired wire changed complete handle/business/progress/ACK state"
            );
        }
    }
    println!(
        "[cursor-revocation] revoked_binding_ownership_before_revoke_disclosure=1 legal_wire_expiry_first=1 known_revoked_and_unknown_handles=2 authenticated_owners=2 expired_read_and_revoke_refusals=8 complete_refusal_footprint_unchanged=1"
    );
    Ok(())
}

pub async fn immutable_cursor_cost_live() -> Result<()> {
    use std::time::Instant;

    use arkret_models_collaboration::sync_frames::account_subscribe::RealmListRequest;
    use coland_storage::SyncCursorStore;
    fn latency(mut values: Vec<f64>) -> Value {
        values.sort_by(f64::total_cmp);
        serde_json::json!({"samples": values.len(), "p50_ms": values[values.len().div_ceil(2)-1],
            "p95_ms": values[(values.len()*95).div_ceil(100)-1], "max_ms": values[values.len()-1]})
    }
    let database = database("cursor-cost")?.context("real PostgreSQL required")?;
    let issuer = MockCoauthIntrospectionServer::spawn_with_internal_secret(
        HARNESS_INTERNAL_AUTHORITY_SECRET,
    )
    .await?;
    let group = TestServerGroup::try_multi_external_with_node_envs(
        "cursor-cost",
        &[station_env(&database.connect_url, &issuer)],
    )
    .await?
    .context("actual Coland process required")?;
    let (client, _) = standard_client(
        group.server(0),
        &issuer,
        "cursor-cost-actor",
        "ak:device:01904100-0000-7000-8000-000000004510",
    )
    .await?;
    for title in ["Cost alpha", "Cost beta", "Cost gamma"] {
        client.create_realm(title).await?;
    }
    let first = client
        .sdk()
        .account_subscribe_batch(&SyncRequestBody {
            catchup: Some(true),
            realm_list: Some(RealmListRequest {
                after: None,
                limit: Some(1),
            }),
            ..Default::default()
        })
        .await?;
    let original = first
        .frames
        .iter()
        .find_map(|frame| frame.realm_list.as_ref())
        .and_then(|page| page.next_cursor.clone())
        .context("actual page handle")?;
    let request = SyncRequestBody {
        catchup: Some(true),
        realm_list: Some(RealmListRequest {
            after: Some(arkret_wire::Cursor::new(original.clone())?),
            limit: Some(1),
        }),
        ..Default::default()
    };
    let before = footprint(&database.connect_url).await?;
    let original_rows = before["cursor_progress_and_ack"]["sync_cursor_handles"]
        .as_array()
        .context("original handles")?;
    let mut phases = Vec::new();
    for concurrency in [1usize, 8usize] {
        let baseline = footprint(&database.connect_url).await?;
        let baseline_count = baseline["cursor_progress_and_ack"]["sync_cursor_handles"]
            .as_array()
            .context("handles")?
            .len();
        let started = Instant::now();
        let mut timings = Vec::new();
        for _ in 0..(24 / concurrency) {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..concurrency {
                let reader = client.clone();
                let request = request.clone();
                tasks.spawn(async move {
                    let start = Instant::now();
                    let response = reader.sdk().account_subscribe_batch(&request).await?;
                    let page = response
                        .frames
                        .iter()
                        .find_map(|frame| frame.realm_list.as_ref())
                        .context("live continuation page")?;
                    ensure!(page.items.len() == 1 && page.next_cursor.is_some());
                    Ok::<f64, anyhow::Error>(start.elapsed().as_secs_f64() * 1000.0)
                });
            }
            while let Some(result) = tasks.join_next().await {
                timings.push(result??);
            }
        }
        let elapsed = started.elapsed().as_secs_f64();
        let after = footprint(&database.connect_url).await?;
        let rows = after["cursor_progress_and_ack"]["sync_cursor_handles"]
            .as_array()
            .context("handles")?;
        ensure!(
            original_rows.iter().all(|row| rows.contains(row)),
            "load rewrote an original frozen progress/expiry/identity"
        );
        phases.push(serde_json::json!({"concurrency":concurrency,"requests":24,"seconds":elapsed,"requests_per_second":24.0/elapsed,
            "latency":latency(timings),"new_handle_rows":rows.len()-baseline_count,"original_instances_unchanged":true}));
    }
    client
        .sdk()
        .account_cursor_revoke(&AccountCursorRevokeRequestBody {
            cursor: original.clone(),
            reason_code: ReasonCode::from_wire("user_requested"),
            revoke_scope: CursorRevokeScope::ThisCursor,
        })
        .await?;
    let refusal_before = footprint(&database.connect_url).await?;
    let error = client
        .sdk()
        .account_subscribe_batch(&request)
        .await
        .expect_err("load cannot resurrect revoked original");
    ensure!(error.error_code() == Some(ErrorCode::CursorRevoked));
    ensure!(footprint(&database.connect_url).await? == refusal_before);
    // This storage observer is test-only; client requests retain the opaque token.
    let original_cursor = arkret_hlc::Cursor::decode(&original)?;
    let db = coland_storage_postgres::Db::connect(
        Some(&database.connect_url),
        coland_storage_postgres::PoolTuning {
            max_size: Some(8),
            acquire_timeout_seconds: Some(30),
        },
    )
    .await?;
    let store = coland_storage_postgres::PgSyncCursorStore {
        pool: db.pool.context("PG pool")?,
    };
    let mut lookup = Vec::new();
    for _ in 0..100 {
        let start = Instant::now();
        ensure!(store.get(&original_cursor.h).await?.is_some());
        lookup.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    let connect = database.connect_url.clone();
    let statistics=tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut connection=postgres::Client::connect(&connect,postgres::NoTls)?;
        let row=connection.query_one("SELECT count(*)::bigint,min(expires_at_ms-issued_at_ms)::bigint,max(expires_at_ms-issued_at_ms)::bigint,max(expires_at_ms)::bigint,pg_total_relation_size('sync_cursor_handles')::bigint,pg_total_relation_size('account_sync_cursor_retention')::bigint FROM sync_cursor_handles",&[])?;
        Ok(serde_json::json!({"postgres_version":connection.query_one("SHOW server_version",&[])?.get::<_,String>(0),"handle_rows":row.get::<_,i64>(0),"minimum_ttl_ms":row.get::<_,i64>(1),"maximum_ttl_ms":row.get::<_,i64>(2),"max_expiry_ms":row.get::<_,i64>(3),"handle_relation_bytes":row.get::<_,i64>(4),"retention_relation_bytes":row.get::<_,i64>(5)}))
    }).await??;
    drop(group);
    let started = Instant::now();
    let kept = store
        .prune_expired(chrono::Utc::now().timestamp_millis())
        .await?;
    let current_gc_ms = started.elapsed().as_secs_f64() * 1000.0;
    ensure!(
        kept == 0 && store.get(&original_cursor.h).await?.is_some(),
        "current-time GC deleted a live immutable handle"
    );
    let maintenance_time = statistics["max_expiry_ms"].as_i64().context("expiry")? + 1;
    let started = Instant::now();
    let removed = store.prune_expired(maintenance_time).await?;
    let expired_gc_ms = started.elapsed().as_secs_f64() * 1000.0;
    ensure!(
        removed as i64 == statistics["handle_rows"].as_i64().context("handle count")?
            && store.get(&original_cursor.h).await?.is_none()
    );
    let result = serde_json::json!({"kind":"actual_process_http_and_postgres_store_measurement","baseline":"same binary, same three-Realm frozen page, concurrency 1 versus 8; no previous-version improvement claim",
        "phases":phases,"handle_lookup":latency(lookup),"storage":statistics,"current_time_gc":{"removed":kept,"ms":current_gc_ms},"expiry_boundary_gc":{"removed":removed,"ms":expired_gc_ms,"clock":"explicit store maintenance cutoff after maximum recorded expiry; no wire lifetime was changed"},
        "revoked_refusal_zero_effect":true,"global_stack_override":false,"deduplication":false});
    if let Ok(path) = std::env::var("COTEST_CURSOR_COST_OUTPUT") {
        std::fs::write(path, serde_json::to_vec_pretty(&result)?)?;
    }
    println!("[cursor-cost] {}", serde_json::to_string(&result)?);
    Ok(())
}
