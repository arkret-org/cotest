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
                &arkret_models_identity::account::AccountDataReplaceRequestBody {
                    set_event: arkret_wire::EventAdmissionSubmission::new(set),
                },
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
