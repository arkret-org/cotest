//! Stateful consumers of the same-core/two-Station account isolation invariant.
//! PostgreSQL execution is explicit and fails if its prerequisites are absent.
use anyhow::{Context, Result, ensure};
use arkret_canonical::{DigestSuite, canonical_json_bytes};
use arkret_models_identity::PrincipalResolutionProjection;
use arkret_wire::{
    AccountId, ActorId, CommitStreamRef, CommittedEventRef, Did, DidCoreId, Event, EventKind,
    RealmCommitId, RealmId, ScopeRef,
};
use chrono::{Duration, Utc};
use serde_json::json;
use soland_storage::*;
use soland_storage_postgres::test_database::TestDatabase;
use soland_storage_postgres::{Db, PgPersistenceStore, PoolTuning};

const DEVICE: &str = "ak:device:01904100-0000-7000-8000-000000002002";
const DATA_KEY: &str = "ak.read_receipt.preferences";

struct AccountFixture {
    account: AccountId,
    pcr: PrincipalResolutionRecord,
    ack: String,
    token: String,
    cursor: String,
}

fn account(station: &str) -> Result<AccountId> {
    Ok(AccountId::new(
        DidCoreId::new("ak:did_core:web:station-isolation.example")?,
        DidCoreId::new(format!("ak:did_core:web:{station}.example"))?,
    ))
}

async fn seed(
    store: &dyn PersistenceStore,
    database_url: &str,
    station: &str,
) -> Result<AccountFixture> {
    let account = account(station)?;
    // A Station owns one immutable device inventory; the production identity
    // bootstrap installs this row before accepting verified devices.
    let database_url = database_url.to_owned();
    let station_id = account.station_id.to_string();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut pg = postgres::Client::connect(&database_url, postgres::NoTls)?;
        pg.execute(
            "INSERT INTO device_inventory_station(singleton, station_id) VALUES(TRUE, $1)",
            &[&station_id],
        )?;
        Ok(())
    })
    .await??;
    let now = arkret_canonical::normalize_timestamp_canonical(Utc::now());
    let pk = store
        .accounts()
        .put(&AccountRecord {
            pk: AccountPk(0),
            principal_id: account.principal_id.clone(),
            station_id: account.station_id.clone(),
            localpart: "alice".into(),
            display_name: Some(station.into()),
            bio: None,
            avatar_blob_ref: None,
            created_at: now,
        })
        .await?;
    ensure!(matches!(
        store
            .account_data()
            .compare_and_set(
                &AccountDataRecord {
                    actor: account.principal_id.to_string(),
                    account_data_key: DATA_KEY.into(),
                    revision: 1,
                    payload: json!({"station": station}),
                    tombstone: false,
                    updated_at: now,
                },
                0
            )
            .await?,
        AccountDataCasResult::Applied(_)
    ));
    let device_authorize_event_id = arkret_wire::EventId::from_digest(
        DigestSuite::Sha256,
        arkret_canonical::digest_bytes(DigestSuite::Sha256, station.as_bytes()),
    );
    let device_authorization = DeviceRevocationGateSelector {
        principal_id: account.principal_id.clone(),
        station_id: account.station_id.clone(),
        device_id: DEVICE.into(),
        authorization_ref: CommittedEventRef {
            event_id: device_authorize_event_id.clone(),
            commit_id: RealmCommitId::new(
                "ak:realm_commit:Ac08ROpjn3Ilj_UaM-_XLY93u4SUTptG0-Q-_CUDb5aS",
            )?,
            stream_ref: CommitStreamRef::Realm {
                realm_id: RealmId::from_event_id(&device_authorize_event_id),
            },
            stream_position: 0,
        },
    };
    store
        .devices()
        .seed_test_record(&DeviceInventoryRecord {
            actor: account.principal_id.to_string(),
            device_id: DEVICE.into(),
            display_name: Some(station.into()),
            verification_state: "verified".into(),
            payload: json!({
                "device_authorization_ref": device_authorization.authorization_ref,
                "station_id": account.station_id.clone(),
            }),
            created_at: now,
            updated_at: now,
            revoked_at: None,
        })
        .await?;
    let token = format!("session-{station}");
    store
        .sessions()
        .put(&SessionRecord {
            token_hash: token.clone(),
            account_pk: pk,
            actor: account.principal_id.to_string(),
            device_id: DEVICE.into(),
            audience: account.station_id.to_string(),
            session_public_key: None,
            agent_session: None,
            expires_at: now + Duration::hours(1),
            created_at: now,
            revoked_at: None,
        })
        .await?;
    let cursor = format!("cursor-{station}");
    store
        .sync_cursors()
        .upsert(&SyncCursorRecord {
            handle: cursor.clone(),
            binding_subject: Some(account.principal_id.to_string()),
            device_id: Some(DEVICE.into()),
            service_id: account.station_id.clone(),
            filter_digest: Some("filter".into()),
            purpose: "stream".into(),
            positions: Some(json!({"station": station})),
            target: None,
            issued_at_ms: now.timestamp_millis(),
            expires_at_ms: (now + Duration::hours(1)).timestamp_millis(),
        })
        .await?;
    store
        .device_messages()
        .append(
            None,
            DeviceMessageRecord {
                idempotency_key: "same-logical-id".into(),
                sender: account.principal_id.to_string(),
                recipient: account.principal_id.to_string(),
                device_id: DEVICE.into(),
                recipient_device_authorization: device_authorization.clone(),
                position: 1,
                content: json!({"station": station}),
                created_at: now,
            },
            100,
        )
        .await?;
    let queue = store
        .device_messages()
        .list_after(account.principal_id.as_str(), DEVICE, 0, 100)
        .await?;
    ensure!(queue.len() == 1);
    let ack = store
        .device_messages()
        .issue_ack_token(account.principal_id.as_str(), DEVICE, queue[0].position)
        .await?
        .context("queue ack token")?;
    store
        .push_devices()
        .register(
            &device_authorization,
            json!({
                "registration_id": "same-registration",
                "account_id": account.clone(),
                "device_id": DEVICE,
                "push_gateway": "https://push.example",
                "push_key": "same-key",
                "platform": null,
                "app_id": "inkson",
                "visible_notification_opt_in": false,
                "push_route_id": "inkson",
                "push_target_id": "ak:pseudonym:push:kosc9iQ4gVct1OB-b6X364WIFIsJFVbVzn7BMBs1sm8",
                "salt_epoch_id": "station-isolation",
                "expires_at": null,
                "retained_push_targets": [],
            }),
        )
        .await?;
    let genesis = arkret_wire::test_support::raw_event_at(
        EventKind::RealmCreate.as_str(),
        ScopeRef::RealmGenesis,
        account.principal_id.clone(),
        account.station_id.clone(),
        json!({"sequence": 0}),
        now,
    )?;
    let genesis = sign_portable_event(genesis, station)?;
    let pcr = PrincipalResolutionRecord {
        account_id: account.clone(),
        pcr_realm_id: genesis.realm_id.clone(),
        genesis_event: genesis.clone(),
        current_event: genesis.clone(),
        projection: PrincipalResolutionProjection {
            did: Did::new("did:web:station-isolation.example")?,
            method_history_head: format!("head-{station}"),
            version_id: "1".into(),
            resolution_event_ref: genesis.event_id.to_string(),
            updated_at: now,
        },
    };
    ensure!(matches!(
        store
            .principal_resolutions()
            .compare_and_set(None, pcr.clone())
            .await?,
        PrincipalResolutionCasResult::Applied(_)
    ));
    Ok(AccountFixture {
        account,
        pcr,
        ack,
        token,
        cursor,
    })
}

async fn verify_isolation(
    left: &dyn PersistenceStore,
    right: &dyn PersistenceStore,
    a: &AccountFixture,
    b: &AccountFixture,
) -> Result<()> {
    ensure!(a.account.principal_id == b.account.principal_id && a.account != b.account);
    let principal = a.account.principal_id.as_str();
    for (own, peer, fixture, other, label) in [
        (left, right, a, b, "station-a"),
        (right, left, b, a, "station-b"),
    ] {
        ensure!(own.accounts().get(&fixture.account).await?.is_some());
        ensure!(own.accounts().get(&other.account).await?.is_none());
        ensure!(
            own.account_data()
                .get(principal, DATA_KEY)
                .await?
                .context("account data")?
                .payload["station"]
                == label
        );
        ensure!(
            own.principal_resolutions()
                .by_account_id(&fixture.account)
                .await?
                == Some(fixture.pcr.clone())
        );
        ensure!(
            own.principal_resolutions()
                .by_account_id(&other.account)
                .await?
                .is_none()
        );
        ensure!(
            own.devices()
                .get(principal, DEVICE)
                .await?
                .context("device")?
                .payload["station_id"]
                == fixture.account.station_id.as_str()
        );
        let stored = fixture.pcr.genesis_event.clone();
        verify_portable_event(&stored, label)?;
        ensure!(
            verify_portable_event(
                &stored,
                if label == "station-a" {
                    "station-b"
                } else {
                    "station-a"
                }
            )
            .is_err()
        );
        let mut rewritten = stored.clone();
        rewritten.actor_id = ActorId::account(other.account.clone());
        ensure!(verify_portable_event(&rewritten, label).is_err());
        ensure!(
            canonical_json_bytes(&stored)? == canonical_json_bytes(&fixture.pcr.genesis_event)?
        );
        let session = own
            .sessions()
            .get(&fixture.token)
            .await?
            .context("own session")?;
        ensure!(session.audience == fixture.account.station_id.as_str());
        ensure!(
            own.accounts()
                .get_by_pk(session.account_pk)
                .await?
                .context("session account")?
                .station_id
                == fixture.account.station_id
        );
        ensure!(peer.sessions().get(&fixture.token).await?.is_none());
        ensure!(
            own.sync_cursors()
                .get(&fixture.cursor)
                .await?
                .context("own cursor")?
                .service_id
                == fixture.account.station_id
        );
        ensure!(peer.sync_cursors().get(&fixture.cursor).await?.is_none());
        ensure!(
            peer.device_messages()
                .ack_with_token(principal, DEVICE, &fixture.ack)
                .await?
                .is_none()
        );
        let queue = own
            .device_messages()
            .list_after(principal, DEVICE, 0, 100)
            .await?;
        ensure!(queue.len() == 1 && queue[0].content["station"] == label);
        ensure!(
            own.push_devices().snapshot_all().await?[0]["account_id"]["station_id"]
                == fixture.account.station_id.as_str()
        );
        let mut takeover = fixture.pcr.clone();
        takeover.account_id = other.account.clone();
        ensure!(
            peer.principal_resolutions()
                .compare_and_set(None, takeover)
                .await
                .is_err()
        );
    }
    // A destructive operation on B must not acknowledge, revoke or rewrite A.
    ensure!(
        right
            .device_messages()
            .ack_with_token(principal, DEVICE, &b.ack)
            .await?
            == Some(1)
    );
    right.sessions().delete(&b.token).await?;
    ensure!(right.sync_cursors().delete(&b.cursor).await?);
    ensure!(
        right
            .push_devices()
            .unregister(&b.account, DEVICE, None, None)
            .await?
            == 1
    );
    ensure!(
        left.device_messages()
            .list_after(principal, DEVICE, 0, 100)
            .await?
            .len()
            == 1
    );
    ensure!(left.sessions().get(&a.token).await?.is_some());
    ensure!(left.sync_cursors().get(&a.cursor).await?.is_some());
    ensure!(left.push_devices().snapshot_all().await?.len() == 1);
    ensure!(
        left.principal_resolutions()
            .by_account_id(&a.account)
            .await?
            == Some(a.pcr.clone())
    );
    Ok(())
}

fn sign_portable_event(event: Event, station: &str) -> Result<Event> {
    use arkret_signatures::{Ed25519PayloadSigner, SignEventOptions, sign_event};
    use arkret_wire::{AuthoredEvent, DidUrl};
    let did = Did::new("did:web:station-isolation.example")?;
    let method = DidUrl::new(format!("{did}#device")).map_err(anyhow::Error::msg)?;
    let producer = Ed25519PayloadSigner::from_did_key_seed([40; 32], did, method.clone());
    let mut authored = AuthoredEvent::from_verified_with_digest_suite(event, DigestSuite::Sha256)?;
    let now = authored.created_at;
    sign_event(
        &mut authored,
        &producer,
        SignEventOptions::new().with_created_at(now),
    )?;
    let event = authored.into_event();
    verify_portable_event(&event, station)?;
    Ok(event)
}

fn verify_portable_event(event: &Event, station: &str) -> Result<()> {
    use arkret_signatures::proof::{PublicKeyMaterial, verify_ed25519_detached_jws_proof};
    event.validate_proof_bindings_with_digest_suite(DigestSuite::Sha256)?;
    ensure!(event.producer_proof.is_some());
    ensure!(
        event.actor_id.route_service_id()
            == &DidCoreId::new(format!("ak:did_core:web:{station}.example"))?
    );
    let producer = event.producer_proof.as_ref().expect("producer proof");
    verify_ed25519_detached_jws_proof(
        producer,
        &canonical_json_bytes(&event.digest_payload()?)?,
        &event.actor_id,
        &PublicKeyMaterial::Ed25519Raw {
            bytes: ed25519_dalek::SigningKey::from_bytes(&[40; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        },
    )?;
    Ok(())
}

async fn connect(url: &str) -> Result<PgPersistenceStore> {
    Ok(PgPersistenceStore::new(
        Db::connect(Some(url), PoolTuning::default())
            .await?
            .pool
            .context("PostgreSQL pool")?,
    ))
}

/// Two Stations, two databases, reopened pools.
///
/// This used to be ignored because it wanted two disposable databases that the
/// suite could not produce. Leases produce them, so it now runs by default and
/// is the only remaining form of this case: the in-memory twin it replaced
/// proved isolation between two process-local maps, not between two databases.
#[tokio::test(flavor = "multi_thread")]
async fn same_core_two_station_accounts_never_merge_state_postgres_reopen() -> Result<()> {
    let left_database = TestDatabase::lease().await;
    let right_database = TestDatabase::lease().await;
    let left = connect(left_database.url()).await?;
    let right = connect(right_database.url()).await?;
    let a = seed(&left, left_database.url(), "station-a").await?;
    let b = seed(&right, right_database.url(), "station-b").await?;
    drop(left);
    drop(right);
    // New pools and repositories cannot consult the initial process-local caches.
    let left = connect(left_database.url()).await?;
    let right = connect(right_database.url()).await?;
    verify_isolation(&left, &right, &a, &b).await
}
