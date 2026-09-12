//! Stateful consumers of the same-core/two-Station account isolation invariant.
//! PostgreSQL execution is explicit and fails if its prerequisites are absent.
use anyhow::{Context, Result, ensure};
use arkret_canonical::{DigestSuite, canonical_json_bytes};
use arkret_models_identity::PrincipalResolutionProjection;
use arkret_wire::{AccountId, ActorId, Did, DidCoreId, Event, EventKind, Hlc, ScopeRef};
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

async fn seed(store: &dyn PersistenceStore, station: &str) -> Result<AccountFixture> {
    let account = account(station)?;
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
    store
        .devices()
        .put(&DeviceInventoryRecord {
            actor: account.principal_id.to_string(),
            device_id: DEVICE.into(),
            display_name: Some(station.into()),
            verification_state: "verified".into(),
            payload: json!({"device_generation": 1, "station_id": account.station_id}),
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
                position: 1,
                content: json!({"station": station}),
                created_at: now,
            },
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
        .register(json!({
            "registration_id": "same-registration", "actor": account.principal_id,
            "device_id": DEVICE, "push_gateway": "https://push.example", "push_key": "same-key",
            "app_id": "inkson", "station_id": account.station_id,
        }))
        .await?;
    let genesis = arkret_wire::test_support::raw_event_at(
        EventKind::RealmCreate.as_str(),
        ScopeRef::RealmGenesis,
        account.principal_id.clone(),
        account.station_id.clone(),
        0,
        Hlc::new("019f00000000-0000-00000001")?,
        json!({"sequence": 0}),
        now,
    )?;
    let genesis = sign_portable_event(genesis, station)?;
    let bytes = canonical_json_bytes(&genesis.digest_payload()?)?;
    store
        .events()
        .put(CanonicalEventRecord {
            event_id: genesis.event_id.to_string(),
            actor_id: genesis.actor_id.to_string(),
            actor_seq: 0,
            realm_id: Some(genesis.realm_id.to_string()),
            kind: genesis.kind.to_string(),
            schema_id: EventKind::RealmCreate
                .descriptor()
                .and_then(|d| d.payload_schema_ref)
                .unwrap_or(arkret_wire::SchemaId::EVENT_PAYLOAD_V1)
                .into(),
            digest_suite: DigestSuite::Sha256,
            canonical_digest: arkret_canonical::digest(DigestSuite::Sha256, &bytes),
            canonical_bytes: bytes,
            envelope: serde_json::to_value(&genesis)?,
            received_at: now,
        })
        .await?;
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
            own.events()
                .get(fixture.pcr.genesis_event.event_id.as_str())
                .await?
                .is_some()
        );
        ensure!(
            peer.events()
                .get(fixture.pcr.genesis_event.event_id.as_str())
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
        let stored: Event = serde_json::from_value(
            own.events()
                .get(fixture.pcr.genesis_event.event_id.as_str())
                .await?
                .context("stored event")?
                .envelope,
        )?;
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
            own.push_devices().snapshot_all().await?[0]["station_id"]
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
            .unregister(principal, DEVICE, None, None)
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
        &method,
        SignEventOptions::new(cotest::fixture_signer_evidence_ref(station)).with_created_at(now),
    )?;
    let event = authored.into_event();
    verify_portable_event(&event, station)?;
    Ok(event)
}

fn verify_portable_event(event: &Event, station: &str) -> Result<()> {
    use arkret_signatures::proof::{PublicKeyMaterial, verify_ed25519_detached_jws_proof};
    event.validate_proof_bindings_with_digest_suite(DigestSuite::Sha256)?;
    ensure!(event.proofs.len() == 1);
    ensure!(
        event.actor_id.route_service_id()
            == &DidCoreId::new(format!("ak:did_core:web:{station}.example"))?
    );
    let producer = &event.proofs[0];
    ensure!(
        producer.signer_resolution_evidence_ref
            == Some(cotest::fixture_signer_evidence_ref(station))
    );
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
    let a = seed(&left, "station-a").await?;
    let b = seed(&right, "station-b").await?;
    drop(left);
    drop(right);
    // New pools and repositories cannot consult the initial process-local caches.
    let left = connect(left_database.url()).await?;
    let right = connect(right_database.url()).await?;
    verify_isolation(&left, &right, &a, &b).await
}
