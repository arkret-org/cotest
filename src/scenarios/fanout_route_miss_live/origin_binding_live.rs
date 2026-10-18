//! An unchanged active key cannot replay after a verified origin handoff.
use arkret_models_collaboration::authority_commit::{
    AuthorityHandoffRequest, HistoricalProducerSignerFactEntry, historical_signer_facts_digest,
};
use arkret_wire::{
    AuthorityBundleRequest, Base64UrlString, DetachedSignatureContext, Hash, RealmAuthorityHandoff,
    RealmAuthorityHandoffId, RealmAuthorityTransition,
};
use coland_storage::AuthorityCommitStore;
use coland_storage_postgres::{Db, PgAuthorityCommitStore, PoolTuning};

use super::idempotency_live::{
    first_stored_request, manual_current_origin_fixture_with_successor, snapshot,
};
use super::*;

pub mod snapshot_matrix;

pub async fn run_removed_origin_binding_replay_live() -> Result<()> {
    let successor = database("federation-origin-successor")?
        .context("origin handoff requires actual PostgreSQL")?;
    let mut fixture = manual_current_origin_fixture_with_successor(
        "federation-removed-origin-binding",
        Some(&successor),
    )
    .await?;
    let (request, event, commit) = first_stored_request(&fixture, "removed-origin-binding").await?;
    let signed_at = Instant::now();
    let active_key = current_federation_key(fixture.group.server(0)).await?;
    let frozen_body = request
        .body()
        .and_then(reqwest::Body::as_bytes)
        .context("exact original request bytes")?
        .to_vec();
    let frozen_headers = request.headers().clone();
    let (change, changed) = activate_successor(&mut fixture, &successor.connect_url).await?;
    // The original receiver stays a replica; only the governor moves X -> Z.
    // Observe that verified tenure through the normal new-origin ingress.
    let replicated = replicate(
        fixture.group.server(1),
        fixture.group.server(2),
        &replication_body(&fixture.alice, &change, &changed).await?,
    )
    .await?;
    ensure!(
        matches!(
            replicated.as_slice(),
            [PeerCommittedReplicationOutcomeRecord::Stored {}]
        ),
        "verified handoff change was not replicated: {replicated:?}"
    );
    ensure_same_commit(
        &changed,
        &wait_held(&fixture.bob, &change.event_id, HELD_WINDOW).await?,
    )?;
    let db = Db::connect(
        Some(&fixture._member_database.connect_url),
        PoolTuning::default(),
    )
    .await?;
    let store = PgAuthorityCommitStore {
        pool: db.pool.context("receiver pool")?,
    };
    let current = store
        .current_authority(&fixture.realm.parse()?)
        .await?
        .context("receiver current authority")?;
    ensure!(
        current.service_id == *fixture.group.server(2).service_id() && current.generation == 1,
        "receiver did not install verified successor origin"
    );
    ensure!(
        current_federation_key(fixture.group.server(0)).await? == active_key,
        "origin binding case changed the active service key"
    );
    ensure!(
        signed_at.elapsed() < Duration::from_secs(240),
        "origin proof reached signature expiry"
    );
    let request_hash = arkret_canonical::sha256_digest(&frozen_body)
        .as_str()
        .to_owned();
    let url = fixture._member_database.connect_url.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut client = postgres::Client::connect(&url, postgres::NoTls)?;
        let count: i64 = client.query_one("SELECT count(*) FROM idempotency_keys WHERE operation_id='ak.peer.events.command.submit.v1' AND request_hash=$1 AND response_body->'outcome'->>'status'='stored'", &[&request_hash])?.get(0);
        ensure!(count == 1, "matching original Stored receipt must still exist");
        Ok(())
    }).await??;
    let before = snapshot(&fixture).await?;
    ensure!(
        request.headers() == &frozen_headers
            && request.body().and_then(reqwest::Body::as_bytes) == Some(frozen_body.as_slice())
    );
    let response = fixture.group.server(1).http().execute(request).await?;
    ensure!(
        response.status() == StatusCode::OK,
        "current unchanged key must pass transport authentication"
    );
    let denied: PeerAuthoritySubmitOutcome = response.json().await?;
    ensure!(
        matches!(&denied, PeerAuthoritySubmitOutcome::CommittedReplication(value)
        if matches!(value.replication_outcomes.as_slice(), [PeerCommittedReplicationOutcomeRecord::Rejected {reason_code}] if reason_code == "capability_denied")),
        "removed origin reused cached success: {denied:?}"
    );
    ensure!(
        snapshot(&fixture).await? == before,
        "origin refusal changed accepted/business state"
    );
    ensure_same_commit(
        &commit,
        &wait_held(&fixture.bob, &event.event_id, HELD_WINDOW).await?,
    )?;
    println!(
        "FEDERATION_FIXTURE /cases/1: three_native_stations=1 accepted_governance_change=1 complete_private_import=1 signed_handoff_activation=1 verified_successor_origin=1 same_active_key=1 same_unexpired_body_signature_and_idempotency_key=1 matching_stored_receipt_retained=1 capability_denied=1 full_snapshot_unchanged=1 original_accepted_fact_preserved=1"
    );
    Ok(())
}

async fn activate_successor(
    fixture: &mut CurrentOriginFixture,
    new_url: &str,
) -> Result<(Event, RealmCommit)> {
    let (old, new) = fixture.group.server_pair_mut(0, 2);
    activate_realm_successor(
        old,
        new,
        &fixture.alice,
        &fixture.alice_account,
        &fixture.realm,
        &fixture._governance_database.connect_url,
        new_url,
    )
    .await
}

pub(crate) async fn activate_realm_successor(
    old: &ArkretServer,
    new: &mut ArkretServer,
    owner: &TestActorClient,
    owner_account: &AccountId,
    realm: &str,
    old_url: &str,
    new_url: &str,
) -> Result<(Event, RealmCommit)> {
    let typed_realm: RealmId = realm.parse()?;
    let mut nonce_bytes = [0u8; 32];
    getrandom::fill(&mut nonce_bytes).map_err(anyhow::Error::msg)?;
    let request = AuthorityBundleRequest {
        realm_id: typed_realm.clone(),
        nonce: Base64UrlString::new(arkret_canonical::base64url_encode(nonce_bytes))
            .map_err(anyhow::Error::msg)?,
    };
    let head = owner
        .sdk()
        .realm_authority_bundle(&request)
        .await?
        .realm_stream_head;
    let change = owner.author_event(realm, EventKind::RealmGovernanceStationChange.as_str(), json!({"expected_governance_generation":0,"expected_realm_stream_commit_id":head.commit_id,"new_governance_station_id":new.service_id()})).await?;
    let changed = submit_and_expect_commit(owner, owner_account, &owner.device_id, &change).await?;
    let db = Db::connect(Some(old_url), PoolTuning::default()).await?;
    let store = PgAuthorityCommitStore {
        pool: db.pool.context("outgoing pool")?,
    };
    let mut material = store
        .realm_state_snapshot_material(&typed_realm)
        .await?
        .context("private snapshot material")?;
    material
        .visible_stream_heads
        .sort_by(|a, b| a.stream_ref.cmp(&b.stream_ref));
    let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let old_key = old.federation_signing_key()?;
    let new_key = new.federation_signing_key()?;
    let old_method =
        DidUrl::new(format!("{}#notary-key", old.service_did())).map_err(anyhow::Error::msg)?;
    let new_method =
        DidUrl::new(format!("{}#notary-key", new.service_did())).map_err(anyhow::Error::msg)?;
    let snapshot = coland_services::authority_commit::build_signed_realm_state_snapshot(
        &material,
        old_method.clone(),
        &old_key,
        at,
    )?;
    let originals = store.handoff_originals(&typed_realm).await?;
    let mut facts = Vec::new();
    for full in &originals {
        if let Some(fact) = store
            .producer_signer_fact(&full.event, &full.commit)
            .await?
        {
            facts.push(HistoricalProducerSignerFactEntry {
                target: arkret_wire::CommittedEventRef {
                    event_id: full.event.event_id.clone(),
                    commit_id: full.commit.commit_id.clone(),
                    stream_ref: full.commit.stream_ref.clone(),
                    stream_position: full.commit.stream_position,
                },
                producer_signer_fact: fact,
            });
        }
    }
    facts.sort_by_key(|entry| {
        (
            arkret_canonical::canonical_json_bytes(&entry.target.stream_ref).unwrap(),
            entry.target.stream_position,
            entry.target.event_id.to_string(),
            entry.target.commit_id.to_string(),
        )
    });
    let mut heads = material.visible_stream_heads;
    heads.sort_by(|a, b| a.stream_ref.cmp(&b.stream_ref));
    let sign = |value: &serde_json::Value,
                context,
                method: DidUrl,
                key: &ed25519_dalek::SigningKey| {
        arkret_signatures::detached_object::sign_detached_object(value, context, method, at, key)
    };
    let mut handoff = RealmAuthorityHandoff {
        pcr_private_state_digest: None,
        handoff_id: RealmAuthorityHandoffId::from_digest(arkret_canonical::sha256_bytes(
            change.event_id.as_str().as_bytes(),
        )),
        realm_id: typed_realm.clone(),
        from_generation: 0,
        to_generation: 1,
        from_service_id: old.service_id().clone(),
        to_service_id: new.service_id().clone(),
        change_event_ref: change.event_id.clone(),
        change_commit_id: changed.commit_id.clone(),
        final_stream_heads_digest: Hash::new(arkret_canonical::canonical_sha256(&heads)?)?,
        historical_signer_facts_digest: Some(historical_signer_facts_digest(&facts)?),
        snapshot_ref: snapshot.snapshot_id.clone(),
        old_authority_signature: changed.signature.clone(),
        new_authority_acceptance_signature: changed.signature.clone(),
    };
    let unsigned = arkret_canonical::unsigned_value(
        &handoff,
        &[
            "old_authority_signature",
            "new_authority_acceptance_signature",
        ],
    )?;
    handoff.old_authority_signature = sign(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityHandoffOld,
        old_method,
        &old_key,
    )?;
    handoff.new_authority_acceptance_signature = sign(
        &unsigned,
        DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
        new_method.clone(),
        &new_key,
    )?;
    let mut bundle = owner.sdk().realm_authority_bundle(&request).await?;
    bundle.authority_transitions.push(RealmAuthorityTransition {
        change_event: change.clone(),
        change_commit: changed.clone(),
        handoff: handoff.clone(),
    });
    bundle.current_generation = 1;
    bundle.current_service_id = new.service_id().clone();
    bundle.current_route_record =
        serde_json::to_value(new.sdk()?.open_service_resolution(new.service_id()).await?)?;
    bundle.bundle_issued_at = at;
    bundle.current_assertion.current_generation = 1;
    bundle.current_assertion.current_service_id = new.service_id().clone();
    bundle.current_assertion.last_handoff_ref = Some(handoff.handoff_id.clone());
    bundle.current_assertion.expires_at = at + chrono::Duration::seconds(60);
    bundle.current_assertion.signature = sign(
        &arkret_canonical::unsigned_value(&bundle.current_assertion, &["signature"])?,
        DetachedSignatureContext::RealmAuthorityCurrentAssertion,
        new_method,
        &new_key,
    )?;
    let activation = AuthorityHandoffRequest {
        pcr_private_state: None,
        handoff,
        final_stream_heads: heads,
        snapshot,
        authority_bundle: bundle,
        historical_signer_facts: Some(facts),
    };
    activation.validate_new_handoff()?;
    activation.validate_imported_signer_facts(&originals)?;
    drop(store);
    drop(originals);
    // Preserve the incoming deployment identity while importing all private
    // Realm ledgers, rather than using the public member snapshot as an import.
    new.stop_external_process().await?;
    import_private_database(old_url, new_url).await?;
    new.start_external_process().await?;
    let (status, body) = new
        .signed_peer_post(
            old,
            "/_arkret/peer/realm-authority/handoff",
            &arkret_canonical::canonical_json_bytes(&activation)?,
            new.service_id(),
        )
        .await?;
    ensure!(
        status.is_success(),
        "incoming native handoff activation: {status} {}",
        String::from_utf8_lossy(&body)
    );
    let (status, body) = old
        .signed_peer_post(
            new,
            "/_arkret/peer/realm-authority/handoff",
            &arkret_canonical::canonical_json_bytes(&activation)?,
            old.service_id(),
        )
        .await?;
    ensure!(
        status.is_success(),
        "outgoing native handoff installation: {status} {}",
        String::from_utf8_lossy(&body)
    );
    Ok((change, changed))
}

async fn import_private_database(source: &str, destination: &str) -> Result<()> {
    let source = source.to_owned();
    let destination = destination.to_owned();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut own=postgres::Client::connect(&destination,postgres::NoTls)?;
        let mut rows=Vec::new();
        for table in ["device_inventory_station","devices","service_identity","webvh_documents","webvh_log_events"] {
            rows.push((table,own.query(&format!("SELECT to_jsonb(r) FROM {table} r"),&[])?.into_iter().map(|r|r.get::<_,serde_json::Value>(0)).collect::<Vec<_>>()));
        }
        drop(own);
        let path=std::env::temp_dir().join(format!("2345c-private-handoff-{}.sql",std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()));
        let dump=std::process::Command::new(std::env::var_os("COTEST_PG_DUMP").unwrap_or_else(|| "pg_dump".into())).args(["--clean","--if-exists","--no-owner","--no-privileges","--file"]).arg(&path).arg(&source).output()?;
        ensure!(dump.status.success(),"private pg_dump: {}",String::from_utf8_lossy(&dump.stderr));
        let restore=std::process::Command::new(std::env::var_os("COTEST_PSQL").unwrap_or_else(|| "psql".into())).args(["--single-transaction","--set=ON_ERROR_STOP=1","--file"]).arg(&path).arg(&destination).output()?;
        std::fs::remove_file(path)?;
        ensure!(restore.status.success(),"private psql import: {}",String::from_utf8_lossy(&restore.stderr));
        let mut own=postgres::Client::connect(&destination,postgres::NoTls)?;
        let mut txn=own.transaction()?;
        txn.execute("DELETE FROM service_identity",&[])?;
        txn.execute("DELETE FROM devices",&[])?;
        txn.execute("DELETE FROM device_inventory_station",&[])?;
        for (table,records) in rows {
            for record in records {
                txn.execute(&format!("INSERT INTO {table} SELECT * FROM jsonb_populate_record(NULL::{table},$1) ON CONFLICT DO NOTHING"),&[&record])?;
            }
        }
        txn.commit()?;
        Ok(())
    }).await?
}
