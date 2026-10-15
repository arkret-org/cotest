//! Operational private import and native signed peer handoff activation.
use arkret_models_collaboration::authority_commit::{
    AuditPairedEventAcceptanceOutcome, AuditPairedEventUnitSubmission, AuthorityHandoffRequest,
    HistoricalProducerSignerFactEntry, historical_signer_facts_digest,
};
use arkret_models_collaboration::strand_watch_operations::WatchAuditReadRequest;
use arkret_wire::{
    AuthorityBundleRequest, Base64UrlString, DetachedSignatureContext, DidUrl, Hash,
    RealmAuthorityHandoff, RealmAuthorityHandoffId, RealmAuthorityTransition,
};
use coland_storage::AuthorityCommitStore;
use coland_storage_postgres::{Db, PgAuthorityCommitStore, PoolTuning};
use serde_json::json;

use super::*;
use crate::harness::CanonicalJsonBody;

pub(super) async fn run(
    group: &mut TestServerGroup,
    delivery: &crate::harness::ScanGapControl,
    old_url: &str,
    new_url: &str,
    owner: &TestActorClient,
    alice: &TestActorClient,
    bob: &TestActorClient,
    realm: &str,
    strand: &StrandId,
    original: &AuditPairedEventUnitSubmission,
    original_outcome: &AuditPairedEventAcceptanceOutcome,
    frozen: &WatchAuditReadRequest,
) -> Result<()> {
    ensure!(old_url != new_url, "handoff uses one database");
    let old = group.server(1);
    let new = group.server(2);
    let typed_realm: RealmId = realm.parse()?;
    let owner_actor = ActorId::account(arkret_wire::AccountId::new(
        owner.principal.as_ref().context("owner")?.core_id.clone(),
        old.service_id().clone(),
    ));
    let mut empty=owner.author_event(realm,EventKind::StrandCreate.as_str(),json!({"object":{"schema":"ak.schema.strand.v1","realm_id":realm,
        "tracks":{"discussion":{"is_primary":true,"profile":"discussion"}},"metadata":{"title":"Never watched before handoff"},
        "state":"active","created_by":owner_actor,"created_at":arkret_canonical::format_timestamp_canonical(chrono::Utc::now())}})).await?;
    empty
        .payload
        .get_mut("object")
        .and_then(serde_json::Value::as_object_mut)
        .context("Strand object")?
        .insert(
            "created_at".to_owned(),
            json!(arkret_canonical::format_timestamp_canonical(
                empty.created_at
            )),
        );
    crate::harness::refresh_typed_event_proof(&mut empty)?;
    submit_and_expect_commit(
        owner,
        owner_actor.as_account_id().context("owner Account")?,
        &owner.device_id,
        &empty,
    )
    .await?;
    let empty_strand = StrandId::from_event_id(&empty.event_id);
    let mut nonce_bytes = [0u8; 32];
    getrandom::fill(&mut nonce_bytes).map_err(anyhow::Error::msg)?;
    let nonce = Base64UrlString::new(arkret_canonical::base64url_encode(nonce_bytes))
        .map_err(anyhow::Error::msg)?;
    let request = AuthorityBundleRequest {
        realm_id: typed_realm.clone(),
        nonce,
    };
    let head = owner
        .sdk()
        .realm_authority_bundle(&request)
        .await?
        .realm_stream_head;
    let selector = StrandWatchCurrentRequestBody {
        realm_id: typed_realm.clone(),
        strand_id: strand.clone(),
        watcher_actor_id: ActorId::account(arkret_wire::AccountId::new(
            bob.principal.as_ref().context("watcher")?.core_id.clone(),
            group.server(0).service_id().clone(),
        )),
    };
    delivery.hold_next_watch_reply();
    let late_client = bob.clone();
    let late_request = selector.clone();
    let late = tokio::spawn(async move {
        Ok::<_, anyhow::Error>(
            late_client
                .post("/_arkret/self/strands/watch/current")
                .canonical_json(&late_request)?
                .send()
                .await?,
        )
    });
    delivery.wait_for_held_watch_reply().await?;
    let change = owner
        .author_event(
            realm,
            EventKind::RealmGovernanceStationChange.as_str(),
            json!({
        "expected_governance_generation":0,"expected_realm_stream_commit_id":head.commit_id,
        "new_governance_station_id":new.service_id()}),
        )
        .await?;
    let account = arkret_wire::AccountId::new(
        owner.principal.as_ref().context("owner")?.core_id.clone(),
        old.service_id().clone(),
    );
    let changed = submit_and_expect_commit(owner, &account, &owner.device_id, &change).await?;
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
        change_event: change,
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
    group.server_mut(2).stop_external_process().await?;
    import_private_database(old_url, new_url).await?;
    group.server_mut(2).start_external_process().await?;
    let old = group.server(1);
    let new = group.server(2);
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
    // Delivery invalidates an observed higher tenure; it is not a distributed
    // oracle for a change the origin has not observed. Force a fresh native
    // read through the new governor before releasing the old accepted reply.
    ensure!(
        matches!(
            read(bob, &selector).await?,
            StrandWatchCurrentOutcome::Current {
                governance_generation: 1,
                ..
            }
        ),
        "origin did not observe the new governor before delayed delivery"
    );
    delivery.release_watch_reply();
    let late = late.await??;
    let status = late.status();
    let body = late.text().await?;
    let problem: serde_json::Value = serde_json::from_str(&body)?;
    ensure!(
        status == StatusCode::SERVICE_UNAVAILABLE
            && problem["type"] == "https://arkret.org/problems/revision_unavailable"
            && !body.contains("watcher_actor_id"),
        "old-tenure reply crossed handoff delivery: {status} {body}"
    );
    for ordinal in [0, 1, 2] {
        group.server_mut(ordinal).restart_external_process().await?;
    }
    let replay: AuditPairedEventAcceptanceOutcome = serde_json::from_value(
        expect_json(
            alice
                .post("/_arkret/self/events")
                .canonical_json(original)?,
            StatusCode::OK,
        )
        .await?,
    )?;
    ensure!(
        &replay == original_outcome,
        "handoff reexecuted an accepted original pair"
    );
    let response = alice
        .post("/_arkret/self/strands/watch/audit-read")
        .canonical_json(frozen)?
        .send()
        .await?;
    ensure!(
        response.status().is_client_error(),
        "old frozen observation became a new-tenure ticket"
    );
    ensure!(
        matches!(
            read(bob, &selector).await?,
            StrandWatchCurrentOutcome::Current { .. }
        ),
        "complete import lost a written selector"
    );
    let absence = StrandWatchCurrentRequestBody {
        strand_id: empty_strand,
        ..selector.clone()
    };
    ensure!(
        matches!(
            read(bob, &absence).await?,
            StrandWatchCurrentOutcome::NeverWritten {
                governance_generation: 1,
                ..
            }
        ),
        "nonzero tenure did not prove never-written from the complete import"
    );
    let update = event(
        bob,
        realm,
        &StrandWatchSetPayload::set(
            strand.clone(),
            selector.watcher_actor_id.clone(),
            StrandWatchLevel::All,
            None,
        )
        .with_expected_value(StrandWatchCurrentValue::Set(StrandWatchExpectedValue {
            level: StrandWatchLevel::Participating,
            level_public: None,
        })),
    )
    .await?;
    let account = selector
        .watcher_actor_id
        .as_account_id()
        .context("watcher Account")?;
    let next = submit_and_expect_commit(bob, account, &bob.device_id, &update).await?;
    ensure!(
        next.governance_generation == 1
            && next.previous_commit_ref.as_ref() == Some(&changed.commit_id),
        "first new-tenure write did not extend the frozen Realm head"
    );
    current(
        read(bob, &selector).await?,
        &next,
        StrandWatchCurrentValue::Set(StrandWatchExpectedValue {
            level: StrandWatchLevel::All,
            level_public: None,
        }),
    )?;
    println!(
        "[watch-handoff] three_native_stations=1 independent_private_import=1 signed_peer_activation=1 generation_one=1 old_pair_exact_replay=1 old_frozen_read_refused=1 late_old_tenure_reply_refused=1 three_station_cold_restart=1"
    );
    Ok(())
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
        let path=std::env::temp_dir().join(format!("2136-private-handoff-{}.sql",std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()));
        let dump=std::process::Command::new("/opt/homebrew/opt/libpq/bin/pg_dump").args(["--clean","--if-exists","--no-owner","--no-privileges","--file"]).arg(&path).arg(&source).output()?;
        ensure!(dump.status.success(),"private pg_dump: {}",String::from_utf8_lossy(&dump.stderr));
        let restore=std::process::Command::new("/opt/homebrew/opt/libpq/bin/psql").args(["--single-transaction","--set=ON_ERROR_STOP=1","--file"]).arg(&path).arg(&destination).output()?;
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
