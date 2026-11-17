//! Read only the real H/G Org source and private effect footprints.
use anyhow::{Context as _, Result, ensure};
use arkret_models_collaboration::governance::holder_quarantine::HolderQuarantine;
use arkret_wire::{AccountId, ActorId, RealmId};
use serde_json::{Value, json};

use crate::harness::ArkretServer;

fn rows(
    db: &mut postgres::Client,
    sql: &str,
    params: &[&(dyn postgres::types::ToSql + Sync)],
) -> Result<Value> {
    Ok(Value::Array(
        db.query(sql, params)?
            .into_iter()
            .map(|row| row.get::<_, Value>(0))
            .collect(),
    ))
}

pub(super) async fn snapshot(
    station: &ArkretServer,
    account: &AccountId,
    realm: &RealmId,
) -> Result<Value> {
    let database = station
        .configured_database_url()
        .context("owned actual Org process database")?
        .to_owned();
    let account = account.clone();
    let realm = realm.to_string();
    tokio::task::spawn_blocking(move||->Result<Value> {
        let mut db=postgres::Client::connect(&database,postgres::NoTls)?;
        let holder=serde_json::to_value(&account)?;
        let actor=ActorId::account(account.clone()).to_string();
        let mut result=serde_json::Map::new();
        result.insert("accounts".into(),rows(&mut db,"SELECT jsonb_build_object('principal_id',principal_id,'station_id',station_id,'display_name',display_name,'disabled_at',disabled_at) FROM accounts WHERE principal_id=$1 AND station_id=$2",&[&account.principal_id.as_str(),&account.station_id.as_str()])?);
        for (key,sql) in [
            ("events","SELECT to_jsonb(e) FROM canonical_events e WHERE realm_id=$1 ORDER BY pk"),
            ("commits","SELECT to_jsonb(c) FROM realm_commits c WHERE realm_id=$1 ORDER BY stream_position"),
            ("authority","SELECT to_jsonb(a) FROM realm_authorities a WHERE realm_id=$1"),
            ("typed_resolution","SELECT to_jsonb(p) FROM principal_resolution_current_states p WHERE pcr_realm_id=$1"),
            ("g_sources","SELECT jsonb_build_object('realm_id',realm_id,'principal_id',principal_id,'station_id',station_id,'source_service_id',source_service_id,'accepted_commit_id',accepted_commit_id,'original_submission',peer_request_json->'event_submission','result',result_json) FROM organization_pcr_genesis_sources WHERE realm_id=$1"),
            ("g_approval_audit","SELECT jsonb_build_object('approval_context',approval_context,'approver_did',approver_did,'nonce',nonce,'event_id',event_id,'accepted_commit_id',accepted_commit_id,'evidence',evidence) FROM event_approval_private_audit WHERE realm_id=$1 ORDER BY nonce"),
            ("h_original","SELECT to_jsonb(f) FROM authority_forward_attempts f JOIN canonical_events e ON e.pk=f.event_pk WHERE e.realm_id=$1 ORDER BY e.pk"),
            ("facts","SELECT jsonb_build_object('commit_id',k.commit_id,'fact',k.producer_source_fact) FROM agent_producer_signer_keys k JOIN realm_commits c ON c.commit_id=k.commit_id WHERE c.realm_id=$1 ORDER BY c.stream_position"),
        ] {result.insert(key.into(),rows(&mut db,sql,&[&realm])?);}
        for (key,sql) in [
            ("consents","SELECT to_jsonb(c) FROM consent_current_states c WHERE holder_account_id=$1 ORDER BY peer_id::text"),
            ("jobs","SELECT to_jsonb(j) FROM consent_private_effect_jobs j WHERE holder_account_id=$1"),
            ("proxy_fences","SELECT to_jsonb(f) FROM consent_private_proxy_fences f WHERE holder_account_id=$1 ORDER BY nonce"),
            ("proxy_cuts","SELECT to_jsonb(c) FROM consent_private_proxy_cuts c WHERE holder_account_id=$1"),
            ("effect_fences","SELECT to_jsonb(f) FROM consent_private_effect_fences f WHERE holder_account_id=$1 ORDER BY nonce"),
            ("effect_cuts","SELECT to_jsonb(c) FROM consent_private_effect_cuts c WHERE holder_account_id=$1"),
        ] {result.insert(key.into(),rows(&mut db,sql,&[&holder])?);}
        result.insert("quarantine".into(),rows(&mut db,"SELECT to_jsonb(a) FROM account_datas a WHERE actor_id=$1 AND account_data_key=$2 AND NOT tombstone AND account_data_source_current(actor_id,account_data_key)",&[&actor,&arkret_wire::AccountDataKey::ACCOUNT_HOLDER_QUARANTINE])?);
        Ok(Value::Object(result))
    }).await?
}

pub(super) fn quarantine(
    snapshot: &Value,
    account: &AccountId,
) -> Result<Option<HolderQuarantine>> {
    let rows = snapshot["quarantine"]
        .as_array()
        .context("actual quarantine rows")?;
    ensure!(rows.len() <= 1, "multiple actual current quarantine cells");
    rows.first()
        .map(|row| -> Result<_> {
            let cell: HolderQuarantine = serde_json::from_value(row["payload"].clone())?;
            cell.validate_holder(account)?;
            Ok(cell)
        })
        .transpose()
}

pub(super) async fn settle(
    hosting: &ArkretServer,
    governor: &ArkretServer,
    account: &AccountId,
    realm: &RealmId,
    requester: &ActorId,
    scope: arkret_wire::ConsentRequestScope,
) -> Result<Value> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(45);
    loop {
        let h = snapshot(hosting, account, realm).await?;
        let g = snapshot(governor, account, realm).await?;
        let matched = quarantine(&g, account)?
            .is_some_and(|cell| cell.live_consent_request(requester, scope).is_some())
            && h["quarantine"]
                .as_array()
                .is_some_and(|rows| rows.len() == 1)
            && h["quarantine"][0]["payload"] == g["quarantine"][0]["payload"]
            && h["quarantine"][0]["revision"] == g["quarantine"][0]["revision"]
            && h["effect_fences"]
                .as_array()
                .is_some_and(|rows| !rows.is_empty())
            && h["effect_cuts"]
                .as_array()
                .is_some_and(|rows| rows.len() == 1)
            && g["jobs"].as_array().is_some_and(|rows| rows.is_empty());
        if matched {
            return Ok(json!({"h":h,"g":g}));
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "real G worker did not publish/ack the exact Org quarantine: H={} G={}",
            arkret_canonical::canonical_sha256(&h)?,
            arkret_canonical::canonical_sha256(&g)?
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

pub(super) fn unchanged_authority(before: &Value, after: &Value) -> Result<()> {
    for field in [
        "accounts",
        "events",
        "commits",
        "authority",
        "typed_resolution",
        "g_sources",
        "g_approval_audit",
        "h_original",
        "facts",
        "consents",
    ] {
        ensure!(
            before[field] == after[field],
            "private request/current modified canonical or immutable Org source {field}"
        );
    }
    Ok(())
}
