//! Read-only original facts from independently owned AA and Station stores.

use base64::Engine as _;

use super::*;

pub(super) async fn issuer(
    source: &Deployment,
    request: &arkret_models_identity::AccountRequestErasureRequestBody,
) -> Result<Value> {
    let url = source.coauth.pg.connect_url.clone();
    let account = json!(source.account);
    let request = request.request_id.to_string();
    tokio::task::spawn_blocking(move ||->Result<Value> {
        let mut db=postgres::Client::connect(&url,postgres::NoTls)?;
        let mut tx=db.build_transaction().isolation_level(postgres::IsolationLevel::RepeatableRead).read_only(true).start()?;
        let original=tx.query_one("SELECT to_jsonb(r)-'canonical_outcome',canonical_outcome,user_id::text FROM user_erasure_requests r WHERE request_id=$1",&[&request])?;
        let bytes:Vec<u8>=original.get(1);
        let user:String=original.get(2);
        let records=tx.query("SELECT to_jsonb(r) FROM account_status_records r WHERE record->'account_id'=$1 ORDER BY status_sequence",&[&account])?.into_iter().map(|row|row.get::<_,Value>(0)).collect::<Vec<_>>();
        let jobs=tx.query("SELECT to_jsonb(j) FROM queue_jobs j WHERE payload->'body'->'publication'->'record'->'account_id'=$1 ORDER BY created_at,id",&[&account])?.into_iter().map(|row|row.get::<_,Value>(0)).collect::<Vec<_>>();
        let authentications=tx.query("SELECT to_jsonb(a) FROM user_session_authentications a JOIN user_sessions s ON s.id=a.user_session_id WHERE s.user_id::text=$1 ORDER BY a.created_at,a.id",&[&user])?.into_iter().map(|row|row.get::<_,Value>(0)).collect::<Vec<_>>();
        let intents=tx.query("SELECT to_jsonb(r)-'canonical_outcome' FROM user_erasure_requests r WHERE user_id::text=$1 ORDER BY recorded_at,request_id",&[&user])?.into_iter().map(|row|row.get::<_,Value>(0)).collect::<Vec<_>>();
        let binding=tx.query("SELECT to_jsonb(b) FROM principal_did_bindings b WHERE user_id::text=$1 AND account_id=$2 ORDER BY binding_version",&[&user,&account])?.into_iter().map(|row|row.get::<_,Value>(0)).collect::<Vec<_>>();
        tx.commit()?;
        Ok(json!({"intent":original.get::<_,Value>(0),"canonical_outcome_base64":base64::engine::general_purpose::STANDARD.encode(&bytes),
            "canonical_outcome":serde_json::from_slice::<Value>(&bytes)?,"records":records,"jobs":jobs,"authentications":authentications,"intents":intents,"bindings":binding}))
    }).await?
}

pub(super) async fn station(source: &Deployment) -> Result<Value> {
    let url = source
        .station
        .owned_database_url()
        .context("native Station private boundary")?
        .to_owned();
    let actor = arkret_wire::ActorId::account(source.account.clone());
    let actor_key = actor.to_string();
    let actor = json!(actor);
    let account = json!(source.account);
    let pcr = source
        .controller
        .principal
        .as_ref()
        .context("accepted PCR")?
        .pcr_realm_id
        .to_string();
    tokio::task::spawn_blocking(move ||->Result<Value> {
        let mut db=postgres::Client::connect(&url,postgres::NoTls)?;
        let mut tx=db.build_transaction().isolation_level(postgres::IsolationLevel::RepeatableRead).read_only(true).start()?;
        let mut result=serde_json::Map::new();
        for (name,sql) in [
            ("data","SELECT to_jsonb(r) FROM account_datas r WHERE actor_id=$1 ORDER BY account_data_key"),
            ("data_changes","SELECT to_jsonb(r) FROM account_data_changes r WHERE actor_id=$1 ORDER BY revision"),
            ("global_versions","SELECT to_jsonb(r) FROM account_global_versions r WHERE actor_key=$1 ORDER BY channel,item_key,revision"),
        ] {
            result.insert(name.into(),json!(tx.query(sql,&[&actor_key])?.into_iter().map(|row|row.get::<_,Value>(0)).collect::<Vec<_>>()));
        }
        result.insert("backups".into(),json!(tx.query("SELECT to_jsonb(r) FROM key_backups r WHERE payload->'actor_id'=$1 ORDER BY id",&[&actor])?.into_iter().map(|row|row.get::<_,Value>(0)).collect::<Vec<_>>()));
        result.insert("private_events".into(),json!(tx.query("SELECT to_jsonb(r) FROM actor_private_events r WHERE envelope->'actor_id'=$1 ORDER BY event_id",&[&actor])?.into_iter().map(|row|row.get::<_,Value>(0)).collect::<Vec<_>>()));
        result.insert("routes".into(),json!(tx.query("SELECT to_jsonb(r) FROM device_push_routes r WHERE route_value->'account_id'=$1 ORDER BY device_id,push_route",&[&account])?.into_iter().map(|row|row.get::<_,Value>(0)).collect::<Vec<_>>()));
        let events:Vec<Value>=tx.query("SELECT to_jsonb(e) FROM canonical_events e WHERE realm_id=$1 ORDER BY pk",&[&pcr])?.into_iter().map(|row|row.get(0)).collect();
        let commits:Vec<Value>=tx.query("SELECT to_jsonb(c) FROM realm_commits c WHERE realm_id=$1 ORDER BY stream_position,commit_id",&[&pcr])?.into_iter().map(|row|row.get(0)).collect();
        result.insert("canonical_pcr".into(),json!({"events":events,"commits":commits}));
        result.insert("completions".into(),json!(tx.query("SELECT response_body FROM idempotency_keys WHERE response_body->'account_id'=$1 AND response_body->>'state'='completed' ORDER BY idempotency_key",&[&account])?.into_iter().map(|row|row.get::<_,Value>(0)).collect::<Vec<_>>()));
        result.insert("replica".into(),json!(tx.query("SELECT record,receipt FROM account_status_replica_records WHERE account_id=$1 ORDER BY status_sequence",&[&account])?.into_iter().map(|row|json!({"record":row.get::<_,Value>(0),"receipt":row.get::<_,Value>(1)})).collect::<Vec<_>>()));
        tx.commit()?;
        Ok(Value::Object(result))
    }).await?
}

pub(super) async fn receiver(
    station: &crate::harness::ArkretServer,
    receipt_id: &str,
) -> Result<Value> {
    let url = station
        .owned_database_url()
        .context("native receipt receiver store")?
        .to_owned();
    let receipt_id = receipt_id.to_owned();
    tokio::task::spawn_blocking(move ||->Result<Value> {
        let mut db=postgres::Client::connect(&url,postgres::NoTls)?;
        let rows=db.query("SELECT to_jsonb(r) FROM idempotency_keys r WHERE operation_id='ak.peer.erasure_receipt.command.submit.v1' OR idempotency_key=$1 ORDER BY operation_id,idempotency_key",&[&format!("erasure-receipt:lookup:{receipt_id}")])?;
        Ok(json!(rows.into_iter().map(|row|row.get::<_,Value>(0)).collect::<Vec<_>>()))
    }).await?
}
