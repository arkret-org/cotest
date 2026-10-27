//! Native fresh-authentication erasure acceptance and exact issuer-ledger replication.
use arkret_models_collaboration::account_lifecycle::*;
use arkret_models_collaboration::account_status::AccountStatusRecord;
use arkret_models_identity::{AccountRequestErasureRequestBody, AccountRequestErasureResponseBody};

use super::*;
use crate::harness::{ArkretServer, expect_json};
const SCOPE: [&str; 5] = [
    "ak.gate.account.command.request_erasure.v1",
    "ak.peer.account_status.command.submit.v1",
    "ak.peer.account_status.read.resolve.v1",
    "ak.peer.erasure_receipt.command.submit.v1",
    "ak.peer.erasure_receipt.resource.get.v1",
];
async fn issuer(
    database: &str,
    request_id: &str,
    account: &arkret_wire::AccountId,
) -> Result<Value> {
    let database = database.to_owned();
    let request_id = request_id.to_owned();
    let account = serde_json::to_value(account)?;
    tokio::task::spawn_blocking(move ||->Result<Value> {
  let mut db=postgres::Client::connect(&database,postgres::NoTls)?;
  let intent=db.query_one("SELECT to_jsonb(r),encode(r.canonical_outcome,'base64') FROM user_erasure_requests r WHERE request_id=$1",&[&request_id])?;
  let row:Value=intent.get(0);let encoded:String=intent.get(1);
  let user=db.query_one("SELECT to_jsonb(u) FROM users u WHERE u.id::text=$1",&[&row["user_id"].as_str().context("native intent owner")?])?.get::<_,Value>(0);
  let records=db.query("SELECT to_jsonb(r) FROM account_status_records r WHERE record->'account_id'=$1 ORDER BY status_sequence",&[&account])?.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>();
  let jobs=db.query("SELECT to_jsonb(j) FROM queue_jobs j WHERE payload->>'record_id' IN (SELECT record_id FROM account_status_records WHERE record->'account_id'=$1) ORDER BY created_at",&[&account])?.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>();
  let heads=db.query("SELECT to_jsonb(h) FROM account_status_ledger_heads h WHERE local_account_id IN (SELECT local_account_id FROM account_status_records WHERE record->'account_id'=$1)",&[&account])?.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>();
  let authentications=db.query("SELECT to_jsonb(a) FROM user_session_authentications a JOIN user_sessions s ON s.id=a.user_session_id WHERE s.user_id::text=$1 ORDER BY a.created_at",&[&row["user_id"].as_str().unwrap()])?.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>();
  Ok(json!({"intent":row,"canonical_outcome_base64":encoded,"authentications":authentications,"user":user,"records":records,"jobs":jobs,"heads":heads}))
 }).await?
}
async fn replica(database: &str, account: &arkret_wire::AccountId) -> Result<Vec<Value>> {
    let database = database.to_owned();
    let account = serde_json::to_value(account)?;
    tokio::task::spawn_blocking(move ||->Result<Vec<Value>> {
  let mut db=postgres::Client::connect(&database,postgres::NoTls)?;
  Ok(db.query("SELECT to_jsonb(r) FROM account_status_replica_records r WHERE account_id=$1 ORDER BY status_sequence",&[&account])?.into_iter().map(|r|r.get(0)).collect())
 }).await?
}
async fn peer(
    station: &ArkretServer,
    path: &str,
    body: &impl serde::Serialize,
    key: Option<&str>,
) -> Result<Value> {
    let bytes = arkret_canonical::canonical_json_bytes(body)?;
    let request = station.signed_peer_post_request_with_idempotency_key(
        station,
        path,
        &bytes,
        station.service_id(),
        key,
    )?;
    let frozen = request
        .try_clone()
        .context("buffered native peer request")?;
    let response = station.http().execute(request).await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    ensure!(
        status.is_success(),
        "native peer {path}: {status} {}",
        String::from_utf8_lossy(&bytes)
    );
    cotest_test_support::operation_observation::record_response(
        Some(&frozen),
        status.as_u16(),
        &bytes,
    )?;
    Ok(serde_json::from_slice(&bytes)?)
}
pub(super) async fn run() -> Result<()> {
    let (result,observations)=observe(crate::harness::heap_future(|| async {
  let mut deployment=crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment_with_erasure_requests("native-account-erasure-status").await?;
  let mut receiver=crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-erasure-receipt-receiver").await?;
  deployment.station.restart_with_federation_mesh(&[receiver.station.url("")]).await?;
  receiver.station.restart_with_federation_mesh(&[deployment.station.url("")]).await?;
  let issuer_continuity=deployment.issuer_continuity.as_ref().context("native issuer continuity producer was not executed")?.clone();
  let issuer_bindings=vec![
   crate::scenarios::_helpers::native_issuer_binding::capture(&deployment.coauth,&deployment.station).await?,
   crate::scenarios::_helpers::native_issuer_binding::capture(&receiver.coauth,&receiver.station).await?,
  ];
  let private_seed=super::account_erasure_receipts::seed(&deployment.station,&deployment.controller,&deployment.account).await?;
  cotest_test_support::provisioning::coauth_account::login(&deployment.http,deployment.coauth.base_url(),"alice","1amTester!").await?;
  let configuration:Value=serde_saphyr::from_reader(std::fs::File::open(deployment.coauth.config.path())?)?;
  let policy=configuration["arkret"]["erasure_request_max_auth_age"].clone();
  ensure!(policy==300,"native erasure deployment omitted its actual configured freshness bound");
  let request=AccountRequestErasureRequestBody {request_id:arkret_identifiers::new_prefixed_uuid7("ak:request:").parse()?};
  let url=format!("{}/_arkret/gate/account/erasure-requests",deployment.coauth.base_url());
  let send=||deployment.http.post(&url).header("Arkret-Operation",SCOPE[0]).header("Origin",deployment.coauth.base_url()).json(&request);
  let accepted=expect_json(send(),reqwest::StatusCode::OK).await?;
  let typed:AccountRequestErasureResponseBody=serde_json::from_value(accepted.clone())?;typed.validate()?;
  ensure!(typed.request_id==request.request_id && typed.principal_id==deployment.account.principal_id && typed.withdrawal_window_ends_at.is_none(),"native erasure acceptance changed its original intent or claimed a withdrawal window");
  let replay=expect_json(send(),reqwest::StatusCode::OK).await?;ensure!(replay==accepted,"erasure exact retry changed its durable acceptance");
  let originals=issuer(&deployment.coauth.pg.connect_url,request.request_id.as_str(),&deployment.account).await?;
  let records=originals["records"].as_array().context("actual issuer ledger")?;ensure!(!records.is_empty(),"erasure acceptance had no actual authority-signed status record");
  let pcr=&deployment.controller.principal.as_ref().context("original Human PCR")?.pcr_realm_id;
  let mut publications=Vec::new();let mut signed_records=Vec::new();
  for row in records {
   let record:AccountStatusRecord=serde_json::from_value(row["record"].clone())?;record.validate_shape()?;
   ensure!(record.account_id==deployment.account && record.principal_control_realm_id==*pcr && record.account_authority_id==*deployment.station.service_id() && !row["issuer_source"].is_null(),"status record lacks its actual issuer source or original Account/PCR");
   let jobs=originals["jobs"].as_array().context("actual publication jobs")?.iter().filter(|r|r["payload"]["record_id"]==json!(record.account_status_record_id)).collect::<Vec<_>>();
   let [job]=jobs.as_slice() else {anyhow::bail!("issuer original has no unique durable publication job")};
   let body:AccountStatusPublicationRequestBody=serde_json::from_value(job["payload"]["body"].clone())?;body.validate_shape()?;
   ensure!(body.publication.record()==&record && job["payload"]["body_digest"]==json!(arkret_canonical::canonical_sha256(&body)?),"publication job changed the actual signed record");
   let key=job["payload"]["idempotency_key"].as_str().context("native publication key")?;
   let posted=peer(&deployment.station,"/_arkret/peer/account-status",&body,Some(key)).await?;
   let receipt:AccountStatusPublicationResponseBody=serde_json::from_value(posted.clone())?;receipt.validate_for_request(&body)?;
   ensure!(matches!(receipt.status,AccountStatusPublicationStatus::Accepted|AccountStatusPublicationStatus::Duplicate) && receipt.receipt.is_some(),"response was not a real terminal replica acceptance");
   let retry=peer(&deployment.station,"/_arkret/peer/account-status",&body,Some(key)).await?;ensure!(retry==posted,"status publication exact retry changed its original receipt");
   signed_records.push(record);publications.push(json!({"body":body,"key":key,"accepted":posted,"replay":retry}));
  }
  ensure!(signed_records.last().context("current signed status")?.status==arkret_models_collaboration::objects::account_status::AccountStatus::ErasurePending,"erasure acceptance did not issue erasure_pending");
  let resolve_request=AccountStatusResolveRequestBody {account_authority_id:deployment.station.service_id().clone(),account_id:deployment.account.clone(),from_status_sequence:1,limit:128};
  let resolved=peer(&deployment.station,"/_arkret/peer/account-status/resolve",&resolve_request,None).await?;
  let result:AccountStatusResolveResponseBody=serde_json::from_value(resolved.clone())?;result.validate_for_request(&resolve_request)?;
  ensure!(result.records==signed_records && !result.has_more && result.next_status_sequence.is_none(),"authority resolve did not return the exact complete issuer ledger");
  let durable=replica(deployment.station.owned_database_url().context("owned replica database")?,&deployment.account).await?;
  ensure!(durable.len()==signed_records.len() && durable.iter().zip(&signed_records).all(|(row,record)|row["record"]==json!(record)),"native replica did not retain the exact issued originals");
  let receipt_evidence=super::account_erasure_receipts::exercise(&deployment.station,&receiver.station,&deployment.account,signed_records.last().context("actual terminal source")?,&private_seed).await?;
  Ok::<_,anyhow::Error>(json!({"issuer_bindings":issuer_bindings,"issuer_continuity":issuer_continuity,"receipt_evidence":receipt_evidence,"erasure_request_max_auth_age":policy,"request":request,"accepted":accepted,"replay":replay,"originals":originals,"publications":publications,"resolve_request":resolve_request,"resolved":resolved,"replica":durable,"original_pcr":pcr,"processes":[deployment.coauth.server.native_process_identity()?,deployment.station.native_process_identity()?,receiver.coauth.server.native_process_identity()?,receiver.station.native_process_identity()?]}))
 })).await;
    retain_attempt("account-erasure-status", &observations)?;
    let mut artifact = result?;
    // Preserve actual domain originals even if a later schema or signature
    // gate fails; this diagnostic never qualifies as executed native coverage.
    retain_diagnostic("account-erasure-status-originals", &artifact)?;
    crate::scenarios::_helpers::native_issuer_binding::verify_continuity(
        &artifact["issuer_continuity"],
    )?;
    let bindings = artifact["issuer_bindings"]
        .as_array()
        .context("native issuer originals")?;
    ensure!(
        bindings.len() == 2,
        "native erasure requires both actual AA bindings"
    );
    let mut services = std::collections::BTreeSet::new();
    for binding in bindings {
        let floor = crate::scenarios::_helpers::native_issuer_binding::verify(binding)?;
        let admitted =
            native_station_resolution(&observations, &floor.service_id, chrono::Utc::now())?;
        arkret_identity::verify_service_resolution_floor(&admitted, &floor)?;
        ensure!(
            services.insert(floor.service_id),
            "native erasure reused one AA for two Stations"
        );
    }
    ensure!(
        services
            == [
                serde_json::from_value(artifact["receipt_evidence"]["source_id"].clone())?,
                serde_json::from_value(artifact["receipt_evidence"]["receiver_id"].clone())?,
            ]
            .into_iter()
            .collect(),
        "native issuer bindings name different receipt participants"
    );
    validate_exchange_schemas(&observations, &SCOPE)?;
    for row in artifact["originals"]["records"]
        .as_array()
        .context("native issuer originals")?
    {
        let record: AccountStatusRecord = serde_json::from_value(row["record"].clone())?;
        let key = native_station_key(
            &observations,
            &record.proof.verification_method,
            record.issued_at,
        )?;
        arkret_signatures::account_status::verify_account_status_record(&record, &key)?;
    }
    for publication in artifact["publications"]
        .as_array()
        .context("native replica originals")?
    {
        let response: AccountStatusPublicationResponseBody =
            serde_json::from_value(publication["accepted"].clone())?;
        let receipt = response.receipt.context("actual replica receipt")?;
        let key = native_station_key(
            &observations,
            &receipt.proof.verification_method,
            receipt.accepted_at,
        )?;
        arkret_signatures::account_status::verify_account_status_receipt(&receipt, &key)?;
    }
    super::account_erasure_receipts::verify(&observations, &artifact["receipt_evidence"])?;
    artifact["case"] = json!("account_erasure_status");
    artifact["format_version"] = json!(1);
    artifact["scope"] = json!(SCOPE);
    artifact["observations"] = serde_json::to_value(observations)?;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("account-erasure-status.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
