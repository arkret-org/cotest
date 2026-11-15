//! Real AA/Station SecurityRotation originals, distinct from single-submit Recovery.
use super::*;
use crate::harness::{CanonicalJsonBody as _, expect_json};
use crate::scenarios::_helpers::canonical_api::CanonicalApiFixture;
use crate::scenarios::security_rotation_live::RotationAuthor;
use arkret_models_crypto::{
    SecurityRotationTransaction, SecurityTransactionCreateRequestBody,
    SecurityTransactionTerminalOutcome,
};

// The native inventory assigns continue to this case. create/get are still
// verified as actual prerequisites without duplicating their coverage owner.
const SCOPE: [&str; 1] = ["ak.self.security_transaction.command.continue.v1"];
const OBSERVED: [&str; 3] = [
    "ak.self.security_transaction.command.create.v1",
    "ak.self.security_transaction.command.continue.v1",
    "ak.self.security_transaction.resource.get.v1",
];

pub(super) async fn run() -> Result<()> {
    let (result,observations)=observe(async {
        let deployment=crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-security-rotation").await?;
        let aa_process=deployment.coauth.server.native_process_identity()?;
        let station_process=deployment.station.native_process_identity()?;
        let database=deployment.station.configured_database_url().context("native Rotation requires an owned isolated Station database")?.to_owned();
        let fixture=CanonicalApiFixture::from_owned(deployment.station,deployment.controller,deployment.http,deployment.endpoints,deployment.oidc_client_id);
        let target=fixture.pair_sibling().await.context("real AA accepts a sibling Device")?;
        let target_device_id=target.principal.as_ref().context("accepted sibling custody")?.device_id.clone();
        let principal=fixture.client.principal.as_ref().context("accepted author custody")?;
        let (author,old_backup,source)=RotationAuthor::prepare_for_client(&fixture.client).await?;
        let before=fixture.client.sdk().list_key_backups(&arkret_models_crypto::KeyBackupsListQuery { agent_id:None,series_id:None,backup_kind:None,cursor:None,limit:None }).await?;
        let (request,binding)=author.rotation("a191",target_device_id.as_str(),principal.device_signing_key.to_bytes(),principal.device_signing_key.to_bytes(),&old_backup,&source)?;
        let SecurityTransactionCreateRequestBody::SecurityRotation(rotation)=&request else { anyhow::bail!("native Rotation constructed Recovery"); };
        request.validate()?;
        let created:SecurityRotationTransaction=serde_json::from_value(expect_json(fixture.client.post("/_arkret/self/security-transactions").canonical_json(&request)?,reqwest::StatusCode::OK).await?)?;
        let mut current=created.clone();
        let resource_path=format!("/_arkret/self/security-transactions/{}",rotation.transaction_id);
        let deadline=std::time::Instant::now()+std::time::Duration::from_secs(30);
        while current.accepted_steps.len()<4 && current.terminal_outcome.is_none() {
            ensure!(std::time::Instant::now()<deadline,"native Rotation worker did not complete all four server steps");
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            current=serde_json::from_value(expect_json(fixture.client.get(&resource_path),reqwest::StatusCode::OK).await?)?;
        }
        ensure!(current.accepted_steps.len()==4 && current.terminal_outcome.is_none()
            && current.revoke_command_outcome.as_ref().is_some_and(|outcome| outcome.outcome==arkret_models_crypto::SecurityRotationRevokeCommandDecision::Accepted),"native worker aborted or skipped a step: {current:?}");
        let local_commit=author.local_commit(&current,rotation)?;
        let continue_path=format!("{resource_path}/continue");
        let completed:SecurityRotationTransaction=serde_json::from_value(expect_json(fixture.client.post(&continue_path).canonical_json(&local_commit)?,reqwest::StatusCode::OK).await?)?;
        ensure!(completed.accepted_steps.len()==5 && completed.accepted_steps[..4]==current.accepted_steps[..]
            && matches!(completed.terminal_outcome,Some(SecurityTransactionTerminalOutcome::Completed{..})),"native client local_commit did not complete Rotation");
        completed.validate_structural()?;
        let replay:SecurityRotationTransaction=serde_json::from_value(expect_json(fixture.client.post(&continue_path).canonical_json(&local_commit)?,reqwest::StatusCode::OK).await?)?;
        let final_get:SecurityRotationTransaction=serde_json::from_value(expect_json(fixture.client.get(&resource_path),reqwest::StatusCode::OK).await?)?;
        let create_replay:SecurityRotationTransaction=serde_json::from_value(expect_json(fixture.client.post("/_arkret/self/security-transactions").canonical_json(&request)?,reqwest::StatusCode::OK).await?)?;
        ensure!(completed==replay && completed==final_get && completed==create_replay,"native Rotation response-loss replay changed its original terminal resource");
        let after=fixture.client.sdk().list_key_backups(&arkret_models_crypto::KeyBackupsListQuery { agent_id:None,series_id:None,backup_kind:None,cursor:None,limit:None }).await?;
        ensure!(matches!(&after.active_series.secret_storage,arkret_models_crypto::BackupActiveSeriesPointer::Active{active_series_id,series_pointer_version} if active_series_id==&binding.new_series_id && *series_pointer_version==2),"native worker failed to switch the authoritative backup pointer");
        ensure!(before.backups.iter().any(|row|row.backup_id==old_backup.backup_id)
            && !after.backups.iter().any(|row|row.backup_id==old_backup.backup_id)
            && after.backups.iter().any(|row|row.backup_id==binding.new_backups[0].backup_id && row.ciphertext_digest==binding.new_backups[0].ciphertext_digest),"native worker did not replace and erase the exact backup objects");
        let target_error=fixture.issue_for_device(&target).await.err().context("revoked target obtained a new actual AA Standard grant")?;
        let Some(arkret_http_client::Error::Api{error:problem,..})=target_error.downcast_ref::<arkret_http_client::Error>() else{anyhow::bail!("target refusal was not an actual AA API decision: {target_error:#}");};
        let target_denial=problem.error_code().context("target refusal lacks registered code")?.as_str().to_owned();
        ensure!(["device_revoked","device_revocation_pending","device_generation_fenced"].contains(&target_denial.as_str()),"target failed outside its actual revoke gate: {problem}");
        let revoke=crate::scenarios::mls_lifecycle_live::accepted_full_view(&fixture.client,&rotation.prepared_plan.revoke_unit.request.events[0].event.event_id).await?;
        let pointer=crate::scenarios::mls_lifecycle_live::accepted_full_view(&fixture.client,&rotation.prepared_plan.backup_rotations[0].active_series_unit.request.events[0].event.event_id).await?;
        ensure!(revoke.event==rotation.prepared_plan.revoke_unit.request.events[0].event
            && pointer.event==rotation.prepared_plan.backup_rotations[0].active_series_unit.request.events[0].event
            && pointer.commit.commit_id==after.active_series.authority_commit_id,"native worker changed signed revoke/pointer originals");
        let transaction_id=rotation.transaction_id.to_string();
        let account=rotation.account_id.clone();
        let erased_id=old_backup.backup_id.to_string();
        let replacement_id=binding.new_backups[0].backup_id.to_string();
        let originals=tokio::task::spawn_blocking(move || -> Result<Value> {
            let mut db=postgres::Client::connect(&database,postgres::NoTls)?;
            let raw=transaction_id.strip_prefix("ak:transaction:").context("transaction UUID")?;
            let row=db.query_one("SELECT to_jsonb(t),canonical_request FROM security_transactions t WHERE id::text=$1 AND principal_id=$2 AND station_id=$3",&[&raw,&account.principal_id.as_str(),&account.station_id.as_str()])?;
            let bytes:Vec<u8>=row.get(1);
            let steps=db.query("SELECT step,canonical_request,response,participant_outcome FROM security_transaction_step_outcomes WHERE transaction_id::text=$1 ORDER BY step",&[&raw])?.into_iter().map(|row| -> Result<Value> {
                let bytes:Vec<u8>=row.get(1);
                Ok(json!({"step":row.get::<_,String>(0),"canonical_request":serde_json::from_slice::<Value>(&bytes)?,"canonical_request_bytes":arkret_canonical::base64url_encode(&bytes),"response":row.get::<_,Value>(2),"participant_outcome":row.get::<_,Option<Value>>(3)}))
            }).collect::<Result<Vec<_>>>()?;
            let erase=db.query("SELECT to_jsonb(p),canonical_request FROM security_transaction_backup_erase_progress p WHERE transaction_id::text=$1",&[&raw])?.into_iter().map(|row| -> Result<Value> {
                let bytes:Vec<u8>=row.get(1);
                Ok(json!({"row":row.get::<_,Value>(0),"canonical_request":serde_json::from_slice::<Value>(&bytes)?,"canonical_request_bytes":arkret_canonical::base64url_encode(&bytes)}))
            }).collect::<Result<Vec<_>>>()?;
            let erased_id=erased_id.strip_prefix("ak:backup:").context("erased backup UUID")?;
            let replacement_id=replacement_id.strip_prefix("ak:backup:").context("replacement backup UUID")?;
            let erased_exists:bool=db.query_one("SELECT EXISTS(SELECT 1 FROM key_backups WHERE id::text=$1)",&[&erased_id])?.get(0);
            let replacement:Value=db.query_one("SELECT payload FROM key_backups WHERE id::text=$1",&[&replacement_id])?.get(0);
            Ok(json!({"transaction":row.get::<_,Value>(0),"canonical_request":serde_json::from_slice::<Value>(&bytes)?,"canonical_request_bytes":arkret_canonical::base64url_encode(&bytes),"steps":steps,"erase_progress":erase,"erased_exists":erased_exists,"replacement":replacement}))
        }).await??;
        ensure!(originals["canonical_request"]==serde_json::to_value(&request)? && originals["transaction"]["kind"]=="security_rotation"
            && originals["transaction"]["prepared_plan"]==serde_json::to_value(&completed.prepared_plan)?
            && originals["transaction"]["accepted_steps"]==serde_json::to_value(&completed.accepted_steps)?
            && originals["transaction"]["terminal_outcome"]==serde_json::to_value(&completed.terminal_outcome)?
            && originals["transaction"]["recovery_completion"].is_null(),"native Rotation durable branch differs from its served original");
        ensure!(originals["erased_exists"]==false && originals["replacement"]==serde_json::to_value(&rotation.prepared_plan.backup_rotations[0].new_backup_envelopes[0])?,"native storage did not physically erase old or preserve exact new ciphertext envelope");
        let steps=originals["steps"].as_array().context("native Rotation step originals")?;
        let names=steps.iter().map(|row|row["step"].as_str().context("native step name")).collect::<Result<std::collections::BTreeSet<_>>>()?;
        ensure!(steps.len()==5 && names==std::collections::BTreeSet::from(["revoke","upload_new_material","switch_authoritative_pointer","erase_old_material","local_commit"]),"Rotation did not retain all five independent step outcomes");
        let local=steps.iter().find(|row|row["step"]=="local_commit").context("local commit original")?;
        ensure!(local["canonical_request"]==serde_json::to_value(&local_commit)? && local["response"]==serde_json::to_value(&completed)?
            && originals["erase_progress"].as_array().is_some_and(|rows|rows.len()==1),"native local_commit or erase provenance is absent");
        Ok::<_,anyhow::Error>(json!({"request":request,"created":created,"worker_completed":current,"local_commit_request":local_commit,"completed":completed,"continue_replay":replay,"final_get":final_get,"create_replay":create_replay,"target_device_id":target_device_id,"target_denial":target_denial,"old_backup":old_backup,"binding":binding,"before":before,"after":after,"revoke":revoke,"pointer":pointer,"authority_originals":originals,"processes":[aa_process,station_process]}))
    }).await;
    retain_attempt("account-security-rotation", &observations)?;
    let mut evidence = result?;
    validate_exchange_schemas(&observations, &OBSERVED)?;
    let sources = [
        serde_json::from_value(evidence["revoke"].clone())?,
        serde_json::from_value(evidence["pointer"].clone())?,
    ];
    verify_native_pcr_commits(&observations, &sources)?;
    evidence["case"] = json!("account_security_rotation");
    evidence["scope"] = json!(SCOPE);
    evidence["observations"] = serde_json::to_value(&observations)?;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("account-security-rotation.json"),
            serde_json::to_vec_pretty(&evidence)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
