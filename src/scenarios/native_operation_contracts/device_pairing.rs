//! Pairing preparation is credited only with the subsequent accepted Device original.
use arkret_models_collaboration::device_pairing::*;
use cotest_test_support::provisioning::{self, FoundingDeviceKey};

use super::*;

const SCOPE: [&str; 2] = [
    "ak.gate.account.command.finalize_device_pairing.v1",
    "ak.gate.account.read.claim_device_pairing_code.v1",
];

async fn pending(database: &str, request_id: &str) -> Result<Value> {
    let database = database.to_owned();
    let request_id = request_id.to_owned();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut database=postgres::Client::connect(&database,postgres::NoTls)?;
        let row=database.query_one("SELECT to_jsonb(p), stage_outcome, finalize_outcome, admission_authorize_event_bytes, admission_recorded_commit_bytes, admission_terminal_outcome_bytes FROM device_pairing_pending p WHERE device_pairing_request_id=$1", &[&request_id])?;
        let mut originals=json!({"record":row.get::<_,Value>(0)});
        for (index,name) in [(1,"stage"),(2,"finalize"),(3,"authorization_submission"),(4,"commit"),(5,"admission")] {
            if let Some(bytes)=row.get::<_,Option<Vec<u8>>>(index) {
                originals[name]=json!({"bytes_base64url":arkret_canonical::base64url_encode(&bytes),"value":serde_json::from_slice::<Value>(&bytes)?});
            }
        }
        Ok(originals)
    }).await?
}

pub(super) async fn run() -> Result<()> {
    let (result,observations)=observe(async {
        let deployment=crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-device-pairing").await?;
        let principal=deployment.controller.principal.as_ref().context("accepted founding Device absent")?;
        let device_id=arkret_wire::DeviceId::new(arkret_identifiers::new_prefixed_uuid7("ak:device:"))?;
        let identity=FoundingDeviceKey::generate("pairing target identity")?;
        let holder=FoundingDeviceKey::generate("pairing target grant holder")?;
        let hpke_seed=FoundingDeviceKey::generate("pairing target HPKE")?;
        let hpke=arkret_crypto::identity_root::derive_identity_recovery_key_material(&hpke_seed.signing_key().to_bytes(),0)?;
        let public=arkret_http_client::Client::builder(deployment.station.base_url().clone()).http_client(deployment.http.clone()).build()?;
        let mut nonce=[0u8;32];getrandom::fill(&mut nonce).context("pairing stage OS nonce")?;
        let stage_request:DevicePairingStageRequestBody=serde_json::from_value(json!({
            "new_device_public_key":{"kty":"OKP","kid":device_id,"algorithm":"Ed25519","key":arkret_canonical::base64url_encode(identity.signing_key().verifying_key().to_bytes())},
            "client_nonce":arkret_canonical::base64url_encode(nonce),
        }))?;
        let staged=public.device_pairing_stage(&stage_request).await?;
        let authorization=provisioning::authorize_with_current_account(&deployment.http,deployment.coauth.base_url(),&deployment.oidc_client_id).await?;
        let handoff=provisioning::create_returning_account_handoff(&deployment.http,deployment.coauth.base_url(),deployment.station.service_id().as_str(),&authorization,holder.clone(),&principal.core_id,&principal.did).await?;
        let target:DevicePairingTargetProof=serde_json::from_value(cotest_test_support::wire::device_pairing_target_proof(json!({
            "account_id":deployment.account,"stage_request":stage_request,"stage_outcome":staged,
            "device_signing_seed_b64url":identity.seed_b64url,"hpke_public_key_b64url":arkret_canonical::base64url_encode(hpke.backup_hpke_public_key),
        }))?)?;
        let request=DevicePairingFinalizeRequestBody{device_pairing_request_id:staged.device_pairing_request_id.clone(),pairing_code:staged.pairing_code.clone(),target_proof:target.clone()};
        let finalized=super::session_grants::post(&deployment,"/_arkret/gate/account/device-pairing/finalizations",SCOPE[0],&handoff.account_handoff_grant,&holder.signing_key(),&request).await?;
        let replay=super::session_grants::post(&deployment,"/_arkret/gate/account/device-pairing/finalizations",SCOPE[0],&handoff.account_handoff_grant,&holder.signing_key(),&request).await?;
        ensure!(finalized==replay,"pairing finalize replay changed its native original");
        let typed:DevicePairingFinalizeResponseBody=serde_json::from_value(finalized.clone())?;
        ensure!(typed.state==DevicePairingState::ReadyForClaim,"target proof is not claimable");
        let before_claim=pending(&deployment.coauth.pg.connect_url,staged.device_pairing_request_id.as_str()).await?;
        let crate::harness::ClientSession::Canonical{grant,signing_key}=deployment.controller.session() else {anyhow::bail!("pairing approval needs the real controller grant")};
        let claim=super::session_grants::post(&deployment,"/_arkret/gate/account/device-pairing/code-claims",SCOPE[1],grant,signing_key,&DevicePairingCodeClaimRequestBody{pairing_code:staged.pairing_code.clone()}).await?;
        let claimed:DevicePairingCodeClaimResponseBody=serde_json::from_value(claim.clone())?;
        ensure!(claimed.device_pairing_request_id==staged.device_pairing_request_id && serde_json::to_value(&claimed.target_proof)?==serde_json::to_value(&target)?,"code claim substituted another target");
        let keys=deployment.controller.sdk().keys_query(&serde_json::from_value(json!({"device_keys":[{"account_id":deployment.account,"device_ids":[principal.device_id]}]}))?).await?;
        let keys=serde_json::to_value(keys)?;
        let generations=keys["device_generations"].as_array().context("native device generations absent")?.iter().filter(|row|row["account_id"]==json!(deployment.account)).collect::<Vec<_>>();
        ensure!(generations.len()==1,"ambiguous native Device generation");
        let generation=generations[0]["generation_state"]["current_device_generation_ref"].as_u64().filter(|value|*value>=1).context("positive native Device generation absent")?;
        let approval:AccountDevicePairRequestBody=serde_json::from_value(cotest_test_support::wire::device_pairing_approval(json!({
            "bootstrap":claimed.bootstrap,"target_proof":target,"approving_account_id":deployment.account,"approving_did":principal.did,
            "approving_device_id":principal.device_id,"approving_signing_seed_b64url":arkret_canonical::base64url_encode(principal.device_signing_key.to_bytes()),
            "principal_control_realm_id":principal.pcr_realm_id,"authorized_generation_ref":generation,
        }))?)?;
        let publication=deployment.controller.verify_publication(approval.clone())?;
        let accepted=super::session_grants::post(&deployment,"/_arkret/gate/account/device-pair",arkret_wire::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_DEVICE_V1,grant,signing_key,&publication).await?;
        let paired:AccountDevicePairResponseBody=serde_json::from_value(accepted.clone())?;
        ensure!(paired.device_id==device_id && paired.authorized_event_ref.event_id==approval.authorize_event.event.event_id,"native pairing admitted another Device");
        let view=crate::scenarios::mls_lifecycle_live::accepted_full_view(&deployment.controller,&paired.authorized_event_ref.event_id).await?;
        let originals=pending(&deployment.coauth.pg.connect_url,staged.device_pairing_request_id.as_str()).await?;
        ensure!(originals["stage"]["value"]==serde_json::to_value(&staged)? && originals["finalize"]["value"]==finalized &&
            originals["admission"]["value"]==accepted && originals["authorization_submission"]["value"]==serde_json::to_value(&approval.authorize_event)? &&
            originals["commit"]["value"]==serde_json::to_value(&view.commit)?,"pairing ledger lost an accepted original");
        ensure!(view.event==approval.authorize_event.event && originals["record"]["admission_state"]=="completed" && originals["record"]["state"]=="authorized", "pairing never reached real PCR admission");
        ensure!(before_claim["record"]["state"]=="ready_for_claim" && before_claim["record"]["code_consumed_at"].is_null(),"code claim prerequisite was not an unconsumed real target");
        Ok::<_,anyhow::Error>((deployment,originals,before_claim,view,claim,approval))
    }).await;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory)?;
        std::fs::write(
            directory.join(format!(
                "attempt-account-device-pairing-{}.json",
                chrono::Utc::now().timestamp_millis()
            )),
            serde_json::to_vec_pretty(
                &json!({"status":"observed_not_verified","observations":observations}),
            )?,
        )?;
    }
    let (deployment, originals, before_claim, view, claim, approval) = result?;
    validate_exchange_schemas(&observations, &SCOPE)?;
    let proof = json!({"case":"account_device_pairing","scope":SCOPE,"observations":observations,
        "authority_originals":originals,"before_claim":before_claim,"claimed":claim,"approval_request":approval,"station_readback":view,
        "processes":[deployment.coauth.server.native_process_identity()?,deployment.station.native_process_identity()?]});
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("account-device-pairing.json"),
            serde_json::to_vec_pretty(&proof)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
