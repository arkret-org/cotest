//! Holder consent through admitted identities, signed PCR state and real quarantine effects.
use arkret_models_collaboration::consent_operations::*;
use arkret_models_collaboration::events_payloads::consent::{ConsentPeer, ConsentPermission};
use arkret_wire::{ActorId, ConsentRequestScope, ConsentScope, DeviceId};

use super::*;
use crate::harness::{CanonicalClientRequest, TestActorClient, expect_json};

const SCOPE: [&str; 3] = [
    "ak.self.consent.command.request.v1",
    "ak.self.consent.command.replace.v1",
    "ak.self.consent.read.current.v1",
];

async fn current(
    holder: &TestActorClient,
    peer: &ConsentPeer,
) -> Result<(
    ConsentCurrentReadRequestBody,
    ConsentCurrentReadResponseBody,
)> {
    let principal = holder
        .principal
        .as_ref()
        .context("admitted holder custody absent")?;
    let account =
        arkret_wire::AccountId::new(principal.core_id.clone(), holder.service_id().parse()?);
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).context("obtain Consent nonce entropy")?;
    let request = ConsentCurrentReadRequestBody {
        holder_account_id: account.clone(),
        peer: peer.clone(),
        audience_actor_id: ActorId::service(account.station_id),
        nonce: arkret_canonical::base64url_encode(nonce),
    };
    let response: ConsentCurrentReadResponseBody = serde_json::from_value(
        expect_json(
            holder.post("/_arkret/self/consent/current").json(&request),
            reqwest::StatusCode::OK,
        )
        .await?,
    )?;
    response.validate_for_request(&request, 0, chrono::Utc::now())?;
    ensure!(
        response.realm_id == principal.pcr_realm_id,
        "Consent current changed its founding PCR"
    );
    Ok((request, response))
}

async fn originals(database: &str, holder: &arkret_wire::AccountId) -> Result<Value> {
    let database = database.to_owned();
    let account = serde_json::to_value(holder)?;
    let actor = ActorId::account(holder.clone()).to_string();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db=postgres::Client::connect(&database,postgres::NoTls)?;
        let current=db.query("SELECT to_jsonb(c) FROM consent_current_states c WHERE holder_account_id=$1",&[&account])?.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>();
        let versions=db.query("SELECT to_jsonb(v) FROM consent_result_versions v JOIN realm_commits c ON c.commit_id=v.commit_id JOIN consent_current_states s ON s.realm_id=c.realm_id WHERE s.holder_account_id=$1 ORDER BY c.stream_position",&[&account])?.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>();
        let quarantine=db.query("SELECT to_jsonb(a) FROM account_datas a WHERE actor_id=$1 AND account_data_key=$2 AND NOT tombstone AND account_data_source_current(actor_id,account_data_key)",&[&actor,&arkret_wire::AccountDataKey::ACCOUNT_HOLDER_QUARANTINE])?.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>();
        Ok(json!({"current":current,"versions":versions,"quarantine":quarantine}))
    }).await?
}

pub(super) async fn run() -> Result<()> {
    let (result,observations)=observe(async {
        let deployment=crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-consent-contract").await?;
        let device=DeviceId::new(arkret_identifiers::new_prefixed_uuid7("ak:device:"))?;
        let ca=deployment.station.tls_ca_path().context("owned Station CA absent")?;
        let requester_http=reqwest::Client::builder().tls_backend_rustls().tls_certs_only(reqwest::Certificate::from_pem_bundle(&std::fs::read(ca)?)?).cookie_store(true).redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(45)).build()?;
        let requester=deployment.station.canonical_client(CanonicalClientRequest {http:&requester_http,endpoints:&deployment.endpoints,oidc_client_id:&deployment.oidc_client_id,handle:"bob",password:"1amTester!",device_id:device.as_str(),display_name:"Consent requester"}).await?;
        let peer=ConsentPeer::Actor {actor_id:ActorId::account(arkret_wire::AccountId::new(requester.principal.as_ref().context("requester custody absent")?.core_id.clone(),deployment.station.service_id().clone()))};
        let database=deployment.station.owned_database_url().context("Consent requires owned native storage")?;
        let before=originals(database,&deployment.account).await?;
        let request=ConsentRequestRequestBody {holder_account_id:deployment.account.clone(),consent_scope:ConsentRequestScope::VoiceCall};
        let accepted=expect_json(requester.post("/_arkret/self/consent/request").json(&request),reqwest::StatusCode::OK).await?;
        let pending=originals(database,&deployment.account).await?;
        ensure!(pending["quarantine"].as_array().is_some_and(|cells|cells.len()==1),"constant Consent response did not prove actual quarantine admission");
        let cell:arkret_models_collaboration::governance::holder_quarantine::HolderQuarantine=serde_json::from_value(pending["quarantine"][0]["payload"].clone())?;
        cell.validate_holder(&deployment.account)?;
        ensure!(cell.live_consent_request(peer.actor_id(),request.consent_scope).is_some(),"quarantine has no exact admitted requester and scope");
        let replay=expect_json(requester.post("/_arkret/self/consent/request").json(&request),reqwest::StatusCode::OK).await?;
        let pending_replay=originals(database,&deployment.account).await?;
        ensure!(replay==accepted && pending_replay==pending,"repeated pending Consent request duplicated or changed the actual admission");
        let first=current(&deployment.controller,&peer).await?;
        ensure!(matches!(first.1.current,ConsentCurrentReadState::NeverWritten),"fresh peer unexpectedly has an existing consent");
        let permissions=vec![ConsentPermission {consent_scope:ConsentScope::VoiceCall,not_before:None,expires_at:Some(arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now()+chrono::Duration::minutes(10))),constraints:None,evidence_ref:None,reason:None}];
        let (granted,grant)=crate::scenarios::consent_call_context::replace_peer_permissions(&deployment.controller,peer.clone(),&first.1,permissions.clone()).await?;
        let grant_commit=crate::scenarios::mls_lifecycle_live::accepted_full_view(&deployment.controller,&grant.event_id).await?;
        let second=current(&deployment.controller,&peer).await?;
        let ConsentCurrentReadState::Present {current_state}=&second.1.current else {anyhow::bail!("admitted consent was absent from signed current");};
        ensure!(current_state.value.permissions==permissions,"signed Consent current changed accepted permissions");
        let granted_originals=originals(database,&deployment.account).await?;
        let (revoked,revoke)=crate::scenarios::consent_call_context::replace_peer_permissions(&deployment.controller,peer.clone(),&second.1,Vec::new()).await?;
        let revoke_commit=crate::scenarios::mls_lifecycle_live::accepted_full_view(&deployment.controller,&revoke.event_id).await?;
        let third=current(&deployment.controller,&peer).await?;
        let ConsentCurrentReadState::Present {current_state}=&third.1.current else {anyhow::bail!("revocation lost the accepted empty current tombstone");};
        ensure!(current_state.value.permissions.is_empty() && current_state.revision!=granted.revision,"Consent revocation did not advance its exact current revision");
        let after=originals(database,&deployment.account).await?;
        retain_diagnostic("consent-originals",&json!({"before":before,"pending":pending,"granted":granted_originals,"after":after}))?;
        ensure!(after["current"].as_array().is_some_and(|r|r.len()==1) && after["versions"].as_array().is_some_and(|r|r.len()==2),"Consent current lacks both immutable accepted versions");
        Ok::<_,anyhow::Error>(json!({"peer":peer,"request":request,"accepted":accepted,"pending_replay":pending_replay,"before":before,"pending":pending,"granted_originals":granted_originals,"after":after,"currents":[{"request":first.0,"response":first.1},{"request":second.0,"response":second.1},{"request":third.0,"response":third.1}],"grant":grant,"granted":granted,"grant_commit":grant_commit,"revoke":revoke,"revoked":revoked,"revoke_commit":revoke_commit,"processes":[deployment.coauth.server.native_process_identity()?,deployment.station.native_process_identity()?]}))
    }).await;
    retain_attempt("account-consent", &observations)?;
    let mut artifact = result?;
    validate_exchange_schemas(&observations, &SCOPE)?;
    for cut in artifact["currents"]
        .as_array()
        .context("Consent current originals absent")?
    {
        let response: ConsentCurrentReadResponseBody =
            serde_json::from_value(cut["response"].clone())?;
        let key = native_station_key(
            &observations,
            &response.proof.verification_method,
            response.evaluated_at,
        )?;
        arkret_signatures::proof::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
            &response.proof.jws,
            &response.signature_input()?,
            &key,
        )?;
    }
    verify_native_pcr_commits(
        &observations,
        &[
            serde_json::from_value(artifact["grant_commit"].clone())?,
            serde_json::from_value(artifact["revoke_commit"].clone())?,
        ],
    )?;
    artifact["case"] = json!("account_consent");

    artifact["scope"] = json!(SCOPE);
    artifact["observations"] = serde_json::to_value(observations)?;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("account-consent.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
