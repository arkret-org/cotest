//! Native IVS custody, accepted invitation, activation and actual OOB delivery.
use arkret_models_collaboration::governance::third_party_invite::*;

use super::*;
use crate::harness::{CanonicalClientRequest, expect_json};
const SCOPE: [&str; 5] = [
    "ak.open.third_party_invite.command.provision.v1",
    "ak.open.third_party_invite.command.activate.v1",
    "ak.open.third_party_invite.read.provisioning_status.v1",
    "ak.open.third_party_invite.command.present_token.v1",
    "ak.self.third_party_invite.read.acceptance_attestation.v1",
];
async fn post(
    deployment:&crate::scenarios::agent_runtime_live::coauth_session_evidence::ActualAgentDeployment,
    path: &str,
    body: &impl serde::Serialize,
) -> Result<Value> {
    expect_json(
        deployment
            .station
            .http()
            .post(deployment.station.url(path))
            .header("content-type", "application/json")
            .body(arkret_canonical::canonical_json_bytes(body)?),
        reqwest::StatusCode::OK,
    )
    .await
}
async fn private_rows(database: &str) -> Result<Vec<Value>> {
    let database = database.to_owned();
    tokio::task::spawn_blocking(move || -> Result<Vec<Value>> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        Ok(db
            .query(
                "SELECT to_jsonb(r) FROM third_party_invite_private r ORDER BY handle_digest",
                &[],
            )?
            .into_iter()
            .map(|r| r.get(0))
            .collect())
    })
    .await?
}
pub(super) async fn run() -> Result<()> {
    let (result,observations)=observe(crate::harness::heap_future(|| async {
  let deployment=crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment_with_third_party_invites("native-third-party-invites").await?;
  let ca=deployment.station.tls_ca_path().context("actual Station CA")?;
  let bob_http=reqwest::Client::builder().tls_backend_rustls().tls_certs_only(reqwest::Certificate::from_pem_bundle(&std::fs::read(ca)?)?).cookie_store(true).redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(45)).build()?;
  let device=arkret_wire::DeviceId::new(arkret_identifiers::new_prefixed_uuid7("ak:device:"))?;
  let bob=deployment.station.canonical_client(CanonicalClientRequest {http:&bob_http,endpoints:&deployment.endpoints,oidc_client_id:&deployment.oidc_client_id,handle:"bob",password:"1amTester!",device_id:device.as_str(),display_name:"Native invite recipient"}).await?;
  let bob_principal=bob.principal.as_ref().context("actual recipient founding custody")?;
  let bob_account=arkret_wire::AccountId::new(bob_principal.core_id.clone(),deployment.station.service_id().clone());
  let created=deployment.controller.create_realm_with(json!({"title":"Native token invitation","public":false,"join_rule":"invite","allowed_third_party_invite_verification_ids":[deployment.station.service_id()],"plaintext_visible_services":[deployment.station.service_id()]})).await?;
  let realm:arkret_wire::RealmId=created["realm_id"].as_str().context("actual invitation Realm")?.parse()?;
  let genesis=crate::scenarios::mls_lifecycle_live::accepted_full_view(&deployment.controller,&arkret_wire::EventId::from_digest(arkret_canonical::DigestSuite::Sha256,realm.digest_bytes())).await?;
  let holder=deployment.controller.principal.as_ref().context("actual inviter custody")?;
  let method=arkret_wire::DidUrl::new(format!("{}#{}",holder.did,holder.device_id)).map_err(anyhow::Error::msg)?;
  let at=arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
  let unsigned=json!({"request_id":arkret_identifiers::new_prefixed_uuid7("ak:request:"),"realm_id":realm,"inviter_account_id":deployment.account,"verification_id":deployment.station.service_id(),"oob_code_kind":"offline_token","delivery_target_uri":"mailto:native-invite-recipient@arkret.test","expires_at":arkret_canonical::format_timestamp_canonical(at+chrono::Duration::hours(1))});
  let digest=arkret_wire::Hash::new(arkret_canonical::canonical_sha256(&unsigned)?)?;
  let proof=arkret_wire::UnsignedPayloadProof {kind:"detached_jws".into(),verification_method:method.clone(),payload_digest:digest.clone(),created_at:at,domain:Some(deployment.station.trust_domain().to_string()),audience:Some(arkret_wire::Audience::Single(deployment.station.service_id().to_string())),proof_purpose:None};
  let bytes=arkret_wire::service_operation_proof_binding_bytes(arkret_wire::ProofContextId::THIRD_PARTY_INVITE_PROVISION_REQUEST_PROOF_V1,arkret_wire::ServiceOperationId::OPEN_THIRD_PARTY_INVITE_COMMAND_PROVISION_V1,Some(json!(deployment.account)),Vec::new(),&digest,&proof)?;
  let jws=arkret_signatures::Ed25519DetachedJwsSigner::new(holder.device_signing_key.clone(),method.to_string()).sign_detached_jws(&bytes);
  let mut wire=unsigned;wire["signature"]=json!(proof.finalize(jws)?);
  let request:ThirdPartyInviteProvisionRequestBody=serde_json::from_value(wire)?;request.validate_for_service(deployment.station.service_id())?;
  let provisioned=post(&deployment,"/_arkret/open/third-party-invites/provision",&request).await?;
  let provision:ThirdPartyInviteProvisionResponseBody=serde_json::from_value(provisioned.clone())?;provision.validate_for_request(&request)?;
  let provision_replay=post(&deployment,"/_arkret/open/third-party-invites/provision",&request).await?;ensure!(provision_replay==provisioned,"IVS reissued material on exact retry");
  let event=deployment.controller.author_event(realm.as_str(),arkret_wire::EventKind::InviteThirdParty.as_str(),json!({"third_party_invite":provision.third_party_invite,"expires_at":arkret_canonical::format_timestamp_canonical(provision.expires_at)})).await?;
  crate::scenarios::human_device_producer_live::submit_and_expect_commit(&deployment.controller,&deployment.account,&deployment.controller.device_id,&event).await?;
  let original=crate::scenarios::mls_lifecycle_live::accepted_full_view(&deployment.controller,&event.event_id).await?;
  let attestation_request=ThirdPartyInviteAcceptanceAttestationRequestBody {realm_id:realm.clone(),invite_id:arkret_wire::InviteId::from_event_id(&event.event_id),provisioning_id:provision.provisioning_id.clone(),verification_id:deployment.station.service_id().clone()};
  let attested=expect_json(deployment.controller.post("/_arkret/self/third-party-invites/acceptance-attestation").json(&attestation_request),reqwest::StatusCode::OK).await?;
  let attestation:ThirdPartyInviteAcceptanceAttestationResponseBody=serde_json::from_value(attested.clone())?;attestation.validate_for_request(&attestation_request)?;
  let activation_request=ThirdPartyInviteActivationRequestBody {provisioning_id:provision.provisioning_id.clone(),acceptance_attestation:attestation.acceptance_attestation};
  let activated=post(&deployment,"/_arkret/open/third-party-invites/activate",&activation_request).await?;
  let activation:ThirdPartyInviteActivationResponseBody=serde_json::from_value(activated.clone())?;activation.validate_for_request(&activation_request)?;
  let activation_replay=post(&deployment,"/_arkret/open/third-party-invites/activate",&activation_request).await?;ensure!(activation_replay==activated,"activation retry changed its durable original");
  let inbox=&deployment.endpoints.mock_email.as_ref().context("actual OOB receiving transport")?.base_url;
  let deadline=std::time::Instant::now()+std::time::Duration::from_secs(60);
  let (delivery,token)=loop {let inbox:Value=deployment.http.get(format!("{inbox}/mock/email/verification/inbox")).query(&[("to","native-invite-recipient@arkret.test")]).send().await?.error_for_status()?.json().await?;let found=inbox["messages"].as_array().context("actual delivered mail")?.iter().find_map(|mail|mail["body"].as_str().and_then(|body|body.split_once("Your invitation code is ")).and_then(|(_,tail)|tail.split_once('.')).map(|(code,_)|(mail.clone(),code.to_owned())));if let Some(value)=found {break value}ensure!(std::time::Instant::now()<deadline,"native provider did not deliver its actual code");tokio::time::sleep(std::time::Duration::from_millis(100)).await;};
  let status_request=ThirdPartyInviteProvisioningStatusRequestBody {provisioning_id:provision.provisioning_id.clone()};
  let status=post(&deployment,"/_arkret/open/third-party-invites/status",&status_request).await?;
  let typed:ThirdPartyInviteProvisioningStatusResponseBody=serde_json::from_value(status.clone())?;typed.validate()?;
  ensure!(typed.provisioning_state==ThirdPartyInviteProvisioningState::Activated && typed.invite_id.as_ref()==Some(&activation.invite_id),"status did not recover its actual activated invite");
  let mut entropy=[0u8;24];getrandom::fill(&mut entropy).context("actual claim nonce")?;
  let present_request=ThirdPartyInvitePresentRequestBody {invite_token:token,realm_id:realm.clone(),subject_account_id:bob_account.clone(),subject_did:bob_principal.did.clone(),claim_nonce:arkret_canonical::base64url_encode(&entropy)};present_request.validate_minimal()?;
  let presented=post(&deployment,"/_arkret/open/third-party-invites/present",&present_request).await?;
  let presented_typed:ThirdPartyInvitePresentResponseBody=serde_json::from_value(presented.clone())?;
  ensure!(presented_typed.invite_id==activation.invite_id && presented_typed.binding_proof.subject_account_id==bob_account && presented_typed.binding_proof.claim_nonce==present_request.claim_nonce,"native IVS changed its actual token holder claim");
  let custody=private_rows(&deployment.coauth.pg.connect_url).await?;
  ensure!(custody.len()==1 && custody[0]["state"]=="consumed" && custody[0]["token_selector"].is_null() && custody[0]["deliver_after"].is_null(),"native presentation did not exhaust its actual single-use custody and delivery selector");
  Ok::<_,anyhow::Error>(json!({"request":request,"provisioned":provisioned,"provision_replay":provision_replay,"genesis":genesis,"original":original,"attestation_request":attestation_request,"attested":attested,"activation_request":activation_request,"activated":activated,"activation_replay":activation_replay,"status_request":status_request,"status":status,"delivery":delivery,"present_request":present_request,"presented":presented,"custody":custody,"processes":[deployment.coauth.server.native_process_identity()?,deployment.station.native_process_identity()?]}))
 })).await;
    retain_attempt("third-party-invites", &observations)?;
    let mut artifact = result?;
    validate_exchange_schemas(&observations, &SCOPE)?;
    let views = ["genesis", "original"]
        .map(|name| serde_json::from_value(artifact[name].clone()))
        .into_iter()
        .collect::<std::result::Result<Vec<arkret_wire::CommittedEventFullView>, _>>()?;
    verify_native_station_commits(&observations, &views)?;
    let attested: ThirdPartyInviteAcceptanceAttestationResponseBody =
        serde_json::from_value(artifact["attested"].clone())?;
    let attestation = &attested.acceptance_attestation;
    let key = native_station_key(
        &observations,
        &attestation.signature.verification_method,
        attestation.signature.created_at,
    )?;
    arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
        &attestation.signature.jws,
        &attestation.proof_binding_bytes()?,
        &key,
    )?;
    let presented: ThirdPartyInvitePresentResponseBody =
        serde_json::from_value(artifact["presented"].clone())?;
    let invite: ThirdPartyInviteProvisionResponseBody =
        serde_json::from_value(artifact["provisioned"].clone())?;
    let bytes=arkret_models_collaboration::governance::membership_invite::invite_binding_proof_transcript_bytes(&presented.binding_proof,presented.invite_id.as_str(),presented.token_commitment.as_str(),attestation.invite_digest()?.as_str())?;
    arkret_signatures::proof::verify_ed25519_raw_transcript_signature(
        &bytes,
        &presented.binding_proof.signature,
        &arkret_signatures::PublicKeyMaterial::Ed25519Multibase {
            value: invite.third_party_invite.verification_public_key,
        },
    )?;
    artifact["case"] = json!("third_party_invites");
    artifact["format_version"] = json!(1);
    artifact["scope"] = json!(SCOPE);
    artifact["observations"] = json!(observations);
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("third-party-invites.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
