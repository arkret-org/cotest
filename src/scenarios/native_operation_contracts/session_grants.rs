//! Native human SessionGrant issuance and rotation use a genuinely admitted Device.
use arkret_models_collaboration::session_grants::{
    SessionGrantRequestBody, SessionGrantResponseBody,
};
use arkret_models_identity::SessionGrantMetadata;
use cotest_test_support::provisioning::{self, FoundingDeviceKey};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Serialize;

use super::*;

const SCOPE: [&str; 3] = [
    "ak.gate.account.command.issue_session_grant.v1",
    "ak.gate.account.command.refresh_session_grant.v1",
    "ak.gate.account.command.logout.v1",
];
type Deployment =
    crate::scenarios::agent_runtime_live::coauth_session_evidence::ActualAgentDeployment;

pub(super) async fn post<T: Serialize>(
    deployment: &Deployment,
    path: &str,
    operation: &str,
    token: &str,
    holder: &SigningKey,
    body: &T,
) -> Result<Value> {
    let url = format!("{}{path}", deployment.coauth.base_url());
    let proof = arkret_signatures::dpop::build_dpop_proof(
        &arkret_signatures::dpop::DpopProofRequest::new("POST", &url).access_token(token),
        holder,
    )?
    .proof_jwt;
    cotest_test_support::operation_observation::send_json_exchange(
        operation,
        deployment
            .http
            .post(url)
            .header("Arkret-Operation", operation)
            .header("Authorization", format!("DPoP {token}"))
            .header("DPoP", proof)
            .json(body),
    )
    .await
}

async fn verify_issued(
    deployment: &Deployment,
    grant: &SessionGrantResponseBody,
    holder: &SigningKey,
) -> Result<Value> {
    let database_url = deployment.coauth.pg.connect_url.clone();
    let secret = grant.session_grant.as_str().to_owned();
    let issuer = deployment.station.service_id().as_str().to_owned();
    let bytes = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
        let mut database = postgres::Client::connect(&database_url, postgres::NoTls)?;
        Ok(database
            .query_one(
                "SELECT canonical_metadata FROM oauth_session_grants WHERE session_grant=$1 AND issuer_id=$2",
                &[&secret, &issuer],
            )?
            .get(0))
    })
    .await??;
    let metadata: SessionGrantMetadata = serde_json::from_slice(&bytes)?;
    metadata.validate()?;
    ensure!(
        arkret_canonical::canonical_json_bytes(&metadata)? == bytes,
        "issuer metadata differs from its canonical original"
    );
    let now = chrono::Utc::now();
    let holder_jwk =
        arkret_models_identity::CanonicalSessionPublicJwk::new(serde_json::to_string(&json!({
            "crv": "Ed25519",
            "kty": "OKP",
            "x": arkret_canonical::base64url_encode(holder.verifying_key().to_bytes()),
        }))?)?;
    grant.validate_binding(
        deployment.station.service_id(),
        &deployment.account,
        deployment.station.service_id(),
        &holder_jwk,
        now,
    )?;
    metadata.validate_request_binding(
        &grant.grant_ref(),
        &deployment.account,
        &deployment.account.station_id,
        now,
    )?;
    let principal = deployment
        .controller
        .principal
        .as_ref()
        .context("accepted Device custody absent")?;
    let device = metadata
        .device_binding
        .as_ref()
        .context("issuer omitted accepted Device binding")?;
    let expected_jkt = arkret_signatures::dpop::dpop_jwk_thumbprint(
        &arkret_signatures::JsonWebKey::from_ed25519_verifying_key(&holder.verifying_key()),
    )?;
    ensure!(
        metadata.id == grant.session_grant_id
            && metadata.issuer_id == grant.issuer_id
            && metadata.session_public_key == grant.session_public_key
            && metadata.scopes == grant.granted_scope
            && metadata.expires_at == grant.expires_at
            && metadata.cnf_jkt == expected_jkt
            && grant.device_id.as_ref() == Some(&principal.device_id)
            && device.device_id == principal.device_id
            && device.authorization_event_id == principal.founding_authorize_event_id,
        "opaque response changed the exact issuer record or accepted holder"
    );
    let key = holder.clone();
    let client = arkret_http_client::Client::builder(deployment.station.base_url().clone())
        .http_client(deployment.http.clone())
        .auth(arkret_http_client::Auth::Dpop(
            arkret_http_client::DpopAuth::with_dpop_token(
                grant.session_grant.as_str().to_owned(),
                move |request| {
                    garth::session::dpop::build_http_dpop_proof(request, &key)
                        .map_err(|error| arkret_http_client::Error::Protocol(error.to_string()))
                },
            ),
        ))
        .build()?;
    let viewer = client.account_viewer().await?;
    ensure!(
        viewer.principal_id == deployment.account.principal_id,
        "Station consumed another opaque grant subject"
    );
    Ok(
        json!({"metadata":metadata,"verified_at":arkret_canonical::format_timestamp_canonical(now),
        "station_viewer":viewer,"credential_digest":arkret_canonical::sha256_digest(grant.session_grant.as_str().as_bytes()),"holder_jkt":expected_jkt}),
    )
}

async fn ledger(deployment: &Deployment, issued: &str, refreshed: &str) -> Result<Value> {
    let database = deployment.coauth.pg.connect_url.clone();
    let tokens = [issued.to_owned(), refreshed.to_owned()];
    let issuer = deployment.station.service_id().as_str().to_owned();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut database = postgres::Client::connect(&database, postgres::NoTls)?;
        let mut rows = Vec::new();
        for token in tokens {
            let row = database.query_one("SELECT to_jsonb(g), to_jsonb(o), o.canonical_outcome, g.canonical_metadata FROM oauth_session_grants g JOIN oauth_session_grant_operations o ON o.id=g.issuance_operation_id WHERE g.session_grant=$1 AND g.issuer_id=$2", &[&token, &issuer])?;
            let bytes: Vec<u8> = row.get(2);
            let preimage: Vec<u8> = row.get(3);
            let original: arkret_models_identity::SessionGrantMetadata = serde_json::from_slice(&preimage)?;
            original.validate()?;
            rows.push(json!({"grant":row.get::<_,Value>(0),"operation":row.get::<_,Value>(1),
                "canonical_outcome_base64url":arkret_canonical::base64url_encode(&bytes),
                "canonical_outcome":serde_json::from_slice::<Value>(&bytes)?,
                "canonical_metadata_base64url":arkret_canonical::base64url_encode(&preimage),"metadata":original}));
        }
        let count: i64 = database.query_one("SELECT count(*) FROM oauth_session_grants", &[])?.get(0);
        Ok(json!({"issued":rows[0],"refreshed":rows[1],"total_grants":count}))
    }).await?
}

pub(super) async fn run() -> Result<()> {
    let (result, observations) = observe(async {
        let deployment = crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-human-session-grants").await?;
        let principal = deployment.controller.principal.as_ref().context("founding Device custody absent")?;
        let holder = FoundingDeviceKey::generate("native-human-session-holder")?;
        let authorization = provisioning::authorize_with_current_account(&deployment.http, deployment.coauth.base_url(), &deployment.oidc_client_id).await?;
        let handoff = provisioning::create_returning_account_handoff(&deployment.http, deployment.coauth.base_url(), deployment.station.service_id().as_str(),
            &authorization, holder.clone(), &principal.core_id, &principal.did).await?;
        let holder_key = holder.signing_key();
        let jkt = arkret_canonical::base64url_encode(arkret_canonical::sha256_bytes(holder.canonical_public_jwk()?.as_bytes()));
        let request: SessionGrantRequestBody = serde_json::from_value(cotest_test_support::wire::human_session_grant_request(json!({
            "principal_did":principal.did,"account_id":deployment.account,"device_id":principal.device_id,"holder_jkt":jkt,
            "account_subject":handoff.account_subject,"account_handoff_grant":handoff.account_handoff_grant,
            "handoff_expires_at":handoff.expires_at,"device_signing_seed_b64url":arkret_canonical::base64url_encode(principal.device_signing_key.to_bytes()),
        }))?)?;
        let issue_url = "/_arkret/gate/account/session-grants";
        let issued = post(&deployment, issue_url, SCOPE[0], &handoff.account_handoff_grant, &holder_key, &request).await?;
        let retry = post(&deployment, issue_url, SCOPE[0], &handoff.account_handoff_grant, &holder_key, &request).await?;
        ensure!(issued == retry, "native issue retry changed its accepted original");
        let issued: SessionGrantResponseBody = serde_json::from_value(issued)?;
        ensure!(issued.previous_session_grant_id.is_none(), "fresh human issuance carried a predecessor");
        ensure!(issued.granted_scope == arkret_models_identity::standard_initial_session_grant_scope(), "human issuance changed the registered standard scope");
        let issued_proof = verify_issued(&deployment, &issued, &holder_key).await?;
        let claims: SessionGrantMetadata = serde_json::from_value(issued_proof["metadata"].clone())?;
        let now = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let unsigned = arkret_wire::UnsignedAcceptedDeviceRefreshPossessionProof {
            context: arkret_wire::AcceptedDevicePossessionProofContext::V1,
            purpose: arkret_wire::AcceptedDeviceRefreshPossessionPurpose::SessionGrantRefresh,
            predecessor_session_grant_ref: claims.grant_ref(),account_id: claims.account_id.clone(),device_id: principal.device_id.clone(),
            audience_id: claims.audience_id.clone(),holder_jkt: jkt.clone(),
            session_intent_digest: arkret_models_collaboration::session_grant_bodies::session_grant_refresh_request_digest(&issued.session_grant,
                &claims.grant_ref(), &claims.account_id.principal_id, &principal.device_id, &claims.audience_id, &jkt)?,
            issued_at: now,expires_at: now + chrono::Duration::minutes(1),
            verification_method: arkret_wire::DidUrl::new(format!("{}#{}", principal.did, principal.device_id)).map_err(anyhow::Error::msg)?,
        };
        let signature = arkret_wire::Base64UrlString::new(arkret_canonical::base64url_encode(
            principal.device_signing_key.sign(&unsigned.canonical_signing_bytes()?).to_bytes(),
        )).map_err(anyhow::Error::msg)?;
        let possession = unsigned.attach_signature(signature)?;
        let request = arkret::session_grant::human_session_grant_refresh_request(issued.session_grant.clone(), Some(claims.audience_id), principal.device_id.clone(), possession)?;
        let refreshed = post(&deployment, "/_arkret/gate/account/session-grants/refresh", SCOPE[1], issued.session_grant.as_str(), &holder_key, &request).await?;
        let retry = post(&deployment, "/_arkret/gate/account/session-grants/refresh", SCOPE[1], issued.session_grant.as_str(), &holder_key, &request).await?;
        ensure!(refreshed == retry, "native refresh retry changed its accepted original");
        let refreshed: SessionGrantResponseBody = serde_json::from_value(refreshed)?;
        refreshed.validate_refresh_binding(&issued, chrono::Utc::now())?;
        ensure!(refreshed.previous_session_grant_id.as_ref() == Some(&issued.session_grant_id), "native refresh lost its exact predecessor");
        let refreshed_proof = verify_issued(&deployment, &refreshed, &holder_key).await?;
        let refreshed_metadata: SessionGrantMetadata = serde_json::from_value(refreshed_proof["metadata"].clone())?;
        ensure!(refreshed_metadata.session_id == claims.session_id
            && refreshed_metadata.scope_details == claims.scope_details
            && refreshed_metadata.holder_binding == claims.holder_binding
            && refreshed_metadata.device_binding == claims.device_binding,
            "refresh changed the immutable session authority bindings");
        let originals = ledger(&deployment, issued.session_grant.as_str(), refreshed.session_grant.as_str()).await?;
        ensure!(originals["total_grants"] == 3 && originals["issued"]["grant"]["lifecycle_state"] == "superseded" &&
            originals["refreshed"]["grant"]["lifecycle_state"] == "active", "native replay minted extra grants or failed to supersede its predecessor");
        ensure!(originals["issued"]["canonical_outcome"] == serde_json::to_value(&issued)? &&
            originals["refreshed"]["canonical_outcome"] == serde_json::to_value(&refreshed)?, "native response differs from the issuer's immutable original");
        let audit = deployment.controller.sdk().principal_resolution_audit(&arkret_models_identity::PrincipalResolutionAuditRequestBody::new(deployment.account.clone())).await?;
        let logout=super::account_logout::exercise(&deployment,issued.session_grant.as_str(),refreshed.session_grant.as_str(),&holder_key,&audit).await?;
        Ok::<_,anyhow::Error>((deployment, originals, issued_proof, refreshed_proof, audit, logout))
    }).await;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory)?;
        std::fs::write(
            directory.join(format!(
                "attempt-account-device-sessions-{}.json",
                chrono::Utc::now().timestamp_millis()
            )),
            serde_json::to_vec_pretty(&json!({
                "status":"observed_not_verified", "observations":observations,
            }))?,
        )?;
    }
    let (deployment, originals, issued, refreshed, audit, logout) = result?;
    ensure!(
        originals["issued"]["metadata"] == issued["metadata"]
            && originals["refreshed"]["metadata"] == refreshed["metadata"],
        "issuer replay changed its immutable canonical metadata"
    );
    validate_exchange_schemas(&observations, &SCOPE)?;
    super::account_logout::verify(&observations, &logout, &refreshed["metadata"])?;
    ensure!(
        !observations.accepted_identity_material.is_empty(),
        "session proof lacks the accepted PCR/DID prerequisite"
    );
    let evidence = json!({"case":"account_device_sessions","scope":SCOPE,
        "observations":observations,"authority_originals":originals,"issued_verification":issued,"refreshed_verification":refreshed,
        "station_readback":audit,"logout":logout,"processes":[deployment.coauth.server.native_process_identity()?,deployment.station.native_process_identity()?]});
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory)?;
        std::fs::write(
            directory.join("account-device-sessions.json"),
            serde_json::to_vec_pretty(&evidence)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
