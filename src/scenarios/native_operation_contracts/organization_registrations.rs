//! External organization control, native history and atomic local lifecycle.
use arkret_models_identity::*;
use arkret_signatures::webvh::{OrganizationInceptionInput, PrincipalRotationInput};
use arkret_wire::{Did, DidCoreId, Hash, PayloadProof, ProofContextId};
use ed25519_dalek::SigningKey;

use super::*;
use crate::harness::{ArkretServer, TestActorClient, expect_json};

const SCOPE: [&str; 5] = [
    "ak.root.identity.organization_registration.command.prepare.v1",
    "ak.root.identity.organization_registration.command.ensure.v1",
    "ak.root.identity.organization_registration.command.refresh.v1",
    "ak.root.identity.organization_registration.command.revoke.v1",
    "ak.root.identity.organization_registration.resource.get.v1",
];
const ROOT: &str = "/_arkret/root/identity/organization-registrations";

fn secret() -> Result<[u8; 32]> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).context("organization key entropy")?;
    Ok(bytes)
}
fn public(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}
fn multikey(seed: &[u8; 32]) -> String {
    arkret_canonical::ed25519_pubkey_to_did_key_multibase(&public(seed))
}

fn control(
    challenge: &OrganizationRegistrationChallenge,
    version: &str,
    head: &Hash,
    key: &SigningKey,
) -> Result<OrganizationControlProof> {
    let method = arkret_wire::DidUrl::new(format!(
        "{}#organization-control",
        challenge.organization_did
    ))
    .map_err(anyhow::Error::msg)?;
    let created = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
    let transcript = json!({"context":ProofContextId::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1,
        "challenge_id":challenge.challenge_id,"organization_id":challenge.organization_id,
        "organization_did":challenge.organization_did,"local_admin_subject_id":challenge.local_admin_subject_id,
        "version_id":version,"log_head_digest":head,"verification_method":method,"created_at":created});
    let signer =
        arkret_signatures::Ed25519DetachedJwsSigner::new(key.clone(), method.as_str().to_owned());
    Ok(OrganizationControlProof {
        proof_kind: OrganizationControlProofKind::ResolvedVerificationMethod,
        quorum_threshold: None,
        proofs: vec![PayloadProof {
            kind: "detached_jws".into(),
            verification_method: method,
            payload_digest: Hash::new(arkret_canonical::canonical_sha256(&transcript)?)?,
            created_at: created,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: signer.sign_detached_jws(&arkret_canonical::canonical_json_bytes(&transcript)?),
        }],
    })
}
async fn prepare(
    actor: &TestActorClient,
    request: &OrganizationRegistrationChallengeRequestBody,
) -> Result<OrganizationRegistrationChallenge> {
    let response = expect_json(
        actor.post(&format!("{ROOT}:prepare")).json(request),
        reqwest::StatusCode::OK,
    )
    .await?;
    let challenge: OrganizationRegistrationChallenge = serde_json::from_value(response)?;
    challenge.validate_for_at(request, chrono::Utc::now())?;
    Ok(challenge)
}
async fn get(
    actor: &TestActorClient,
    id: &DidCoreId,
) -> Result<OrganizationRegistrationResponseBody> {
    let value = expect_json(
        actor.get(ROOT).query(&[("organization_id", id.as_str())]),
        reqwest::StatusCode::OK,
    )
    .await?;
    let response: OrganizationRegistrationResponseBody = serde_json::from_value(value)?;
    response.validate()?;
    ensure!(!response.created, "get creates no registration");
    Ok(response)
}
async fn ledger(database: &str, id: &DidCoreId) -> Result<Value> {
    let database = database.to_owned();
    let id = id.to_string();
    tokio::task::spawn_blocking(move ||->Result<Value> {
        let mut db=postgres::Client::connect(&database,postgres::NoTls)?;let mut snapshot=serde_json::Map::new();
        for table in ["organization_registration_challenges","organization_registration_outcomes","organization_registration_states"] {
            let records=db.query(&format!("SELECT to_jsonb(t) FROM {table} t WHERE organization_id=$1 ORDER BY to_jsonb(t)::text"),&[&id])?.into_iter().map(|r|r.get::<_,Value>(0)).collect::<Vec<_>>();snapshot.insert(table.into(),json!(records));
        }
        Ok(Value::Object(snapshot))
    }).await?
}
async fn method_entries(database: &str, did: &Did) -> Result<Vec<Value>> {
    let database = database.to_owned();
    let did = did.to_string();
    tokio::task::spawn_blocking(move || -> Result<Vec<Value>> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        Ok(db
            .query(
                "SELECT operation FROM webvh_log_events WHERE did=$1 ORDER BY sequence",
                &[&did],
            )?
            .into_iter()
            .map(|r| r.get(0))
            .collect())
    })
    .await?
}
async fn publish(
    provider: &ArkretServer,
    operator: &str,
    request: &DidOperationSubmitRequestBody,
) -> Result<DidOperationSubmitResponseBody> {
    let value = expect_json(
        provider
            .http()
            .post(provider.url("/_arkret/root/identity/submit-did-operation"))
            .bearer_auth(operator)
            .json(request),
        reqwest::StatusCode::OK,
    )
    .await?;
    let accepted: DidOperationSubmitResponseBody = serde_json::from_value(value)?;
    accepted.validate_accepted_for_request(request)?;
    Ok(accepted)
}

pub(super) async fn run() -> Result<()> {
    let (result,observations)=observe(async {
        let mut deployment=crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-organization-registry").await?;
        let administrator=deployment.account.principal_id.clone();
        deployment.station.restart_with_registry_administrators(std::slice::from_ref(&administrator)).await?;
        let external=crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-organization-provider").await?;
        let operator=external.webvh_registration_bearer.as_str();
        let provider=&external.station;
        let root=secret()?;let next=secret()?;let future=secret()?;let control_seed=secret()?;
        let control_key=SigningKey::from_bytes(&control_seed);let next_key=multikey(&next);
        let local_id=format!("org-{}",arkret_identifiers::new_prefixed_uuid7(""));
        let inception=arkret_signatures::webvh::prepare_organization_inception(&OrganizationInceptionInput {provider_endpoint:&provider.base_url(),local_id:&local_id,version_created_at:chrono::Utc::now()-chrono::Duration::seconds(2),root_seed:&root,next_root_public_key_multibase:&next_key,control_public_key:&public(&control_seed)})?;
        let accepted_inception=publish(provider,operator,&inception.submit_body).await?;
        let did=Did::new(&inception.did)?;let organization=arkret_wire::project_did_to_core_id(&did)?;
        let database=deployment.station.owned_database_url().context("registry native database")?;
        let provider_database=provider.owned_database_url().context("provider native database")?;
        let external_before=method_entries(provider_database,&did).await?;
        ensure!(external_before==vec![inception.log_entry.clone()] && method_entries(database,&did).await?.is_empty(),"organization was not independently published before registration");
        arkret_signatures::webvh::validate_webvh_history_at(&did,&external_before,chrono::Utc::now())?;
        let request=OrganizationRegistrationChallengeRequestBody {organization_id:organization.clone(),organization_did:did.clone(),local_admin_subject_id:administrator.clone(),requested_scopes:vec![OrganizationRegistrationScope::OrganizationProfileManage,OrganizationRegistrationScope::OrganizationRealmEndorse,OrganizationRegistrationScope::OrganizationServiceDelegate]};
        let challenge=prepare(&deployment.controller,&request).await?;
        ensure!(challenge.audience_id==*deployment.station.service_id() && challenge.origin.as_str().trim_end_matches('/')==deployment.station.base_url().as_str().trim_end_matches('/'),"challenge issuer or origin differs from registry");
        let head=Hash::new(arkret_canonical::canonical_sha256(&inception.log_entry)?)?;
        let ensure_request=OrganizationRegistrationEnsureRequestBody {organization_id:organization.clone(),organization_did:did.clone(),challenge_id:challenge.challenge_id.clone(),version_id:inception.version_id.clone(),log_head_digest:head.clone(),control_proof:control(&challenge,&inception.version_id,&head,&control_key)?,local_admin_subject_id:administrator.clone(),requested_scopes:request.requested_scopes.clone(),handle_attestation:None};
        ensure_request.validate_for_challenge_at(&challenge,chrono::Utc::now())?;
        let issued:OrganizationRegistrationResponseBody=serde_json::from_value(expect_json(deployment.controller.post(&format!("{ROOT}:ensure")).json(&ensure_request),reqwest::StatusCode::OK).await?)?;
        issued.validate()?;ensure!(issued.created && issued.registration_generation()==1 && issued.registration_receipt.status==OrganizationRegistrationStatus::Active,"first organization generation was not created");
        let replay:OrganizationRegistrationResponseBody=serde_json::from_value(expect_json(deployment.controller.post(&format!("{ROOT}:ensure")).json(&ensure_request),reqwest::StatusCode::OK).await?)?;
        ensure!(!replay.created && replay.registration_receipt==issued.registration_receipt,"ensure retry changed the accepted receipt");
        let first_get=get(&deployment.controller,&organization).await?;ensure!(first_get==replay,"get differs from accepted generation");
        let after_ensure=ledger(database,&organization).await?;
        let future_key=multikey(&future);
        let rotation=arkret_signatures::webvh::prepare_organization_rotation(&PrincipalRotationInput {did:did.as_str(),local_id:&local_id,previous_entries:&external_before,version_created_at:chrono::Utc::now(),current_root_seed:&next,next_root_public_key_multibase:&future_key,state:&inception.log_entry["state"]})?;
        let accepted_rotation=publish(provider,operator,&rotation.submit_body).await?;
        let refresh_challenge=prepare(&deployment.controller,&request).await?;
        let refresh_head=Hash::new(arkret_canonical::canonical_sha256(&rotation.log_entry)?)?;
        let refresh_request=OrganizationRegistrationRefreshRequestBody {organization_id:organization.clone(),organization_did:did.clone(),challenge_id:refresh_challenge.challenge_id.clone(),version_id:rotation.version_id.clone(),log_head_digest:refresh_head.clone(),control_proof:control(&refresh_challenge,&rotation.version_id,&refresh_head,&control_key)?};
        refresh_request.validate_for_challenge_at(&refresh_challenge,&administrator,&request.requested_scopes,chrono::Utc::now())?;
        let refreshed:OrganizationRegistrationResponseBody=serde_json::from_value(expect_json(deployment.controller.post(&format!("{ROOT}:refresh")).json(&refresh_request),reqwest::StatusCode::OK).await?)?;
        refreshed.validate()?;ensure!(!refreshed.created && refreshed.registration_generation()==1 && refreshed.version_id()==rotation.version_id && refreshed.registration_receipt.log_head_digest==refresh_head,"refresh changed generation or ignored the actual rotation");
        let refresh_replay:OrganizationRegistrationResponseBody=serde_json::from_value(expect_json(deployment.controller.post(&format!("{ROOT}:refresh")).json(&refresh_request),reqwest::StatusCode::OK).await?)?;
        ensure!(refresh_replay==refreshed,"refresh retry changed its original receipt");
        let after_refresh=ledger(database,&organization).await?;
        let revoke_request=OrganizationRegistrationRevokeRequestBody {organization_id:organization.clone(),reason_code:Some(OrganizationRegistrationRevokeReason::OrganizationRegistrationWithdrawn)};
        let revoked:OrganizationRegistrationResponseBody=serde_json::from_value(expect_json(deployment.controller.post(&format!("{ROOT}:revoke")).json(&revoke_request),reqwest::StatusCode::OK).await?)?;
        revoked.validate()?;ensure!(!revoked.created && revoked.registration_generation()==1 && revoked.registration_receipt.status==OrganizationRegistrationStatus::Revoked,"revoke did not terminate the same local generation");
        let revoke_replay:OrganizationRegistrationResponseBody=serde_json::from_value(expect_json(deployment.controller.post(&format!("{ROOT}:revoke")).json(&revoke_request),reqwest::StatusCode::OK).await?)?;
        let final_get=get(&deployment.controller,&organization).await?;
        ensure!(revoke_replay==revoked && final_get==revoked,"terminal read or retry changed the revoked original");
        let after_revoke=ledger(database,&organization).await?;
        let external_after=method_entries(provider_database,&did).await?;
        ensure!(external_after==vec![inception.log_entry.clone(),rotation.log_entry.clone()] && method_entries(database,&did).await?.is_empty(),"local registration changed or hosted external method history");
        let public_history:IdentityLogListResponseBody=serde_json::from_value(expect_json(provider.http().get(provider.url("/_arkret/root/identity/log")).query(&[("did",did.as_str())]),reqwest::StatusCode::OK).await?)?;
        ensure!(public_history.entries==external_after && public_history.did==did,"public organization history differs from accepted provider originals");
        arkret_signatures::webvh::validate_webvh_history_at(&did,&public_history.entries,chrono::Utc::now())?;
        Ok::<_,anyhow::Error>(json!({"organization_id":organization,"administrator":administrator,"challenge_request":request,"challenge":challenge,"ensure_request":ensure_request,"issued":issued,"ensure_replay":replay,"first_get":first_get,"after_ensure":after_ensure,"refresh_challenge":refresh_challenge,"refresh_request":refresh_request,"refreshed":refreshed,"refresh_replay":refresh_replay,"after_refresh":after_refresh,"revoke_request":revoke_request,"revoked":revoked,"revoke_replay":revoke_replay,"final_get":final_get,"after_revoke":after_revoke,"external_before":external_before,"external_after":external_after,"public_history":public_history,"accepted_inception":accepted_inception,"accepted_rotation":accepted_rotation,"registry_native_history":[],"processes":[deployment.coauth.server.native_process_identity()?,deployment.station.native_process_identity()?,provider.native_process_identity()?,external.coauth.server.native_process_identity()?]}))
    }).await;
    retain_attempt("organization-registrations", &observations)?;
    let mut artifact = result?;
    validate_exchange_schemas(&observations, &SCOPE)?;
    let history: IdentityLogListResponseBody =
        serde_json::from_value(artifact["public_history"].clone())?;
    for (request_name, challenge_name) in [
        ("ensure_request", "challenge"),
        ("refresh_request", "refresh_challenge"),
    ] {
        let request = &artifact[request_name];
        let challenge = &artifact[challenge_name];
        for proof in request["control_proof"]["proofs"]
            .as_array()
            .context("control proofs")?
        {
            let proof: PayloadProof = serde_json::from_value(proof.clone())?;
            let point = arkret_signatures::webvh::validate_webvh_history_at(
                &history.did,
                &history.entries,
                proof.created_at,
            )?;
            ensure!(
                point.document["authentication"]
                    .as_array()
                    .is_some_and(|methods| methods.contains(&json!(proof.verification_method))),
                "control method lacks the actual signing-time authentication relationship"
            );
            let document: arkret_identity::DidDocument = serde_json::from_value(point.document)?;
            let key = arkret_identity::public_key_material_from_document(
                &document,
                &proof.verification_method,
            )?;
            let transcript = json!({"context":ProofContextId::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1,"challenge_id":request["challenge_id"],"organization_id":request["organization_id"],"organization_did":request["organization_did"],"local_admin_subject_id":challenge["local_admin_subject_id"],"version_id":request["version_id"],"log_head_digest":request["log_head_digest"],"verification_method":proof.verification_method,"created_at":proof.created_at});
            ensure!(
                proof.payload_digest.as_str() == arkret_canonical::canonical_sha256(&transcript)?,
                "control transcript differs from actual beneficiary-bound request"
            );
            arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
                &proof.jws,
                &arkret_canonical::canonical_json_bytes(&transcript)?,
                &key,
            )?;
        }
    }
    for name in ["issued", "refreshed", "revoked"] {
        let response: OrganizationRegistrationResponseBody =
            serde_json::from_value(artifact[name].clone())?;
        response.validate()?;
        let receipt = &response.registration_receipt;
        let key = native_station_key(
            &observations,
            &receipt.proof.verification_method,
            receipt.issued_at,
        )?;
        arkret_signatures::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
            &receipt.proof.jws,
            &receipt.proof_signing_bytes()?,
            &key,
        )?;
    }
    artifact["case"] = json!("organization_registrations");
    artifact["format_version"] = json!(1);
    artifact["scope"] = json!(SCOPE);
    artifact["observations"] = serde_json::to_value(observations)?;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("organization-registrations.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
