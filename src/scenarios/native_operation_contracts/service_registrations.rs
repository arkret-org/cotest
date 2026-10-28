//! Public registration replay uses the service's actual native bootstrap original.
use arkret_models_identity::service_identity::{
    CanonicalServiceUrl, ServiceRegistrationEnsureRequestBody, ServiceRegistrationKey,
    ServiceRegistrationResponseBody, ServiceWebvhInceptionOperation,
};
use arkret_wire::ServiceKind;

use super::*;
use crate::harness::expect_json;

const SCOPE: [&str; 2] = [
    "ak.root.identity.service_registration.command.ensure.v1",
    "ak.root.identity.service_registration.resource.get.v1",
];

async fn original(database: &str, key: &ServiceRegistrationKey) -> Result<Value> {
    let database = database.to_owned();
    let kind = key.service_kind().as_str().to_owned();
    let url = key.public_base_url().as_str().to_owned();
    tokio::task::spawn_blocking(move || ->Result<Value> {
        let mut db=postgres::Client::connect(&database,postgres::NoTls)?;
        let row=db.query_one("SELECT to_jsonb(r),l.operation,(SELECT count(*) FROM webvh_log_events h WHERE h.did=l.did) FROM service_identity_registrations r JOIN webvh_log_events l ON l.did=(r.outcome#>>'{did_document,id}') AND l.sequence=1 WHERE r.service_kind=$1 AND r.public_base_url=$2",&[&kind,&url])?;
        Ok(json!({"registration":row.get::<_,Value>(0),"inception_operation":row.get::<_,Value>(1),"entry_count":row.get::<_,i64>(2)}))
    }).await?
}

pub(super) async fn run() -> Result<()> {
    let (result,observations)=observe(async {
        let deployment=crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-service-registrations").await?;
        let key=ServiceRegistrationKey::new(ServiceKind::Station,CanonicalServiceUrl::new(deployment.station.base_url().as_str())?)?;
        let database=deployment.station.owned_database_url().context("owned registry database absent")?;
        let before=original(database,&key).await?;
        let read=||deployment.station.http().get(deployment.station.url("/_arkret/root/identity/service-registrations")).bearer_auth(&deployment.webvh_registration_bearer).query(&[("service_kind",key.service_kind().as_str()),("public_base_url",key.public_base_url().as_str())]);
        let found=expect_json(read(),reqwest::StatusCode::OK).await?;
        let accepted:ServiceRegistrationResponseBody=serde_json::from_value(found.clone())?;
        accepted.validate_for(&key)?;
        ensure!(accepted.registration_receipt.service_id==*deployment.station.service_id() && accepted.did_document.id==*deployment.station.service_did() && before["registration"]["outcome"]["registration_receipt"]==found["registration_receipt"] && before["registration"]["outcome"]["did_document"]==found["did_document"] && found["created"]==false,"public get differs from the actual native service identity");
        let inception:ServiceWebvhInceptionOperation=serde_json::from_value(before["inception_operation"].clone())?;
        let request=ServiceRegistrationEnsureRequestBody::new(key.clone(),inception,format!("native-registry-{}",arkret_identifiers::new_prefixed_uuid7("ak:request:")),Some(accepted.registration_receipt.clone()))?;
        let send=||deployment.station.http().post(deployment.station.url("/_arkret/root/identity/service-registrations:ensure")).bearer_auth(&deployment.webvh_registration_bearer).json(&request);
        let ensured=expect_json(send(),reqwest::StatusCode::OK).await?;
        let replay=expect_json(send(),reqwest::StatusCode::OK).await?;
        let typed:ServiceRegistrationResponseBody=serde_json::from_value(ensured.clone())?;
        typed.validate_ensure_response(&request)?;
        let after_get=expect_json(read(),reqwest::StatusCode::OK).await?;
        let after=original(database,&key).await?;
        ensure!(found==ensured && ensured==replay && replay==after_get && before["inception_operation"]==after["inception_operation"] && before["registration"]["outcome"]==after["registration"]["outcome"] && before["entry_count"]==after["entry_count"],"native ensure replay changed the original document, receipt or durable registration");
        Ok::<_,anyhow::Error>(json!({"key":key,"before":before,"get":found,"ensure_request":request,"ensured":ensured,"replay":replay,"after_get":after_get,"after":after,"processes":[deployment.coauth.server.native_process_identity()?,deployment.station.native_process_identity()?]}))
    }).await;
    retain_attempt("service-registrations", &observations)?;
    let mut artifact = result?;
    validate_exchange_schemas(&observations, &SCOPE)?;
    let response: ServiceRegistrationResponseBody =
        serde_json::from_value(artifact["get"].clone())?;
    let receipt = &response.registration_receipt;
    ensure!(
        receipt.proof.payload_digest == receipt.expected_payload_digest()?
            && receipt.registration_receipt_id == receipt.expected_registration_receipt_id()?,
        "registration receipt changed its canonical identity"
    );
    let key = native_station_key(
        &observations,
        &receipt.proof.verification_method,
        receipt.proof.created_at,
    )?;
    arkret_signatures::proof::Ed25519DetachedJwsVerifier::new().verify_detached_jws(
        &receipt.proof.jws,
        &receipt.proof_binding_bytes()?,
        &key,
    )?;
    artifact["case"] = json!("service_registrations");

    artifact["scope"] = json!(SCOPE);
    artifact["observations"] = serde_json::to_value(observations)?;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("service-registrations.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
