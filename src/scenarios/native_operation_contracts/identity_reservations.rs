//! Native frozen reservations, fresh authentication and published method history.
use arkret_models_identity::{
    CanonicalSessionPublicJwk, DidBindingChallengeRequestBody, DidBindingChallengeResponseBody,
    DidOperationSubmitRequestBody, DidOperationSubmitResponseBody, IdentityAbandonmentRequestBody,
    IdentityAbandonmentResponseBody, IdentityBindingChallengeRequestBody,
    IdentityLogListResponseBody, PrincipalRegistrationAnchor,
};
use cotest_test_support::provisioning::{self, AccountHandoff, FoundingDeviceKey};

use super::*;
use crate::harness::expect_json;
use crate::scenarios::agent_runtime_live::coauth_session_evidence::ActualAgentDeployment;

const SCOPE: [&str; 3] = [
    "ak.gate.account.command.abandon_identity_creation.v1",
    "ak.gate.account.command.issue_did_binding_challenge.v1",
    "ak.root.identity.command.submit_did_operation.v1",
];

async fn user(deployment: &ActualAgentDeployment, handle: &str) -> Result<reqwest::Client> {
    let ca = deployment
        .station
        .tls_ca_path()
        .context("owned Station CA absent")?;
    let http = reqwest::Client::builder()
        .tls_backend_rustls()
        .tls_certs_only(reqwest::Certificate::from_pem_bundle(&std::fs::read(ca)?)?)
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(45))
        .build()?;
    provisioning::provision_unbound_account(
        &http,
        &deployment.endpoints,
        &provisioning::UnboundAccount {
            handle: handle.into(),
            email: format!("{handle}@example.test"),
            password: "1amTester!".into(),
            display_name: handle.into(),
        },
    )
    .await?;
    Ok(http)
}

async fn handoff(
    deployment: &ActualAgentDeployment,
    http: &reqwest::Client,
    key: FoundingDeviceKey,
) -> Result<AccountHandoff> {
    let authorization = provisioning::authorize_with_current_account(
        http,
        deployment.coauth.base_url(),
        &deployment.oidc_client_id,
    )
    .await?;
    provisioning::create_account_handoff(
        http,
        deployment.coauth.base_url(),
        deployment.station.service_id().as_str(),
        &authorization,
        key,
    )
    .await
}

async fn post(
    http: &reqwest::Client,
    base: &str,
    handoff: &AccountHandoff,
    operation: &str,
    path: &str,
    body: &impl serde::Serialize,
) -> Result<Value> {
    let url = format!("{}{path}", base.trim_end_matches('/'));
    let proof = arkret_signatures::dpop::build_dpop_proof(
        &arkret_signatures::dpop::DpopProofRequest::new("POST", &url)
            .access_token(&handoff.account_handoff_grant),
        &handoff.device_key.signing_key(),
    )?
    .proof_jwt;
    cotest_test_support::operation_observation::send_json_exchange(
        operation,
        http.post(url)
            .header("Arkret-Operation", operation)
            .header(
                "Authorization",
                format!("DPoP {}", handoff.account_handoff_grant),
            )
            .header("DPoP", proof)
            .header("Content-Type", "application/json")
            .body(arkret_canonical::canonical_json_bytes(body)?),
    )
    .await
}

async fn ledger(database: &str) -> Result<Value> {
    let database = database.to_owned();
    tokio::task::spawn_blocking(move || -> Result<Value> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        let mut snapshot = serde_json::Map::new();
        for table in [
            "identity_creation_leases",
            "identity_binding_challenges",
            "did_binding_challenges",
            "account_handoff_grants",
            "identity_abandonments",
            "identity_orphan_anchor_tombstones",
            "user_sessions",
            "user_session_authentications",
        ] {
            let rows = db
                .query(
                    &format!("SELECT to_jsonb(t) FROM {table} t ORDER BY to_jsonb(t)::text"),
                    &[],
                )?
                .into_iter()
                .map(|r| r.get::<_, Value>(0))
                .collect::<Vec<_>>();
            snapshot.insert(table.into(), json!(rows));
        }
        Ok(Value::Object(snapshot))
    })
    .await?
}

async fn pcr_count(database: &str, realm: &arkret_wire::RealmId) -> Result<i64> {
    let database = database.to_owned();
    let realm = realm.to_string();
    tokio::task::spawn_blocking(move || -> Result<i64> {
        let mut db = postgres::Client::connect(&database, postgres::NoTls)?;
        Ok(db
            .query_one(
                "SELECT count(*) FROM canonical_events WHERE realm_id=$1",
                &[&realm],
            )?
            .get(0))
    })
    .await?
}

pub(super) async fn run() -> Result<()> {
    let (result,observations)=observe(async {
        let deployment=crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-identity-reservations").await?;
        let bob=user(&deployment,"bob").await?;
        let holder=FoundingDeviceKey::generate("reservation-holder")?;
        let pending=handoff(&deployment,&bob,holder.clone()).await?;
        let facts=provisioning::describe_station(&bob,&deployment.endpoints).await?;
        let device=arkret_identifiers::new_prefixed_uuid7("ak:device:");
        let prepared=provisioning::prepare_principal_registration(&bob,provisioning::FoundPrincipalRequest {coauth_base:deployment.coauth.base_url(),station_base:&deployment.endpoints.coland_base_url,trust_domain:&facts.trust_domain,audience_id:&facts.service_id,device_id:&device,display_name:"Abandoned provisional owner"},&pending).await?;
        let creation=prepared.register_body.identity_creation.as_ref().context("frozen creation absent")?;
        let before=ledger(&deployment.coauth.pg.connect_url).await?;
        let station_database=deployment.station.owned_database_url().context("native Station database absent")?;
        let absent_before=pcr_count(station_database,&creation.pcr_genesis_unit.create().realm_id).await?;
        ensure!(absent_before==0,"abandonment candidate already has accepted PCR state");
        provisioning::coauth_account::login(&bob,deployment.coauth.base_url(),"bob","1amTester!").await?;
        let fresh=handoff(&deployment,&bob,holder).await?;
        ensure!(fresh.binding["identity_creation_lease"]["identity_creation_lease_id"]==json!(creation.identity_creation_lease_id),"fresh authentication changed the frozen lease");
        let fresh_original=ledger(&deployment.coauth.pg.connect_url).await?;
        let abandon=IdentityAbandonmentRequestBody {request_id:arkret_identifiers::new_prefixed_uuid7("ak:request:").parse()?,identity_creation_lease_id:creation.identity_creation_lease_id.clone(),lease_fence:creation.lease_fence,principal_id:prepared.register_body.principal_id.clone(),did_version_id:creation.registration_did_evidence_draft.version_id.clone()};
        abandon.validate()?;
        let abandoned=post(&bob,deployment.coauth.base_url(),&fresh,SCOPE[0],"/_arkret/gate/account/identity-abandonments",&abandon).await?;
        let typed:IdentityAbandonmentResponseBody=serde_json::from_value(abandoned.clone())?;
        ensure!(typed.request_id==abandon.request_id && typed.principal_id==abandon.principal_id && typed.did_version_id==abandon.did_version_id && typed.account_subject==fresh.account_subject,"abandonment changed its frozen owner or identity");
        let replay=post(&bob,deployment.coauth.base_url(),&fresh,SCOPE[0],"/_arkret/gate/account/identity-abandonments",&abandon).await?;
        ensure!(replay==abandoned,"abandonment retry did not return its original terminal result");
        let after=ledger(&deployment.coauth.pg.connect_url).await?;
        let absent_after=pcr_count(station_database,&creation.pcr_genesis_unit.create().realm_id).await?;
        ensure!(absent_after==0 && after["identity_orphan_anchor_tombstones"].as_array().context("tombstones absent")?.iter().filter(|r|r["principal_id"]==json!(abandon.principal_id) && r["did_version_id"]==abandon.did_version_id).count()==1,"abandonment lacks its unique real tombstone or changed PCR state");
        ensure!(!after["identity_creation_leases"].as_array().unwrap().iter().any(|r|r["lease_id"]==abandon.identity_creation_lease_id),"abandoned lease remains usable");

        let charlie=user(&deployment,"charlie").await?;
        let published_handoff=handoff(&deployment,&charlie,FoundingDeviceKey::generate("published-owner")?).await?;
        let fixture=cotest_test_support::wire::principal_registration_fixture(json!({"station_url":deployment.endpoints.coland_base_url,"gate_account_base_url":format!("{}/_arkret/gate/account",deployment.coauth.base_url()),"handoff_request_id":published_handoff.request_id,"identity_creation_lease":published_handoff.binding["identity_creation_lease"],"device_id":arkret_identifiers::new_prefixed_uuid7("ak:device:"),"trust_domain":facts.trust_domain,"initial_session":{"session_public_key":published_handoff.device_key.canonical_public_jwk()?,"audience_id":facts.service_id}}))?;
        let candidate:IdentityBindingChallengeRequestBody=serde_json::from_value(fixture["challenge_request"].clone())?;
        let anchor=&candidate.principal_registration_anchor;
        let derived=arkret_identity::validate_principal_registration_anchor(anchor)?;
        let PrincipalRegistrationAnchor::WebvhRegistration {registration_did_operation,..}=anchor;
        let native_request:DidOperationSubmitRequestBody=(**registration_did_operation).clone();
        let root_url=deployment.station.url("/_arkret/root/identity/submit-did-operation");
        let frozen_native_request=arkret_canonical::canonical_json_bytes(&native_request)?;
        let issue=||deployment.station.http().post(root_url.clone()).bearer_auth(&deployment.webvh_registration_bearer).header("Content-Type","application/json").body(frozen_native_request.clone());
        let published=cotest_test_support::operation_observation::send_json_exchange(SCOPE[2],issue()).await?;
        let accepted:DidOperationSubmitResponseBody=serde_json::from_value(published.clone())?;
        accepted.validate_accepted_for_request(&native_request)?;
        let root_replay=cotest_test_support::operation_observation::send_json_exchange(SCOPE[2],issue()).await?;
        let replayed:DidOperationSubmitResponseBody=serde_json::from_value(root_replay.clone())?;
        replayed.validate_accepted_for_request(&native_request)?;
        ensure!(replayed.accepted_at==accepted.accepted_at && replayed.operation_ref==accepted.operation_ref,"method replay changed its original acceptance");
        let history:IdentityLogListResponseBody=serde_json::from_value(expect_json(deployment.controller.get("/_arkret/root/identity/log").query(&[("did",candidate.did.as_str())]),reqwest::StatusCode::OK).await?)?;
        ensure!(history.did==candidate.did && history.entries==vec![serde_json::to_value(&native_request.operation)?],"native publication does not retain the exact method original");
        arkret_signatures::webvh::validate_webvh_history_at(&history.did,&history.entries,accepted.accepted_at)?;
        let bind=DidBindingChallengeRequestBody {request_id:arkret_identifiers::new_prefixed_uuid7("ak:request:").parse()?,identity_creation_lease_id:candidate.identity_creation_lease_id.clone(),lease_fence:candidate.lease_fence,principal_id:arkret_wire::project_did_to_core_id(&candidate.did)?,did:candidate.did.clone(),principal_registration_anchor:candidate.principal_registration_anchor.clone(),pcr_realm_id:candidate.pcr_realm_id.clone(),realm_create_payload_digest:candidate.realm_create_payload_digest.clone(),founding_authorize_payload_digest:candidate.founding_authorize_payload_digest.clone(),initial_session_request_digest:candidate.initial_session_request_digest.clone()};
        let binding=post(&charlie,deployment.coauth.base_url(),&published_handoff,SCOPE[1],"/_arkret/gate/account/did-binding-challenges",&bind).await?;
        let binding_replay=post(&charlie,deployment.coauth.base_url(),&published_handoff,SCOPE[1],"/_arkret/gate/account/did-binding-challenges",&bind).await?;
        let challenge:DidBindingChallengeResponseBody=serde_json::from_value(binding.clone())?;
        let jwk=CanonicalSessionPublicJwk::new(published_handoff.device_key.canonical_public_jwk()?)?;
        ensure!(binding==binding_replay && challenge.request_id==bind.request_id && challenge.principal_id==bind.principal_id && challenge.did==bind.did && challenge.did_version_id==native_request.operation["versionId"].as_str().context("method version absent")? && challenge.control_key_digest==derived.control_key_digest && challenge.dpop_jkt==jwk.thumbprint_sha256()? && challenge.account_subject==published_handoff.account_subject && challenge.audience_id==*deployment.station.service_id(),"published DID challenge changed its actual method or holder coordinates");
        let published_originals=ledger(&deployment.coauth.pg.connect_url).await?;
        Ok::<_,anyhow::Error>(json!({"abandon_request":abandon,"abandoned":abandoned,"abandon_replay":replay,"before":before,"fresh_authentication":fresh_original,"after_abandonment":after,"pcr_count_before":absent_before,"pcr_count_after":absent_after,"native_request":native_request,"published":published,"root_replay":root_replay,"history":history,"validated_anchor":{"principal_id":derived.principal_id,"did_version_id":derived.did_version_id,"control_key_digest":derived.control_key_digest,"method_history_head":derived.method_history_head},"binding_request":bind,"binding":binding,"binding_replay":binding_replay,"published_originals":published_originals,"processes":[deployment.coauth.server.native_process_identity()?,deployment.station.native_process_identity()?]}))
    }).await;
    retain_attempt("identity-reservations", &observations)?;
    let mut artifact = result?;
    validate_exchange_schemas(&observations, &SCOPE)?;
    artifact["case"] = json!("identity_reservations");
    artifact["format_version"] = json!(1);
    artifact["scope"] = json!(SCOPE);
    artifact["observations"] = serde_json::to_value(observations)?;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("identity-reservations.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
