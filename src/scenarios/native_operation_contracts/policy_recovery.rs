//! Recovery success is bound to native originals and the issuer's exact opaque record.
use arkret_models_crypto::{RecoveryTransactionCompletion, SecurityTransaction};
use arkret_models_identity::{IssueRecoveryCompletionGrantResponseBody, SessionGrantMetadata};

use super::*;
use crate::harness::{ClientSession, expect_json};
use crate::scenarios::_helpers::canonical_api::CanonicalApiFixture;
use crate::scenarios::human_pcr_station_binding::recovery;

const SCOPE: [&str; 6] = [
    "ak.root.identity.recovery_session.command.create.v1",
    "ak.root.identity.recovery_session.command.submit_proof.v1",
    "ak.root.identity.recovery_session.resource.get.v1",
    "ak.self.security_transaction.command.create.v1",
    "ak.self.security_transaction.resource.get.v1",
    "ak.gate.account.command.issue_recovery_completion_grant.v1",
];

pub(super) async fn run() -> Result<()> {
    let (result, observations) = observe(async {
        let deployment = crate::scenarios::agent_runtime_live::coauth_session_evidence::actual_agent_deployment("native-policy-recovery").await?;
        let http = deployment.http.clone();
        let coauth_origin = deployment.coauth.base_url().to_owned();
        let issuer_database = deployment.coauth.pg.connect_url.clone();
        let fixture = CanonicalApiFixture::from_owned(deployment.station, deployment.controller, deployment.http, deployment.endpoints, deployment.oidc_client_id);
        let authority = recovery::prepare_recovery_authority(&fixture.client).await?;
        let policy = crate::scenarios::mls_lifecycle_live::accepted_full_view(&fixture.client, &authority.policy_event.event_id).await?;
        ensure!(policy.event == authority.policy_event, "policy admission changed the signed original");
        let completed = recovery::complete_native(&fixture, &authority.method, authority.seed).await?;
        let url = format!("{coauth_origin}/_arkret/gate/account/recovery-session-grants/issue");
        let issue = || -> Result<_> {
            let proof = arkret_signatures::dpop::build_dpop_proof(
                &arkret_signatures::dpop::DpopProofRequest::new("POST", &url).access_token(&completed.handoff.account_handoff_grant),
                &completed.handoff.device_key.signing_key(),
            )?.proof_jwt;
            Ok(http.post(&url).header("Arkret-Operation", SCOPE[5]).header("Authorization", format!("DPoP {}", completed.handoff.account_handoff_grant)).header("DPoP", proof).json(&completed.request))
        };
        let issued = cotest_test_support::operation_observation::send_json_exchange(SCOPE[5], issue()?).await?;
        let replay = cotest_test_support::operation_observation::send_json_exchange(SCOPE[5], issue()?).await?;
        ensure!(issued == replay, "completion replay changed the original issuance");
        let response: IssueRecoveryCompletionGrantResponseBody = serde_json::from_value(issued.clone())?;
        let grant = response.issued_session;
        grant.validate_binding(
            &completed.request.terminal_receipt.session_grant_ref.issuer_id,
            &completed.request.terminal_receipt.account_id,
            &completed.request.initial_session.audience_id,
            &completed.request.initial_session.session_public_key,
            chrono::Utc::now(),
        )?;
        garth::SessionGrantState::from_initial_registration_outcome(&completed.request.initial_session, grant.clone(), response.issued_at)?;
        let native = &completed.completion;
        let c = &native.completion_attestation;
        let mut principal = completed.candidate.principal.clone().context("replacement custody absent")?;
        principal.founding_authorize_event_id = c.device_authorization_event_ref.event_id.clone();
        let ClientSession::Canonical { signing_key, .. } = completed.candidate.session() else { anyhow::bail!("native recovery requires canonical holder custody") };
        let client = fixture.server.actor_client(principal.did.as_str(), principal.device_id.as_str(), ClientSession::Canonical { grant: grant.session_grant.as_str().to_owned(), signing_key: signing_key.clone() }, Some(principal.clone()))?;
        let transaction: SecurityTransaction = serde_json::from_value(expect_json(client.get(&format!("/_arkret/self/security-transactions/{}", c.transaction_id)), reqwest::StatusCode::OK).await?)?;
        ensure!(matches!(&transaction, SecurityTransaction::Recovery(value) if value == native), "resource lost the full original signed R or C");
        let authorize = crate::scenarios::mls_lifecycle_live::accepted_full_view(&client, &c.device_authorization_event_ref.event_id).await?;
        let reanchor = crate::scenarios::mls_lifecycle_live::accepted_full_view(&client, &c.reanchor_event_ref.event_id).await?;
        ensure!(authorize.commit.realm_id == policy.commit.realm_id && reanchor.commit.realm_id == policy.commit.realm_id
            && authorize.commit.governance_generation == policy.commit.governance_generation, "Human recovery changed PCR lineage or governor");
        let hpke = arkret_crypto::identity_root::derive_identity_recovery_key_material(&principal.device_signing_key.to_bytes(), 0)?;
        ensure!(principal.device_hpke_private_key.as_ref().context("replacement HPKE custody absent")?.as_slice() == hpke.backup_hpke_serialized_private_key.as_slice(), "replacement HPKE custody differs from its submitted key");
        let station_database = fixture.server.configured_database_url().context("owned Station database absent")?.to_owned();
        let transaction_id = c.transaction_id.to_string();
        let issuer_id = grant.issuer_id.to_string();
        let principal_id = grant.account_id.principal_id.to_string();
        let account_station_id = grant.account_id.station_id.to_string();
        let token = grant.session_grant.as_str().to_owned();
        let originals = tokio::task::spawn_blocking(move || -> Result<Value> {
            let mut station = postgres::Client::connect(&station_database, postgres::NoTls)?;
            let raw_id = transaction_id.strip_prefix("ak:transaction:").context("transaction id prefix")?;
            let transaction = station.query_one("SELECT to_jsonb(t), canonical_request FROM security_transactions t WHERE id::text=$1 AND principal_id=$2 AND station_id=$3", &[&raw_id,&principal_id,&account_station_id])?;
            let canonical: Vec<u8> = transaction.get(1);
            let sessions = station.query("SELECT to_jsonb(s) FROM recovery_sessions s WHERE transaction_id::text=$1", &[&raw_id])?.into_iter().map(|row|row.get::<_,Value>(0)).collect::<Vec<_>>();
            let steps = station.query("SELECT to_jsonb(s) FROM security_transaction_step_outcomes s WHERE transaction_id::text=$1", &[&raw_id])?.into_iter().map(|row|row.get::<_,Value>(0)).collect::<Vec<_>>();
            let mut issuer = postgres::Client::connect(&issuer_database, postgres::NoTls)?;
            let issuance = issuer.query_one("SELECT to_jsonb(i), canonical_request, canonical_outcome FROM recovery_completion_grant_issuances i WHERE issuer_id=$1 AND principal_id=$2 AND account_station_id=$3 AND transaction_id=$4", &[&issuer_id,&principal_id,&account_station_id,&transaction_id])?;
            let request: Vec<u8> = issuance.get(1);
            let outcome: Vec<u8> = issuance.get(2);
            let grant = issuer.query_one("SELECT to_jsonb(g), canonical_metadata FROM oauth_session_grants g WHERE issuer_id=$1 AND session_grant=$2", &[&issuer_id,&token])?;
            let metadata_bytes: Vec<u8> = grant.get(1);
            let metadata: SessionGrantMetadata = serde_json::from_slice(&metadata_bytes)?;
            metadata.validate()?;
            ensure!(arkret_canonical::canonical_json_bytes(&metadata)? == metadata_bytes, "issuer metadata was not stored as its exact canonical record");
            Ok(json!({"transaction":transaction.get::<_,Value>(0), "transaction_request":serde_json::from_slice::<Value>(&canonical)?, "transaction_request_bytes":arkret_canonical::base64url_encode(&canonical),
                "sessions":sessions,"steps":steps,"issuance":issuance.get::<_,Value>(0),"issuance_request":serde_json::from_slice::<Value>(&request)?,"issuance_request_bytes":arkret_canonical::base64url_encode(&request),"issuance_outcome":serde_json::from_slice::<Value>(&outcome)?,"issuance_outcome_bytes":arkret_canonical::base64url_encode(&outcome),"grant":grant.get::<_,Value>(0),"metadata":metadata,"metadata_bytes":arkret_canonical::base64url_encode(&metadata_bytes)}))
        }).await??;
        let metadata: SessionGrantMetadata = serde_json::from_value(originals["metadata"].clone())?;
        let binding = metadata.device_binding.as_ref().context("completion Device binding absent")?;
        ensure!(metadata.credential_class == arkret_models_identity::SessionGrantCredentialClass::Standard
            && metadata.account_id == grant.account_id && metadata.grant_ref() == grant.grant_ref()
            && metadata.not_before <= chrono::Utc::now() && metadata.expires_at == grant.expires_at && metadata.expires_at > chrono::Utc::now()
            && metadata.cnf_jkt == completed.request.initial_session.session_public_key.thumbprint_sha256()?
            && binding.authorization_event_id == c.device_authorization_event_ref.event_id && binding.model_generation_ref == c.new_model_generation_ref,
            "completion issuer record differs from its exact accepted native authorization, generation or holder");
        let durable_native: RecoveryTransactionCompletion = serde_json::from_value(originals["transaction"]["recovery_completion"].clone())?;
        ensure!(originals["issuance_request"] == serde_json::to_value(&completed.request)? && originals["issuance_outcome"] == issued
            && durable_native == *native
            && originals["transaction"]["prepared_plan"].is_null() && originals["transaction"]["terminal_outcome"].is_null()
            && originals["steps"].as_array().is_some_and(Vec::is_empty), "Recovery native ledgers retained a prepared branch or differ from served originals");
        ensure!(originals["sessions"].as_array().is_some_and(|rows| rows.len()==1 && rows[0]["state"]=="completed"), "recovery session did not complete durably");
        Ok::<_, anyhow::Error>(json!({"policy":policy,"transaction":transaction,"completion_request":completed.request,"issued":issued,"metadata":metadata,"reanchor":reanchor,"authorize":authorize,"authority_originals":originals,"processes":[deployment.coauth.server.native_process_identity()?,fixture.server.native_process_identity()?]}))
    }).await;
    retain_attempt("account-policy-recovery", &observations)?;
    let result = result?;
    validate_exchange_schemas(&observations, &SCOPE)?;
    let views = ["policy", "reanchor", "authorize"]
        .map(|member| serde_json::from_value(result[member].clone()))
        .into_iter()
        .collect::<std::result::Result<Vec<arkret_wire::CommittedEventFullView>, _>>()?;
    verify_native_pcr_commits(&observations, &views)?;
    views[2].commit.validate_successor_of(&views[1].commit)?;
    let mut artifact = result;
    artifact["case"] = json!("account_policy_recovery");
    artifact["scope"] = json!(SCOPE);
    artifact["observations"] = serde_json::to_value(observations)?;
    if let Some(directory) = std::env::var_os("COTEST_NATIVE_OPERATION_EVIDENCE_DIR") {
        std::fs::write(
            std::path::PathBuf::from(directory).join("account-policy-recovery.json"),
            serde_json::to_vec_pretty(&artifact)?,
        )?;
    }
    for operation in SCOPE {
        println!("native operation contract passed: {operation}");
    }
    Ok(())
}
